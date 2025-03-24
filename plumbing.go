package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// this file is for cx1clientgo internal functionality like sending HTTP requests

func (c Cx1Client) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	for name, headers := range *header {
		for _, h := range headers {
			request.Header.Add(name, h)
		}
	}

	//request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.authToken))
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", c.cx1UserAgent)
	}

	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	return request, nil
}

func (c Cx1Client) sendRequestInternal(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	response, err := c.sendRequestRaw(method, url, body, header)
	var resBody []byte
	if response != nil && response.Body != nil {
		resBody, _ = io.ReadAll(response.Body)
		response.Body.Close()
	}

	return resBody, err
}

func (c Cx1Client) sendRequestRaw(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	var requestBody io.Reader
	var bodyBytes []byte

	c.logger.Tracef("Sending %v request to URL %v", method, url)

	if body != nil {
		closer := io.NopCloser(body)
		bodyBytes, _ := io.ReadAll(closer)
		requestBody = bytes.NewBuffer(bodyBytes)
		defer closer.Close()
	}

	request, err := c.createRequest(method, url, requestBody, &header, nil)
	if err != nil {
		c.logger.Tracef("Unable to create request: %s", err)
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		// special handling: some proxies terminate connections resulting in a "remote error: tls: user canceled" failures
		// the request actually succeeded and there is likely to be data in the response
		if err.Error() == "remote error: tls: user canceled" {
			c.logger.Warnf("Potentially benign error from HTTP connection: %s", err)
			// continue processing as normal below
		} else {
			c.logger.Tracef("Failed HTTP request: '%s'", err)
			var resBody []byte
			if response != nil && response.Body != nil {
				resBody, _ = io.ReadAll(response.Body)
			}
			c.recordRequestDetailsInErrorCase(bodyBytes, resBody)

			return response, err
		}
	}
	if response.StatusCode >= 400 {
		resBody, _ := io.ReadAll(response.Body)
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		var msg map[string]interface{}
		err = json.Unmarshal(resBody, &msg)
		if err == nil {
			var str string
			if msg["message"] != nil {
				str = msg["message"].(string)
			} else if msg["error_description"] != nil {
				str = msg["error_description"].(string)
			} else if msg["error"] != nil {
				str = msg["error"].(string)
			} else if msg["errorMessage"] != nil {
				str = msg["errorMessage"].(string)
			} else {
				if len(str) > 20 {
					str = string(resBody)[:20]
				} else {
					str = string(resBody)
				}
			}
			return response, fmt.Errorf("HTTP %v: %v", response.Status, str)
		} else {
			str := string(resBody)
			if len(str) > 20 {
				str = str[:20]
			}
			return response, fmt.Errorf("HTTP %v: %s", response.Status, str)
		}
		//return response, fmt.Errorf("HTTP Response: " + response.Status)
	}

	return response, nil
}

func (c Cx1Client) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
	return c.sendRequestInternal(method, cx1url, body, header)
}

func (c Cx1Client) sendRequestRawCx1(method, url string, body io.Reader, header http.Header) (*http.Response, error) {
	cx1url := fmt.Sprintf("%v/api%v", c.baseUrl, url)
	return c.sendRequestRaw(method, cx1url, body, header)
}

func (c Cx1Client) sendRequestIAM(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c Cx1Client) sendRequestRawIAM(method, base, url string, body io.Reader, header http.Header) (*http.Response, error) {
	iamurl := fmt.Sprintf("%v%v/realms/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestRaw(method, iamurl, body, header)
}

// not sure what to call this one? used for /console/ calls, not part of the /realms/ path
func (c Cx1Client) sendRequestOther(method, base, url string, body io.Reader, header http.Header) ([]byte, error) {
	iamurl := fmt.Sprintf("%v%v/%v%v", c.iamUrl, base, c.tenant, url)
	return c.sendRequestInternal(method, iamurl, body, header)
}

func (c Cx1Client) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte) {
	if len(requestBody) != 0 {
		c.logger.Tracef("Request body: %s", string(requestBody))
	}
	if len(responseBody) != 0 {
		c.logger.Tracef("Response body: %s", string(responseBody))
	}
}

func parseJWT(jwtToken string) (claims Cx1Claims, err error) {
	_, err = jwt.ParseWithClaims(jwtToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(nil), nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		err = fmt.Errorf("failed to parse cx1 jwt token: %v", err)
		return
	}

	if claims.ISS != "" {
		var issURL *url.URL
		issURL, err = url.Parse(claims.ISS)
		if err != nil {
			err = fmt.Errorf("failed to parse iss claim as URL: %v", err)
			return
		}

		if claims.IAMURL == "" {
			claims.IAMURL = fmt.Sprintf("%v://%v", issURL.Scheme, issURL.Host)
		}

		parts := strings.Split(issURL.Path, "/")
		if claims.TenantName == "" {
			claims.TenantName = parts[len(parts)-1:][0]
		}
	}

	if claims.Expiry != 0 {
		claims.ExpiryTime = time.Unix(claims.Expiry, 0)
	}

	return
}

func (c Cx1Client) GetUserAgent() string {
	return c.cx1UserAgent
}
func (c *Cx1Client) SetUserAgent(ua string) {
	c.cx1UserAgent = ua
}

// this function set the U-A to be the old one that was previously default in Cx1ClientGo
func (c *Cx1Client) SetUserAgentFirefox() {
	c.cx1UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"
}
