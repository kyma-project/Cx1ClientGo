package Cx1ClientGo

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	//"io/ioutil"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var cxOrigin = "Cx1-Client-GoLang"

//var astAppID string
//var tenantID string
//var tenantOwner *TenantOwner
// var cxVersion VersionInfo
//var cx1UserAgent string = "Cx1ClientGo"

// Main entry for users of this client when using OAuth Client ID & Client Secret:
func NewOAuthClient(client *http.Client, base_url string, iam_url string, tenant string, client_id string, client_secret string, logger *logrus.Logger) (*Cx1Client, error) {
	if base_url == "" || iam_url == "" || tenant == "" || client_id == "" || client_secret == "" || logger == nil {
		return nil, fmt.Errorf("unable to create client: invalid parameters provided")
	}

	if l := len(base_url); base_url[l-1:] == "/" {
		base_url = base_url[:l-1]
	}
	if l := len(iam_url); iam_url[l-1:] == "/" {
		iam_url = iam_url[:l-1]
	}

	ctx := context.Background()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	conf := &clientcredentials.Config{
		ClientID:     client_id,
		ClientSecret: client_secret,
		TokenURL:     fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant),
	}

	oauthclient := conf.Client(ctx)

	cli := Cx1Client{
		httpClient: oauthclient,
		baseUrl:    base_url,
		iamUrl:     iam_url,
		tenant:     tenant,
		logger:     logger}

	token, err := conf.Token(ctx)
	if err != nil {
		return nil, err
	} else {
		cli.parseJWT(token.AccessToken)
	}

	cli.InitializeClient(false)

	oidcclient, err := cli.GetClientByName(client_id)
	if err != nil {
		logger.Warningf("Failed to retrieve information for OIDC Client %v", client_id)
	} else {
		user, _ := cli.GetServiceAccountByID(oidcclient.ID)
		cli.user = &user
	}

	cli.IsUser = false

	return &cli, nil
}

// Main entry for users of this client when using API Key
func NewAPIKeyClient(client *http.Client, base_url string, iam_url string, tenant string, api_key string, logger *logrus.Logger) (*Cx1Client, error) {
	if base_url == "" || iam_url == "" || tenant == "" || api_key == "" || logger == nil {
		return nil, fmt.Errorf("unable to create client: invalid parameters provided")
	}

	if l := len(base_url); base_url[l-1:] == "/" {
		base_url = base_url[:l-1]
	}
	if l := len(iam_url); iam_url[l-1:] == "/" {
		iam_url = iam_url[:l-1]
	}

	ctx := context.Background()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	conf := &oauth2.Config{
		ClientID: "ast-app",
		Endpoint: oauth2.Endpoint{
			TokenURL: fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant),
		},
	}

	refreshToken := &oauth2.Token{
		AccessToken:  "",
		RefreshToken: api_key,
		Expiry:       time.Now().UTC(),
	}

	token, err := conf.TokenSource(ctx, refreshToken).Token()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return nil, err
	}

	oauthclient := conf.Client(ctx, token)

	cli := Cx1Client{
		httpClient: oauthclient,
		baseUrl:    base_url,
		iamUrl:     iam_url,
		tenant:     tenant,
		logger:     logger}

	cli.InitializeClient(false)
	cli.parseJWT(token.AccessToken)

	_, _ = cli.GetCurrentUser()
	cli.IsUser = true

	return &cli, nil
}

func ResumeAPIKeyClient(client *http.Client, base_url, iam_url, tenant, api_key, last_token string, logger *logrus.Logger) (*Cx1Client, error) {
	if base_url == "" || iam_url == "" || tenant == "" || api_key == "" || logger == nil {
		return nil, fmt.Errorf("unable to create client: invalid parameters provided")
	}

	if l := len(base_url); base_url[l-1:] == "/" {
		base_url = base_url[:l-1]
	}
	if l := len(iam_url); iam_url[l-1:] == "/" {
		iam_url = iam_url[:l-1]
	}

	ctx := context.Background()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	conf := &oauth2.Config{
		ClientID: "ast-app",
		Endpoint: oauth2.Endpoint{
			TokenURL: fmt.Sprintf("%v/auth/realms/%v/protocol/openid-connect/token", iam_url, tenant),
		},
	}

	expiry, err := parseJWTExpiry(last_token)
	if err != nil {
		logger.Warningf("Failed parsing last token: %s", err)
	}

	refreshToken := &oauth2.Token{
		AccessToken:  last_token,
		RefreshToken: api_key,
		Expiry:       expiry.UTC(),
	}

	token, err := conf.TokenSource(ctx, refreshToken).Token()
	if err != nil {
		err = fmt.Errorf("failed getting a token: %s", err)
		logger.Error(err.Error())
		return nil, err
	}

	oauthclient := conf.Client(ctx, token)

	cli := Cx1Client{
		httpClient: oauthclient,
		baseUrl:    base_url,
		iamUrl:     iam_url,
		tenant:     tenant,
		logger:     logger}

	cli.InitializeClient(true)
	cli.parseJWT(token.AccessToken)
	cli.IsUser = true

	return &cli, nil
}

// Convenience function that reads command-line flags to create the Cx1Client
func NewClient(client *http.Client, logger *logrus.Logger) (*Cx1Client, error) {
	APIKey := flag.String("apikey", "", "CheckmarxOne API Key (if not using client id/secret)")
	ClientID := flag.String("client", "", "CheckmarxOne Client ID (if not using API Key)")
	ClientSecret := flag.String("secret", "", "CheckmarxOne Client Secret (if not using API Key)")
	Cx1URL := flag.String("cx1", "", "Optional: CheckmarxOne platform URL, if not defined in the test config.yaml")
	IAMURL := flag.String("iam", "", "Optional: CheckmarxOne IAM URL, if not defined in the test config.yaml")
	Tenant := flag.String("tenant", "", "Optional: CheckmarxOne tenant, if not defined in the test config.yaml")
	flag.Parse()

	if *APIKey == "" && (*ClientID == "" || *ClientSecret == "") {
		return nil, fmt.Errorf("no credentials provided - need to supply either 'apikey' or 'client' and 'secret' parameters")
	}

	if *Cx1URL == "" || *IAMURL == "" || *Tenant == "" {
		return nil, fmt.Errorf("no server details provided - need to supply 'cx1' and 'iam' URL parameters plus 'tenant'")
	}

	if *APIKey != "" {
		return NewAPIKeyClient(client, *Cx1URL, *IAMURL, *Tenant, *APIKey, logger)
	} else {
		return NewOAuthClient(client, *Cx1URL, *IAMURL, *Tenant, *ClientID, *ClientSecret, logger)
	}
}

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

func (c Cx1Client) String() string {
	return fmt.Sprintf("%v on %v ", c.tenant, c.baseUrl)
}

func (c *Cx1Client) InitializeClient(quick bool) error {
	c.SetUserAgent("Cx1ClientGo")
	if !quick {
		_ = c.GetTenantID()
		_ = c.GetASTAppID()
		_, _ = c.GetTenantOwner()

		if err := c.RefreshFlags(); err != nil {
			c.logger.Warnf("Failed to get tenant flags: %s", err)
		}
	}
	cxVersion, err := c.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to retrieve cx1 version: %s", err)
	}
	c.version = &cxVersion

	if check, _ := c.version.CheckCxOne("3.12.7"); check >= 0 {
		c.logger.Tracef("Version %v > 3.12.7: AUDIT_QUERY_TENANT = Tenant, AUDIT_QUERY_APPLICATION = Application", c.version.CxOne)
		AUDIT_QUERY_TENANT = "Tenant"
		AUDIT_QUERY_APPLICATION = "Application"
	}

	if check, _ := c.version.CheckCxOne("3.30.45"); check >= 0 {
		c.logger.Tracef("Version %v > 3.30.0: ScanSortCreatedDescending = -created_at", c.version.CxOne)
		ScanSortCreatedDescending = "-created_at"
	}

	c.InitializeClientVars()
	c.InitializePaginationSettings()

	return nil
}

func (c *Cx1Client) RefreshFlags() error {
	var flags map[string]bool = make(map[string]bool, 0)

	c.logger.Debug("Get Cx1 tenant flags")
	var FlagResponse []struct {
		Name   string `json:"name"`
		Status bool   `json:"status"`
		// Payload interface{} `json:"payload"` // ignoring the payload for now
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/flags?filter=%v", c.tenantID), nil, nil)

	if err != nil {
		return err
	}

	err = json.Unmarshal(response, &FlagResponse)
	if err != nil {
		return err
	}

	for _, fr := range FlagResponse {
		flags[fr.Name] = fr.Status
	}

	c.flags = flags

	return nil
}

func (c *Cx1Client) parseJWT(jwtToken string) error {
	_, err := jwt.ParseWithClaims(jwtToken, &c.claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(nil), nil
	})
	return err
}

func parseJWTExpiry(last_token string) (time.Time, error) {
	// Parse the JWT token to get the claims
	parser := new(jwt.Parser)
	tokenClaims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(last_token, &tokenClaims)
	if err != nil {
		return time.Now(), fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Extract the expiration time from the claims
	if exp, ok := tokenClaims["exp"]; ok {
		switch exp := exp.(type) {
		case float64:
			return time.Unix(int64(exp), 0), nil
		case json.Number:
			expInt, err := exp.Int64()
			if err != nil {
				return time.Now(), fmt.Errorf("failed to parse exp claim as int64: %v", err)
			}
			return time.Unix(expInt, 0), nil
		default:
			return time.Now(), fmt.Errorf("unexpected type for exp claim: %T", exp)
		}
	} else {
		return time.Now(), fmt.Errorf("exp claim not found in JWT token")
	}
}

func (c Cx1Client) GetFlags() map[string]bool {
	return c.flags
}

func (c Cx1Client) GetLicense() ASTLicense {
	return c.claims.Cx1License
}

func (c Cx1Client) GetClaims() Cx1Claims {
	return c.claims
}

func (c Cx1Client) IsEngineAllowed(engine string) bool {
	for _, eng := range c.claims.Cx1License.LicenseData.AllowedEngines {
		if strings.EqualFold(engine, eng) {
			return true
		}
	}
	if strings.EqualFold(engine, "apisec") {
		return c.IsEngineAllowed("API Security")
	}
	return false
}

func (c Cx1Client) CheckFlag(flag string) (bool, error) {
	setting, ok := c.flags[flag]
	if !ok {
		return false, fmt.Errorf("no such flag: %v", flag)
	}

	return setting, nil
}

func (c *Cx1Client) GetTenantOwner() (TenantOwner, error) {
	if c.tenantOwner != nil {
		return *c.tenantOwner, nil
	}

	var owner TenantOwner

	response, err := c.sendRequestIAM(http.MethodGet, "/auth", "/owner", nil, nil)
	if err != nil {
		return owner, err
	}

	err = json.Unmarshal(response, &owner)
	if err == nil {
		c.tenantOwner = &owner
	}
	return owner, err
}

func (c Cx1Client) GetVersion() (VersionInfo, error) {
	if c.version != nil {
		return *c.version, nil
	}

	var v VersionInfo
	response, err := c.sendRequest(http.MethodGet, "/versions", nil, nil)
	if err != nil {
		return v, err
	}

	err = json.Unmarshal(response, &v)
	if err != nil {
		return v, err
	}

	v.Parse()
	return v, nil
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

func (c *Cx1Client) GetAccessToken() (string, error) {
	if c.httpClient == nil {
		return "", fmt.Errorf("http client is not initialized")
	}

	// Check if the Transport is an oauth2.Transport
	transport, ok := c.httpClient.Transport.(*oauth2.Transport)
	if !ok {
		return "", fmt.Errorf("http client's transport is not an oauth2.Transport or *Transport")
	}

	// Get the TokenSource from the Transport
	tokenSource := transport.Source

	// Get the current token from the TokenSource
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token from TokenSource: %w", err)
	}

	return token.AccessToken, nil
}
