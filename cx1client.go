package Cx1ClientGo

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	//"io/ioutil"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var cxOrigin = "Cx1-Golang-Client"
var astAppID string
var tenantID string
var tenantOwner *TenantOwner
var cxVersion VersionInfo

// Main entry for users of this client when using OAuth Client ID & Client Secret:
func NewOAuthClient(client *http.Client, base_url string, iam_url string, tenant string, client_id string, client_secret string, logger *logrus.Logger) (*Cx1Client, error) {
	if base_url == "" || iam_url == "" || tenant == "" || client_id == "" || client_secret == "" || logger == nil {
		return nil, fmt.Errorf("unable to create client: invalid parameters provided")
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

	cli.InitializeClient()

	user, _ := cli.GetServiceAccountByID(client_id)
	cli.user = &user

	return &cli, nil
}

// Main entry for users of this client when using API Key
func NewAPIKeyClient(client *http.Client, base_url string, iam_url string, tenant string, api_key string, logger *logrus.Logger) (*Cx1Client, error) {
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

	cli.InitializeClient()
	cli.parseJWT(token.AccessToken)

	_, _ = cli.GetCurrentUser()

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
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0")
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

func (c *Cx1Client) InitializeClient() {
	_ = c.GetTenantID()
	_ = c.GetASTAppID()
	_, _ = c.GetTenantOwner()
	cxVersion, _ = c.GetVersion()
	if cxVersion.CheckCxOne("3.12.7") >= 0 {
		AUDIT_QUERY_TENANT = "Tenant"
		AUDIT_QUERY_APPLICATION = "Application"
	}

	err := c.RefreshFlags()
	if err != nil {
		c.logger.Warnf("Failed to get tenant flags: %s", err)
	}

	c.consts.MigrationPollingMaxSeconds = 300 // 5 min
	c.consts.MigrationPollingDelaySeconds = 30

	c.consts.AuditEnginePollingMaxSeconds = 300 // 5 min
	c.consts.AuditEnginePollingDelaySeconds = 30

	c.consts.AuditScanPollingMaxSeconds = 600 // 10 min
	c.consts.AuditScanPollingDelaySeconds = 30

	c.consts.AuditCompilePollingMaxSeconds = 600 // 10 min
	c.consts.AuditCompilePollingDelaySeconds = 30

	c.consts.AuditLanguagePollingMaxSeconds = 300 // 5 min
	c.consts.AuditLanguagePollingDelaySeconds = 30

	c.consts.ScanPollingMaxSeconds = 0
	c.consts.ScanPollingDelaySeconds = 30

	c.consts.ProjectApplicationLinkPollingDelaySeconds = 5
	c.consts.ProjectApplicationLinkPollingMaxSeconds = 300 // 5 min
}

func (c *Cx1Client) RefreshFlags() error {
	var flags map[string]bool = make(map[string]bool, 0)

	c.logger.Debug("Get Cx1 tenant flags")
	var FlagResponse []struct {
		Name   string `json:"name"`
		Status bool   `json:"status"`
		// Payload interface{} `json:"payload"` // ignoring the payload for now
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/flags?filter=%v", tenantID), nil, nil)

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

func (c Cx1Client) GetClientVars() ClientVars {
	c.logger.Debug("Retrieving client vars - polling limits set in seconds")
	return c.consts
}

func (c *Cx1Client) SetClientVars(clientvars ClientVars) {
	c.consts = clientvars
}

func (c Cx1Client) GetTenantOwner() (TenantOwner, error) {
	if tenantOwner != nil {
		return *tenantOwner, nil
	}

	var owner TenantOwner

	response, err := c.sendRequestIAM(http.MethodGet, "/auth", "/owner", nil, nil)
	if err != nil {
		return owner, err
	}

	err = json.Unmarshal(response, &owner)
	if err == nil {
		tenantOwner = &owner
	}
	return owner, err
}

func (c Cx1Client) GetVersion() (VersionInfo, error) {
	var v VersionInfo
	response, err := c.sendRequest(http.MethodGet, "/versions", nil, nil)
	if err != nil {
		return v, err
	}

	err = json.Unmarshal(response, &v)
	return v, err
}

func (v VersionInfo) String() string {
	return fmt.Sprintf("CxOne %v, SAST %v, KICS %v", v.CxOne, v.SAST, v.KICS)
}

// version check returns -1 (current cx1 version lower), 0 (equal), 1 (current cx1 version greater)
func (v VersionInfo) CheckCxOne(version string) int {
	check := versionStringToInts(version)
	cx1 := versionStringToInts(v.CxOne)

	if check[0] < cx1[0] {
		return 1
	} else if check[0] > cx1[0] {
		return -1
	} else {
		if check[1] < cx1[1] {
			return 1
		} else if check[1] > cx1[1] {
			return -1
		} else {
			if check[2] < cx1[2] {
				return 1
			} else if check[2] > cx1[2] {
				return -1
			} else {
				return 0
			}
		}
	}
}

func versionStringToInts(version string) []int64 {
	if version == "" {
		return []int64{0, 0, 0}
	}
	str := strings.Split(version, ".")
	ints := make([]int64, len(str))
	for id, val := range str {
		ints[id], _ = strconv.ParseInt(val, 10, 64)
	}
	return ints
}
