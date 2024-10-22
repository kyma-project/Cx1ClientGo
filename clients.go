package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Clients
func (c Cx1Client) GetClients() ([]OIDCClient, error) {
	c.logger.Debug("Getting OIDC Clients")
	var json_clients []map[string]interface{}
	var clients []OIDCClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/clients?briefRepresentation=true", nil, nil)
	if err != nil {
		return clients, err
	}

	err = json.Unmarshal(response, &json_clients)
	if err != nil {
		return clients, err
	}

	clients = make([]OIDCClient, len(json_clients))
	for id, client := range json_clients {
		clients[id], err = clientFromMap(client)
		if err != nil {
			return clients, err
		}
	}

	c.logger.Tracef("Got %d clients", len(clients))
	return clients, err
}

func (c Cx1Client) GetClientByID(id string) (OIDCClient, error) {
	c.logger.Debugf("Getting OIDC client with ID %v", id)
	var client OIDCClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v", id), nil, nil)
	if err != nil {
		return client, err
	}

	var json_client map[string]interface{}
	err = json.Unmarshal(response, &json_client)
	if err != nil {
		return client, err
	}

	return clientFromMap(json_client)
}

func (c Cx1Client) GetClientByName(clientName string) (OIDCClient, error) {
	c.logger.Debugf("Getting OIDC client with name %v", clientName)

	var client OIDCClient
	clients, err := c.GetClients()
	if err != nil {
		return client, err
	}

	for _, c := range clients {
		if c.ClientID == clientName {
			client = c
			return client, nil
		}
	}

	return client, fmt.Errorf("no such client %v found", clientName)
}

func (c Cx1Client) GetClientSecret(client *OIDCClient) (string, error) {
	c.logger.Debugf("Getting OIDC client secret for %v", client.String())

	var responseBody struct {
		Type  string
		Value string
	}

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/client-secret", client.ID), nil, nil)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(response, &responseBody)
	if err == nil {
		client.ClientSecret = responseBody.Value
	}
	return responseBody.Value, err
}

func (c Cx1Client) CreateClient(name string, notificationEmails []string, secretExpiration int) (OIDCClient, error) {
	c.logger.Debugf("Creating OIDC client with name %v", name)

	notificationEmailsStr := "[\"" + strings.Join(notificationEmails, "\",\"") + "\"]"
	c.logger.Infof("Setting emails: %v", notificationEmailsStr)

	body := map[string]interface{}{
		"enabled": true,
		"attributes": map[string]interface{}{
			"lastUpdate":                    time.Now().UnixMilli(),
			"client.secret.creation.time":   time.Now().Unix(),
			"client.secret.expiration.time": time.Now().AddDate(0, 0, secretExpiration).Unix(),
			"notificationEmail":             notificationEmailsStr,
			"secretExpiration":              fmt.Sprintf("%d", secretExpiration),
		},
		"redirectUris":           []string{},
		"clientId":               name,
		"protocol":               "openid-connect",
		"frontchannelLogout":     true,
		"publicClient":           false,
		"serviceAccountsEnabled": true,
		"standardFlowEnabled":    false,
	}

	jsonBody, _ := json.Marshal(body)

	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/clients", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return OIDCClient{}, err
	}

	newClient, err := c.GetClientByName(name)
	if err != nil {
		return newClient, err
	}

	groupScope, err := c.GetClientScopeByName("groups")
	if err != nil {
		return newClient, fmt.Errorf("failed to get 'groups' client scope to add to new client: %s", err)
	}

	err = c.AddClientScopeByID(newClient.ID, groupScope.ID)
	if err != nil {
		return newClient, fmt.Errorf("failed to add 'groups' client scope to new client: %s", err)
	}

	err = c.SaveClient(newClient)
	return newClient, err
}

func clientFromMap(data map[string]interface{}) (OIDCClient, error) {
	var client OIDCClient

	jsonData, err := json.Marshal(data)
	if err != nil {
		return client, fmt.Errorf("failed to marshal unmarshaled json: %s", err)
	}

	err = json.Unmarshal(jsonData, &client)
	if err != nil {
		return client, fmt.Errorf("failed to re-unmarshal json: %s", err)
	}

	client.OIDCClientRaw = data
	if client.OIDCClientRaw["attributes"] != nil {
		if client.OIDCClientRaw["attributes"].(map[string]interface{})["client.secret.expiration.time"] != nil {
			timestamp := client.OIDCClientRaw["attributes"].(map[string]interface{})["client.secret.expiration.time"].(string)
			client.ClientSecretExpiry, _ = strconv.ParseUint(timestamp, 10, 64)
		}
		if client.OIDCClientRaw["attributes"].(map[string]interface{})["creator"] != nil {
			client.Creator = client.OIDCClientRaw["attributes"].(map[string]interface{})["creator"].(string)
		}
	}

	return client, nil
}

/*
The SaveClient function should be used sparingly - it will use the contents of the OIDCClient.OIDCClientRaw variable of type map[string]interface{} in the PUT request.
As a result, changes to the member variables in the OIDCClient object itself (creator & clientsecretexpiry) will not be saved using this method unless they are also updated in OIDCClientRaw.
*/
func (c Cx1Client) SaveClient(client OIDCClient) error {
	c.logger.Debugf("Updating OIDC client with name %v", client.ClientID)

	jsonBody, _ := json.Marshal(client.OIDCClientRaw)

	_, err := c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/clients/%v", client.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) AddClientScopeByID(oidcId, clientScopeId string) error {
	c.logger.Debugf("Adding client scope %v to OIDC Client %v", clientScopeId, oidcId)

	_, err := c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/clients/%v/default-client-scopes/%v", oidcId, clientScopeId), nil, nil)
	return err
}

func (c Cx1Client) DeleteClientByID(id string) error {
	c.logger.Debugf("Deleting OIDC client with ID %v", id)
	if strings.EqualFold(id, c.GetASTAppID()) {
		return fmt.Errorf("attempt to delete the ast-app client (ID: %v) prevented - this will break your tenant", id)
	}
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/clients/%v", id), nil, nil)
	return err
}

func (c Cx1Client) GetServiceAccountByID(oidcId string) (User, error) {
	c.logger.Debugf("Getting service account user behind OIDC client with ID %v", oidcId)
	var user User
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/service-account-user", oidcId), nil, nil)
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &user)
	return user, err
}

func (c Cx1Client) GetTenantID() string {
	if tenantID != "" {
		return tenantID
	}

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "", nil, nil)
	if err != nil {
		c.logger.Warnf("Failed to retrieve tenant ID: %s", err)
		return tenantID
	}

	var realms struct {
		ID    string `json:"id"`
		Realm string `json:"realm"`
	} // Sometimes this returns an array of one element? Is it possible to return multiple?

	err = json.Unmarshal(response, &realms)
	if err != nil {
		c.logger.Warnf("Failed to parse tenant ID: %s", err)
		c.logger.Tracef("Response was: %v", string(response))
		return tenantID
	}

	//for _, r := range realms {
	if realms.Realm == c.tenant {
		tenantID = realms.ID
	}
	//}
	if tenantID == "" {
		c.logger.Warnf("Failed to retrieve tenant ID: no tenant found matching %v", c.tenant)
	}

	return tenantID
}

func (c Cx1Client) GetTenantName() string {
	return c.tenant
}

func (c Cx1Client) GetClientScopes() ([]OIDCClientScope, error) {
	c.logger.Debug("Getting OIDC Client Scopes")
	var clientscopes []OIDCClientScope

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/client-scopes", nil, nil)
	if err != nil {
		return clientscopes, err
	}

	err = json.Unmarshal(response, &clientscopes)
	c.logger.Tracef("Got %d client scopes", len(clientscopes))
	return clientscopes, err
}

func (c Cx1Client) GetClientScopeByName(name string) (OIDCClientScope, error) {
	clientScopes, err := c.GetClientScopes()
	if err != nil {
		return OIDCClientScope{}, err
	}

	for _, cs := range clientScopes {
		if cs.Name == name {
			return cs, nil
		}
	}

	return OIDCClientScope{}, fmt.Errorf("client-scope %v not found", name)
}

// convenience function
func (c Cx1Client) GetASTAppID() string {
	if astAppID == "" {
		client, err := c.GetClientByName("ast-app")
		if err != nil {
			c.logger.Warnf("Error finding AST App ID: %s", err)
			return ""
		}

		astAppID = client.ID
	}

	return astAppID
}

func (c Cx1Client) RegenerateClientSecret(client OIDCClient) (string, error) {
	clientId := client.ID
	body := map[string]interface{}{
		"realm":  c.tenant,
		"client": clientId,
	}

	type RespBody struct {
		Type  string
		Value string
	}
	var secretResponse RespBody

	jsonBody, _ := json.Marshal(body)

	response, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/clients/%s/client-secret", clientId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(response, &secretResponse)
	if err != nil {
		return "", err
	}

	return secretResponse.Value, nil
}

func (client OIDCClient) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(client.ID), client.ClientID)
}
