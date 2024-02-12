package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Clients
func (c Cx1Client) GetClients() ([]OIDCClient, error) {
	c.logger.Debug("Getting OIDC Clients")
	var clients []OIDCClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/clients?briefRepresentation=true", nil, nil)
	if err != nil {
		return clients, err
	}

	err = json.Unmarshal(response, &clients)
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

	err = json.Unmarshal(response, &client)
	return client, err
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

func (c Cx1Client) CreateClient(name string, notificationEmails []string, secretExpiration int) (OIDCClient, error) {
	c.logger.Debugf("Creating OIDC client with name %v", name)

	body := map[string]interface{}{
		"enabled": true,
		"attributes": map[string]interface{}{
			"lastUpdate":                    time.Now().UnixMilli(),
			"client.secret.creation.time":   time.Now().Unix(),
			"client.secret.expiration.time": time.Now().AddDate(0, 0, secretExpiration).Unix(),
			"notificationEmail":             notificationEmails,
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
	return newClient, err
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
