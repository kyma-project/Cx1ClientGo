package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Roles and Clients
func (c *Cx1Client) GetClients() ([]KeyCloakClient, error) {
	c.logger.Debug("Getting KeyCloak Clients")
	var clients []KeyCloakClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/clients?briefRepresentation=true", nil, nil)
	if err != nil {
		return clients, err
	}

	err = json.Unmarshal(response, &clients)
	c.logger.Tracef("Got %d clients", len(clients))
	return clients, err
}

func (c *Cx1Client) GetClientByName(clientName string) (KeyCloakClient, error) {
	c.logger.Debugf("Getting KeyCloak client with name %v", clientName)

	var client KeyCloakClient
	clients, err := c.GetClients()
	if err != nil {
		return client, err
	}

	for _, c := range clients {
		if c.Name == clientName {
			client = c
			return client, nil
		}
	}

	return client, fmt.Errorf("no such client %v found", clientName)
}