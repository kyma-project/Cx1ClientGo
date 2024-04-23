package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (c Cx1Client) GetAccessAssignmentByID(entityId, resourceId string) (AccessAssignment, error) {
	c.logger.Debugf("Getting access assignment for entityId %v and resourceId %v", entityId, resourceId)
	var aa AccessAssignment
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/?entity-id=%v&resource-id=%v", entityId, resourceId), nil, nil)

	if err != nil {
		return aa, err
	}

	err = json.Unmarshal(response, &aa)
	return aa, err
}

func (c Cx1Client) AddAccessAssignment(access AccessAssignment) error {
	c.logger.Debugf("Creating access assignment for entityId %v and resourceId %v", access.EntityID, access.ResourceID)

	type AccessAssignmentPOST struct {
		TenantID     string   `json:"tenantID"`
		EntityID     string   `json:"entityID"`
		EntityType   string   `json:"entityType"`
		EntityName   string   `json:"entityName"`
		EntityRoles  []string `json:"entityRoles"`
		ResourceID   string   `json:"resourceID"`
		ResourceType string   `json:"resourceType"`
		ResourceName string   `json:"resourceName"`
		CreatedAt    string   `json:"createdAt"`
	}

	roles := make([]string, 0)
	for _, r := range access.EntityRoles {
		roles = append(roles, r.Name)
	}

	accessPost := AccessAssignmentPOST{
		TenantID:     access.TenantID,
		EntityID:     access.EntityID,
		EntityType:   access.EntityType,
		EntityName:   access.EntityName,
		EntityRoles:  roles,
		ResourceID:   access.ResourceID,
		ResourceType: access.ResourceType,
		ResourceName: access.ResourceName,
		CreatedAt:    access.CreatedAt,
	}

	body, err := json.Marshal(accessPost)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPost, "/access-management", bytes.NewReader(body), nil)
	return err
}

func (c Cx1Client) GetEntitiesAccessToResourceByID(resourceId, resourceType string) ([]AccessAssignment, error) {
	c.logger.Debugf("Getting the entities with access assignment for resourceId %v", resourceId)
	var aas []AccessAssignment

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/entities-for?resource-id=%v&resource-type=%v", resourceId, resourceType), nil, nil)
	if err != nil {
		return aas, err
	}

	err = json.Unmarshal(response, &aas)
	return aas, err
}

/*
This function will return partially-filled structures as returned by Cx1 API. Only the EntityID, EntityType, EntityRoles.ID, ResourceID, and ResourceType values will be filled
The resulting access assignments will have the following structure:

	AccessAssignment{
		TenantID:     "",
		EntityID:     entityId, (provided in function call)
		EntityType:   entityType, (provided in function call)
		EntityName:   "",
		EntityRoles:  []AccessAssignedRole{
			AccessAssignedRole{
				Id:   "Cx1-role-ID",
				Name: "",
			}
		},
		ResourceID:   "resource-id",
		ResourceType: "resource-type",
		ResourceName: "",
		CreatedAt:    "",
	}
*/
func (c Cx1Client) GetResourcesAccessibleToEntityByID(entityId, entityType string, resourceTypes []string) ([]AccessAssignment, error) {
	var aas []AccessAssignment
	c.logger.Debugf("Getting the resources accessible to entity %v", entityId)

	type AccessAssignmentRAW struct {
		Roles        []string `json:"roles"`
		ResourceID   string   `json:"id"`
		ResourceType string   `json:"type"`
	}
	var aar []AccessAssignmentRAW

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/resources-for?entity-id=%v&entity-type=%v&resource-types=%v", entityId, entityType, strings.Join(resourceTypes, ",")), nil, nil)
	if err != nil {
		return aas, err
	}

	err = json.Unmarshal(response, &aar)
	if err != nil {
		return aas, err
	}

	aas = make([]AccessAssignment, len(aar))
	for id, a := range aar {
		aas[id] = AccessAssignment{
			EntityID:     entityId,
			EntityType:   entityType,
			ResourceID:   a.ResourceID,
			ResourceType: a.ResourceType,
		}
		aas[id].EntityRoles = make([]AccessAssignedRole, len(a.Roles))
		for rid, r := range a.Roles {
			aas[rid].EntityRoles[rid] = AccessAssignedRole{
				Id:   r,
				Name: "",
			}
		}
	}

	return aas, nil
}

func (c Cx1Client) CheckAccessToResourceByID(resourceId, resourceType, action string) (bool, error) {
	c.logger.Debugf("Checking current user access for resource %v and action %v", resourceId, action)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/has-access?resource-id=%v&resource-type=%v&action=%v", resourceId, resourceType, action), nil, nil)
	if err != nil {
		return false, err
	}

	var accessResponse struct {
		AccessGranted bool `json:"accessGranted"`
	}

	err = json.Unmarshal(response, &accessResponse)
	return accessResponse.AccessGranted, err
}

func (c Cx1Client) CheckAccessibleResources(resourceTypes []string, action string) (bool, []AccessibleResource, error) {
	c.logger.Debugf("Checking current user accessible resources for action %v", action)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/access-management/get-resources?resource-types=%v&action=%v", strings.Join(resourceTypes, ","), action), nil, nil)
	var responseStruct struct {
		All       bool                 `json:"all"`
		Resources []AccessibleResource `json:"resources"`
	}

	if err != nil {
		return responseStruct.All, responseStruct.Resources, err
	}

	err = json.Unmarshal(response, &responseStruct)
	return responseStruct.All, responseStruct.Resources, err
}

func (c Cx1Client) DeleteAccessAssignmentByID(entityId, resourceId string) error {
	c.logger.Debugf("Deleting access assignment between entity %v and resource %v", entityId, resourceId)
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/access-management?resource-id=%v&entity-id=%v", resourceId, entityId), nil, nil)
	return err
}
