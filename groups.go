package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (g *Group) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(g.GroupID), g.Name)
}

func (c Cx1Client) CreateGroup(groupname string) (Group, error) {
	c.logger.Debugf("Create Group: %v ", groupname)
	data := map[string]interface{}{
		"name": groupname,
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Group{}, err
	}

	_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", "/groups", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error creating group %v: %s", groupname, err)
		return Group{}, err
	}

	return c.GetGroupByName(groupname)
}

func (c Cx1Client) CreateChildGroup(parentGroup *Group, childGroupName string) (Group, error) {
	c.logger.Debugf("Create child Group: %v ", childGroupName)
	var child_group Group
	data := map[string]interface{}{
		"name": childGroupName,
	}
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return child_group, err
	}

	response, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/groups/"+parentGroup.GroupID+"/children", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Errorf("Error creating group: %s", err)
		return child_group, err
	}

	err = json.Unmarshal(response, &child_group)
	if err != nil {
		c.logger.Errorf("Error unmarshalling new child group: %s", err)
		return child_group, err
	}

	parentGroup.SubGroups = append(parentGroup.SubGroups, child_group)

	return child_group, err
}

func (c Cx1Client) GetGroupsPIP() ([]Group, error) {
	c.logger.Debug("Get cx1 groups pip")
	var groups []Group
	response, err := c.sendRequestIAM(http.MethodGet, "/auth", "/pip/groups", nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	return groups, err
}

func (c Cx1Client) GetGroupPIPByName(groupname string) (Group, error) {
	c.logger.Debugf("Get Cx1 Group by name: %v", groupname)

	groups, err := c.GetGroupsPIP()
	if err != nil {
		return Group{}, err
	}

	for _, g := range groups {
		if g.Name == groupname {
			return g, nil
		}
	}

	return Group{}, fmt.Errorf("no such group %v found", groupname)
}

// this returns all groups including all subgroups
func (c Cx1Client) GetGroups() ([]Group, error) {
	c.logger.Debug("Get Cx1 Groups")
	var groups []Group

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/groups?briefRepresentation=false&q", nil, nil)
	if err != nil {
		return groups, err
	}

	err = json.Unmarshal(response, &groups)
	c.logger.Tracef("Got %d groups", len(groups))

	if c.version.CheckCxOne("3.20.0") >= 0 { // after 3.20 there's a keycloak upgrade to 23.0.7, affecting the behavior of the group apis
		for i := range groups {
			setGroupFilled(&groups[i])
		}
	}

	return groups, err
}

func (c Cx1Client) GetGroupByName(groupname string) (Group, error) {
	c.logger.Debugf("Get Cx1 Group by name: %v", groupname)
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups?briefRepresentation=false&search=%v", url.PathEscape(groupname)), nil, nil)
	if err != nil {
		return Group{}, err
	}
	var groups []Group
	err = json.Unmarshal(response, &groups)

	if err != nil {
		c.logger.Tracef("Error retrieving group %v: %s", groupname, err)
		return Group{}, err
	}

	c.logger.Tracef("Got %d groups", len(groups))

	for i := range groups {
		if c.version.CheckCxOne("3.20.0") >= 0 {
			setGroupFilled(&groups[i])
		}
		if groups[i].Name == groupname {
			match := groups[i]
			return match, nil
		} else {
			subg, err := groups[i].FindSubgroupByName(groupname)
			if err == nil {
				return subg, nil
			}
		}
	}

	return Group{}, fmt.Errorf("no group %v found", groupname)
}

// this function returns all top-level groups matching the search string, or
// if a sub-group matches the search, it will return the parent group and only the matching subgroups
func (c Cx1Client) GetGroupsByName(groupname string) ([]Group, error) {
	c.logger.Debugf("Get Cx1 Group by name: %v", groupname)
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups?briefRepresentation=true&search=%v", url.PathEscape(groupname)), nil, nil)
	if err != nil {
		return []Group{}, err
	}
	var groups []Group
	err = json.Unmarshal(response, &groups)

	if err != nil {
		return groups, err
	} else if c.version.CheckCxOne("3.20.0") >= 0 {
		for i := range groups {
			setGroupFilled(&groups[i])
		}
	}

	return groups, nil
}

func (c Cx1Client) DeleteGroup(group *Group) error {
	c.logger.Debugf("Deleting Group %v...", group.String())
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/groups/%v", group.GroupID), nil, http.Header{})
	return err
}

func (c Cx1Client) GetGroupByID(groupID string) (Group, error) {
	c.logger.Debugf("Getting Group with ID %v...", groupID)
	var group Group

	body := url.Values{
		"briefRepresentation": {"true"},
	}

	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v?%v", groupID, body.Encode()), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching group %v failed: %s", groupID, err)
		return group, err
	}

	err = json.Unmarshal(data, &group)
	if c.version.CheckCxOne("3.20.0") == -1 && err == nil {
		group.Filled = true
	}
	return group, err
}

func (c Cx1Client) GetGroupChildren(group *Group) ([]Group, error) {
	var groups []Group
	if group.SubGroupCount == 0 {
		return groups, nil
	}

	var err error
	groups, err = c.GetGroupChildrenByID(group.GroupID, 0, group.SubGroupCount)
	if err != nil {
		return groups, err
	}
	group.SubGroups = groups
	group.Filled = true
	return groups, nil
}

func (c Cx1Client) GetGroupChildrenByID(groupID string, first, max int) ([]Group, error) {
	var groups []Group
	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v/children?briefRepresentation=false&first=%d&max=%d", groupID, first, max), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching group %v children failed: %s", groupID, err)
		return groups, err
	}

	err = json.Unmarshal(data, &groups)
	return groups, err
}

// this function returns a group matching a path, however as of keycloak 23.0.7 this endpoint
// is missing the subGroupCount field, which other parts of cx1clientgo rely on, so this function
// will automatically trigger a GetGroupByID call
func (c Cx1Client) GetGroupByPath(path string) (Group, error) {
	c.logger.Debugf("Getting Group with path %v...", path)
	var group Group

	data, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/group-by-path/%v", path), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching group %v failed: %s", path, err)
		return group, err
	}

	err = json.Unmarshal(data, &group)
	if err != nil {
		return group, err
	}
	return c.GetGroupByID(group.GroupID)
}

func (c Cx1Client) GroupLink(g *Group) string {
	return fmt.Sprintf("%v/auth/admin/%v/console/#/realms/%v/groups/%v", c.iamUrl, c.tenant, c.tenant, g.GroupID)
}

func (c Cx1Client) SetGroupParent(g *Group, parent *Group) error {
	body := map[string]string{
		"id":   g.GroupID,
		"name": g.Name,
	}
	jsonBody, _ := json.Marshal(body)
	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/groups/%v/children", parent.GroupID), bytes.NewReader(jsonBody), http.Header{})
	if err != nil {
		c.logger.Tracef("Failed to add child to parent: %s", err)
		return err
	}

	return nil
}

func (c Cx1Client) UpdateGroup(g *Group) error {
	if !g.Filled {
		if c.version.CheckCxOne("3.20.0") >= 0 {
			return fmt.Errorf("group %v data is not filled (use GetGroupChildren) - may be missing expected roles & subgroups, update aborted", g.String())
		} else {
			return fmt.Errorf("group %v data is not filled (use GetGroupByID) - may be missing expected roles & subgroups, update aborted", g.String())
		}
	}

	err := c.groupRoleChange(g)
	if err != nil {
		return fmt.Errorf("failed to update role changes for group %v: %s", g.String(), err)
	}

	jsonBody, _ := json.Marshal(*g)
	_, err = c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/groups/%v", g.GroupID), bytes.NewReader(jsonBody), http.Header{})
	return err
}

func (g *Group) AddRole(clientName, roleName string) error {
	if !g.Filled {
		return fmt.Errorf("group is not filled, first fetch the details via GetGroupByID")
	}

	if g.ClientRoles == nil {
		g.ClientRoles = make(map[string][]string)
	}

	_, ok := g.ClientRoles[clientName]
	if !ok {
		g.ClientRoles[clientName] = make([]string, 0)
	}

	for _, role := range g.ClientRoles[clientName] {
		if strings.EqualFold(role, roleName) {
			return fmt.Errorf("group already has role %v - %v", clientName, roleName)
		}
	}

	g.ClientRoles[clientName] = append(g.ClientRoles[clientName], roleName)

	return nil
}

func (g *Group) RemoveRole(clientName, roleName string) error {
	if !g.Filled {
		return fmt.Errorf("group %v is not filled, first fetch the details via GetGroupByID", g.String())
	}

	_, ok := g.ClientRoles[clientName]
	if !ok {
		return fmt.Errorf("group %v does not have the %v client", g.String(), clientName)
	}

	for id, role := range g.ClientRoles[clientName] {
		if strings.EqualFold(role, roleName) {
			return fmt.Errorf("group already has role %v - %v", clientName, roleName)
		} else {
			if id != len(g.ClientRoles[clientName])-1 {
				g.ClientRoles[clientName][id] = g.ClientRoles[clientName][len(g.ClientRoles[clientName])-1]
			}
			g.ClientRoles[clientName] = g.ClientRoles[clientName][:len(g.ClientRoles[clientName])-1]
			return nil
		}
	}

	return fmt.Errorf("group %v does not have the %v - %v role", g.String(), clientName, roleName)
}

func (c Cx1Client) groupRoleChange(g *Group) error {
	orig_group, err := c.GetGroupByID(g.GroupID)
	if err != nil {
		return fmt.Errorf("failed to get original group info for group %v: %s", g.String(), err)
	}

	add_roles := map[string][]string{}
	del_roles := map[string][]string{}

	for new_client, new_roles := range g.ClientRoles {
		if _, ok := orig_group.ClientRoles[new_client]; !ok {
			add_roles[new_client] = new_roles
		} else {
			for _, nr := range new_roles {
				found := false
				for _, or := range orig_group.ClientRoles[new_client] {
					if strings.EqualFold(nr, or) {
						found = true
						break
					}
				}
				if !found {
					add_roles[new_client] = append(add_roles[new_client], nr)
				}
			}
		}
	}

	for orig_client, orig_roles := range orig_group.ClientRoles {
		if _, ok := g.ClientRoles[orig_client]; !ok {
			del_roles[orig_client] = orig_roles
		} else {
			for _, nr := range orig_roles {
				found := false
				for _, or := range g.ClientRoles[orig_client] {
					if strings.EqualFold(nr, or) {
						found = true
						break
					}
				}
				if !found {
					del_roles[orig_client] = append(del_roles[orig_client], nr)
				}
			}
		}
	}

	err = c.DeleteRolesFromGroup(g, del_roles)
	if err != nil {
		return fmt.Errorf("failed to delete roles from group %v: %s", g.String(), err)
	}

	err = c.AddRolesToGroup(g, add_roles)
	if err != nil {
		return fmt.Errorf("failed to add roles to group %v: %s", g.String(), err)
	}

	return nil
}

/*
clientRoles map looks like: "ast-app" : { "ast-scanner", "ast-viewer" }
*/
func (c Cx1Client) DeleteRolesFromGroup(g *Group, clientRoles map[string][]string) error {
	type roleid struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var role_list []roleid

	for client, roles := range clientRoles {
		kc_client, err := c.GetClientByName(client)
		if err != nil {
			return fmt.Errorf("failed to retrieve client %v: %s", client, err)
		}

		client_role_set, err := c.GetRolesByClientID(kc_client.ID)
		if err != nil {
			return fmt.Errorf("failed to retrieve roles for client %v: %s", client, err)
		}

		for _, r := range roles {
			for _, kcr := range client_role_set {
				if strings.EqualFold(r, kcr.Name) {
					role_list = append(role_list, roleid{kcr.RoleID, kcr.Name})
				}
			}
		}

		if len(role_list) > 0 {
			jsonBody, _ := json.Marshal(role_list)
			_, err = c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/groups/%v/role-mappings/clients/%v", g.GroupID, kc_client.ID), bytes.NewReader(jsonBody), http.Header{})
			if err != nil {
				return fmt.Errorf("failed to remove roles from group %v: %s", g.String(), err)
			}
		} else {
			c.logger.Warnf("DeleteRolesFromGroup called but there are no roles to delete")
		}
	}

	return nil
}

/*
clientRoles map looks like: "ast-app" : { "ast-scanner", "ast-viewer" }
*/
func (c Cx1Client) AddRolesToGroup(g *Group, clientRoles map[string][]string) error {
	type roleid struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var role_list []roleid

	for client, roles := range clientRoles {
		kc_client, err := c.GetClientByName(client)
		if err != nil {
			return fmt.Errorf("failed to retrieve client %v: %s", client, err)
		}

		client_role_set, err := c.GetRolesByClientID(kc_client.ID) // all roles in keycloak/iam
		if err != nil {
			return fmt.Errorf("failed to retrieve roles for client %v: %s", client, err)
		}

		for _, r := range roles {
			for _, kcr := range client_role_set {
				if strings.EqualFold(r, kcr.Name) {
					role_list = append(role_list, roleid{kcr.RoleID, kcr.Name})
				}
			}
		}

		if len(role_list) > 0 {
			jsonBody, _ := json.Marshal(role_list)
			_, err = c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/groups/%v/role-mappings/clients/%v", g.GroupID, kc_client.ID), bytes.NewReader(jsonBody), http.Header{})
			if err != nil {
				return fmt.Errorf("failed to add roles to group %v: %s", g.String(), err)
			}
		} else {
			c.logger.Warnf("AddRolesToGroup called but there are no roles to add")
		}
	}

	return nil
}

func (c Cx1Client) GetGroupMembers(group *Group) ([]User, error) {
	return c.GetGroupMembersByID(group.GroupID)
}

func (c Cx1Client) GetGroupMembersByID(groupID string) ([]User, error) {
	var users []User

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/groups/%v/members", groupID), nil, http.Header{})
	if err != nil {
		c.logger.Tracef("Fetching group %v member failed: %s", groupID, err)
		return users, err
	}

	err = json.Unmarshal(response, &users)
	return users, err
}

// convenience
func (c Cx1Client) GetOrCreateGroupByName(name string) (Group, error) {
	group, err := c.GetGroupByName(name)
	if err != nil {
		group, err = c.CreateGroup(name)
		if err != nil {
			return group, err
		}
	}

	return group, nil
}

func (g *Group) FindSubgroupByName(name string) (Group, error) {
	for _, s := range g.SubGroups {
		if s.Name == name {
			return s, nil
		} else {
			subg, err := s.FindSubgroupByName(name)
			if err == nil {
				return subg, nil
			}
		}
	}

	return Group{}, fmt.Errorf("group %v does not contain subgroup named %v", g.String(), name)
}

// internal convenience, called from functions that retrieve groups including their subgroups
func setGroupFilled(group *Group) {
	if len(group.SubGroups) == int(group.SubGroupCount) {
		group.Filled = true
	}

	for i := range group.SubGroups {
		setGroupFilled(&group.SubGroups[i])
	}
}
