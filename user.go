package Cx1ClientGo

import "fmt"

func (u User) String() string {
	if u.FirstName == "" && u.LastName == "" && u.Email == "" {
		return fmt.Sprintf("[%v] %v", ShortenGUID(u.UserID), u.UserName)
	}
	return fmt.Sprintf("[%v] %v %v (%v)", ShortenGUID(u.UserID), u.FirstName, u.LastName, u.Email)
}
func (u WhoAmI) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(u.UserID), u.Name)
}

func (u User) HasRole(role *Role) (bool, error) {
	return u.HasRoleByID(role.RoleID)
}
func (u User) HasRoleByID(roleID string) (bool, error) {
	if !u.FilledRoles {
		return false, fmt.Errorf("user roles have not been retrieved, use GetUserRoles(user)")
	}

	for _, r := range u.Roles {
		if r.RoleID == roleID {
			return true, nil
		}
	}
	return false, nil
}
func (u User) HasRoleByName(role string) (bool, error) {
	if !u.FilledRoles {
		return false, fmt.Errorf("user roles have not been retrieved, use GetUserRoles(user)")
	}

	for _, r := range u.Roles {
		if r.Name == role {
			return true, nil
		}
	}
	return false, nil
}

func (u User) IsInGroup(group *Group) (bool, error) {
	return u.IsInGroupByID(group.GroupID)
}
func (u User) IsInGroupByID(groupId string) (bool, error) {
	if !u.FilledGroups {
		return false, fmt.Errorf("user groups have not been retrieved, use GetUserGroups(user)")
	}

	for _, g := range u.Groups {
		if g.GroupID == groupId {
			return true, nil
		}
	}
	return false, nil
}
func (u User) IsInGroupByName(groupName string) (bool, error) {
	if !u.FilledGroups {
		return false, fmt.Errorf("user groups have not been retrieved, use GetUserGroups(user)")
	}

	for _, g := range u.Groups {
		if g.Name == groupName {
			return true, nil
		}
	}
	return false, nil
}

func (u *User) AddGroup(client *Cx1Client, group *Group) error {
	//client.AddUserRoles( u,
	return nil
}

func (u User) Save(client *Cx1Client) error {
	return client.UpdateUser(&u)
}
func (u User) Delete(client *Cx1Client) error {
	return client.DeleteUser(&u)
}
func (u User) Link(client *Cx1Client) string {
	return client.UserLink(&u)
}
