// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.2.
package vtm

import (
	"encoding/json"
)

type UserGroup struct {
	connector           *vtmConnector
	UserGroupProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetUserGroup(name string) (*UserGroup, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetUserGroup(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/user_groups/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(UserGroup)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object UserGroup) Apply() (*UserGroup, *vtmErrorResponse) {
	marshalled, err := json.Marshal(object)
	if err != nil {
		panic(err)
	}
	data, ok := object.connector.put(string(marshalled), STANDARD_OBJ)
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	if err := json.NewDecoder(data).Decode(&object); err != nil {
		panic(err)
	}
	return &object, nil
}

func (vtm VirtualTrafficManager) NewUserGroup(name string) *UserGroup {
	object := new(UserGroup)

	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/user_groups/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteUserGroup(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/user_groups/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListUserGroups() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/user_groups")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	objectList := new(vtmObjectChildren)
	if err := json.NewDecoder(data).Decode(objectList); err != nil {
		panic(err)
	}
	var stringList []string
	for _, obj := range objectList.Children {
		stringList = append(stringList, obj.Name)
	}
	return &stringList, nil
}

type UserGroupProperties struct {
	Basic struct {
		// A description for the group.
		Description *string `json:"description,omitempty"`

		// Members of this group must renew their passwords after this number
		//  of days. To disable password expiry for the group set this to
		//  "0" (zero). Note that this setting applies only to local users.
		PasswordExpireTime *int `json:"password_expire_time,omitempty"`

		// A table defining which level of permission this group has for
		//  specific configuration elements.
		Permissions *UserGroupPermissionsTable `json:"permissions,omitempty"`

		// Inactive UI sessions will timeout after this number of seconds.
		//  To disable inactivity timeouts for the group set this to "0"
		//  (zero).
		Timeout *int `json:"timeout,omitempty"`
	} `json:"basic"`
}

type UserGroupPermissions struct {
	// Permission level for the configuration element (none, ro or full)
	AccessLevel *string `json:"access_level,omitempty"`

	// Configuration element to which this group has a level of permission.
	Name *string `json:"name,omitempty"`
}

type UserGroupPermissionsTable []UserGroupPermissions
