// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type UserAuthenticator struct {
	connector                   *vtmConnector
	UserAuthenticatorProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetUserAuthenticator(name string) (*UserAuthenticator, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetUserAuthenticator(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/user_authenticators/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(UserAuthenticator)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object UserAuthenticator) Apply() (*UserAuthenticator, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewUserAuthenticator(name string, typeParam string) *UserAuthenticator {
	object := new(UserAuthenticator)
	object.Basic.Type = &typeParam
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/user_authenticators/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteUserAuthenticator(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/user_authenticators/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListUserAuthenticators() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/user_authenticators")
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

type UserAuthenticatorProperties struct {
	Basic struct {
		// A description of the authenticator.
		Description *string `json:"description,omitempty"`

		// Whether or not this authenticator is enabled.
		Enabled *bool `json:"enabled,omitempty"`

		// The type and protocol used by this authentication service.
		Type *string `json:"type,omitempty"`
	} `json:"basic"`

	Ldap struct {
		// The base DN (Distinguished Name) under which directory searches
		//  will be applied.  The entries for your users should all appear
		//  under this DN. An example of a typical base DN is: "OU=users,
		//  DC=mycompany, DC=local"
		BaseDn *string `json:"base_dn,omitempty"`

		// Template to construct the bind DN (Distinguished Name) from the
		//  username. The string "%u" will be replaced by the username.
		//  Examples: "%u@mycompany.local" for Active Directory or "cn=%u,
		//  dc=mycompany, dc=local" for both LDAP and Active Directory.
		BindDn *string `json:"bind_dn,omitempty"`

		// The bind DN (Distinguished Name) for a user can either be searched
		//  for in the directory using the *base distinguished name* and
		//  *filter* values, or it can be constructed from the username.
		DnMethod *string `json:"dn_method,omitempty"`

		// If the *group attribute* is not defined, or returns no results
		//  for the user logging in, the group named here will be used. If
		//  not specified, users will be denied access to the traffic manager
		//  if no groups matching a Permission Group can be found for them
		//  in the directory.
		FallbackGroup *string `json:"fallback_group,omitempty"`

		// A filter that can be used to extract a unique user record located
		//  under the base DN (Distinguished Name).  The string "%u" will
		//  be replaced by the username. This filter is used to find a user's
		//  bind DN when *dn_method* is set to "Search", and to extract group
		//  information if the *group filter* is not specified. Examples:
		//  "sAMAccountName=%u" for Active Directory, or "uid=%u" for some
		//  Unix LDAP schemas.
		Filter *string `json:"filter,omitempty"`

		// The LDAP attribute that gives a user's group. If there are multiple
		//  entries for the attribute all will be extracted and they'll be
		//  lexicographically sorted, then the first one to match a Permission
		//  Group name will be used.
		GroupAttribute *string `json:"group_attribute,omitempty"`

		// The sub-field of the group attribute that gives a user's group.
		//  For example, if *group_attribute* is "memberOf" and this retrieves
		//  values of the form "CN=mygroup, OU=groups, OU=users, DC=mycompany,
		//  DC=local" you would set group_field to "CN".  If there are multiple
		//  matching fields only the first matching field will be used.
		GroupField *string `json:"group_field,omitempty"`

		// If the user record returned by *filter* does not contain the
		//  required group information you may specify an alternative group
		//  search filter here. This will usually be required if you have
		//  Unix/POSIX-style user records. If multiple records are returned
		//  the list of group names will be extracted from all of them. The
		//  string "%u" will be replaced by the username. Example: "(&(memberUid=%u)(objectClass=posixGroup))"
		GroupFilter *string `json:"group_filter,omitempty"`

		// The port to connect to the LDAP server on.
		Port *int `json:"port,omitempty"`

		// The bind DN (Distinguished Name) to use when searching the directory
		//  for a user's bind DN.  You can leave this blank if it is possible
		//  to perform the bind DN search using an anonymous bind.
		SearchDn *string `json:"search_dn,omitempty"`

		// If binding to the LDAP server using "search_dn" requires a password,
		//  enter it here.
		SearchPassword *string `json:"search_password,omitempty"`

		// The IP or hostname of the LDAP server.
		Server *string `json:"server,omitempty"`

		// Connection timeout in seconds.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"ldap"`

	Radius struct {
		// If no group is found using the vendor and group identifiers,
		//  or the group found is not valid, the group specified here will
		//  be used.
		FallbackGroup *string `json:"fallback_group,omitempty"`

		// The RADIUS identifier for the attribute that specifies an account's
		//  group.  May be left blank if *fallback group* is specified.
		GroupAttribute *int `json:"group_attribute,omitempty"`

		// The RADIUS identifier for the vendor of the RADIUS attribute
		//  that specifies an account's group.  Leave blank if using a standard
		//  attribute (i.e. for Filter-Id set group_attribute to 11).
		GroupVendor *int `json:"group_vendor,omitempty"`

		// This value is sent to the RADIUS server.
		NasIdentifier *string `json:"nas_identifier,omitempty"`

		// This value is sent to the RADIUS server, if left blank the address
		//  of the interfaced used to connect to the server will be used.
		NasIpAddress *string `json:"nas_ip_address,omitempty"`

		// The port to connect to the RADIUS server on.
		Port *int `json:"port,omitempty"`

		// Secret key shared with the RADIUS server.
		Secret *string `json:"secret,omitempty"`

		// The IP or hostname of the RADIUS server.
		Server *string `json:"server,omitempty"`

		// Connection timeout in seconds.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"radius"`

	TacacsPlus struct {
		// Authentication type to use.
		AuthType *string `json:"auth_type,omitempty"`

		// If "group_service" is not used, or no group value is provided
		//  for the user by the TACACS+ server, the group specified here
		//  will be used. If this is not specified, users with no TACACS+
		//  defined group will be denied access.
		FallbackGroup *string `json:"fallback_group,omitempty"`

		// The TACACS+ "service" field that provides each user's group.
		GroupField *string `json:"group_field,omitempty"`

		// The TACACS+ "service" that provides each user's group field.
		GroupService *string `json:"group_service,omitempty"`

		// The port to connect to the TACACS+ server on.
		Port *int `json:"port,omitempty"`

		// Secret key shared with the TACACS+ server.
		Secret *string `json:"secret,omitempty"`

		// The IP or hostname of the TACACS+ server.
		Server *string `json:"server,omitempty"`

		// Connection timeout in seconds.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"tacacs_plus"`
}
