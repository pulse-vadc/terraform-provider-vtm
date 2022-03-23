// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 7.1.
package vtm

import (
	"encoding/json"
)

type RuleAuthenticator struct {
	connector                   *vtmConnector
	RuleAuthenticatorProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetRuleAuthenticator(name string) (*RuleAuthenticator, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetRuleAuthenticator(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/rule_authenticators/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(RuleAuthenticator)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object RuleAuthenticator) Apply() (*RuleAuthenticator, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewRuleAuthenticator(name string) *RuleAuthenticator {
	object := new(RuleAuthenticator)

	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/rule_authenticators/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteRuleAuthenticator(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/rule_authenticators/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListRuleAuthenticators() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/rule_authenticators")
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

type RuleAuthenticatorProperties struct {
	Basic struct {
		// The hostname or IP address of the remote authenticator.
		Host *string `json:"host,omitempty"`

		// A description of the authenticator.
		Note *string `json:"note,omitempty"`

		// The port on which the remote authenticator should be contacted.
		Port *int `json:"port,omitempty"`
	} `json:"basic"`

	Ldap struct {
		// A list of attributes to return from the search. If blank, no
		//  attributes will be returned. If set to '*' then all user attributes
		//  will be returned.
		Attributes *[]string `json:"attributes,omitempty"`

		// The distinguished name (DN) of the 'bind' user. The traffic manager
		//  will connect to the LDAP server as this user when searching for
		//  user records.
		BindDn *string `json:"bind_dn,omitempty"`

		// The password for the bind user.
		BindPassword *string `json:"bind_password,omitempty"`

		// The filter used to locate the LDAP record for the user being
		//  authenticated. Any occurrences of '"%u"' in the filter will be
		//  replaced by the name of the user being authenticated.
		Filter *string `json:"filter,omitempty"`

		// The base distinguished name (DN) under which user records are
		//  located on the server.
		FilterBaseDn *string `json:"filter_base_dn,omitempty"`

		// The SSL certificate that the traffic manager should use to validate
		//  the remote server. If no certificate is specified then no signature
		//  validation will be performed.
		SslCert *string `json:"ssl_cert,omitempty"`

		// Whether or not to enable SSL encryption to the LDAP server.
		SslEnabled *bool `json:"ssl_enabled,omitempty"`

		// The type of LDAP SSL encryption to use.
		SslType *string `json:"ssl_type,omitempty"`
	} `json:"ldap"`
}
