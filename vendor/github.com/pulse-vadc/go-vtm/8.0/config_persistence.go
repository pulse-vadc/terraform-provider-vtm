// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.0.
package vtm

import (
	"encoding/json"
)

type Persistence struct {
	connector             *vtmConnector
	PersistenceProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetPersistence(name string) (*Persistence, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetPersistence(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/persistence/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Persistence)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Persistence) Apply() (*Persistence, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewPersistence(name string) *Persistence {
	object := new(Persistence)

	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/persistence/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeletePersistence(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/persistence/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListPersistences() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/persistence")
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

type PersistenceProperties struct {
	Basic struct {
		// The cookie name to use for tracking session persistence.
		Cookie *string `json:"cookie,omitempty"`

		// Whether or not the session should be deleted when a session failure
		//  occurs. (Note, setting a failure mode of 'choose a new node'
		//  implicitly deletes the session.)
		Delete *bool `json:"delete,omitempty"`

		// The action the pool should take if the session data is invalid
		//  or it cannot contact the node specified by the session.
		FailureMode *string `json:"failure_mode,omitempty"`

		// A description of the session persistence class.
		Note *string `json:"note,omitempty"`

		// When using IP-based session persistence, ensure all requests
		//  from this IPv4 subnet, specified as a prefix length, are sent
		//  to the same node. If set to 0, requests from different IPv4 addresses
		//  will be load-balanced individually.
		SubnetPrefixLengthV4 *int `json:"subnet_prefix_length_v4,omitempty"`

		// When using IP-based session persistence, ensure all requests
		//  from this IPv6 subnet, specified as a prefix length, are sent
		//  to the same node. If set to 0, requests from different IPv6 addresses
		//  will be load-balanced individually.
		SubnetPrefixLengthV6 *int `json:"subnet_prefix_length_v6,omitempty"`

		// Whether or not the cookie should be inserted in every response
		//  sent to the client when using transparent session affinity. If
		//  set to "No" then the cookie is inserted only if the corresponding
		//  request did not already contain a matching cookie.
		TransparentAlwaysSetCookie *bool `json:"transparent_always_set_cookie,omitempty"`

		// The cookie directives to include in the cookie sent when using
		//  transparent session affinity. If more than one directive is included,
		//  the semi-colon separator between them must be included in this
		//  string. The semi-colon separator between the cookie value and
		//  the first directive should not be included in this string.
		TransparentDirectives *string `json:"transparent_directives,omitempty"`

		// The type of session persistence to use.
		Type *string `json:"type,omitempty"`

		// The redirect URL to send clients to if the session persistence
		//  is configured to redirect users when a node dies.
		Url *string `json:"url,omitempty"`
	} `json:"basic"`
}
