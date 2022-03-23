// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 7.1.
package vtm

import (
	"encoding/json"
)

type AptimizerScope struct {
	connector                *vtmConnector
	AptimizerScopeProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetAptimizerScope(name string) (*AptimizerScope, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetAptimizerScope(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/aptimizer/scopes/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(AptimizerScope)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object AptimizerScope) Apply() (*AptimizerScope, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewAptimizerScope(name string) *AptimizerScope {
	object := new(AptimizerScope)

	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/aptimizer/scopes/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteAptimizerScope(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/aptimizer/scopes/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListAptimizerScopes() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/aptimizer/scopes")
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

type AptimizerScopeProperties struct {
	Basic struct {
		// If the hostnames for this scope are aliases of each other, the
		//  canonical hostname will be used for requests to the server.
		CanonicalHostname *string `json:"canonical_hostname,omitempty"`

		// The hostnames to limit acceleration to.
		Hostnames *[]string `json:"hostnames,omitempty"`

		// The root path of the application defined by this application
		//  scope.
		Root *string `json:"root,omitempty"`
	} `json:"basic"`
}
