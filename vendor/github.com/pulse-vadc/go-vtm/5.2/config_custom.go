// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type Custom struct {
	connector        *vtmConnector
	CustomProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetCustom(name string) (*Custom, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetCustom(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/custom/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Custom)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Custom) Apply() (*Custom, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewCustom(name string) *Custom {
	object := new(Custom)

	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/custom/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteCustom(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/custom/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListCustoms() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/custom")
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

type CustomProperties struct {
	Basic struct {
		// This table contains named lists of strings
		StringLists *CustomStringListsTable `json:"string_lists,omitempty"`
	} `json:"basic"`
}

type CustomStringLists struct {
	// Name of list
	Name *string `json:"name,omitempty"`

	// Named list of user-specified strings.
	Value *[]string `json:"value,omitempty"`
}

type CustomStringListsTable []CustomStringLists
