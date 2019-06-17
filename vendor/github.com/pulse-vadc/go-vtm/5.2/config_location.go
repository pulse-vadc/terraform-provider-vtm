// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type Location struct {
	connector          *vtmConnector
	LocationProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetLocation(name string) (*Location, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetLocation(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/locations/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Location)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Location) Apply() (*Location, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewLocation(name string, id int) *Location {
	object := new(Location)
	object.Basic.Id = &id
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/locations/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteLocation(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/locations/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListLocations() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/locations")
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

type LocationProperties struct {
	Basic struct {
		// The identifier of this location.
		Id *int `json:"id,omitempty"`

		// The latitude of this location.
		Latitude *float64 `json:"latitude,omitempty"`

		// The longitude of this location.
		Longitude *float64 `json:"longitude,omitempty"`

		// A note, used to describe this location.
		Note *string `json:"note,omitempty"`

		// Does this location contain traffic managers and configuration
		//  or is it a recipient of GLB requests?
		Type *string `json:"type,omitempty"`
	} `json:"basic"`
}
