// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type Bandwidth struct {
	connector           *vtmConnector
	BandwidthProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetBandwidth(name string) (*Bandwidth, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetBandwidth(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/bandwidth/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Bandwidth)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Bandwidth) Apply() (*Bandwidth, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewBandwidth(name string) *Bandwidth {
	object := new(Bandwidth)

	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/bandwidth/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteBandwidth(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/bandwidth/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListBandwidths() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/bandwidth")
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

type BandwidthProperties struct {
	Basic struct {
		// The maximum bandwidth to allocate to connections that are associated
		//  with this bandwidth class (in kbits/second).
		Maximum *int `json:"maximum,omitempty"`

		// A description of this bandwidth class.
		Note *string `json:"note,omitempty"`

		// The scope of the bandwidth class.
		Sharing *string `json:"sharing,omitempty"`
	} `json:"basic"`
}
