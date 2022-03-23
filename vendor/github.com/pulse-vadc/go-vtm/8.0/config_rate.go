// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.0.
package vtm

import (
	"encoding/json"
)

type Rate struct {
	connector      *vtmConnector
	RateProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetRate(name string) (*Rate, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetRate(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/rate/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Rate)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Rate) Apply() (*Rate, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewRate(name string) *Rate {
	object := new(Rate)

	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/rate/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteRate(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/rate/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListRates() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/rate")
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

type RateProperties struct {
	Basic struct {
		// Requests that are associated with this rate class will be rate-shaped
		//  to this many requests per minute, set to "0" to disable the limit.
		MaxRatePerMinute *int `json:"max_rate_per_minute,omitempty"`

		// Although requests will be rate-shaped to the "max_rate_per_minute",
		//  the traffic manager will also rate limit per-second. This smooths
		//  traffic so that a full minute's traffic will not be serviced
		//  in the first second of the minute, set this to "0" to disable
		//  the per-second limit.
		MaxRatePerSecond *int `json:"max_rate_per_second,omitempty"`

		// A description of the rate class.
		Note *string `json:"note,omitempty"`
	} `json:"basic"`
}
