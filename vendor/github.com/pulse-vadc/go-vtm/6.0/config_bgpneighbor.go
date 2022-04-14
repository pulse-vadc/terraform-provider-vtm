// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type Bgpneighbor struct {
	connector             *vtmConnector
	BgpneighborProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetBgpneighbor(name string) (*Bgpneighbor, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetBgpneighbor(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/bgpneighbors/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Bgpneighbor)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Bgpneighbor) Apply() (*Bgpneighbor, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewBgpneighbor(name string) *Bgpneighbor {
	object := new(Bgpneighbor)

	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/bgpneighbors/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteBgpneighbor(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/bgpneighbors/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListBgpneighbors() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/bgpneighbors")
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

type BgpneighborProperties struct {
	Basic struct {
		// The IP address of the BGP neighbor
		Address *string `json:"address,omitempty"`

		// The minimum interval between the sending of BGP routing updates
		//  to neighbors. Note that as a result of jitter, as defined for
		//  BGP, the interval during which no advertisements are sent will
		//  be between 75% and 100% of this value.
		AdvertisementInterval *int `json:"advertisement_interval,omitempty"`

		// The AS number for the BGP neighbor
		AsNumber *int `json:"as_number,omitempty"`

		// The password to be used for authentication of sessions with neighbors
		AuthenticationPassword *string `json:"authentication_password,omitempty"`

		// The period after which the BGP session with the neighbor is deemed
		//  to have become idle - and requires re-establishment - if the
		//  neighbor falls silent.
		Holdtime *int `json:"holdtime,omitempty"`

		// The interval at which messages are sent to the BGP neighbor to
		//  keep the mutual BGP session established.
		Keepalive *int `json:"keepalive,omitempty"`

		// The traffic managers that are to use this neighbor
		Machines *[]string `json:"machines,omitempty"`
	} `json:"basic"`
}
