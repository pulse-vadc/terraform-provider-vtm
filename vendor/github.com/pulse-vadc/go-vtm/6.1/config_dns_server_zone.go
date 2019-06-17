// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type DnsServerZone struct {
	connector               *vtmConnector
	DnsServerZoneProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetDnsServerZone(name string) (*DnsServerZone, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetDnsServerZone(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/dns_server/zones/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(DnsServerZone)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object DnsServerZone) Apply() (*DnsServerZone, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewDnsServerZone(name string, origin string, zonefile string) *DnsServerZone {
	object := new(DnsServerZone)
	object.Basic.Origin = &origin
	object.Basic.Zonefile = &zonefile
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/dns_server/zones/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteDnsServerZone(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/dns_server/zones/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListDnsServerZones() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/dns_server/zones")
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

type DnsServerZoneProperties struct {
	Basic struct {
		// The domain origin of this Zone.
		Origin *string `json:"origin,omitempty"`

		// The Zone File encapsulated by this Zone.
		Zonefile *string `json:"zonefile,omitempty"`
	} `json:"basic"`
}
