// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type ApplianceNat struct {
	connector              *vtmConnector
	ApplianceNatProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetApplianceNat() (*ApplianceNat, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/appliance/nat")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ApplianceNat)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object ApplianceNat) Apply() (*ApplianceNat, *vtmErrorResponse) {
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

type ApplianceNatProperties struct {
	Basic struct {
		// This is table 'many_to_one_all_ports'
		ManyToOneAllPorts *ApplianceNatManyToOneAllPortsTable `json:"many_to_one_all_ports,omitempty"`

		// This is table 'many_to_one_port_locked'
		ManyToOnePortLocked *ApplianceNatManyToOnePortLockedTable `json:"many_to_one_port_locked,omitempty"`

		// This is table 'one_to_one'
		OneToOne *ApplianceNatOneToOneTable `json:"one_to_one,omitempty"`

		// This is table 'port_mapping'
		PortMapping *ApplianceNatPortMappingTable `json:"port_mapping,omitempty"`
	} `json:"basic"`
}

type ApplianceNatManyToOneAllPorts struct {
	// Pool of a "many to one overload" type NAT rule.
	Pool *string `json:"pool,omitempty"`

	// A unique rule identifier
	RuleNumber *string `json:"rule_number,omitempty"`

	// TIP Group of a "many to one overload" type NAT rule.
	Tip *string `json:"tip,omitempty"`
}

type ApplianceNatManyToOneAllPortsTable []ApplianceNatManyToOneAllPorts

type ApplianceNatManyToOnePortLocked struct {
	// Pool of a "many to one port locked" type NAT rule.
	Pool *string `json:"pool,omitempty"`

	// Port number of a "many to one port locked" type NAT rule.
	Port *int `json:"port,omitempty"`

	// Protocol of a "many to one port locked" type NAT rule.
	Protocol *string `json:"protocol,omitempty"`

	// A unique rule identifier
	RuleNumber *string `json:"rule_number,omitempty"`

	// TIP Group of a "many to one port locked" type NAT rule.
	Tip *string `json:"tip,omitempty"`
}

type ApplianceNatManyToOnePortLockedTable []ApplianceNatManyToOnePortLocked

type ApplianceNatOneToOne struct {
	// Enabling the inbound part of a "one to one" type NAT rule.
	EnableInbound *bool `json:"enable_inbound,omitempty"`

	// IP Address of a "one to one" type NAT rule.
	Ip *string `json:"ip,omitempty"`

	// A unique rule identifier
	RuleNumber *string `json:"rule_number,omitempty"`

	// TIP group of a "one to one" type NAT rule.
	Tip *string `json:"tip,omitempty"`
}

type ApplianceNatOneToOneTable []ApplianceNatOneToOne

type ApplianceNatPortMapping struct {
	// First port of the dest. port range of a "port mapping" rule.
	DportFirst *int `json:"dport_first,omitempty"`

	// Last port of the dest. port range of a "port mapping" rule.
	DportLast *int `json:"dport_last,omitempty"`

	// A unique rule identifier
	RuleNumber *string `json:"rule_number,omitempty"`

	// Target Virtual Server of a "port mapping" rule.
	VirtualServer *string `json:"virtual_server,omitempty"`
}

type ApplianceNatPortMappingTable []ApplianceNatPortMapping
