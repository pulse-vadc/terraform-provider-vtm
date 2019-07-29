// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type Security struct {
	connector          *vtmConnector
	SecurityProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetSecurity() (*Security, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/security")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Security)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Security) Apply() (*Security, *vtmErrorResponse) {
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

type SecurityProperties struct {
	Basic struct {
		// Access to the admin server and REST API is restricted by usernames
		//  and passwords. You can further restrict access to just trusted
		//  IP addresses, CIDR IP subnets or DNS wildcards. These access
		//  restrictions are also used when another traffic manager initially
		//  joins the cluster, after joining the cluster these restrictions
		//  are no longer used. Care must be taken when changing this setting,
		//  as it can cause the administration server to become inaccessible.</br>Access
		//  to the admin UI will not be affected until it is restarted.
		Access *[]string `json:"access,omitempty"`
	} `json:"basic"`

	SshIntrusion struct {
		// The amount of time in seconds to ban an offending host for.
		Bantime *int `json:"bantime,omitempty"`

		// The list of hosts to permanently ban, identified by IP address
		//  or DNS hostname in a space-separated list.
		Blacklist *[]string `json:"blacklist,omitempty"`

		// Whether or not the SSH Intrusion Prevention tool is enabled.
		Enabled *bool `json:"enabled,omitempty"`

		// The window of time in seconds the maximum number of connection
		//  attempts applies to. More than (maxretry) failed attempts in
		//  this time span will trigger a ban.
		Findtime *int `json:"findtime,omitempty"`

		// The number of failed connection attempts a host can make before
		//  being banned.
		Maxretry *int `json:"maxretry,omitempty"`

		// The list of hosts to never ban, identified by IP address, DNS
		//  hostname or subnet mask, in a space-separated list.
		Whitelist *[]string `json:"whitelist,omitempty"`
	} `json:"ssh_intrusion"`
}
