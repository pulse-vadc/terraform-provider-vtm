// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 4.0.
package vtm

import (
	"encoding/json"
)

type TrafficIpsTrafficIpStatistics struct {
	Statistics struct {
		State *string `json:"state"`
		Time  *int    `json:"time"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetTrafficIpsTrafficIpStatistics(name string) (*TrafficIpsTrafficIpStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/4.0/status/local_tm/statistics/traffic_ips/traffic_ip/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(TrafficIpsTrafficIpStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
