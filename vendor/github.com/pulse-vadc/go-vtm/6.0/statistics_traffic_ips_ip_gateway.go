// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type TrafficIpsIpGatewayStatistics struct {
	Statistics struct {
		ArpMessage           *int `json:"arp_message"`
		GatewayPingRequests  *int `json:"gateway_ping_requests"`
		GatewayPingResponses *int `json:"gateway_ping_responses"`
		NodePingRequests     *int `json:"node_ping_requests"`
		NodePingResponses    *int `json:"node_ping_responses"`
		NumberInet46         *int `json:"number_inet46"`
		NumberRaisedInet46   *int `json:"number_raised_inet46"`
		PingResponseErrors   *int `json:"ping_response_errors"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetTrafficIpsIpGatewayStatistics() (*TrafficIpsIpGatewayStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/status/local_tm/statistics/traffic_ips/ip_gateway")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(TrafficIpsIpGatewayStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
