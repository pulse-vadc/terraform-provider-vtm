// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 4.0.
package vtm

import (
	"encoding/json"
)

type ListenIpStatistics struct {
	Statistics struct {
		BytesIn         *int `json:"bytes_in"`
		BytesInHi       *int `json:"bytes_in_hi"`
		BytesInLo       *int `json:"bytes_in_lo"`
		BytesOut        *int `json:"bytes_out"`
		BytesOutHi      *int `json:"bytes_out_hi"`
		BytesOutLo      *int `json:"bytes_out_lo"`
		CurrentConn     *int `json:"current_conn"`
		MaxConn         *int `json:"max_conn"`
		TotalConn       *int `json:"total_conn"`
		TotalRequests   *int `json:"total_requests"`
		TotalRequestsHi *int `json:"total_requests_hi"`
		TotalRequestsLo *int `json:"total_requests_lo"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetListenIpStatistics(name string) (*ListenIpStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/4.0/status/local_tm/statistics/listen_ips/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ListenIpStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
