// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type NodesNodeInet46Statistics struct {
	Statistics struct {
		BytesFromNode   *int    `json:"bytes_from_node"`
		BytesToNode     *int    `json:"bytes_to_node"`
		CurrentConn     *int    `json:"current_conn"`
		CurrentRequests *int    `json:"current_requests"`
		Errors          *int    `json:"errors"`
		Failures        *int    `json:"failures"`
		IdleConns       *int    `json:"idle_conns"`
		NewConn         *int    `json:"new_conn"`
		PooledConn      *int    `json:"pooled_conn"`
		Port            *int    `json:"port"`
		ResponseMax     *int    `json:"response_max"`
		ResponseMean    *int    `json:"response_mean"`
		ResponseMin     *int    `json:"response_min"`
		State           *string `json:"state"`
		TotalConn       *int    `json:"total_conn"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetNodesNodeInet46Statistics(name string) (*NodesNodeInet46Statistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/status/local_tm/statistics/nodes/node_inet46/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(NodesNodeInet46Statistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
