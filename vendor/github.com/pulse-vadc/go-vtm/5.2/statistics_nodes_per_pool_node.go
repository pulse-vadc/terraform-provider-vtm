// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type NodesPerPoolNodeStatistics struct {
	Statistics struct {
		BytesFromNode      *int    `json:"bytes_from_node"`
		BytesFromNodeHi    *int    `json:"bytes_from_node_hi"`
		BytesFromNodeLo    *int    `json:"bytes_from_node_lo"`
		BytesToNode        *int    `json:"bytes_to_node"`
		BytesToNodeHi      *int    `json:"bytes_to_node_hi"`
		BytesToNodeLo      *int    `json:"bytes_to_node_lo"`
		CurrentConn        *int    `json:"current_conn"`
		CurrentRequests    *int    `json:"current_requests"`
		Errors             *int    `json:"errors"`
		Failures           *int    `json:"failures"`
		IdleConns          *int    `json:"idle_conns"`
		L4StatelessBuckets *int    `json:"l4_stateless_buckets"`
		NewConn            *int    `json:"new_conn"`
		NodePort           *int    `json:"node_port"`
		PktsFromNode       *int    `json:"pkts_from_node"`
		PktsFromNodeHi     *int    `json:"pkts_from_node_hi"`
		PktsFromNodeLo     *int    `json:"pkts_from_node_lo"`
		PktsToNode         *int    `json:"pkts_to_node"`
		PktsToNodeHi       *int    `json:"pkts_to_node_hi"`
		PktsToNodeLo       *int    `json:"pkts_to_node_lo"`
		PooledConn         *int    `json:"pooled_conn"`
		ResponseMax        *int    `json:"response_max"`
		ResponseMean       *int    `json:"response_mean"`
		ResponseMin        *int    `json:"response_min"`
		State              *string `json:"state"`
		TotalConn          *int    `json:"total_conn"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetNodesPerPoolNodeStatistics(name string) (*NodesPerPoolNodeStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/status/local_tm/statistics/nodes/per_pool_node/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(NodesPerPoolNodeStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
