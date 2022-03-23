// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type PoolStatistics struct {
	Statistics struct {
		Algorithm          *string `json:"algorithm"`
		BwLimitBytesDrop   *int    `json:"bw_limit_bytes_drop"`
		BwLimitBytesDropHi *int    `json:"bw_limit_bytes_drop_hi"`
		BwLimitBytesDropLo *int    `json:"bw_limit_bytes_drop_lo"`
		BwLimitPktsDrop    *int    `json:"bw_limit_pkts_drop"`
		BwLimitPktsDropHi  *int    `json:"bw_limit_pkts_drop_hi"`
		BwLimitPktsDropLo  *int    `json:"bw_limit_pkts_drop_lo"`
		BytesIn            *int    `json:"bytes_in"`
		BytesInHi          *int    `json:"bytes_in_hi"`
		BytesInLo          *int    `json:"bytes_in_lo"`
		BytesOut           *int    `json:"bytes_out"`
		BytesOutHi         *int    `json:"bytes_out_hi"`
		BytesOutLo         *int    `json:"bytes_out_lo"`
		ConnsQueued        *int    `json:"conns_queued"`
		Disabled           *int    `json:"disabled"`
		Draining           *int    `json:"draining"`
		MaxQueueTime       *int    `json:"max_queue_time"`
		MeanQueueTime      *int    `json:"mean_queue_time"`
		MinQueueTime       *int    `json:"min_queue_time"`
		Nodes              *int    `json:"nodes"`
		Persistence        *string `json:"persistence"`
		QueueTimeouts      *int    `json:"queue_timeouts"`
		SessionMigrated    *int    `json:"session_migrated"`
		State              *string `json:"state"`
		TotalConn          *int    `json:"total_conn"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetPoolStatistics(name string) (*PoolStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/status/local_tm/statistics/pools/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(PoolStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
