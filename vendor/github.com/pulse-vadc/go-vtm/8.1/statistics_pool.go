// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.1.
package vtm

import (
	"encoding/json"
)

type PoolStatistics struct {
	Statistics struct {
		Algorithm        *string `json:"algorithm"`
		BytesIn          *int    `json:"bytes_in"`
		BytesOut         *int    `json:"bytes_out"`
		ConnsQueued      *int    `json:"conns_queued"`
		Disabled         *int    `json:"disabled"`
		Draining         *int    `json:"draining"`
		Http1XxResponses *int    `json:"http1xx_responses"`
		Http2XxResponses *int    `json:"http2xx_responses"`
		Http3XxResponses *int    `json:"http3xx_responses"`
		Http4XxResponses *int    `json:"http4xx_responses"`
		Http503Retries   *int    `json:"http503_retries"`
		Http5XxResponses *int    `json:"http5xx_responses"`
		MaxQueueTime     *int    `json:"max_queue_time"`
		MeanQueueTime    *int    `json:"mean_queue_time"`
		MinQueueTime     *int    `json:"min_queue_time"`
		Nodes            *int    `json:"nodes"`
		Persistence      *string `json:"persistence"`
		QueueTimeouts    *int    `json:"queue_timeouts"`
		SessionMigrated  *int    `json:"session_migrated"`
		State            *string `json:"state"`
		TotalConn        *int    `json:"total_conn"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetPoolStatistics(name string) (*PoolStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.1/status/local_tm/statistics/pools/" + name)
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
