// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.1.
package vtm

import (
	"encoding/json"
)

type ConnectionRateLimitStatistics struct {
	Statistics struct {
		ConnsEntered  *int `json:"conns_entered"`
		ConnsLeft     *int `json:"conns_left"`
		CurrentRate   *int `json:"current_rate"`
		Dropped       *int `json:"dropped"`
		MaxRatePerMin *int `json:"max_rate_per_min"`
		MaxRatePerSec *int `json:"max_rate_per_sec"`
		QueueLength   *int `json:"queue_length"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetConnectionRateLimitStatistics(name string) (*ConnectionRateLimitStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.1/status/local_tm/statistics/connection_rate_limit/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ConnectionRateLimitStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
