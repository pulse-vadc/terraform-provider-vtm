// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type ServiceLevelMonitorStatistics struct {
	Statistics struct {
		Conforming   *int    `json:"conforming"`
		CurrentConns *int    `json:"current_conns"`
		IsOK         *string `json:"is_o_k"`
		ResponseMax  *int    `json:"response_max"`
		ResponseMean *int    `json:"response_mean"`
		ResponseMin  *int    `json:"response_min"`
		TotalConn    *int    `json:"total_conn"`
		TotalNonConf *int    `json:"total_non_conf"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetServiceLevelMonitorStatistics(name string) (*ServiceLevelMonitorStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/status/local_tm/statistics/service_level_monitors/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ServiceLevelMonitorStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
