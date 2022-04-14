// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type PerNodeSlmPerNodeServiceLevelInet46Statistics struct {
	Statistics struct {
		NodePort     *int `json:"node_port"`
		ResponseMax  *int `json:"response_max"`
		ResponseMean *int `json:"response_mean"`
		ResponseMin  *int `json:"response_min"`
		TotalConn    *int `json:"total_conn"`
		TotalNonConf *int `json:"total_non_conf"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetPerNodeSlmPerNodeServiceLevelInet46Statistics(name string) (*PerNodeSlmPerNodeServiceLevelInet46Statistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/status/local_tm/statistics/per_node_slm/per_node_service_level_inet46/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(PerNodeSlmPerNodeServiceLevelInet46Statistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
