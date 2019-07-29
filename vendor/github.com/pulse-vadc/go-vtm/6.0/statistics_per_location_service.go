// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type PerLocationServiceStatistics struct {
	Statistics struct {
		Draining      *string `json:"draining"`
		FrontendState *string `json:"frontend_state"`
		Load          *int    `json:"load"`
		MonitorState  *string `json:"monitor_state"`
		Responses     *int    `json:"responses"`
		State         *string `json:"state"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetPerLocationServiceStatistics(name string) (*PerLocationServiceStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/status/local_tm/statistics/per_location_service/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(PerLocationServiceStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
