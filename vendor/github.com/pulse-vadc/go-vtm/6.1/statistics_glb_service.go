// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type GlbServiceStatistics struct {
	Statistics struct {
		Discarded  *int `json:"discarded"`
		Responses  *int `json:"responses"`
		Unmodified *int `json:"unmodified"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetGlbServiceStatistics(name string) (*GlbServiceStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/status/local_tm/statistics/glb_services/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(GlbServiceStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
