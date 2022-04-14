// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 7.0.
package vtm

import (
	"encoding/json"
)

type ActionStatistics struct {
	Statistics struct {
		Processed *int `json:"processed"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetActionStatistics(name string) (*ActionStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.0/status/local_tm/statistics/actions/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ActionStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
