// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 4.0.
package vtm

import (
	"encoding/json"
)

type ExtrasUserCounters32Statistics struct {
	Statistics struct {
		Counter *int `json:"counter"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetExtrasUserCounters32Statistics() (*ExtrasUserCounters32Statistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/4.0/status/local_tm/statistics/extras/user_counters_32")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ExtrasUserCounters32Statistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
