// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.1.
package vtm

import (
	"encoding/json"
)

type BandwidthStatistics struct {
	Statistics struct {
		BytesOut  *int `json:"bytes_out"`
		Guarantee *int `json:"guarantee"`
		Maximum   *int `json:"maximum"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetBandwidthStatistics(name string) (*BandwidthStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.1/status/local_tm/statistics/bandwidth/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(BandwidthStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
