// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 4.0.
package vtm

import (
	"encoding/json"
)

type BandwidthStatistics struct {
	Statistics struct {
		BytesDrop   *int `json:"bytes_drop"`
		BytesDropHi *int `json:"bytes_drop_hi"`
		BytesDropLo *int `json:"bytes_drop_lo"`
		BytesOut    *int `json:"bytes_out"`
		BytesOutHi  *int `json:"bytes_out_hi"`
		BytesOutLo  *int `json:"bytes_out_lo"`
		Guarantee   *int `json:"guarantee"`
		Maximum     *int `json:"maximum"`
		PktsDrop    *int `json:"pkts_drop"`
		PktsDropHi  *int `json:"pkts_drop_hi"`
		PktsDropLo  *int `json:"pkts_drop_lo"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetBandwidthStatistics(name string) (*BandwidthStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/4.0/status/local_tm/statistics/bandwidth/" + name)
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
