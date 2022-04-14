// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type SslOcspStaplingStatistics struct {
	Statistics struct {
		CacheCount   *int `json:"cache_count"`
		Count        *int `json:"count"`
		FailureCount *int `json:"failure_count"`
		GoodCount    *int `json:"good_count"`
		RevokedCount *int `json:"revoked_count"`
		SuccessCount *int `json:"success_count"`
		UnknownCount *int `json:"unknown_count"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetSslOcspStaplingStatistics() (*SslOcspStaplingStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/status/local_tm/statistics/ssl_ocsp_stapling")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SslOcspStaplingStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
