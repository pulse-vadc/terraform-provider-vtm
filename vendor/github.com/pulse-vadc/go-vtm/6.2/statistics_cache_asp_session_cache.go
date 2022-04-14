// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.2.
package vtm

import (
	"encoding/json"
)

type CacheAspSessionCacheStatistics struct {
	Statistics struct {
		Entries    *int `json:"entries"`
		EntriesMax *int `json:"entries_max"`
		HitRate    *int `json:"hit_rate"`
		Hits       *int `json:"hits"`
		Lookups    *int `json:"lookups"`
		Misses     *int `json:"misses"`
		Oldest     *int `json:"oldest"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetCacheAspSessionCacheStatistics() (*CacheAspSessionCacheStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.2/status/local_tm/statistics/cache/asp_session_cache")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(CacheAspSessionCacheStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
