// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.1.
package vtm

import (
	"encoding/json"
)

type CacheWebCacheStatistics struct {
	Statistics struct {
		Entries                  *int `json:"entries"`
		HitRate                  *int `json:"hit_rate"`
		Hits                     *int `json:"hits"`
		Lookups                  *int `json:"lookups"`
		MaxEntries               *int `json:"max_entries"`
		MemMaximum               *int `json:"mem_maximum"`
		MemUsed                  *int `json:"mem_used"`
		Misses                   *int `json:"misses"`
		Oldest                   *int `json:"oldest"`
		UrlStoreAllocated        *int `json:"url_store_allocated"`
		UrlStoreFree             *int `json:"url_store_free"`
		UrlStoreSize             *int `json:"url_store_size"`
		UrlStoreTotalAllocations *int `json:"url_store_total_allocations"`
		UrlStoreTotalFailures    *int `json:"url_store_total_failures"`
		UrlStoreTotalFrees       *int `json:"url_store_total_frees"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetCacheWebCacheStatistics() (*CacheWebCacheStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.1/status/local_tm/statistics/cache/web_cache")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(CacheWebCacheStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
