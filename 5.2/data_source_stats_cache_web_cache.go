// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object CacheWebCache
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceCacheWebCacheStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCacheWebCacheStatisticsRead,
		Schema: map[string]*schema.Schema{

			// The number of items in the web cache.
			"entries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The percentage of web cache lookups that succeeded.
			"hit_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a page has been successfully found in the web
			//  cache.
			"hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a page has been looked up in the web cache.
			"lookups": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum number of items in the web cache.
			"max_entries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum amount of memory the web cache can use in kilobytes.
			"mem_maximum": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total memory used by the web cache in kilobytes.
			"mem_used": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a page has not been found in the web cache.
			"misses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The age of the oldest item in the web cache (in seconds).
			"oldest": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Amount of allocated space in the web cache URL store.
			"url_store_allocated": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Amount of free space in the web cache URL store.
			"url_store_free": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total amount of space in the web cache URL store.
			"url_store_size": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of allocations for the web cache URL store.
			"url_store_total_allocations": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of allocation failures for the web cache URL store.
			"url_store_total_failures": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of blocks freed in the web cache URL store.
			"url_store_total_frees": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceCacheWebCacheStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetCacheWebCacheStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_web_cache: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "entries"
	d.Set("entries", int(*object.Statistics.Entries))

	lastAssignedField = "hit_rate"
	d.Set("hit_rate", int(*object.Statistics.HitRate))

	lastAssignedField = "hits"
	d.Set("hits", int(*object.Statistics.Hits))

	lastAssignedField = "lookups"
	d.Set("lookups", int(*object.Statistics.Lookups))

	lastAssignedField = "max_entries"
	d.Set("max_entries", int(*object.Statistics.MaxEntries))

	lastAssignedField = "mem_maximum"
	d.Set("mem_maximum", int(*object.Statistics.MemMaximum))

	lastAssignedField = "mem_used"
	d.Set("mem_used", int(*object.Statistics.MemUsed))

	lastAssignedField = "misses"
	d.Set("misses", int(*object.Statistics.Misses))

	lastAssignedField = "oldest"
	d.Set("oldest", int(*object.Statistics.Oldest))

	lastAssignedField = "url_store_allocated"
	d.Set("url_store_allocated", int(*object.Statistics.UrlStoreAllocated))

	lastAssignedField = "url_store_free"
	d.Set("url_store_free", int(*object.Statistics.UrlStoreFree))

	lastAssignedField = "url_store_size"
	d.Set("url_store_size", int(*object.Statistics.UrlStoreSize))

	lastAssignedField = "url_store_total_allocations"
	d.Set("url_store_total_allocations", int(*object.Statistics.UrlStoreTotalAllocations))

	lastAssignedField = "url_store_total_failures"
	d.Set("url_store_total_failures", int(*object.Statistics.UrlStoreTotalFailures))

	lastAssignedField = "url_store_total_frees"
	d.Set("url_store_total_frees", int(*object.Statistics.UrlStoreTotalFrees))
	d.SetId("web_cache")
	return nil
}
