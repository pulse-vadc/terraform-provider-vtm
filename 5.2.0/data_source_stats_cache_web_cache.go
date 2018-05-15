// Copyright (C) 2018, Pulse Secure, LLC. 
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

func dataSourceCacheWebCacheStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetCacheWebCacheStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_web_cache: %v", err.ErrorText)
	}
	d.Set("entries", int(*object.Statistics.Entries))
	d.Set("hit_rate", int(*object.Statistics.HitRate))
	d.Set("hits", int(*object.Statistics.Hits))
	d.Set("lookups", int(*object.Statistics.Lookups))
	d.Set("max_entries", int(*object.Statistics.MaxEntries))
	d.Set("mem_maximum", int(*object.Statistics.MemMaximum))
	d.Set("mem_used", int(*object.Statistics.MemUsed))
	d.Set("misses", int(*object.Statistics.Misses))
	d.Set("oldest", int(*object.Statistics.Oldest))
	d.Set("url_store_allocated", int(*object.Statistics.UrlStoreAllocated))
	d.Set("url_store_free", int(*object.Statistics.UrlStoreFree))
	d.Set("url_store_size", int(*object.Statistics.UrlStoreSize))
	d.Set("url_store_total_allocations", int(*object.Statistics.UrlStoreTotalAllocations))
	d.Set("url_store_total_failures", int(*object.Statistics.UrlStoreTotalFailures))
	d.Set("url_store_total_frees", int(*object.Statistics.UrlStoreTotalFrees))
	d.SetId("web_cache")
	return nil
}
