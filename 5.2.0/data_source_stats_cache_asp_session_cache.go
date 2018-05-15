// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object CacheAspSessionCache
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceCacheAspSessionCacheStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCacheAspSessionCacheStatisticsRead,
		Schema: map[string]*schema.Schema{

			// The total number of ASP sessions stored in the cache.
			"entries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum number of ASP sessions in the cache.
			"entries_max": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The percentage of ASP session lookups that succeeded.
			"hit_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a ASP session entry has been successfully found
			//  in the cache.
			"hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a ASP session entry has been looked up in the
			//  cache.
			"lookups": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a ASP session entry has not been available in
			//  the cache.
			"misses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The age of the oldest ASP session in the cache (in seconds).
			"oldest": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceCacheAspSessionCacheStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetCacheAspSessionCacheStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_asp_session_cache: %v", err.ErrorText)
	}
	d.Set("entries", int(*object.Statistics.Entries))
	d.Set("entries_max", int(*object.Statistics.EntriesMax))
	d.Set("hit_rate", int(*object.Statistics.HitRate))
	d.Set("hits", int(*object.Statistics.Hits))
	d.Set("lookups", int(*object.Statistics.Lookups))
	d.Set("misses", int(*object.Statistics.Misses))
	d.Set("oldest", int(*object.Statistics.Oldest))
	d.SetId("asp_session_cache")
	return nil
}
