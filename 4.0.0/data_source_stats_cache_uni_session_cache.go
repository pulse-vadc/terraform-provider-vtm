// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object CacheUniSessionCache
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceCacheUniSessionCacheStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCacheUniSessionCacheStatisticsRead,
		Schema: map[string]*schema.Schema{

			// The total number of universal sessions stored in the cache.
			"entries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum number of universal sessions in the cache.
			"entries_max": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The percentage of universal session lookups that succeeded.
			"hit_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a universal session entry has been successfully
			//  found in the cache.
			"hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a universal session entry has been looked up
			//  in the cache.
			"lookups": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a universal session entry has not been available
			//  in the cache.
			"misses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The age of the oldest universal session in the cache (in seconds).
			"oldest": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceCacheUniSessionCacheStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetCacheUniSessionCacheStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_uni_session_cache: %v", err.ErrorText)
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

	lastAssignedField = "entries_max"
	d.Set("entries_max", int(*object.Statistics.EntriesMax))

	lastAssignedField = "hit_rate"
	d.Set("hit_rate", int(*object.Statistics.HitRate))

	lastAssignedField = "hits"
	d.Set("hits", int(*object.Statistics.Hits))

	lastAssignedField = "lookups"
	d.Set("lookups", int(*object.Statistics.Lookups))

	lastAssignedField = "misses"
	d.Set("misses", int(*object.Statistics.Misses))

	lastAssignedField = "oldest"
	d.Set("oldest", int(*object.Statistics.Oldest))
	d.SetId("uni_session_cache")
	return nil
}
