// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object CacheSslCache
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func dataSourceCacheSslCacheStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCacheSslCacheStatisticsRead,
		Schema: map[string]*schema.Schema{

			// The total number of SSL sessions stored in the server cache.
			"entries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum number of SSL entries in the server cache.
			"entries_max": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The percentage of SSL server cache lookups that succeeded.
			"hit_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a SSL entry has been successfully found in the
			//  server cache.
			"hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a SSL entry has been looked up in the server
			//  cache.
			"lookups": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a SSL entry has not been available in the server
			//  cache.
			"misses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The age of the oldest SSL session in the server cache (in seconds).
			"oldest": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceCacheSslCacheStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetCacheSslCacheStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_ssl_cache: %v", err.ErrorText)
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
	d.SetId("ssl_cache")
	return nil
}
