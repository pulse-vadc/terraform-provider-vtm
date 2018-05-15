// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object ConnectionRateLimit
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceConnectionRateLimitStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceConnectionRateLimitStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Connections that have entered the rate class and have been queued.
			"conns_entered": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections that have left the rate class.
			"conns_left": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The average rate that requests are passing through this rate
			//  class.
			"current_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests dropped from this rate class without being processed
			//  (e.g. timeouts).
			"dropped": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum rate that requests may pass through this rate class
			//  (requests/min).
			"max_rate_per_min": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The maximum rate that requests may pass through this rate class
			//  (requests/sec).
			"max_rate_per_sec": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The current number of requests queued by this rate class.
			"queue_length": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceConnectionRateLimitStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetConnectionRateLimitStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_connection_rate_limit '%v': %v", objectName, err.ErrorText)
	}
	d.Set("conns_entered", int(*object.Statistics.ConnsEntered))
	d.Set("conns_left", int(*object.Statistics.ConnsLeft))
	d.Set("current_rate", int(*object.Statistics.CurrentRate))
	d.Set("dropped", int(*object.Statistics.Dropped))
	d.Set("max_rate_per_min", int(*object.Statistics.MaxRatePerMin))
	d.Set("max_rate_per_sec", int(*object.Statistics.MaxRatePerSec))
	d.Set("queue_length", int(*object.Statistics.QueueLength))
	d.SetId(objectName)
	return nil
}
