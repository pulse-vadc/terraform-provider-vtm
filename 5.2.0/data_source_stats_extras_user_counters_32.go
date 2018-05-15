// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object ExtrasUserCounters32
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceExtrasUserCounters32Statistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceExtrasUserCounters32StatisticsRead,
		Schema: map[string]*schema.Schema{

			// The value of the user counter.
			"counter": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceExtrasUserCounters32StatisticsRead(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetExtrasUserCounters32Statistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_user_counters_32: %v", err.ErrorText)
	}
	d.Set("counter", int(*object.Statistics.Counter))
	d.SetId("user_counters_32")
	return nil
}
