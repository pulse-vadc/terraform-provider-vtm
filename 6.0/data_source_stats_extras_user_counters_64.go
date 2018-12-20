// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object ExtrasUserCounters64
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceExtrasUserCounters64Statistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceExtrasUserCounters64StatisticsRead,
		Schema: map[string]*schema.Schema{

			// The value of the 64-bit user counter.
			"counter": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceExtrasUserCounters64StatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetExtrasUserCounters64Statistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_user_counters_64: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "counter"
	d.Set("counter", int(*object.Statistics.Counter))
	d.SetId("user_counters_64")
	return nil
}
