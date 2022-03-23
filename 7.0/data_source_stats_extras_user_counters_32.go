// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object ExtrasUserCounters32
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
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

func dataSourceExtrasUserCounters32StatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetExtrasUserCounters32Statistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_user_counters_32: %v", err.ErrorText)
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
	d.SetId("user_counters_32")
	return nil
}
