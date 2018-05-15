// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceRate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRateRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Requests that are associated with this rate class will be rate-shaped
			//  to this many requests per minute, set to "0" to disable the limit.
			"max_rate_per_minute": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// Although requests will be rate-shaped to the "max_rate_per_minute",
			//  the traffic manager will also rate limit per-second. This smooths
			//  traffic so that a full minute's traffic will not be serviced
			//  in the first second of the minute, set this to "0" to disable
			//  the per-second limit.
			"max_rate_per_second": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// A description of the rate class.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceRateRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetRate(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rate '%v': %v", objectName, err.ErrorText)
	}
	d.Set("max_rate_per_minute", int(*object.Basic.MaxRatePerMinute))
	d.Set("max_rate_per_second", int(*object.Basic.MaxRatePerSecond))
	d.Set("note", string(*object.Basic.Note))

	d.SetId(objectName)
	return nil
}
