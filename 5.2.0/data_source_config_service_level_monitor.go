// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceServiceLevelMonitor() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceServiceLevelMonitorRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// A description for the SLM class.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Responses that arrive within this time limit, expressed in milliseconds,
			//  are treated as conforming.
			"response_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      1000,
			},

			// When the percentage of conforming responses drops below this
			//  level, a serious error level message will be emitted.
			"serious_threshold": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 100),
				Default:      0,
			},

			// When the percentage of conforming responses drops below this
			//  level, a warning message will be emitted.
			"warning_threshold": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 100),
				Default:      50,
			},
		},
	}
}

func dataSourceServiceLevelMonitorRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetServiceLevelMonitor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_service_level_monitor '%v': %v", objectName, err.ErrorText)
	}
	d.Set("note", string(*object.Basic.Note))
	d.Set("response_time", int(*object.Basic.ResponseTime))
	d.Set("serious_threshold", int(*object.Basic.SeriousThreshold))
	d.Set("warning_threshold", int(*object.Basic.WarningThreshold))

	d.SetId(objectName)
	return nil
}
