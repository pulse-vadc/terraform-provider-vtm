// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object PerLocationService
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourcePerLocationServiceStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePerLocationServiceStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The draining state of this location for this GLB Service.
			"draining": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The frontend state of this location for this GLB Service.
			"frontend_state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The load metric for this location for this GLB Service.
			"load": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The monitor state of this location for this GLB Service.
			"monitor_state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Number of A records that have been altered to point to this location
			//  for this GLB Service.
			"responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The state of this location for this GLB Service.
			"state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourcePerLocationServiceStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetPerLocationServiceStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_per_location_service '%v': %v", objectName, err.ErrorText)
	}
	d.Set("draining", string(*object.Statistics.Draining))
	d.Set("frontend_state", string(*object.Statistics.FrontendState))
	d.Set("load", int(*object.Statistics.Load))
	d.Set("monitor_state", string(*object.Statistics.MonitorState))
	d.Set("responses", int(*object.Statistics.Responses))
	d.Set("state", string(*object.Statistics.State))
	d.SetId(objectName)
	return nil
}
