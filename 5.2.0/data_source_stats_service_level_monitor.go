// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object ServiceLevelMonitor
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceServiceLevelMonitorStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceServiceLevelMonitorStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Percentage of requests associated with this SLM class that are
			//  conforming
			"conforming": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of connections currently associated with this SLM
			//  class.
			"current_conns": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Indicates if this SLM class is currently conforming.
			"is_o_k": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Maximum response time (ms) in the last second for this SLM class.
			"response_max": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Mean response time (ms) in the last second for this SLM class.
			"response_mean": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Minimum response time (ms) in the last second for this SLM class.
			"response_min": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests handled by this SLM class.
			"total_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Non-conforming requests handled by this SLM class.
			"total_non_conf": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceServiceLevelMonitorStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetServiceLevelMonitorStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_service_level_monitors '%v': %v", objectName, err.ErrorText)
	}
	d.Set("conforming", int(*object.Statistics.Conforming))
	d.Set("current_conns", int(*object.Statistics.CurrentConns))
	d.Set("is_o_k", string(*object.Statistics.IsOK))
	d.Set("response_max", int(*object.Statistics.ResponseMax))
	d.Set("response_mean", int(*object.Statistics.ResponseMean))
	d.Set("response_min", int(*object.Statistics.ResponseMin))
	d.Set("total_conn", int(*object.Statistics.TotalConn))
	d.Set("total_non_conf", int(*object.Statistics.TotalNonConf))
	d.SetId(objectName)
	return nil
}
