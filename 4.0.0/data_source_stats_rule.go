// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object Rule
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceRuleStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRuleStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Number of times this TrafficScript rule has aborted.
			"aborts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this TrafficScript rule has discarded the connection.
			"discards": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this TrafficScript rule has exceeded the execution
			//  time warning threshold.
			"execution_time_warnings": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this TrafficScript rule has been executed.
			"executions": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this TrafficScript rule has selected a pool to
			//  use.
			"pool_select": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this TrafficScript rule has responded directly
			//  to the client.
			"responds": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this TrafficScript rule has forced the request
			//  to be retried.
			"retries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceRuleStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetRuleStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rules '%v': %v", objectName, err.ErrorText)
	}
	d.Set("aborts", int(*object.Statistics.Aborts))
	d.Set("discards", int(*object.Statistics.Discards))
	d.Set("execution_time_warnings", int(*object.Statistics.ExecutionTimeWarnings))
	d.Set("executions", int(*object.Statistics.Executions))
	d.Set("pool_select", int(*object.Statistics.PoolSelect))
	d.Set("responds", int(*object.Statistics.Responds))
	d.Set("retries", int(*object.Statistics.Retries))
	d.SetId(objectName)
	return nil
}
