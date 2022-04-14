// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object Rule
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
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

func dataSourceRuleStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetRuleStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rules '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "aborts"
	d.Set("aborts", int(*object.Statistics.Aborts))

	lastAssignedField = "discards"
	d.Set("discards", int(*object.Statistics.Discards))

	lastAssignedField = "execution_time_warnings"
	d.Set("execution_time_warnings", int(*object.Statistics.ExecutionTimeWarnings))

	lastAssignedField = "executions"
	d.Set("executions", int(*object.Statistics.Executions))

	lastAssignedField = "pool_select"
	d.Set("pool_select", int(*object.Statistics.PoolSelect))

	lastAssignedField = "responds"
	d.Set("responds", int(*object.Statistics.Responds))

	lastAssignedField = "retries"
	d.Set("retries", int(*object.Statistics.Retries))
	d.SetId(objectName)
	return nil
}
