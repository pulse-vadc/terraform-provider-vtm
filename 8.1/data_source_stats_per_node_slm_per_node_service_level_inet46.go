// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object PerNodeSlmPerNodeServiceLevelInet46
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func dataSourcePerNodeSlmPerNodeServiceLevelInet46Statistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePerNodeSlmPerNodeServiceLevelInet46StatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The port number of this node.
			"node_port": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Maximum response time (ms) in the last second for this SLM class
			//  to this node.
			"response_max": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Mean response time (ms) in the last second for this SLM class
			//  to this node.
			"response_mean": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Minimum response time (ms) in the last second for this SLM class
			//  to this node.
			"response_min": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests handled by this SLM class to this node.
			"total_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Non-conforming requests handled by this SLM class to this node.
			"total_non_conf": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourcePerNodeSlmPerNodeServiceLevelInet46StatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetPerNodeSlmPerNodeServiceLevelInet46Statistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_per_node_service_level_inet46 '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "node_port"
	d.Set("node_port", int(*object.Statistics.NodePort))

	lastAssignedField = "response_max"
	d.Set("response_max", int(*object.Statistics.ResponseMax))

	lastAssignedField = "response_mean"
	d.Set("response_mean", int(*object.Statistics.ResponseMean))

	lastAssignedField = "response_min"
	d.Set("response_min", int(*object.Statistics.ResponseMin))

	lastAssignedField = "total_conn"
	d.Set("total_conn", int(*object.Statistics.TotalConn))

	lastAssignedField = "total_non_conf"
	d.Set("total_non_conf", int(*object.Statistics.TotalNonConf))
	d.SetId(objectName)
	return nil
}
