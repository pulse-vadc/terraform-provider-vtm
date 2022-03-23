// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object NodesNode
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceNodesNodeStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceNodesNodeStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Requests currently established to this node. ( does not include
			//  idle keepalives ).
			"current_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections currently established to this node.
			"current_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of timeouts, connection problems and other errors for
			//  this node.
			"errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Failures of this node.
			"failures": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests that created a new connection to this node.
			"new_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests that reused an existing pooled/keepalive connection
			//  rather than creating a new TCP connection.
			"pooled_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The port this node listens on.
			"port": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Maximum response time (ms) in the last second for this node.
			"response_max": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Mean response time (ms) in the last second for this node.
			"response_mean": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Minimum response time (ms) in the last second for this node.
			"response_min": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The state of this node.
			"state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Requests sent to this node.
			"total_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceNodesNodeStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetNodesNodeStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_node '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "current_conn"
	d.Set("current_conn", int(*object.Statistics.CurrentConn))

	lastAssignedField = "current_requests"
	d.Set("current_requests", int(*object.Statistics.CurrentRequests))

	lastAssignedField = "errors"
	d.Set("errors", int(*object.Statistics.Errors))

	lastAssignedField = "failures"
	d.Set("failures", int(*object.Statistics.Failures))

	lastAssignedField = "new_conn"
	d.Set("new_conn", int(*object.Statistics.NewConn))

	lastAssignedField = "pooled_conn"
	d.Set("pooled_conn", int(*object.Statistics.PooledConn))

	lastAssignedField = "port"
	d.Set("port", int(*object.Statistics.Port))

	lastAssignedField = "response_max"
	d.Set("response_max", int(*object.Statistics.ResponseMax))

	lastAssignedField = "response_mean"
	d.Set("response_mean", int(*object.Statistics.ResponseMean))

	lastAssignedField = "response_min"
	d.Set("response_min", int(*object.Statistics.ResponseMin))

	lastAssignedField = "state"
	d.Set("state", string(*object.Statistics.State))

	lastAssignedField = "total_conn"
	d.Set("total_conn", int(*object.Statistics.TotalConn))
	d.SetId(objectName)
	return nil
}
