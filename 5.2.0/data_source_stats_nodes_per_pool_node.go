// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object NodesPerPoolNode
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceNodesPerPoolNodeStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceNodesPerPoolNodeStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Bytes received from this node.
			"bytes_from_node": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes sent to this node.
			"bytes_to_node": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Current connections established to a node, includes idle connections.
			"current_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Active connections established to this node, does not include
			//  idle connections.
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

			// Number of idle HTTP connections to this node.
			"idle_conns": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of hash buckets occupied for this node for L4 stateless
			//  processing.
			"l4_stateless_buckets": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests that created a new connection to this node.
			"new_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The port that this node listens on.
			"node_port": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Packets received from this node.
			"pkts_from_node": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Packets sent to this node.
			"pkts_to_node": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests that reused an existing pooled/keepalive connection
			//  rather than creating a new TCP connection.
			"pooled_conn": &schema.Schema{
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

func dataSourceNodesPerPoolNodeStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetNodesPerPoolNodeStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_per_pool_node '%v': %v", objectName, err.ErrorText)
	}
	d.Set("bytes_from_node", int(*object.Statistics.BytesFromNode))
	d.Set("bytes_to_node", int(*object.Statistics.BytesToNode))
	d.Set("current_conn", int(*object.Statistics.CurrentConn))
	d.Set("current_requests", int(*object.Statistics.CurrentRequests))
	d.Set("errors", int(*object.Statistics.Errors))
	d.Set("failures", int(*object.Statistics.Failures))
	d.Set("idle_conns", int(*object.Statistics.IdleConns))
	d.Set("l4_stateless_buckets", int(*object.Statistics.L4StatelessBuckets))
	d.Set("new_conn", int(*object.Statistics.NewConn))
	d.Set("node_port", int(*object.Statistics.NodePort))
	d.Set("pkts_from_node", int(*object.Statistics.PktsFromNode))
	d.Set("pkts_to_node", int(*object.Statistics.PktsToNode))
	d.Set("pooled_conn", int(*object.Statistics.PooledConn))
	d.Set("response_max", int(*object.Statistics.ResponseMax))
	d.Set("response_mean", int(*object.Statistics.ResponseMean))
	d.Set("response_min", int(*object.Statistics.ResponseMin))
	d.Set("state", string(*object.Statistics.State))
	d.Set("total_conn", int(*object.Statistics.TotalConn))
	d.SetId(objectName)
	return nil
}
