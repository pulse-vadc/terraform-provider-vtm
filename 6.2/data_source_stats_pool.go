// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object Pool
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func dataSourcePoolStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePoolStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The load-balancing algorithm the pool uses.
			"algorithm": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Bytes received by this pool from nodes.
			"bytes_in": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes sent by this pool to nodes.
			"bytes_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total connections currently queued to this pool.
			"conns_queued": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of nodes in this pool that are disabled.
			"disabled": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of nodes in this pool which are draining.
			"draining": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 1xx responses returned by this pool.
			"http1xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 2xx responses returned by this pool.
			"http2xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 3xx responses returned by this pool.
			"http3xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 4xx responses returned by this pool.
			"http4xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times the pool received an HTTP 503 response from a
			//  node and retried it against a different node.
			"http503_retries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 5xx responses returned by this pool.
			"http5xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Maximum time a connection was queued for, over the last second.
			"max_queue_time": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Mean time a connection was queued for, over the last second.
			"mean_queue_time": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Minimum time a connection was queued for, over the last second.
			"min_queue_time": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of nodes registered with this pool.
			"nodes": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The session persistence method this pool uses
			"persistence": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Total connections that timed-out while queued.
			"queue_timeouts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Sessions migrated to a new node because the desired node was
			//  unavailable.
			"session_migrated": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The state of this pool.
			"state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Requests sent to this pool.
			"total_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourcePoolStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetPoolStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_pools '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "algorithm"
	d.Set("algorithm", string(*object.Statistics.Algorithm))

	lastAssignedField = "bytes_in"
	d.Set("bytes_in", int(*object.Statistics.BytesIn))

	lastAssignedField = "bytes_out"
	d.Set("bytes_out", int(*object.Statistics.BytesOut))

	lastAssignedField = "conns_queued"
	d.Set("conns_queued", int(*object.Statistics.ConnsQueued))

	lastAssignedField = "disabled"
	d.Set("disabled", int(*object.Statistics.Disabled))

	lastAssignedField = "draining"
	d.Set("draining", int(*object.Statistics.Draining))

	lastAssignedField = "http1xx_responses"
	d.Set("http1xx_responses", int(*object.Statistics.Http1XxResponses))

	lastAssignedField = "http2xx_responses"
	d.Set("http2xx_responses", int(*object.Statistics.Http2XxResponses))

	lastAssignedField = "http3xx_responses"
	d.Set("http3xx_responses", int(*object.Statistics.Http3XxResponses))

	lastAssignedField = "http4xx_responses"
	d.Set("http4xx_responses", int(*object.Statistics.Http4XxResponses))

	lastAssignedField = "http503_retries"
	d.Set("http503_retries", int(*object.Statistics.Http503Retries))

	lastAssignedField = "http5xx_responses"
	d.Set("http5xx_responses", int(*object.Statistics.Http5XxResponses))

	lastAssignedField = "max_queue_time"
	d.Set("max_queue_time", int(*object.Statistics.MaxQueueTime))

	lastAssignedField = "mean_queue_time"
	d.Set("mean_queue_time", int(*object.Statistics.MeanQueueTime))

	lastAssignedField = "min_queue_time"
	d.Set("min_queue_time", int(*object.Statistics.MinQueueTime))

	lastAssignedField = "nodes"
	d.Set("nodes", int(*object.Statistics.Nodes))

	lastAssignedField = "persistence"
	d.Set("persistence", string(*object.Statistics.Persistence))

	lastAssignedField = "queue_timeouts"
	d.Set("queue_timeouts", int(*object.Statistics.QueueTimeouts))

	lastAssignedField = "session_migrated"
	d.Set("session_migrated", int(*object.Statistics.SessionMigrated))

	lastAssignedField = "state"
	d.Set("state", string(*object.Statistics.State))

	lastAssignedField = "total_conn"
	d.Set("total_conn", int(*object.Statistics.TotalConn))
	d.SetId(objectName)
	return nil
}
