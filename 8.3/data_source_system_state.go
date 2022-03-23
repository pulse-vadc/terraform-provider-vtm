// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.3"
)

func dataSourceSystemState() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSystemStateRead,
		Schema: map[string]*schema.Schema{

			// The error_level of the traffic manager.
			"state_error_level": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"ok", "warn", "error", "fatal"}, false),
				Default:      "ok",
			},

			// List of configuration errors for the traffic manager
			"state_errors": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// A table of nodes which have failed on the traffic manager
			"state_failed_nodes": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// node
						"node": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// pools
						"pools": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Default:  nil,
						},
					},
				},
			},

			// Current active license or Community_Edition
			"state_license": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			//
			"state_pools": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// active_nodes
						"active_nodes": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Default:  nil,
						},

						// disabled_nodes
						"disabled_nodes": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Default:  nil,
						},

						// draining_nodes
						"draining_nodes": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Default:  nil,
						},

						// failure_pool
						"failure_pool": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// List of traffic IP errors for the traffic manager
			"state_tip_errors": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// A table of virtual server status
			"state_virtual_servers": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// pool
						"pool": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// port
						"port": &schema.Schema{
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntAtLeast(0),
							Default:      1,
						},

						// throughput
						"throughput": &schema.Schema{
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
						},

						// ts_redirect_pools
						"ts_redirect_pools": &schema.Schema{
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Default:  nil,
						},
					},
				},
			},
		},
	}
}

func dataSourceSystemStateRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetSystemState()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_state: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "state_error_level"
	d.Set("state_error_level", string(*object.State.ErrorLevel))
	lastAssignedField = "state_errors"
	d.Set("state_errors", []string(*object.State.Errors))
	lastAssignedField = "state_failed_nodes"
	stateFailedNodes := make([]map[string]interface{}, 0, len(*object.State.FailedNodes))
	for _, item := range *object.State.FailedNodes {
		itemTerraform := make(map[string]interface{})
		if item.Node != nil {
			itemTerraform["node"] = string(*item.Node)
		}
		if item.Pools != nil {
			itemTerraform["pools"] = []string(*item.Pools)
		}
		stateFailedNodes = append(stateFailedNodes, itemTerraform)
	}
	d.Set("state_failed_nodes", stateFailedNodes)
	stateFailedNodesJson, _ := json.Marshal(stateFailedNodes)
	d.Set("state_failed_nodes_json", stateFailedNodesJson)
	lastAssignedField = "state_license"
	d.Set("state_license", string(*object.State.License))
	lastAssignedField = "state_pools"
	statePools := make([]map[string]interface{}, 0, len(*object.State.Pools))
	for _, item := range *object.State.Pools {
		itemTerraform := make(map[string]interface{})
		if item.ActiveNodes != nil {
			itemTerraform["active_nodes"] = []string(*item.ActiveNodes)
		}
		if item.DisabledNodes != nil {
			itemTerraform["disabled_nodes"] = []string(*item.DisabledNodes)
		}
		if item.DrainingNodes != nil {
			itemTerraform["draining_nodes"] = []string(*item.DrainingNodes)
		}
		if item.FailurePool != nil {
			itemTerraform["failure_pool"] = string(*item.FailurePool)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		statePools = append(statePools, itemTerraform)
	}
	d.Set("state_pools", statePools)
	statePoolsJson, _ := json.Marshal(statePools)
	d.Set("state_pools_json", statePoolsJson)
	lastAssignedField = "state_tip_errors"
	d.Set("state_tip_errors", []string(*object.State.TipErrors))
	lastAssignedField = "state_virtual_servers"
	stateVirtualServers := make([]map[string]interface{}, 0, len(*object.State.VirtualServers))
	for _, item := range *object.State.VirtualServers {
		itemTerraform := make(map[string]interface{})
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Pool != nil {
			itemTerraform["pool"] = string(*item.Pool)
		}
		if item.Port != nil {
			itemTerraform["port"] = int(*item.Port)
		}
		if item.Throughput != nil {
			itemTerraform["throughput"] = int(*item.Throughput)
		}
		if item.TsRedirectPools != nil {
			itemTerraform["ts_redirect_pools"] = []string(*item.TsRedirectPools)
		}
		stateVirtualServers = append(stateVirtualServers, itemTerraform)
	}
	d.Set("state_virtual_servers", stateVirtualServers)
	stateVirtualServersJson, _ := json.Marshal(stateVirtualServers)
	d.Set("state_virtual_servers_json", stateVirtualServersJson)
	d.SetId("state")
	return nil
}
