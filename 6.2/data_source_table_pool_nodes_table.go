// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func dataSourcePoolNodesTableTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePoolNodesTableTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// node
			"node": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// priority
			"priority": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      1,
			},

			// source_ip
			"source_ip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// state
			"state": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"active", "disabled", "draining"}, false),
				Default:      "active",
			},

			// weight
			"weight": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 100),
				Default:      1,
			},
		},
	}
}

func dataSourcePoolNodesTableTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.PoolNodesTable{
		Node:     getStringAddr(d.Get("node").(string)),
		Priority: getIntAddr(d.Get("priority").(int)),
		SourceIp: getStringAddr(d.Get("source_ip").(string)),
		State:    getStringAddr(d.Get("state").(string)),
		Weight:   getIntAddr(d.Get("weight").(int)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("PoolNodesTable")
	return nil
}
