// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/7.1"
)

func dataSourceTrafficManagerIpTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerIpTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// addr
			"addr": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// isexternal
			"isexternal": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// mask
			"mask": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// name
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceTrafficManagerIpTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerIp{
		Addr:       getStringAddr(d.Get("addr").(string)),
		Isexternal: getBoolAddr(d.Get("isexternal").(bool)),
		Mask:       getStringAddr(d.Get("mask").(string)),
		Name:       getStringAddr(d.Get("name").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerIp")
	return nil
}
