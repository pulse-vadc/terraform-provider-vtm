// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/8.2"
)

func dataSourceTrafficManagerRoutesTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerRoutesTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// gw
			"gw": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// if
			"if": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
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

func dataSourceTrafficManagerRoutesTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerRoutes{
		Gw:   getStringAddr(d.Get("gw").(string)),
		If:   getStringAddr(d.Get("if").(string)),
		Mask: getStringAddr(d.Get("mask").(string)),
		Name: getStringAddr(d.Get("name").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerRoutes")
	return nil
}
