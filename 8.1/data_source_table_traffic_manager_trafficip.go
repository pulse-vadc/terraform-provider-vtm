// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func dataSourceTrafficManagerTrafficipTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerTrafficipTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// name
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// networks
			"networks": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceTrafficManagerTrafficipTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerTrafficip{
		Name:     getStringAddr(d.Get("name").(string)),
		Networks: getStringListAddr(expandStringList(d.Get("networks").([]interface{}))),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerTrafficip")
	return nil
}
