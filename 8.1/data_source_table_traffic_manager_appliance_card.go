// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func dataSourceTrafficManagerApplianceCardTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerApplianceCardTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// interfaces
			"interfaces": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// label
			"label": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "-",
			},

			// name
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceTrafficManagerApplianceCardTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerApplianceCard{
		Interfaces: getStringListAddr(expandStringList(d.Get("interfaces").([]interface{}))),
		Label:      getStringAddr(d.Get("label").(string)),
		Name:       getStringAddr(d.Get("name").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerApplianceCard")
	return nil
}
