// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/7.1"
)

func dataSourceTrafficManagerApplianceSysctlTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerApplianceSysctlTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// description
			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// sysctl
			"sysctl": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// value
			"value": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceTrafficManagerApplianceSysctlTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerApplianceSysctl{
		Description: getStringAddr(d.Get("description").(string)),
		Sysctl:      getStringAddr(d.Get("sysctl").(string)),
		Value:       getStringAddr(d.Get("value").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerApplianceSysctl")
	return nil
}
