// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceTrafficManagerHostsTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerHostsTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// ip_address
			"ip_address": &schema.Schema{
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

func dataSourceTrafficManagerHostsTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerHosts{
		IpAddress: getStringAddr(d.Get("ip_address").(string)),
		Name:      getStringAddr(d.Get("name").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerHosts")
	return nil
}
