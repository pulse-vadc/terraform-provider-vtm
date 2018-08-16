// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceTrafficIpGroupIpMappingTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficIpGroupIpMappingTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// ip
			"ip": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// traffic_manager
			"traffic_manager": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceTrafficIpGroupIpMappingTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficIpGroupIpMapping{
		Ip:             getStringAddr(d.Get("ip").(string)),
		TrafficManager: getStringAddr(d.Get("traffic_manager").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficIpGroupIpMapping")
	return nil
}
