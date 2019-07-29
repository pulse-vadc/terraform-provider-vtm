// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceGlobalSettingsApplianceReturnpathTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceGlobalSettingsApplianceReturnpathTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// ipv4
			"ipv4": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// ipv6
			"ipv6": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// mac
			"mac": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceGlobalSettingsApplianceReturnpathTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.GlobalSettingsApplianceReturnpath{
		Ipv4: getStringAddr(d.Get("ipv4").(string)),
		Ipv6: getStringAddr(d.Get("ipv6").(string)),
		Mac:  getStringAddr(d.Get("mac").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("GlobalSettingsApplianceReturnpath")
	return nil
}
