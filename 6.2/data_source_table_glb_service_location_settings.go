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

func dataSourceGlbServiceLocationSettingsTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceGlbServiceLocationSettingsTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// ips
			"ips": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// location
			"location": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// monitors
			"monitors": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Default:  nil,
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

func dataSourceGlbServiceLocationSettingsTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.GlbServiceLocationSettings{
		Ips:      getStringListAddr(expandStringList(d.Get("ips").([]interface{}))),
		Location: getStringAddr(d.Get("location").(string)),
		Monitors: getStringListAddr(expandStringList(d.Get("monitors").([]interface{}))),
		Weight:   getIntAddr(d.Get("weight").(int)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("GlbServiceLocationSettings")
	return nil
}
