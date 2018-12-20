// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceMonitorArgumentsTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceMonitorArgumentsTableRead,

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

			// name
			"name": &schema.Schema{
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

func dataSourceMonitorArgumentsTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.MonitorArguments{
		Description: getStringAddr(d.Get("description").(string)),
		Name:        getStringAddr(d.Get("name").(string)),
		Value:       getStringAddr(d.Get("value").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("MonitorArguments")
	return nil
}
