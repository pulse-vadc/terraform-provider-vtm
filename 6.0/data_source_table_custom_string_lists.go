// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceCustomStringListsTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCustomStringListsTableRead,

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

			// value
			"value": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceCustomStringListsTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.CustomStringLists{
		Name:  getStringAddr(d.Get("name").(string)),
		Value: getStringListAddr(expandStringList(d.Get("value").([]interface{}))),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("CustomStringLists")
	return nil
}
