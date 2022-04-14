// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceUserGroupPermissionsTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceUserGroupPermissionsTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// access_level
			"access_level": &schema.Schema{
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

func dataSourceUserGroupPermissionsTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.UserGroupPermissions{
		AccessLevel: getStringAddr(d.Get("access_level").(string)),
		Name:        getStringAddr(d.Get("name").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("UserGroupPermissions")
	return nil
}
