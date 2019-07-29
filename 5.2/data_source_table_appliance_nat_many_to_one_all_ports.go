// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceApplianceNatManyToOneAllPortsTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceApplianceNatManyToOneAllPortsTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// pool
			"pool": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// rule_number
			"rule_number": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// tip
			"tip": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceApplianceNatManyToOneAllPortsTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.ApplianceNatManyToOneAllPorts{
		Pool:       getStringAddr(d.Get("pool").(string)),
		RuleNumber: getStringAddr(d.Get("rule_number").(string)),
		Tip:        getStringAddr(d.Get("tip").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("ApplianceNatManyToOneAllPorts")
	return nil
}
