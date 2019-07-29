// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceApplianceNatPortMappingTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceApplianceNatPortMappingTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// dport_first
			"dport_first": &schema.Schema{
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			// dport_last
			"dport_last": &schema.Schema{
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			// rule_number
			"rule_number": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// virtual_server
			"virtual_server": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceApplianceNatPortMappingTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.ApplianceNatPortMapping{
		DportFirst:    getIntAddr(d.Get("dport_first").(int)),
		DportLast:     getIntAddr(d.Get("dport_last").(int)),
		RuleNumber:    getStringAddr(d.Get("rule_number").(string)),
		VirtualServer: getStringAddr(d.Get("virtual_server").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("ApplianceNatPortMapping")
	return nil
}
