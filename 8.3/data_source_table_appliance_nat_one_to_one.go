// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/8.3"
)

func dataSourceApplianceNatOneToOneTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceApplianceNatOneToOneTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// enable_inbound
			"enable_inbound": &schema.Schema{
				Type:     schema.TypeBool,
				Required: true,
			},

			// ip
			"ip": &schema.Schema{
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

func dataSourceApplianceNatOneToOneTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.ApplianceNatOneToOne{
		EnableInbound: getBoolAddr(d.Get("enable_inbound").(bool)),
		Ip:            getStringAddr(d.Get("ip").(string)),
		RuleNumber:    getStringAddr(d.Get("rule_number").(string)),
		Tip:           getStringAddr(d.Get("tip").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("ApplianceNatOneToOne")
	return nil
}
