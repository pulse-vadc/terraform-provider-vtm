// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceApplianceNatManyToOnePortLockedTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceApplianceNatManyToOnePortLockedTableRead,

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

			// port
			"port": &schema.Schema{
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			// protocol
			"protocol": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"icmp", "sctp", "tcp", "udp", "udplite"}, false),
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

func dataSourceApplianceNatManyToOnePortLockedTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.ApplianceNatManyToOnePortLocked{
		Pool:       getStringAddr(d.Get("pool").(string)),
		Port:       getIntAddr(d.Get("port").(int)),
		Protocol:   getStringAddr(d.Get("protocol").(string)),
		RuleNumber: getStringAddr(d.Get("rule_number").(string)),
		Tip:        getStringAddr(d.Get("tip").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("ApplianceNatManyToOnePortLocked")
	return nil
}
