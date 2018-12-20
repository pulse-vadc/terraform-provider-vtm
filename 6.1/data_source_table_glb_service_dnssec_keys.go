// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceGlbServiceDnssecKeysTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceGlbServiceDnssecKeysTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// domain
			"domain": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// ssl_key
			"ssl_key": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGlbServiceDnssecKeysTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.GlbServiceDnssecKeys{
		Domain: getStringAddr(d.Get("domain").(string)),
		SslKey: getStringListAddr(d.Get("ssl_key").([]string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("GlbServiceDnssecKeys")
	return nil
}
