// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/8.0"
)

func dataSourceVirtualServerServerCertHostMappingTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVirtualServerServerCertHostMappingTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// alt_certificates
			"alt_certificates": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Default:  nil,
			},

			// certificate
			"certificate": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// host
			"host": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceVirtualServerServerCertHostMappingTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.VirtualServerServerCertHostMapping{
		AltCertificates: getStringListAddr(expandStringList(d.Get("alt_certificates").([]interface{}))),
		Certificate:     getStringAddr(d.Get("certificate").(string)),
		Host:            getStringAddr(d.Get("host").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("VirtualServerServerCertHostMapping")
	return nil
}
