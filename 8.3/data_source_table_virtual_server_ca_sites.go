// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.3"
)

func dataSourceVirtualServerCaSitesTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVirtualServerCaSitesTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// cert_headers
			"cert_headers": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"all", "none", "simple"}, false),
			},

			// client_cas
			"client_cas": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// host
			"host": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// request_cert
			"request_cert": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"dont_request", "request", "require"}, false),
			},
		},
	}
}

func dataSourceVirtualServerCaSitesTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.VirtualServerCaSites{
		CertHeaders: getStringAddr(d.Get("cert_headers").(string)),
		ClientCas:   getStringListAddr(expandStringList(d.Get("client_cas").([]interface{}))),
		Host:        getStringAddr(d.Get("host").(string)),
		RequestCert: getStringAddr(d.Get("request_cert").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("VirtualServerCaSites")
	return nil
}
