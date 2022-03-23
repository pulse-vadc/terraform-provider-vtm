// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceVirtualServerOcspIssuersTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVirtualServerOcspIssuersTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// aia
			"aia": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// issuer
			"issuer": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// nonce
			"nonce": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"off", "on", "strict"}, false),
				Default:      "off",
			},

			// required
			"required": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"none", "optional", "strict"}, false),
				Default:      "optional",
			},

			// responder_cert
			"responder_cert": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// signer
			"signer": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// url
			"url": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceVirtualServerOcspIssuersTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.VirtualServerOcspIssuers{
		Aia:           getBoolAddr(d.Get("aia").(bool)),
		Issuer:        getStringAddr(d.Get("issuer").(string)),
		Nonce:         getStringAddr(d.Get("nonce").(string)),
		Required:      getStringAddr(d.Get("required").(string)),
		ResponderCert: getStringAddr(d.Get("responder_cert").(string)),
		Signer:        getStringAddr(d.Get("signer").(string)),
		Url:           getStringAddr(d.Get("url").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("VirtualServerOcspIssuers")
	return nil
}
