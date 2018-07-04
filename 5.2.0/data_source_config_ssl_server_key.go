// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceSslServerKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSslServerKeyRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Notes for this certificate
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Private key for certificate
			"private": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Public certificate
			"public": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Certificate Signing Request for certificate
			"request": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceSslServerKeyRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslServerKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_ssl_server_key '%v': %v", objectName, err.ErrorText)
	}
	d.Set("note", string(*object.Basic.Note))
	d.Set("private", string(*object.Basic.Private))
	d.Set("public", string(*object.Basic.Public))
	d.Set("request", string(*object.Basic.Request))

	d.SetId(objectName)
	return nil
}
