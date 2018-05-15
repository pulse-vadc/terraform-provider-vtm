// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceSamlTrustedidp() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSamlTrustedidpRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Whether or not to add the zlib header when compressing the AuthnRequest
			"add_zlib_header": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The certificate used to verify Assertions signed by the identity
			//  provider
			"certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The entity id of the IDP
			"entity_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not SAML responses will be verified strictly
			"strict_verify": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The IDP URL to which Authentication Requests should be sent
			"url": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceSamlTrustedidpRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSamlTrustedidp(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_saml_trustedidp '%v': %v", objectName, err.ErrorText)
	}
	d.Set("add_zlib_header", bool(*object.Basic.AddZlibHeader))
	d.Set("certificate", string(*object.Basic.Certificate))
	d.Set("entity_id", string(*object.Basic.EntityId))
	d.Set("strict_verify", bool(*object.Basic.StrictVerify))
	d.Set("url", string(*object.Basic.Url))

	d.SetId(objectName)
	return nil
}
