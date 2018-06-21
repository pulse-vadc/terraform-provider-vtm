// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceDnsServerZone() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceDnsServerZoneRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The domain origin of this Zone.
			"origin": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The Zone File encapsulated by this Zone.
			"zonefile": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceDnsServerZoneRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetDnsServerZone(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_dns_server_zone '%v': %v", objectName, err.ErrorText)
	}
	d.Set("origin", string(*object.Basic.Origin))
	d.Set("zonefile", string(*object.Basic.Zonefile))

	d.SetId(objectName)
	return nil
}
