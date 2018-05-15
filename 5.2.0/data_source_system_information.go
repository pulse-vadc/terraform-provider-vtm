// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceSystemInformation() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSystemInformationRead,

		Schema: map[string]*schema.Schema{

			// Version number of the Traffic Manager instance.
			"information_tm_version": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The universally unique identifier for the Traffic Manager instance.
			"information_uuid": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceSystemInformationRead(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetSystemInformation()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_information: %v", err.ErrorText)
	}
	d.Set("information_tm_version", string(*object.Information.TmVersion))
	d.Set("information_uuid", string(*object.Information.Uuid))

	d.SetId("information")
	return nil
}
