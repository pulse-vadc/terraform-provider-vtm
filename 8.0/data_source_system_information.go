// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/8.0"
)

func dataSourceSystemInformation() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSystemInformationRead,
		Schema: map[string]*schema.Schema{

			// The type of platform on which the Traffic Manager instance is
			//  running on.
			"information_platform": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

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

func dataSourceSystemInformationRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetSystemInformation()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_information: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "information_platform"
	d.Set("information_platform", string(*object.Information.Platform))
	lastAssignedField = "information_tm_version"
	d.Set("information_tm_version", string(*object.Information.TmVersion))
	lastAssignedField = "information_uuid"
	d.Set("information_uuid", string(*object.Information.Uuid))
	d.SetId("information")
	return nil
}
