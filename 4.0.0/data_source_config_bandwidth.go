// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceBandwidth() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceBandwidthRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The maximum bandwidth to allocate to connections that are associated
			//  with this bandwidth class (in kbits/second).
			"maximum": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 20000000),
				Default:      10000,
			},

			// A description of this bandwidth class.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The scope of the bandwidth class.
			"sharing": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"cluster", "connection", "machine"}, false),
				Default:      "cluster",
			},
		},
	}
}

func dataSourceBandwidthRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetBandwidth(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_bandwidth '%v': %v", objectName, err.ErrorText)
	}
	d.Set("maximum", int(*object.Basic.Maximum))
	d.Set("note", string(*object.Basic.Note))
	d.Set("sharing", string(*object.Basic.Sharing))

	d.SetId(objectName)
	return nil
}
