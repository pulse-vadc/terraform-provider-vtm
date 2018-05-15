// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceLocation() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceLocationRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The identifier of this location.
			"identifier": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2000000000),
			},

			// The latitude of this location.
			"latitude": &schema.Schema{
				Type:     schema.TypeFloat,
				Optional: true,
				Default:  0.0,
			},

			// The longitude of this location.
			"longitude": &schema.Schema{
				Type:     schema.TypeFloat,
				Optional: true,
				Default:  0.0,
			},

			// A note, used to describe this location.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Does this location contain traffic managers and configuration
			//  or is it a recipient of GLB requests?
			"type": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"config", "glb"}, false),
				Default:      "config",
			},
		},
	}
}

func dataSourceLocationRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetLocation(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_location '%v': %v", objectName, err.ErrorText)
	}
	d.Set("identifier", int(*object.Basic.Id))
	d.Set("latitude", float64(*object.Basic.Latitude))
	d.Set("longitude", float64(*object.Basic.Longitude))
	d.Set("note", string(*object.Basic.Note))
	d.Set("type", string(*object.Basic.Type))

	d.SetId(objectName)
	return nil
}
