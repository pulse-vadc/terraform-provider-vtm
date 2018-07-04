// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceLocation() *schema.Resource {
	return &schema.Resource{
		Read:   resourceLocationRead,
		Exists: resourceLocationExists,
		Create: resourceLocationCreate,
		Update: resourceLocationUpdate,
		Delete: resourceLocationDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

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
				Required:     true,
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

func resourceLocationRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
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

func resourceLocationExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetLocation(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceLocationCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewLocation(objectName, d.Get("identifier").(int))
	setInt(&object.Basic.Id, d, "identifier")
	setFloat(&object.Basic.Latitude, d, "latitude")
	setFloat(&object.Basic.Longitude, d, "longitude")
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Type, d, "type")

	object.Apply()
	d.SetId(objectName)
	return nil
}

func resourceLocationUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetLocation(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_location '%v': %v", objectName, err)
	}
	setInt(&object.Basic.Id, d, "identifier")
	setFloat(&object.Basic.Latitude, d, "latitude")
	setFloat(&object.Basic.Longitude, d, "longitude")
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Type, d, "type")

	object.Apply()
	d.SetId(objectName)
	return nil
}

func resourceLocationDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteLocation(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_location '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
