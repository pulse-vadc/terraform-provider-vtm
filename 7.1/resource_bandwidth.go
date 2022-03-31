// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/7.1"
)

func resourceBandwidth() *schema.Resource {
	return &schema.Resource{
		Read:   resourceBandwidthRead,
		Exists: resourceBandwidthExists,
		Create: resourceBandwidthCreate,
		Update: resourceBandwidthUpdate,
		Delete: resourceBandwidthDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceBandwidthSchema(),
	}
}

func getResourceBandwidthSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

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
	}
}

func resourceBandwidthRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetBandwidth(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_bandwidth '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "maximum"
	d.Set("maximum", int(*object.Basic.Maximum))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "sharing"
	d.Set("sharing", string(*object.Basic.Sharing))
	d.SetId(objectName)
	return nil
}

func resourceBandwidthExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetBandwidth(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceBandwidthCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewBandwidth(objectName)
	resourceBandwidthObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_bandwidth '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceBandwidthUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetBandwidth(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_bandwidth '%v': %v", objectName, err)
	}
	resourceBandwidthObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_bandwidth '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceBandwidthObjectFieldAssignments(d *schema.ResourceData, object *vtm.Bandwidth) {
	setInt(&object.Basic.Maximum, d, "maximum")
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Sharing, d, "sharing")
}

func resourceBandwidthDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteBandwidth(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_bandwidth '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
