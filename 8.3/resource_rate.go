// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.3"
)

func resourceRate() *schema.Resource {
	return &schema.Resource{
		Read:   resourceRateRead,
		Exists: resourceRateExists,
		Create: resourceRateCreate,
		Update: resourceRateUpdate,
		Delete: resourceRateDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceRateSchema(),
	}
}

func getResourceRateSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Requests that are associated with this rate class will be rate-shaped
		//  to this many requests per minute, set to "0" to disable the limit.
		"max_rate_per_minute": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// Although requests will be rate-shaped to the "max_rate_per_minute",
		//  the traffic manager will also rate limit per-second. This smooths
		//  traffic so that a full minute's traffic will not be serviced
		//  in the first second of the minute, set this to "0" to disable
		//  the per-second limit.
		"max_rate_per_second": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// A description of the rate class.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},
	}
}

func resourceRateRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetRate(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rate '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "max_rate_per_minute"
	d.Set("max_rate_per_minute", int(*object.Basic.MaxRatePerMinute))
	lastAssignedField = "max_rate_per_second"
	d.Set("max_rate_per_second", int(*object.Basic.MaxRatePerSecond))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	d.SetId(objectName)
	return nil
}

func resourceRateExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetRate(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceRateCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewRate(objectName)
	resourceRateObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_rate '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceRateUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetRate(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_rate '%v': %v", objectName, err)
	}
	resourceRateObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_rate '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceRateObjectFieldAssignments(d *schema.ResourceData, object *vtm.Rate) {
	setInt(&object.Basic.MaxRatePerMinute, d, "max_rate_per_minute")
	setInt(&object.Basic.MaxRatePerSecond, d, "max_rate_per_second")
	setString(&object.Basic.Note, d, "note")
}

func resourceRateDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteRate(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_rate '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
