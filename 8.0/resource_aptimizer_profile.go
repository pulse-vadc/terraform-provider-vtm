// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.0"
)

func resourceAptimizerProfile() *schema.Resource {
	return &schema.Resource{
		Read:   resourceAptimizerProfileRead,
		Exists: resourceAptimizerProfileExists,
		Create: resourceAptimizerProfileCreate,
		Update: resourceAptimizerProfileUpdate,
		Delete: resourceAptimizerProfileDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceAptimizerProfileSchema(),
	}
}

func getResourceAptimizerProfileSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// If Web Accelerator can finish optimizing the resource within
		//  this time limit then serve the optimized content to the client,
		//  otherwise complete the optimization in the background and return
		//  the original content to the client. If set to 0, Web Accelerator
		//  will always wait for the optimization to complete before sending
		//  a response to the client.
		"background_after": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 999999),
			Default:      0,
		},

		// If a web page contains resources that have not yet been optimized,
		//  fetch and optimize those resources in the background and send
		//  a partially optimized web page to clients until all resources
		//  on that page are ready.
		"background_on_additional_resources": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Set the Web Accelerator mode to turn acceleration on or off.
		"mode": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"active", "idle", "stealth"}, false),
			Default:      "active",
		},

		// Show the Web Accelerator information bar on optimized web pages.
		//  This requires HTML optimization to be enabled in the acceleration
		//  settings.
		"show_info_bar": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
	}
}

func resourceAptimizerProfileRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerProfile(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_profile '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "background_after"
	d.Set("background_after", int(*object.Basic.BackgroundAfter))
	lastAssignedField = "background_on_additional_resources"
	d.Set("background_on_additional_resources", bool(*object.Basic.BackgroundOnAdditionalResources))
	lastAssignedField = "mode"
	d.Set("mode", string(*object.Basic.Mode))
	lastAssignedField = "show_info_bar"
	d.Set("show_info_bar", bool(*object.Basic.ShowInfoBar))
	d.SetId(objectName)
	return nil
}

func resourceAptimizerProfileExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerProfile(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceAptimizerProfileCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewAptimizerProfile(objectName)
	resourceAptimizerProfileObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_profile '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceAptimizerProfileUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerProfile(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_profile '%v': %v", objectName, err)
	}
	resourceAptimizerProfileObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_profile '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceAptimizerProfileObjectFieldAssignments(d *schema.ResourceData, object *vtm.AptimizerProfile) {
	setInt(&object.Basic.BackgroundAfter, d, "background_after")
	setBool(&object.Basic.BackgroundOnAdditionalResources, d, "background_on_additional_resources")
	setString(&object.Basic.Mode, d, "mode")
	setBool(&object.Basic.ShowInfoBar, d, "show_info_bar")
}

func resourceAptimizerProfileDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteAptimizerProfile(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_profile '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
