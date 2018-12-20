// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func resourceServiceLevelMonitor() *schema.Resource {
	return &schema.Resource{
		Read:   resourceServiceLevelMonitorRead,
		Exists: resourceServiceLevelMonitorExists,
		Create: resourceServiceLevelMonitorCreate,
		Update: resourceServiceLevelMonitorUpdate,
		Delete: resourceServiceLevelMonitorDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceServiceLevelMonitorSchema(),
	}
}

func getResourceServiceLevelMonitorSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// A description for the SLM class.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Responses that arrive within this time limit, expressed in milliseconds,
		//  are treated as conforming.
		"response_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      1000,
		},

		// When the percentage of conforming responses drops below this
		//  level, a serious error level message will be emitted.
		"serious_threshold": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 100),
			Default:      0,
		},

		// When the percentage of conforming responses drops below this
		//  level, a warning message will be emitted.
		"warning_threshold": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 100),
			Default:      50,
		},
	}
}

func resourceServiceLevelMonitorRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetServiceLevelMonitor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_service_level_monitor '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "response_time"
	d.Set("response_time", int(*object.Basic.ResponseTime))
	lastAssignedField = "serious_threshold"
	d.Set("serious_threshold", int(*object.Basic.SeriousThreshold))
	lastAssignedField = "warning_threshold"
	d.Set("warning_threshold", int(*object.Basic.WarningThreshold))
	d.SetId(objectName)
	return nil
}

func resourceServiceLevelMonitorExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetServiceLevelMonitor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceServiceLevelMonitorCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewServiceLevelMonitor(objectName)
	resourceServiceLevelMonitorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_service_level_monitor '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceServiceLevelMonitorUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetServiceLevelMonitor(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_service_level_monitor '%v': %v", objectName, err)
	}
	resourceServiceLevelMonitorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_service_level_monitor '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceServiceLevelMonitorObjectFieldAssignments(d *schema.ResourceData, object *vtm.ServiceLevelMonitor) {
	setString(&object.Basic.Note, d, "note")
	setInt(&object.Basic.ResponseTime, d, "response_time")
	setInt(&object.Basic.SeriousThreshold, d, "serious_threshold")
	setInt(&object.Basic.WarningThreshold, d, "warning_threshold")
}

func resourceServiceLevelMonitorDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteServiceLevelMonitor(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_service_level_monitor '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
