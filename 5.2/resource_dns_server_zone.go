// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceDnsServerZone() *schema.Resource {
	return &schema.Resource{
		Read:   resourceDnsServerZoneRead,
		Exists: resourceDnsServerZoneExists,
		Create: resourceDnsServerZoneCreate,
		Update: resourceDnsServerZoneUpdate,
		Delete: resourceDnsServerZoneDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceDnsServerZoneSchema(),
	}
}

func getResourceDnsServerZoneSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The domain origin of this Zone.
		"origin": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// The Zone File encapsulated by this Zone.
		"zonefile": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},
	}
}

func resourceDnsServerZoneRead(d *schema.ResourceData, tm interface{}) (readError error) {
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
		return fmt.Errorf("Failed to read vtm_zone '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "origin"
	d.Set("origin", string(*object.Basic.Origin))
	lastAssignedField = "zonefile"
	d.Set("zonefile", string(*object.Basic.Zonefile))
	d.SetId(objectName)
	return nil
}

func resourceDnsServerZoneExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetDnsServerZone(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceDnsServerZoneCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewDnsServerZone(objectName, d.Get("origin").(string), d.Get("zonefile").(string))
	resourceDnsServerZoneObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_zone '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceDnsServerZoneUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetDnsServerZone(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_zone '%v': %v", objectName, err)
	}
	resourceDnsServerZoneObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_zone '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceDnsServerZoneObjectFieldAssignments(d *schema.ResourceData, object *vtm.DnsServerZone) {
	setString(&object.Basic.Origin, d, "origin")
	setString(&object.Basic.Zonefile, d, "zonefile")
}

func resourceDnsServerZoneDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteDnsServerZone(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_zone '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
