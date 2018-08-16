// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func resourceSslClientKey() *schema.Resource {
	return &schema.Resource{
		Read:   resourceSslClientKeyRead,
		Exists: resourceSslClientKeyExists,
		Create: resourceSslClientKeyCreate,
		Update: resourceSslClientKeyUpdate,
		Delete: resourceSslClientKeyDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceSslClientKeySchema(),
	}
}

func getResourceSslClientKeySchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Notes for this certificate
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// Private key for certificate
		"private": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
			DiffSuppressFunc: suppressHashedDiffs("private"),
		},

		// Public certificate
		"public": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// Certificate Signing Request for certificate
		"request": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},
	}
}

func resourceSslClientKeyRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslClientKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_client_key '%v': %v", objectName, err.ErrorText)
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
	lastAssignedField = "private"
	d.Set("private", string(*object.Basic.Private))
	lastAssignedField = "public"
	d.Set("public", string(*object.Basic.Public))
	lastAssignedField = "request"
	d.Set("request", string(*object.Basic.Request))
	d.SetId(objectName)
	return nil
}

func resourceSslClientKeyExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetSslClientKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceSslClientKeyCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewSslClientKey(objectName, d.Get("note").(string), d.Get("private").(string), d.Get("public").(string), d.Get("request").(string))
	resourceSslClientKeyObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_client_key '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSslClientKeyUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslClientKey(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_client_key '%v': %v", objectName, err)
	}
	resourceSslClientKeyObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_client_key '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSslClientKeyObjectFieldAssignments(d *schema.ResourceData, object *vtm.SslClientKey) {
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Private, d, "private")
	setString(&object.Basic.Public, d, "public")
	setString(&object.Basic.Request, d, "request")
}

func resourceSslClientKeyDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteSslClientKey(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_client_key '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
