// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.2"
)

func resourceSslServerKey() *schema.Resource {
	return &schema.Resource{
		Read:   resourceSslServerKeyRead,
		Exists: resourceSslServerKeyExists,
		Create: resourceSslServerKeyCreate,
		Update: resourceSslServerKeyUpdate,
		Delete: resourceSslServerKeyDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceSslServerKeySchema(),
	}
}

func getResourceSslServerKeySchema() map[string]*schema.Schema {
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

func resourceSslServerKeyRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslServerKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_server_key '%v': %v", objectName, err.ErrorText)
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

func resourceSslServerKeyExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetSslServerKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceSslServerKeyCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewSslServerKey(objectName, d.Get("note").(string), d.Get("private").(string), d.Get("public").(string), d.Get("request").(string))
	resourceSslServerKeyObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_server_key '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSslServerKeyUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslServerKey(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_server_key '%v': %v", objectName, err)
	}
	resourceSslServerKeyObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_server_key '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSslServerKeyObjectFieldAssignments(d *schema.ResourceData, object *vtm.SslServerKey) {
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Private, d, "private")
	setString(&object.Basic.Public, d, "public")
	setString(&object.Basic.Request, d, "request")
}

func resourceSslServerKeyDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteSslServerKey(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_server_key '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
