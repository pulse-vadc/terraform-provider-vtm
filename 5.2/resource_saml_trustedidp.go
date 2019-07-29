// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceSamlTrustedidp() *schema.Resource {
	return &schema.Resource{
		Read:   resourceSamlTrustedidpRead,
		Exists: resourceSamlTrustedidpExists,
		Create: resourceSamlTrustedidpCreate,
		Update: resourceSamlTrustedidpUpdate,
		Delete: resourceSamlTrustedidpDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceSamlTrustedidpSchema(),
	}
}

func getResourceSamlTrustedidpSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Whether or not to add the zlib header when compressing the AuthnRequest
		"add_zlib_header": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The certificate used to verify Assertions signed by the identity
		//  provider
		"certificate": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// The entity id of the IDP
		"entity_id": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// Whether or not SAML responses will be verified strictly
		"strict_verify": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The IDP URL to which Authentication Requests should be sent
		"url": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},
	}
}

func resourceSamlTrustedidpRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetSamlTrustedidp(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_trustedidp '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "add_zlib_header"
	d.Set("add_zlib_header", bool(*object.Basic.AddZlibHeader))
	lastAssignedField = "certificate"
	d.Set("certificate", string(*object.Basic.Certificate))
	lastAssignedField = "entity_id"
	d.Set("entity_id", string(*object.Basic.EntityId))
	lastAssignedField = "strict_verify"
	d.Set("strict_verify", bool(*object.Basic.StrictVerify))
	lastAssignedField = "url"
	d.Set("url", string(*object.Basic.Url))
	d.SetId(objectName)
	return nil
}

func resourceSamlTrustedidpExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetSamlTrustedidp(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceSamlTrustedidpCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewSamlTrustedidp(objectName, d.Get("certificate").(string), d.Get("entity_id").(string), d.Get("url").(string))
	resourceSamlTrustedidpObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_trustedidp '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSamlTrustedidpUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSamlTrustedidp(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_trustedidp '%v': %v", objectName, err)
	}
	resourceSamlTrustedidpObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_trustedidp '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSamlTrustedidpObjectFieldAssignments(d *schema.ResourceData, object *vtm.SamlTrustedidp) {
	setBool(&object.Basic.AddZlibHeader, d, "add_zlib_header")
	setString(&object.Basic.Certificate, d, "certificate")
	setString(&object.Basic.EntityId, d, "entity_id")
	setBool(&object.Basic.StrictVerify, d, "strict_verify")
	setString(&object.Basic.Url, d, "url")
}

func resourceSamlTrustedidpDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteSamlTrustedidp(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_trustedidp '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
