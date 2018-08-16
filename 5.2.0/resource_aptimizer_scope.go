// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceAptimizerScope() *schema.Resource {
	return &schema.Resource{
		Read:   resourceAptimizerScopeRead,
		Exists: resourceAptimizerScopeExists,
		Create: resourceAptimizerScopeCreate,
		Update: resourceAptimizerScopeUpdate,
		Delete: resourceAptimizerScopeDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceAptimizerScopeSchema(),
	}
}

func getResourceAptimizerScopeSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// If the hostnames for this scope are aliases of each other, the
		//  canonical hostname will be used for requests to the server.
		"canonical_hostname": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The hostnames to limit acceleration to.
		"hostnames": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The root path of the application defined by this application
		//  scope.
		"root": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "/",
		},
	}
}

func resourceAptimizerScopeRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerScope(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_scope '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "canonical_hostname"
	d.Set("canonical_hostname", string(*object.Basic.CanonicalHostname))
	lastAssignedField = "hostnames"
	d.Set("hostnames", []string(*object.Basic.Hostnames))
	lastAssignedField = "root"
	d.Set("root", string(*object.Basic.Root))
	d.SetId(objectName)
	return nil
}

func resourceAptimizerScopeExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerScope(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceAptimizerScopeCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewAptimizerScope(objectName)
	resourceAptimizerScopeObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_scope '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceAptimizerScopeUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerScope(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_scope '%v': %v", objectName, err)
	}
	resourceAptimizerScopeObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_scope '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceAptimizerScopeObjectFieldAssignments(d *schema.ResourceData, object *vtm.AptimizerScope) {
	setString(&object.Basic.CanonicalHostname, d, "canonical_hostname")

	if _, ok := d.GetOk("hostnames"); ok {
		setStringSet(&object.Basic.Hostnames, d, "hostnames")
	} else {
		object.Basic.Hostnames = &[]string{}
		d.Set("hostnames", []string(*object.Basic.Hostnames))
	}
	setString(&object.Basic.Root, d, "root")
}

func resourceAptimizerScopeDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteAptimizerScope(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_scope '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
