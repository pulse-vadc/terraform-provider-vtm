// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func resourcePersistence() *schema.Resource {
	return &schema.Resource{
		Read:   resourcePersistenceRead,
		Exists: resourcePersistenceExists,
		Create: resourcePersistenceCreate,
		Update: resourcePersistenceUpdate,
		Delete: resourcePersistenceDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourcePersistenceSchema(),
	}
}

func getResourcePersistenceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The cookie name to use for tracking session persistence.
		"cookie": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not the session should be deleted when a session failure
		//  occurs. (Note, setting a failure mode of 'choose a new node'
		//  implicitly deletes the session.)
		"delete": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The action the pool should take if the session data is invalid
		//  or it cannot contact the node specified by the session.
		"failure_mode": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"close", "new_node", "url"}, false),
			Default:      "new_node",
		},

		// A description of the session persistence class.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// When using IP-based session persistence, ensure all requests
		//  from this IPv4 subnet, specified as a prefix length, are sent
		//  to the same node. If set to 0, requests from different IPv4 addresses
		//  will be load-balanced individually.
		"subnet_prefix_length_v4": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 31),
			Default:      0,
		},

		// When using IP-based session persistence, ensure all requests
		//  from this IPv6 subnet, specified as a prefix length, are sent
		//  to the same node. If set to 0, requests from different IPv6 addresses
		//  will be load-balanced individually.
		"subnet_prefix_length_v6": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 127),
			Default:      0,
		},

		// The type of session persistence to use.
		"type": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"asp", "cookie", "ip", "j2ee", "named", "ssl", "transparent", "universal", "x_zeus"}, false),
			Default:      "ip",
		},

		// The redirect URL to send clients to if the session persistence
		//  is configured to redirect users when a node dies.
		"url": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},
	}
}

func resourcePersistenceRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetPersistence(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_persistence '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "cookie"
	d.Set("cookie", string(*object.Basic.Cookie))
	lastAssignedField = "delete"
	d.Set("delete", bool(*object.Basic.Delete))
	lastAssignedField = "failure_mode"
	d.Set("failure_mode", string(*object.Basic.FailureMode))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "subnet_prefix_length_v4"
	d.Set("subnet_prefix_length_v4", int(*object.Basic.SubnetPrefixLengthV4))
	lastAssignedField = "subnet_prefix_length_v6"
	d.Set("subnet_prefix_length_v6", int(*object.Basic.SubnetPrefixLengthV6))
	lastAssignedField = "type"
	d.Set("type", string(*object.Basic.Type))
	lastAssignedField = "url"
	d.Set("url", string(*object.Basic.Url))
	d.SetId(objectName)
	return nil
}

func resourcePersistenceExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetPersistence(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourcePersistenceCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewPersistence(objectName)
	resourcePersistenceObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_persistence '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourcePersistenceUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetPersistence(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_persistence '%v': %v", objectName, err)
	}
	resourcePersistenceObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_persistence '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourcePersistenceObjectFieldAssignments(d *schema.ResourceData, object *vtm.Persistence) {
	setString(&object.Basic.Cookie, d, "cookie")
	setBool(&object.Basic.Delete, d, "delete")
	setString(&object.Basic.FailureMode, d, "failure_mode")
	setString(&object.Basic.Note, d, "note")
	setInt(&object.Basic.SubnetPrefixLengthV4, d, "subnet_prefix_length_v4")
	setInt(&object.Basic.SubnetPrefixLengthV6, d, "subnet_prefix_length_v6")
	setString(&object.Basic.Type, d, "type")
	setString(&object.Basic.Url, d, "url")
}

func resourcePersistenceDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeletePersistence(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_persistence '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
