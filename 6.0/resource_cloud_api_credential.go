// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func resourceCloudApiCredential() *schema.Resource {
	return &schema.Resource{
		Read:   resourceCloudApiCredentialRead,
		Exists: resourceCloudApiCredentialExists,
		Create: resourceCloudApiCredentialCreate,
		Update: resourceCloudApiCredentialUpdate,
		Delete: resourceCloudApiCredentialDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceCloudApiCredentialSchema(),
	}
}

func getResourceCloudApiCredentialSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The vCenter server hostname or IP address.
		"api_server": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The traffic manager creates and destroys nodes via API calls.
		//  This setting specifies (in seconds) how long to wait for such
		//  calls to complete.
		"cloud_api_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 999999),
			Default:      200,
		},

		// The first part of the credentials for the cloud user.  Typically
		//  this is some variation on the username concept.
		"cred1": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The second part of the credentials for the cloud user.  Typically
		//  this is some variation on the password concept.
		"cred2": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The third part of the credentials for the cloud user.  Typically
		//  this is some variation on the authentication token concept.
		"cred3": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The script to call for communication with the cloud API.
		"script": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The traffic manager will periodically check the status of the
		//  cloud through an API call. This setting specifies the interval
		//  between such updates.
		"update_interval": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 999999),
			Default:      30,
		},
	}
}

func resourceCloudApiCredentialRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetCloudApiCredential(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_cloud_api_credential '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "api_server"
	d.Set("api_server", string(*object.Basic.ApiServer))
	lastAssignedField = "cloud_api_timeout"
	d.Set("cloud_api_timeout", int(*object.Basic.CloudApiTimeout))
	lastAssignedField = "cred1"
	d.Set("cred1", string(*object.Basic.Cred1))
	lastAssignedField = "cred2"
	d.Set("cred2", string(*object.Basic.Cred2))
	lastAssignedField = "cred3"
	d.Set("cred3", string(*object.Basic.Cred3))
	lastAssignedField = "script"
	d.Set("script", string(*object.Basic.Script))
	lastAssignedField = "update_interval"
	d.Set("update_interval", int(*object.Basic.UpdateInterval))
	d.SetId(objectName)
	return nil
}

func resourceCloudApiCredentialExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetCloudApiCredential(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceCloudApiCredentialCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewCloudApiCredential(objectName)
	resourceCloudApiCredentialObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_cloud_api_credential '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceCloudApiCredentialUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetCloudApiCredential(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_cloud_api_credential '%v': %v", objectName, err)
	}
	resourceCloudApiCredentialObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_cloud_api_credential '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceCloudApiCredentialObjectFieldAssignments(d *schema.ResourceData, object *vtm.CloudApiCredential) {
	setString(&object.Basic.ApiServer, d, "api_server")
	setInt(&object.Basic.CloudApiTimeout, d, "cloud_api_timeout")
	setString(&object.Basic.Cred1, d, "cred1")
	setString(&object.Basic.Cred2, d, "cred2")
	setString(&object.Basic.Cred3, d, "cred3")
	setString(&object.Basic.Script, d, "script")
	setInt(&object.Basic.UpdateInterval, d, "update_interval")
}

func resourceCloudApiCredentialDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteCloudApiCredential(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_cloud_api_credential '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
