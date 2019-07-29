// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func resourceKerberosKrb5Conf() *schema.Resource {
	return &schema.Resource{
		Read:   resourceKerberosKrb5ConfRead,
		Exists: resourceKerberosKrb5ConfExists,
		Create: resourceKerberosKrb5ConfCreate,
		Update: resourceKerberosKrb5ConfUpdate,
		Delete: resourceKerberosKrb5ConfDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceKerberosKrb5ConfSchema(),
	}
}

func getResourceKerberosKrb5ConfSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Object text
		"content": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},
	}
}

func resourceKerberosKrb5ConfRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetKerberosKrb5Conf(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_krb5conf '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	d.Set("content", object)
	d.SetId(objectName)
	return nil
}

func resourceKerberosKrb5ConfExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetKerberosKrb5Conf(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceKerberosKrb5ConfCreate(d *schema.ResourceData, tm interface{}) error {
	err := resourceKerberosKrb5ConfUpdate(d, tm)
	if err != nil {
		return fmt.Errorf("%v", strings.Replace(err.Error(), "update", "create", 1))
	}
	return nil
}

func resourceKerberosKrb5ConfUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	objectContent := d.Get("content").(string)
	err := tm.(*vtm.VirtualTrafficManager).SetKerberosKrb5Conf(objectName, objectContent)
	if err != nil {
		return fmt.Errorf("Failed to create vtm_krb5conf '%v': %v", objectName, err.ErrorText)
	}
	d.SetId(objectName)
	return nil
}

func resourceKerberosKrb5ConfDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteKerberosKrb5Conf(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_krb5conf '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
