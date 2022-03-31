// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
)

func resourceKerberosPrincipal() *schema.Resource {
	return &schema.Resource{
		Read:   resourceKerberosPrincipalRead,
		Exists: resourceKerberosPrincipalExists,
		Create: resourceKerberosPrincipalCreate,
		Update: resourceKerberosPrincipalUpdate,
		Delete: resourceKerberosPrincipalDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceKerberosPrincipalSchema(),
	}
}

func getResourceKerberosPrincipalSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// A list of "<hostname/ip>:<port>" pairs for Kerberos key distribution
		//  center (KDC) services to be explicitly used for the realm of
		//  the principal.  If no KDCs are explicitly configured, DNS will
		//  be used to discover the KDC(s) to use.
		"kdcs": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The name of the Kerberos keytab file containing suitable credentials
		//  to authenticate as the specified Kerberos principal.
		"keytab": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// The name of an optional Kerberos configuration file (krb5.conf).
		"krb5conf": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The Kerberos realm where the principal belongs.
		"realm": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The service name part of the Kerberos principal name the traffic
		//  manager should use to authenticate itself.
		"service": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},
	}
}

func resourceKerberosPrincipalRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetKerberosPrincipal(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_principal '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "kdcs"
	d.Set("kdcs", []string(*object.Basic.Kdcs))
	lastAssignedField = "keytab"
	d.Set("keytab", string(*object.Basic.Keytab))
	lastAssignedField = "krb5conf"
	d.Set("krb5conf", string(*object.Basic.Krb5Conf))
	lastAssignedField = "realm"
	d.Set("realm", string(*object.Basic.Realm))
	lastAssignedField = "service"
	d.Set("service", string(*object.Basic.Service))
	d.SetId(objectName)
	return nil
}

func resourceKerberosPrincipalExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetKerberosPrincipal(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceKerberosPrincipalCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewKerberosPrincipal(objectName, d.Get("keytab").(string), d.Get("service").(string))
	resourceKerberosPrincipalObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_principal '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceKerberosPrincipalUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetKerberosPrincipal(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_principal '%v': %v", objectName, err)
	}
	resourceKerberosPrincipalObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_principal '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceKerberosPrincipalObjectFieldAssignments(d *schema.ResourceData, object *vtm.KerberosPrincipal) {

	if _, ok := d.GetOk("kdcs"); ok {
		setStringList(&object.Basic.Kdcs, d, "kdcs")
	} else {
		object.Basic.Kdcs = &[]string{}
		d.Set("kdcs", []string(*object.Basic.Kdcs))
	}
	setString(&object.Basic.Keytab, d, "keytab")
	setString(&object.Basic.Krb5Conf, d, "krb5conf")
	setString(&object.Basic.Realm, d, "realm")
	setString(&object.Basic.Service, d, "service")
}

func resourceKerberosPrincipalDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteKerberosPrincipal(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_principal '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
