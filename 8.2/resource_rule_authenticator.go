// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.2"
)

func resourceRuleAuthenticator() *schema.Resource {
	return &schema.Resource{
		Read:   resourceRuleAuthenticatorRead,
		Exists: resourceRuleAuthenticatorExists,
		Create: resourceRuleAuthenticatorCreate,
		Update: resourceRuleAuthenticatorUpdate,
		Delete: resourceRuleAuthenticatorDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceRuleAuthenticatorSchema(),
	}
}

func getResourceRuleAuthenticatorSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The hostname or IP address of the remote authenticator.
		"host": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// A description of the authenticator.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The port on which the remote authenticator should be contacted.
		"port": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 65535),
			Default:      389,
		},

		// A list of attributes to return from the search. If blank, no
		//  attributes will be returned. If set to '*' then all user attributes
		//  will be returned.
		"ldap_attributes": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The distinguished name (DN) of the 'bind' user. The traffic manager
		//  will connect to the LDAP server as this user when searching for
		//  user records.
		"ldap_bind_dn": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The password for the bind user.
		"ldap_bind_password": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The filter used to locate the LDAP record for the user being
		//  authenticated. Any occurrences of '"%u"' in the filter will be
		//  replaced by the name of the user being authenticated.
		"ldap_filter": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The base distinguished name (DN) under which user records are
		//  located on the server.
		"ldap_filter_base_dn": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The SSL certificate that the traffic manager should use to validate
		//  the remote server. If no certificate is specified then no signature
		//  validation will be performed.
		"ldap_ssl_cert": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not to enable SSL encryption to the LDAP server.
		"ldap_ssl_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The type of LDAP SSL encryption to use.
		"ldap_ssl_type": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"ldaps", "starttls"}, false),
			Default:      "ldaps",
		},
	}
}

func resourceRuleAuthenticatorRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetRuleAuthenticator(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rule_authenticator '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "host"
	d.Set("host", string(*object.Basic.Host))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "port"
	d.Set("port", int(*object.Basic.Port))
	lastAssignedField = "ldap_attributes"
	d.Set("ldap_attributes", []string(*object.Ldap.Attributes))
	lastAssignedField = "ldap_bind_dn"
	d.Set("ldap_bind_dn", string(*object.Ldap.BindDn))
	lastAssignedField = "ldap_bind_password"
	d.Set("ldap_bind_password", string(*object.Ldap.BindPassword))
	lastAssignedField = "ldap_filter"
	d.Set("ldap_filter", string(*object.Ldap.Filter))
	lastAssignedField = "ldap_filter_base_dn"
	d.Set("ldap_filter_base_dn", string(*object.Ldap.FilterBaseDn))
	lastAssignedField = "ldap_ssl_cert"
	d.Set("ldap_ssl_cert", string(*object.Ldap.SslCert))
	lastAssignedField = "ldap_ssl_enabled"
	d.Set("ldap_ssl_enabled", bool(*object.Ldap.SslEnabled))
	lastAssignedField = "ldap_ssl_type"
	d.Set("ldap_ssl_type", string(*object.Ldap.SslType))
	d.SetId(objectName)
	return nil
}

func resourceRuleAuthenticatorExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetRuleAuthenticator(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceRuleAuthenticatorCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewRuleAuthenticator(objectName)
	resourceRuleAuthenticatorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_rule_authenticator '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceRuleAuthenticatorUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetRuleAuthenticator(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_rule_authenticator '%v': %v", objectName, err)
	}
	resourceRuleAuthenticatorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_rule_authenticator '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceRuleAuthenticatorObjectFieldAssignments(d *schema.ResourceData, object *vtm.RuleAuthenticator) {
	setString(&object.Basic.Host, d, "host")
	setString(&object.Basic.Note, d, "note")
	setInt(&object.Basic.Port, d, "port")

	if _, ok := d.GetOk("ldap_attributes"); ok {
		setStringSet(&object.Ldap.Attributes, d, "ldap_attributes")
	} else {
		object.Ldap.Attributes = &[]string{}
		d.Set("ldap_attributes", []string(*object.Ldap.Attributes))
	}
	setString(&object.Ldap.BindDn, d, "ldap_bind_dn")
	setString(&object.Ldap.BindPassword, d, "ldap_bind_password")
	setString(&object.Ldap.Filter, d, "ldap_filter")
	setString(&object.Ldap.FilterBaseDn, d, "ldap_filter_base_dn")
	setString(&object.Ldap.SslCert, d, "ldap_ssl_cert")
	setBool(&object.Ldap.SslEnabled, d, "ldap_ssl_enabled")
	setString(&object.Ldap.SslType, d, "ldap_ssl_type")
}

func resourceRuleAuthenticatorDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteRuleAuthenticator(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_rule_authenticator '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
