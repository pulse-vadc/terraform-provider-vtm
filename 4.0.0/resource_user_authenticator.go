// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func resourceUserAuthenticator() *schema.Resource {
	return &schema.Resource{
		Read:   resourceUserAuthenticatorRead,
		Exists: resourceUserAuthenticatorExists,
		Create: resourceUserAuthenticatorCreate,
		Update: resourceUserAuthenticatorUpdate,
		Delete: resourceUserAuthenticatorDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceUserAuthenticatorSchema(),
	}
}

func getResourceUserAuthenticatorSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// A description of the authenticator.
		"description": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not this authenticator is enabled.
		"enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The type and protocol used by this authentication service.
		"type": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ValidateFunc: validation.StringInSlice([]string{"ldap", "radius", "tacacs_plus"}, false),
		},

		// The base DN (Distinguished Name) under which directory searches
		//  will be applied.  The entries for your users should all appear
		//  under this DN. An example of a typical base DN is: "OU=users,
		//  DC=mycompany, DC=local"
		"ldap_base_dn": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Template to construct the bind DN (Distinguished Name) from the
		//  username. The string "%u" will be replaced by the username.
		//  Examples: "%u@mycompany.local" for Active Directory or "cn=%u,
		//  dc=mycompany, dc=local" for both LDAP and Active Directory.
		"ldap_bind_dn": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The bind DN (Distinguished Name) for a user can either be searched
		//  for in the directory using the *base distinguished name* and
		//  *filter* values, or it can be constructed from the username.
		"ldap_dn_method": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"construct", "none", "search"}, false),
			Default:      "none",
		},

		// If the *group attribute* is not defined, or returns no results
		//  for the user logging in, the group named here will be used. If
		//  not specified, users will be denied access to the traffic manager
		//  if no groups matching a Permission Group can be found for them
		//  in the directory.
		"ldap_fallback_group": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// A filter that can be used to extract a unique user record located
		//  under the base DN (Distinguished Name).  The string "%u" will
		//  be replaced by the username. This filter is used to find a user's
		//  bind DN when *dn_method* is set to "Search", and to extract group
		//  information if the *group filter* is not specified. Examples:
		//  "sAMAccountName=%u" for Active Directory, or "uid=%u" for some
		//  Unix LDAP schemas.
		"ldap_filter": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The LDAP attribute that gives a user's group. If there are multiple
		//  entries for the attribute all will be extracted and they'll be
		//  lexicographically sorted, then the first one to match a Permission
		//  Group name will be used.
		"ldap_group_attribute": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The sub-field of the group attribute that gives a user's group.
		//  For example, if *group_attribute* is "memberOf" and this retrieves
		//  values of the form "CN=mygroup, OU=groups, OU=users, DC=mycompany,
		//  DC=local" you would set group_field to "CN".  If there are multiple
		//  matching fields only the first matching field will be used.
		"ldap_group_field": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// If the user record returned by *filter* does not contain the
		//  required group information you may specify an alternative group
		//  search filter here. This will usually be required if you have
		//  Unix/POSIX-style user records. If multiple records are returned
		//  the list of group names will be extracted from all of them. The
		//  string "%u" will be replaced by the username. Example: "(&(memberUid=%u)(objectClass=posixGroup))"
		"ldap_group_filter": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The port to connect to the LDAP server on.
		"ldap_port": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      389,
		},

		// The bind DN (Distinguished Name) to use when searching the directory
		//  for a user's bind DN.  You can leave this blank if it is possible
		//  to perform the bind DN search using an anonymous bind.
		"ldap_search_dn": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// If binding to the LDAP server using "search_dn" requires a password,
		//  enter it here.
		"ldap_search_password": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The IP or hostname of the LDAP server.
		"ldap_server": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Connection timeout in seconds.
		"ldap_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      30,
		},

		// If no group is found using the vendor and group identifiers,
		//  or the group found is not valid, the group specified here will
		//  be used.
		"radius_fallback_group": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The RADIUS identifier for the attribute that specifies an account's
		//  group.  May be left blank if *fallback group* is specified.
		"radius_group_attribute": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      1,
		},

		// The RADIUS identifier for the vendor of the RADIUS attribute
		//  that specifies an account's group.  Leave blank if using a standard
		//  attribute (i.e. for Filter-Id set group_attribute to 11).
		"radius_group_vendor": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      7146,
		},

		// This value is sent to the RADIUS server.
		"radius_nas_identifier": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// This value is sent to the RADIUS server, if left blank the address
		//  of the interfaced used to connect to the server will be used.
		"radius_nas_ip_address": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The port to connect to the RADIUS server on.
		"radius_port": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      1812,
		},

		// Secret key shared with the RADIUS server.
		"radius_secret": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The IP or hostname of the RADIUS server.
		"radius_server": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Connection timeout in seconds.
		"radius_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      30,
		},

		// Authentication type to use.
		"tacacs_plus_auth_type": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"ascii", "pap"}, false),
			Default:      "pap",
		},

		// If "group_service" is not used, or no group value is provided
		//  for the user by the TACACS+ server, the group specified here
		//  will be used. If this is not specified, users with no TACACS+
		//  defined group will be denied access.
		"tacacs_plus_fallback_group": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The TACACS+ "service" field that provides each user's group.
		"tacacs_plus_group_field": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "permission-group",
		},

		// The TACACS+ "service" that provides each user's group field.
		"tacacs_plus_group_service": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "zeus",
		},

		// The port to connect to the TACACS+ server on.
		"tacacs_plus_port": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      49,
		},

		// Secret key shared with the TACACS+ server.
		"tacacs_plus_secret": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The IP or hostname of the TACACS+ server.
		"tacacs_plus_server": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Connection timeout in seconds.
		"tacacs_plus_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      30,
		},
	}
}

func resourceUserAuthenticatorRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetUserAuthenticator(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_user_authenticator '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "description"
	d.Set("description", string(*object.Basic.Description))
	lastAssignedField = "enabled"
	d.Set("enabled", bool(*object.Basic.Enabled))
	lastAssignedField = "type"
	d.Set("type", string(*object.Basic.Type))
	lastAssignedField = "ldap_base_dn"
	d.Set("ldap_base_dn", string(*object.Ldap.BaseDn))
	lastAssignedField = "ldap_bind_dn"
	d.Set("ldap_bind_dn", string(*object.Ldap.BindDn))
	lastAssignedField = "ldap_dn_method"
	d.Set("ldap_dn_method", string(*object.Ldap.DnMethod))
	lastAssignedField = "ldap_fallback_group"
	d.Set("ldap_fallback_group", string(*object.Ldap.FallbackGroup))
	lastAssignedField = "ldap_filter"
	d.Set("ldap_filter", string(*object.Ldap.Filter))
	lastAssignedField = "ldap_group_attribute"
	d.Set("ldap_group_attribute", string(*object.Ldap.GroupAttribute))
	lastAssignedField = "ldap_group_field"
	d.Set("ldap_group_field", string(*object.Ldap.GroupField))
	lastAssignedField = "ldap_group_filter"
	d.Set("ldap_group_filter", string(*object.Ldap.GroupFilter))
	lastAssignedField = "ldap_port"
	d.Set("ldap_port", int(*object.Ldap.Port))
	lastAssignedField = "ldap_search_dn"
	d.Set("ldap_search_dn", string(*object.Ldap.SearchDn))
	lastAssignedField = "ldap_search_password"
	d.Set("ldap_search_password", string(*object.Ldap.SearchPassword))
	lastAssignedField = "ldap_server"
	d.Set("ldap_server", string(*object.Ldap.Server))
	lastAssignedField = "ldap_timeout"
	d.Set("ldap_timeout", int(*object.Ldap.Timeout))
	lastAssignedField = "radius_fallback_group"
	d.Set("radius_fallback_group", string(*object.Radius.FallbackGroup))
	lastAssignedField = "radius_group_attribute"
	d.Set("radius_group_attribute", int(*object.Radius.GroupAttribute))
	lastAssignedField = "radius_group_vendor"
	d.Set("radius_group_vendor", int(*object.Radius.GroupVendor))
	lastAssignedField = "radius_nas_identifier"
	d.Set("radius_nas_identifier", string(*object.Radius.NasIdentifier))
	lastAssignedField = "radius_nas_ip_address"
	d.Set("radius_nas_ip_address", string(*object.Radius.NasIpAddress))
	lastAssignedField = "radius_port"
	d.Set("radius_port", int(*object.Radius.Port))
	lastAssignedField = "radius_secret"
	d.Set("radius_secret", string(*object.Radius.Secret))
	lastAssignedField = "radius_server"
	d.Set("radius_server", string(*object.Radius.Server))
	lastAssignedField = "radius_timeout"
	d.Set("radius_timeout", int(*object.Radius.Timeout))
	lastAssignedField = "tacacs_plus_auth_type"
	d.Set("tacacs_plus_auth_type", string(*object.TacacsPlus.AuthType))
	lastAssignedField = "tacacs_plus_fallback_group"
	d.Set("tacacs_plus_fallback_group", string(*object.TacacsPlus.FallbackGroup))
	lastAssignedField = "tacacs_plus_group_field"
	d.Set("tacacs_plus_group_field", string(*object.TacacsPlus.GroupField))
	lastAssignedField = "tacacs_plus_group_service"
	d.Set("tacacs_plus_group_service", string(*object.TacacsPlus.GroupService))
	lastAssignedField = "tacacs_plus_port"
	d.Set("tacacs_plus_port", int(*object.TacacsPlus.Port))
	lastAssignedField = "tacacs_plus_secret"
	d.Set("tacacs_plus_secret", string(*object.TacacsPlus.Secret))
	lastAssignedField = "tacacs_plus_server"
	d.Set("tacacs_plus_server", string(*object.TacacsPlus.Server))
	lastAssignedField = "tacacs_plus_timeout"
	d.Set("tacacs_plus_timeout", int(*object.TacacsPlus.Timeout))
	d.SetId(objectName)
	return nil
}

func resourceUserAuthenticatorExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetUserAuthenticator(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceUserAuthenticatorCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewUserAuthenticator(objectName, d.Get("type").(string))
	resourceUserAuthenticatorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_user_authenticator '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceUserAuthenticatorUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetUserAuthenticator(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_user_authenticator '%v': %v", objectName, err)
	}
	resourceUserAuthenticatorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_user_authenticator '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceUserAuthenticatorObjectFieldAssignments(d *schema.ResourceData, object *vtm.UserAuthenticator) {
	setString(&object.Basic.Description, d, "description")
	setBool(&object.Basic.Enabled, d, "enabled")
	setString(&object.Basic.Type, d, "type")
	setString(&object.Ldap.BaseDn, d, "ldap_base_dn")
	setString(&object.Ldap.BindDn, d, "ldap_bind_dn")
	setString(&object.Ldap.DnMethod, d, "ldap_dn_method")
	setString(&object.Ldap.FallbackGroup, d, "ldap_fallback_group")
	setString(&object.Ldap.Filter, d, "ldap_filter")
	setString(&object.Ldap.GroupAttribute, d, "ldap_group_attribute")
	setString(&object.Ldap.GroupField, d, "ldap_group_field")
	setString(&object.Ldap.GroupFilter, d, "ldap_group_filter")
	setInt(&object.Ldap.Port, d, "ldap_port")
	setString(&object.Ldap.SearchDn, d, "ldap_search_dn")
	setString(&object.Ldap.SearchPassword, d, "ldap_search_password")
	setString(&object.Ldap.Server, d, "ldap_server")
	setInt(&object.Ldap.Timeout, d, "ldap_timeout")
	setString(&object.Radius.FallbackGroup, d, "radius_fallback_group")
	setInt(&object.Radius.GroupAttribute, d, "radius_group_attribute")
	setInt(&object.Radius.GroupVendor, d, "radius_group_vendor")
	setString(&object.Radius.NasIdentifier, d, "radius_nas_identifier")
	setString(&object.Radius.NasIpAddress, d, "radius_nas_ip_address")
	setInt(&object.Radius.Port, d, "radius_port")
	setString(&object.Radius.Secret, d, "radius_secret")
	setString(&object.Radius.Server, d, "radius_server")
	setInt(&object.Radius.Timeout, d, "radius_timeout")
	setString(&object.TacacsPlus.AuthType, d, "tacacs_plus_auth_type")
	setString(&object.TacacsPlus.FallbackGroup, d, "tacacs_plus_fallback_group")
	setString(&object.TacacsPlus.GroupField, d, "tacacs_plus_group_field")
	setString(&object.TacacsPlus.GroupService, d, "tacacs_plus_group_service")
	setInt(&object.TacacsPlus.Port, d, "tacacs_plus_port")
	setString(&object.TacacsPlus.Secret, d, "tacacs_plus_secret")
	setString(&object.TacacsPlus.Server, d, "tacacs_plus_server")
	setInt(&object.TacacsPlus.Timeout, d, "tacacs_plus_timeout")
}

func resourceUserAuthenticatorDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteUserAuthenticator(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_user_authenticator '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
