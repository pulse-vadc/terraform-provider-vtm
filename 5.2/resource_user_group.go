// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceUserGroup() *schema.Resource {
	return &schema.Resource{
		Read:   resourceUserGroupRead,
		Exists: resourceUserGroupExists,
		Create: resourceUserGroupCreate,
		Update: resourceUserGroupUpdate,
		Delete: resourceUserGroupDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceUserGroupSchema(),
	}
}

func getResourceUserGroupSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// A description for the group.
		"description": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Members of this group must renew their passwords after this number
		//  of days. To disable password expiry for the group set this to
		//  "0" (zero). Note that this setting applies only to local users.
		"password_expire_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 65535),
			Default:      0,
		},

		// A table defining which level of permission this group has for
		//  specific configuration elements.
		"permissions": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{

					// access_level
					"access_level": &schema.Schema{
						Type:     schema.TypeString,
						Required: true,
					},

					// name
					"name": &schema.Schema{
						Type:     schema.TypeString,
						Required: true,
					},
				},
			},
		},

		// JSON representation of permissions
		"permissions_json": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.ValidateJsonString,
		},

		// Inactive UI sessions will timeout after this number of seconds.
		//  To disable inactivity timeouts for the group set this to "0"
		//  (zero).
		"timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 999999),
			Default:      30,
		},
	}
}

func resourceUserGroupRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetUserGroup(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_user_group '%v': %v", objectName, err.ErrorText)
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
	lastAssignedField = "password_expire_time"
	d.Set("password_expire_time", int(*object.Basic.PasswordExpireTime))
	lastAssignedField = "permissions"
	permissions := make([]map[string]interface{}, 0, len(*object.Basic.Permissions))
	for _, item := range *object.Basic.Permissions {
		itemTerraform := make(map[string]interface{})
		if item.AccessLevel != nil {
			itemTerraform["access_level"] = string(*item.AccessLevel)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		permissions = append(permissions, itemTerraform)
	}
	d.Set("permissions", permissions)
	permissionsJson, _ := json.Marshal(permissions)
	d.Set("permissions_json", permissionsJson)
	lastAssignedField = "timeout"
	d.Set("timeout", int(*object.Basic.Timeout))
	d.SetId(objectName)
	return nil
}

func resourceUserGroupExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetUserGroup(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceUserGroupCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewUserGroup(objectName)
	resourceUserGroupObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_user_group '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceUserGroupUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetUserGroup(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_user_group '%v': %v", objectName, err)
	}
	resourceUserGroupObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_user_group '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceUserGroupObjectFieldAssignments(d *schema.ResourceData, object *vtm.UserGroup) {
	setString(&object.Basic.Description, d, "description")
	setInt(&object.Basic.PasswordExpireTime, d, "password_expire_time")
	setInt(&object.Basic.Timeout, d, "timeout")

	object.Basic.Permissions = &vtm.UserGroupPermissionsTable{}
	if permissionsJson, ok := d.GetOk("permissions_json"); ok {
		_ = json.Unmarshal([]byte(permissionsJson.(string)), object.Basic.Permissions)
	} else if permissions, ok := d.GetOk("permissions"); ok {
		for _, row := range permissions.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.UserGroupPermissions{}
			VtmObject.AccessLevel = getStringAddr(itemTerraform["access_level"].(string))
			VtmObject.Name = getStringAddr(itemTerraform["name"].(string))
			*object.Basic.Permissions = append(*object.Basic.Permissions, VtmObject)
		}
		d.Set("permissions", permissions)
	} else {
		d.Set("permissions", make([]map[string]interface{}, 0, len(*object.Basic.Permissions)))
	}
}

func resourceUserGroupDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteUserGroup(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_user_group '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
