// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceUserGroup() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceUserGroupRead,

		Schema: map[string]*schema.Schema{

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
		},
	}
}

func dataSourceUserGroupRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetUserGroup(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_user_group '%v': %v", objectName, err.ErrorText)
	}
	d.Set("description", string(*object.Basic.Description))
	d.Set("password_expire_time", int(*object.Basic.PasswordExpireTime))

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
	d.Set("timeout", int(*object.Basic.Timeout))

	d.SetId(objectName)
	return nil
}
