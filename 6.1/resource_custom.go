// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func resourceCustom() *schema.Resource {
	return &schema.Resource{
		Read:   resourceCustomRead,
		Exists: resourceCustomExists,
		Create: resourceCustomCreate,
		Update: resourceCustomUpdate,
		Delete: resourceCustomDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceCustomSchema(),
	}
}

func getResourceCustomSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// This table contains named lists of strings
		"string_lists": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{

					// name
					"name": &schema.Schema{
						Type:     schema.TypeString,
						Required: true,
					},

					// value
					"value": &schema.Schema{
						Type:     schema.TypeList,
						Required: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},

		// JSON representation of string_lists
		"string_lists_json": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.ValidateJsonString,
		},
	}
}

func resourceCustomRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetCustom(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_custom '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "string_lists"
	stringLists := make([]map[string]interface{}, 0, len(*object.Basic.StringLists))
	for _, item := range *object.Basic.StringLists {
		itemTerraform := make(map[string]interface{})
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Value != nil {
			itemTerraform["value"] = []string(*item.Value)
		}
		stringLists = append(stringLists, itemTerraform)
	}
	d.Set("string_lists", stringLists)
	stringListsJson, _ := json.Marshal(stringLists)
	d.Set("string_lists_json", stringListsJson)
	d.SetId(objectName)
	return nil
}

func resourceCustomExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetCustom(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceCustomCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewCustom(objectName)
	resourceCustomObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_custom '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceCustomUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetCustom(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_custom '%v': %v", objectName, err)
	}
	resourceCustomObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_custom '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceCustomObjectFieldAssignments(d *schema.ResourceData, object *vtm.Custom) {

	object.Basic.StringLists = &vtm.CustomStringListsTable{}
	if stringListsJson, ok := d.GetOk("string_lists_json"); ok {
		_ = json.Unmarshal([]byte(stringListsJson.(string)), object.Basic.StringLists)
	} else if stringLists, ok := d.GetOk("string_lists"); ok {
		for _, row := range stringLists.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.CustomStringLists{}
			VtmObject.Name = getStringAddr(itemTerraform["name"].(string))
			VtmObject.Value = getStringListAddr(expandStringList(itemTerraform["value"].([]interface{})))
			*object.Basic.StringLists = append(*object.Basic.StringLists, VtmObject)
		}
		d.Set("string_lists", stringLists)
	} else {
		d.Set("string_lists", make([]map[string]interface{}, 0, len(*object.Basic.StringLists)))
	}
}

func resourceCustomDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteCustom(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_custom '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
