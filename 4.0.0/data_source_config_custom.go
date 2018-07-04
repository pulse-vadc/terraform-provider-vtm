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

func dataSourceCustom() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCustomRead,

		Schema: map[string]*schema.Schema{

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
		},
	}
}

func dataSourceCustomRead(d *schema.ResourceData, tm interface{}) error {
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
