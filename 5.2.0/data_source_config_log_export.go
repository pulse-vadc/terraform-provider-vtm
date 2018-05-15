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

func dataSourceLogExport() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceLogExportRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Whether entries from the specified log files should be exported
			//  only from appliances.
			"appliance_only": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Export entries from the log files included in this category.
			"enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The set of files to export as part of this category, specified
			//  as a list of glob patterns.
			"files": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// How much historic log activity should be exported.
			"history": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"all", "none", "recent"}, false),
				Default:      "none",
			},

			// The number of days of historic log entries that should be exported.
			"history_period": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      10,
			},

			// This is table 'metadata'
			"metadata": &schema.Schema{
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
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of metadata
			"metadata_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// A description of this category of log files.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceLogExportRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetLogExport(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_log_export '%v': %v", objectName, err.ErrorText)
	}
	d.Set("appliance_only", bool(*object.Basic.ApplianceOnly))
	d.Set("enabled", bool(*object.Basic.Enabled))
	d.Set("files", []string(*object.Basic.Files))
	d.Set("history", string(*object.Basic.History))
	d.Set("history_period", int(*object.Basic.HistoryPeriod))

	metadata := make([]map[string]interface{}, 0, len(*object.Basic.Metadata))
	for _, item := range *object.Basic.Metadata {
		itemTerraform := make(map[string]interface{})
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Value != nil {
			itemTerraform["value"] = string(*item.Value)
		}
		metadata = append(metadata, itemTerraform)
	}
	d.Set("metadata", metadata)
	metadataJson, _ := json.Marshal(metadata)
	d.Set("metadata_json", metadataJson)
	d.Set("note", string(*object.Basic.Note))

	d.SetId(objectName)
	return nil
}
