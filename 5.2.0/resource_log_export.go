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

func resourceLogExport() *schema.Resource {
	return &schema.Resource{
		Read:   resourceLogExportRead,
		Exists: resourceLogExportExists,
		Create: resourceLogExportCreate,
		Update: resourceLogExportUpdate,
		Delete: resourceLogExportDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceLogExportSchema(),
	}
}

func getResourceLogExportSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

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
			Type:     schema.TypeSet,
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
	}
}

func resourceLogExportRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetLogExport(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_log_export '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "appliance_only"
	d.Set("appliance_only", bool(*object.Basic.ApplianceOnly))
	lastAssignedField = "enabled"
	d.Set("enabled", bool(*object.Basic.Enabled))
	lastAssignedField = "files"
	d.Set("files", []string(*object.Basic.Files))
	lastAssignedField = "history"
	d.Set("history", string(*object.Basic.History))
	lastAssignedField = "history_period"
	d.Set("history_period", int(*object.Basic.HistoryPeriod))
	lastAssignedField = "metadata"
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
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	d.SetId(objectName)
	return nil
}

func resourceLogExportExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetLogExport(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceLogExportCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewLogExport(objectName)
	resourceLogExportObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_log_export '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceLogExportUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetLogExport(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_log_export '%v': %v", objectName, err)
	}
	resourceLogExportObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_log_export '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceLogExportObjectFieldAssignments(d *schema.ResourceData, object *vtm.LogExport) {
	setBool(&object.Basic.ApplianceOnly, d, "appliance_only")
	setBool(&object.Basic.Enabled, d, "enabled")

	if _, ok := d.GetOk("files"); ok {
		setStringSet(&object.Basic.Files, d, "files")
	} else {
		object.Basic.Files = &[]string{}
		d.Set("files", []string(*object.Basic.Files))
	}
	setString(&object.Basic.History, d, "history")
	setInt(&object.Basic.HistoryPeriod, d, "history_period")
	setString(&object.Basic.Note, d, "note")

	object.Basic.Metadata = &vtm.LogExportMetadataTable{}
	if metadataJson, ok := d.GetOk("metadata_json"); ok {
		_ = json.Unmarshal([]byte(metadataJson.(string)), object.Basic.Metadata)
	} else if metadata, ok := d.GetOk("metadata"); ok {
		for _, row := range metadata.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.LogExportMetadata{}
			VtmObject.Name = getStringAddr(itemTerraform["name"].(string))
			VtmObject.Value = getStringAddr(itemTerraform["value"].(string))
			*object.Basic.Metadata = append(*object.Basic.Metadata, VtmObject)
		}
		d.Set("metadata", metadata)
	} else {
		d.Set("metadata", make([]map[string]interface{}, 0, len(*object.Basic.Metadata)))
	}
}

func resourceLogExportDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteLogExport(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_log_export '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
