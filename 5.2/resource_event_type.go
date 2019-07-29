// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceEventType() *schema.Resource {
	return &schema.Resource{
		Read:   resourceEventTypeRead,
		Exists: resourceEventTypeExists,
		Create: resourceEventTypeCreate,
		Update: resourceEventTypeUpdate,
		Delete: resourceEventTypeDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceEventTypeSchema(),
	}
}

func getResourceEventTypeSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The actions triggered by events matching this event type, as
		//  a list of action references.
		"actions": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// If set to "Yes" this indicates that this configuration is built-in
		//  (provided as part of the software) and must not be deleted or
		//  edited.
		"built_in": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// A description of this event type.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Cloud credentials event tags
		"cloudcredentials_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Cloud credentials object names
		"cloudcredentials_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Configuration file event tags
		"config_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Fault tolerance event tags
		"faulttolerance_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// General event tags
		"general_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// GLB service event tags
		"glb_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// GLB service object names
		"glb_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Java event tags
		"java_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// License key event tags
		"licensekeys_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// License key object names
		"licensekeys_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Location event tags
		"locations_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Location object names
		"locations_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Monitor event tags
		"monitors_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Monitors object names
		"monitors_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Pool key event tags
		"pools_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Pool object names
		"pools_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Service protection class event tags
		"protection_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Service protection class object names
		"protection_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Rule event tags
		"rules_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Rule object names
		"rules_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// SLM class event tags
		"slm_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// SLM class object names
		"slm_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// SSL event tags
		"ssl_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// SSL hardware event tags
		"sslhw_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// TrafficScript event tags
		"trafficscript_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Virtual server event tags
		"vservers_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Virtual server object names
		"vservers_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Traffic manager event tags
		"zxtms_event_tags": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Traffic manager object names
		"zxtms_objects": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},
	}
}

func resourceEventTypeRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetEventType(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_event_type '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "actions"
	d.Set("actions", []string(*object.Basic.Actions))
	lastAssignedField = "built_in"
	d.Set("built_in", bool(*object.Basic.BuiltIn))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "cloudcredentials_event_tags"
	d.Set("cloudcredentials_event_tags", []string(*object.Cloudcredentials.EventTags))
	lastAssignedField = "cloudcredentials_objects"
	d.Set("cloudcredentials_objects", []string(*object.Cloudcredentials.Objects))
	lastAssignedField = "config_event_tags"
	d.Set("config_event_tags", []string(*object.Config.EventTags))
	lastAssignedField = "faulttolerance_event_tags"
	d.Set("faulttolerance_event_tags", []string(*object.Faulttolerance.EventTags))
	lastAssignedField = "general_event_tags"
	d.Set("general_event_tags", []string(*object.General.EventTags))
	lastAssignedField = "glb_event_tags"
	d.Set("glb_event_tags", []string(*object.Glb.EventTags))
	lastAssignedField = "glb_objects"
	d.Set("glb_objects", []string(*object.Glb.Objects))
	lastAssignedField = "java_event_tags"
	d.Set("java_event_tags", []string(*object.Java.EventTags))
	lastAssignedField = "licensekeys_event_tags"
	d.Set("licensekeys_event_tags", []string(*object.Licensekeys.EventTags))
	lastAssignedField = "licensekeys_objects"
	d.Set("licensekeys_objects", []string(*object.Licensekeys.Objects))
	lastAssignedField = "locations_event_tags"
	d.Set("locations_event_tags", []string(*object.Locations.EventTags))
	lastAssignedField = "locations_objects"
	d.Set("locations_objects", []string(*object.Locations.Objects))
	lastAssignedField = "monitors_event_tags"
	d.Set("monitors_event_tags", []string(*object.Monitors.EventTags))
	lastAssignedField = "monitors_objects"
	d.Set("monitors_objects", []string(*object.Monitors.Objects))
	lastAssignedField = "pools_event_tags"
	d.Set("pools_event_tags", []string(*object.Pools.EventTags))
	lastAssignedField = "pools_objects"
	d.Set("pools_objects", []string(*object.Pools.Objects))
	lastAssignedField = "protection_event_tags"
	d.Set("protection_event_tags", []string(*object.Protection.EventTags))
	lastAssignedField = "protection_objects"
	d.Set("protection_objects", []string(*object.Protection.Objects))
	lastAssignedField = "rules_event_tags"
	d.Set("rules_event_tags", []string(*object.Rules.EventTags))
	lastAssignedField = "rules_objects"
	d.Set("rules_objects", []string(*object.Rules.Objects))
	lastAssignedField = "slm_event_tags"
	d.Set("slm_event_tags", []string(*object.Slm.EventTags))
	lastAssignedField = "slm_objects"
	d.Set("slm_objects", []string(*object.Slm.Objects))
	lastAssignedField = "ssl_event_tags"
	d.Set("ssl_event_tags", []string(*object.Ssl.EventTags))
	lastAssignedField = "sslhw_event_tags"
	d.Set("sslhw_event_tags", []string(*object.Sslhw.EventTags))
	lastAssignedField = "trafficscript_event_tags"
	d.Set("trafficscript_event_tags", []string(*object.Trafficscript.EventTags))
	lastAssignedField = "vservers_event_tags"
	d.Set("vservers_event_tags", []string(*object.Vservers.EventTags))
	lastAssignedField = "vservers_objects"
	d.Set("vservers_objects", []string(*object.Vservers.Objects))
	lastAssignedField = "zxtms_event_tags"
	d.Set("zxtms_event_tags", []string(*object.Zxtms.EventTags))
	lastAssignedField = "zxtms_objects"
	d.Set("zxtms_objects", []string(*object.Zxtms.Objects))
	d.SetId(objectName)
	return nil
}

func resourceEventTypeExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetEventType(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceEventTypeCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewEventType(objectName)
	resourceEventTypeObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_event_type '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceEventTypeUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetEventType(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_event_type '%v': %v", objectName, err)
	}
	resourceEventTypeObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_event_type '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceEventTypeObjectFieldAssignments(d *schema.ResourceData, object *vtm.EventType) {

	if _, ok := d.GetOk("actions"); ok {
		setStringList(&object.Basic.Actions, d, "actions")
	} else {
		object.Basic.Actions = &[]string{}
		d.Set("actions", []string(*object.Basic.Actions))
	}
	setBool(&object.Basic.BuiltIn, d, "built_in")
	setString(&object.Basic.Note, d, "note")

	if _, ok := d.GetOk("cloudcredentials_event_tags"); ok {
		setStringList(&object.Cloudcredentials.EventTags, d, "cloudcredentials_event_tags")
	} else {
		object.Cloudcredentials.EventTags = &[]string{}
		d.Set("cloudcredentials_event_tags", []string(*object.Cloudcredentials.EventTags))
	}

	if _, ok := d.GetOk("cloudcredentials_objects"); ok {
		setStringList(&object.Cloudcredentials.Objects, d, "cloudcredentials_objects")
	} else {
		object.Cloudcredentials.Objects = &[]string{}
		d.Set("cloudcredentials_objects", []string(*object.Cloudcredentials.Objects))
	}

	if _, ok := d.GetOk("config_event_tags"); ok {
		setStringList(&object.Config.EventTags, d, "config_event_tags")
	} else {
		object.Config.EventTags = &[]string{}
		d.Set("config_event_tags", []string(*object.Config.EventTags))
	}

	if _, ok := d.GetOk("faulttolerance_event_tags"); ok {
		setStringList(&object.Faulttolerance.EventTags, d, "faulttolerance_event_tags")
	} else {
		object.Faulttolerance.EventTags = &[]string{}
		d.Set("faulttolerance_event_tags", []string(*object.Faulttolerance.EventTags))
	}

	if _, ok := d.GetOk("general_event_tags"); ok {
		setStringList(&object.General.EventTags, d, "general_event_tags")
	} else {
		object.General.EventTags = &[]string{}
		d.Set("general_event_tags", []string(*object.General.EventTags))
	}

	if _, ok := d.GetOk("glb_event_tags"); ok {
		setStringList(&object.Glb.EventTags, d, "glb_event_tags")
	} else {
		object.Glb.EventTags = &[]string{}
		d.Set("glb_event_tags", []string(*object.Glb.EventTags))
	}

	if _, ok := d.GetOk("glb_objects"); ok {
		setStringList(&object.Glb.Objects, d, "glb_objects")
	} else {
		object.Glb.Objects = &[]string{}
		d.Set("glb_objects", []string(*object.Glb.Objects))
	}

	if _, ok := d.GetOk("java_event_tags"); ok {
		setStringList(&object.Java.EventTags, d, "java_event_tags")
	} else {
		object.Java.EventTags = &[]string{}
		d.Set("java_event_tags", []string(*object.Java.EventTags))
	}

	if _, ok := d.GetOk("licensekeys_event_tags"); ok {
		setStringList(&object.Licensekeys.EventTags, d, "licensekeys_event_tags")
	} else {
		object.Licensekeys.EventTags = &[]string{}
		d.Set("licensekeys_event_tags", []string(*object.Licensekeys.EventTags))
	}

	if _, ok := d.GetOk("licensekeys_objects"); ok {
		setStringList(&object.Licensekeys.Objects, d, "licensekeys_objects")
	} else {
		object.Licensekeys.Objects = &[]string{}
		d.Set("licensekeys_objects", []string(*object.Licensekeys.Objects))
	}

	if _, ok := d.GetOk("locations_event_tags"); ok {
		setStringList(&object.Locations.EventTags, d, "locations_event_tags")
	} else {
		object.Locations.EventTags = &[]string{}
		d.Set("locations_event_tags", []string(*object.Locations.EventTags))
	}

	if _, ok := d.GetOk("locations_objects"); ok {
		setStringList(&object.Locations.Objects, d, "locations_objects")
	} else {
		object.Locations.Objects = &[]string{}
		d.Set("locations_objects", []string(*object.Locations.Objects))
	}

	if _, ok := d.GetOk("monitors_event_tags"); ok {
		setStringList(&object.Monitors.EventTags, d, "monitors_event_tags")
	} else {
		object.Monitors.EventTags = &[]string{}
		d.Set("monitors_event_tags", []string(*object.Monitors.EventTags))
	}

	if _, ok := d.GetOk("monitors_objects"); ok {
		setStringList(&object.Monitors.Objects, d, "monitors_objects")
	} else {
		object.Monitors.Objects = &[]string{}
		d.Set("monitors_objects", []string(*object.Monitors.Objects))
	}

	if _, ok := d.GetOk("pools_event_tags"); ok {
		setStringList(&object.Pools.EventTags, d, "pools_event_tags")
	} else {
		object.Pools.EventTags = &[]string{}
		d.Set("pools_event_tags", []string(*object.Pools.EventTags))
	}

	if _, ok := d.GetOk("pools_objects"); ok {
		setStringList(&object.Pools.Objects, d, "pools_objects")
	} else {
		object.Pools.Objects = &[]string{}
		d.Set("pools_objects", []string(*object.Pools.Objects))
	}

	if _, ok := d.GetOk("protection_event_tags"); ok {
		setStringList(&object.Protection.EventTags, d, "protection_event_tags")
	} else {
		object.Protection.EventTags = &[]string{}
		d.Set("protection_event_tags", []string(*object.Protection.EventTags))
	}

	if _, ok := d.GetOk("protection_objects"); ok {
		setStringList(&object.Protection.Objects, d, "protection_objects")
	} else {
		object.Protection.Objects = &[]string{}
		d.Set("protection_objects", []string(*object.Protection.Objects))
	}

	if _, ok := d.GetOk("rules_event_tags"); ok {
		setStringList(&object.Rules.EventTags, d, "rules_event_tags")
	} else {
		object.Rules.EventTags = &[]string{}
		d.Set("rules_event_tags", []string(*object.Rules.EventTags))
	}

	if _, ok := d.GetOk("rules_objects"); ok {
		setStringList(&object.Rules.Objects, d, "rules_objects")
	} else {
		object.Rules.Objects = &[]string{}
		d.Set("rules_objects", []string(*object.Rules.Objects))
	}

	if _, ok := d.GetOk("slm_event_tags"); ok {
		setStringList(&object.Slm.EventTags, d, "slm_event_tags")
	} else {
		object.Slm.EventTags = &[]string{}
		d.Set("slm_event_tags", []string(*object.Slm.EventTags))
	}

	if _, ok := d.GetOk("slm_objects"); ok {
		setStringList(&object.Slm.Objects, d, "slm_objects")
	} else {
		object.Slm.Objects = &[]string{}
		d.Set("slm_objects", []string(*object.Slm.Objects))
	}

	if _, ok := d.GetOk("ssl_event_tags"); ok {
		setStringList(&object.Ssl.EventTags, d, "ssl_event_tags")
	} else {
		object.Ssl.EventTags = &[]string{}
		d.Set("ssl_event_tags", []string(*object.Ssl.EventTags))
	}

	if _, ok := d.GetOk("sslhw_event_tags"); ok {
		setStringList(&object.Sslhw.EventTags, d, "sslhw_event_tags")
	} else {
		object.Sslhw.EventTags = &[]string{}
		d.Set("sslhw_event_tags", []string(*object.Sslhw.EventTags))
	}

	if _, ok := d.GetOk("trafficscript_event_tags"); ok {
		setStringList(&object.Trafficscript.EventTags, d, "trafficscript_event_tags")
	} else {
		object.Trafficscript.EventTags = &[]string{}
		d.Set("trafficscript_event_tags", []string(*object.Trafficscript.EventTags))
	}

	if _, ok := d.GetOk("vservers_event_tags"); ok {
		setStringList(&object.Vservers.EventTags, d, "vservers_event_tags")
	} else {
		object.Vservers.EventTags = &[]string{}
		d.Set("vservers_event_tags", []string(*object.Vservers.EventTags))
	}

	if _, ok := d.GetOk("vservers_objects"); ok {
		setStringList(&object.Vservers.Objects, d, "vservers_objects")
	} else {
		object.Vservers.Objects = &[]string{}
		d.Set("vservers_objects", []string(*object.Vservers.Objects))
	}

	if _, ok := d.GetOk("zxtms_event_tags"); ok {
		setStringList(&object.Zxtms.EventTags, d, "zxtms_event_tags")
	} else {
		object.Zxtms.EventTags = &[]string{}
		d.Set("zxtms_event_tags", []string(*object.Zxtms.EventTags))
	}

	if _, ok := d.GetOk("zxtms_objects"); ok {
		setStringList(&object.Zxtms.Objects, d, "zxtms_objects")
	} else {
		object.Zxtms.Objects = &[]string{}
		d.Set("zxtms_objects", []string(*object.Zxtms.Objects))
	}
}

func resourceEventTypeDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteEventType(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_event_type '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
