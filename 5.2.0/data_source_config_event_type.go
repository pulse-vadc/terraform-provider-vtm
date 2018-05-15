// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceEventType() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceEventTypeRead,

		Schema: map[string]*schema.Schema{

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
		},
	}
}

func dataSourceEventTypeRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetEventType(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_event_type '%v': %v", objectName, err.ErrorText)
	}
	d.Set("actions", []string(*object.Basic.Actions))
	d.Set("built_in", bool(*object.Basic.BuiltIn))
	d.Set("note", string(*object.Basic.Note))
	d.Set("cloudcredentials_event_tags", []string(*object.Cloudcredentials.EventTags))
	d.Set("cloudcredentials_objects", []string(*object.Cloudcredentials.Objects))
	d.Set("config_event_tags", []string(*object.Config.EventTags))
	d.Set("faulttolerance_event_tags", []string(*object.Faulttolerance.EventTags))
	d.Set("general_event_tags", []string(*object.General.EventTags))
	d.Set("glb_event_tags", []string(*object.Glb.EventTags))
	d.Set("glb_objects", []string(*object.Glb.Objects))
	d.Set("java_event_tags", []string(*object.Java.EventTags))
	d.Set("licensekeys_event_tags", []string(*object.Licensekeys.EventTags))
	d.Set("licensekeys_objects", []string(*object.Licensekeys.Objects))
	d.Set("locations_event_tags", []string(*object.Locations.EventTags))
	d.Set("locations_objects", []string(*object.Locations.Objects))
	d.Set("monitors_event_tags", []string(*object.Monitors.EventTags))
	d.Set("monitors_objects", []string(*object.Monitors.Objects))
	d.Set("pools_event_tags", []string(*object.Pools.EventTags))
	d.Set("pools_objects", []string(*object.Pools.Objects))
	d.Set("protection_event_tags", []string(*object.Protection.EventTags))
	d.Set("protection_objects", []string(*object.Protection.Objects))
	d.Set("rules_event_tags", []string(*object.Rules.EventTags))
	d.Set("rules_objects", []string(*object.Rules.Objects))
	d.Set("slm_event_tags", []string(*object.Slm.EventTags))
	d.Set("slm_objects", []string(*object.Slm.Objects))
	d.Set("ssl_event_tags", []string(*object.Ssl.EventTags))
	d.Set("sslhw_event_tags", []string(*object.Sslhw.EventTags))
	d.Set("trafficscript_event_tags", []string(*object.Trafficscript.EventTags))
	d.Set("vservers_event_tags", []string(*object.Vservers.EventTags))
	d.Set("vservers_objects", []string(*object.Vservers.Objects))
	d.Set("zxtms_event_tags", []string(*object.Zxtms.EventTags))
	d.Set("zxtms_objects", []string(*object.Zxtms.Objects))

	d.SetId(objectName)
	return nil
}
