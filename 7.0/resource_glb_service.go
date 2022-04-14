// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
)

func resourceGlbService() *schema.Resource {
	return &schema.Resource{
		Read:   resourceGlbServiceRead,
		Exists: resourceGlbServiceExists,
		Create: resourceGlbServiceCreate,
		Update: resourceGlbServiceUpdate,
		Delete: resourceGlbServiceDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceGlbServiceSchema(),
	}
}

func getResourceGlbServiceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Defines the global load balancing algorithm to be used.
		"algorithm": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"chained", "geo", "hybrid", "load", "round_robin", "weighted_random"}, false),
			Default:      "hybrid",
		},

		// Do all monitors assigned to a location need to report success
		//  in order for it to be considered healthy?
		"all_monitors_needed": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The last location to fail will be available as soon as it recovers.
		"autorecovery": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Enable/Disable automatic failback mode.
		"chained_auto_failback": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The locations this service operates for and defines the order
		//  in which locations fail.
		"chained_location_order": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Locations recovering from a failure will become disabled.
		"disable_on_failure": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// A table mapping domains to the private keys that authenticate
		//  them
		"dnssec_keys": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{

					// domain
					"domain": &schema.Schema{
						Type:     schema.TypeString,
						Required: true,
					},

					// ssl_key
					"ssl_key": &schema.Schema{
						Type:     schema.TypeSet,
						Required: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},

		// JSON representation of dnssec_keys
		"dnssec_keys_json": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.ValidateJsonString,
		},

		// The domains shown here should be a list of Fully Qualified Domain
		//  Names that you would like to balance globally. Responses from
		//  the back end DNS servers for queries that do not match this list
		//  will be forwarded to the client unmodified. Note: "*" may be
		//  used as a wild card.
		"domains": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Enable/Disable our response manipulation of DNS.
		"enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// How much should the locality of visitors affect the choice of
		//  location used? This value is a percentage, 0% means that no locality
		//  information will be used, and 100% means that locality will always
		//  control which location is used. Values between the two extremes
		//  will act accordingly.
		"geo_effect": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 100),
			Default:      50,
		},

		// The response to be sent in case there are no locations available.
		"last_resort_response": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// This is the list of locations for which this service is draining.
		//  A location that is draining will never serve any of its service
		//  IP addresses for this domain. This can be used to take a location
		//  off-line.
		"location_draining": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Table containing location specific settings.
		"location_settings": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{

					// ips
					"ips": &schema.Schema{
						Type:     schema.TypeSet,
						Required: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},

					// location
					"location": &schema.Schema{
						Type:     schema.TypeString,
						Required: true,
					},

					// monitors
					"monitors": &schema.Schema{
						Type:     schema.TypeSet,
						Optional: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
						Default:  nil,
					},

					// weight
					"weight": &schema.Schema{
						Type:         schema.TypeInt,
						Optional:     true,
						ValidateFunc: validation.IntBetween(1, 100),
						Default:      1,
					},
				},
			},
		},

		// JSON representation of location_settings
		"location_settings_json": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.ValidateJsonString,
		},

		// Return all or none of the IPs under complete failure.
		"return_ips_on_fail": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Response rules to be applied in the context of the service, in
		//  order, comma separated.
		"rules": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The TTL for the DNS resource records handled by the GLB service.
		"ttl": &schema.Schema{
			Type:     schema.TypeInt,
			Optional: true,
			Default:  -1,
		},

		// Log connections to this GLB service?
		"log_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The filename the verbose query information should be logged to.
		//  Appliances will ignore this.
		"log_filename": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "%zeushome%/zxtm/log/services/%g.log",
		},

		// The format of the log lines.
		"log_format": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "%t, %s, %l, %q, %g, %n, %d, %a",
		},
	}
}

func resourceGlbServiceRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetGlbService(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_glb_service '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "algorithm"
	d.Set("algorithm", string(*object.Basic.Algorithm))
	lastAssignedField = "all_monitors_needed"
	d.Set("all_monitors_needed", bool(*object.Basic.AllMonitorsNeeded))
	lastAssignedField = "autorecovery"
	d.Set("autorecovery", bool(*object.Basic.Autorecovery))
	lastAssignedField = "chained_auto_failback"
	d.Set("chained_auto_failback", bool(*object.Basic.ChainedAutoFailback))
	lastAssignedField = "chained_location_order"
	d.Set("chained_location_order", []string(*object.Basic.ChainedLocationOrder))
	lastAssignedField = "disable_on_failure"
	d.Set("disable_on_failure", bool(*object.Basic.DisableOnFailure))
	lastAssignedField = "dnssec_keys"
	dnssecKeys := make([]map[string]interface{}, 0, len(*object.Basic.DnssecKeys))
	for _, item := range *object.Basic.DnssecKeys {
		itemTerraform := make(map[string]interface{})
		if item.Domain != nil {
			itemTerraform["domain"] = string(*item.Domain)
		}
		if item.SslKey != nil {
			itemTerraform["ssl_key"] = []string(*item.SslKey)
		}
		dnssecKeys = append(dnssecKeys, itemTerraform)
	}
	d.Set("dnssec_keys", dnssecKeys)
	dnssecKeysJson, _ := json.Marshal(dnssecKeys)
	d.Set("dnssec_keys_json", dnssecKeysJson)
	lastAssignedField = "domains"
	d.Set("domains", []string(*object.Basic.Domains))
	lastAssignedField = "enabled"
	d.Set("enabled", bool(*object.Basic.Enabled))
	lastAssignedField = "geo_effect"
	d.Set("geo_effect", int(*object.Basic.GeoEffect))
	lastAssignedField = "last_resort_response"
	d.Set("last_resort_response", []string(*object.Basic.LastResortResponse))
	lastAssignedField = "location_draining"
	d.Set("location_draining", []string(*object.Basic.LocationDraining))
	lastAssignedField = "location_settings"
	locationSettings := make([]map[string]interface{}, 0, len(*object.Basic.LocationSettings))
	for _, item := range *object.Basic.LocationSettings {
		itemTerraform := make(map[string]interface{})
		if item.Ips != nil {
			itemTerraform["ips"] = []string(*item.Ips)
		}
		if item.Location != nil {
			itemTerraform["location"] = string(*item.Location)
		}
		if item.Monitors != nil {
			itemTerraform["monitors"] = []string(*item.Monitors)
		}
		if item.Weight != nil {
			itemTerraform["weight"] = int(*item.Weight)
		}
		locationSettings = append(locationSettings, itemTerraform)
	}
	d.Set("location_settings", locationSettings)
	locationSettingsJson, _ := json.Marshal(locationSettings)
	d.Set("location_settings_json", locationSettingsJson)
	lastAssignedField = "return_ips_on_fail"
	d.Set("return_ips_on_fail", bool(*object.Basic.ReturnIpsOnFail))
	lastAssignedField = "rules"
	d.Set("rules", []string(*object.Basic.Rules))
	lastAssignedField = "ttl"
	d.Set("ttl", int(*object.Basic.Ttl))
	lastAssignedField = "log_enabled"
	d.Set("log_enabled", bool(*object.Log.Enabled))
	lastAssignedField = "log_filename"
	d.Set("log_filename", string(*object.Log.Filename))
	lastAssignedField = "log_format"
	d.Set("log_format", string(*object.Log.Format))
	d.SetId(objectName)
	return nil
}

func resourceGlbServiceExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetGlbService(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceGlbServiceCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewGlbService(objectName)
	resourceGlbServiceObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_glb_service '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceGlbServiceUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetGlbService(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_glb_service '%v': %v", objectName, err)
	}
	resourceGlbServiceObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_glb_service '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceGlbServiceObjectFieldAssignments(d *schema.ResourceData, object *vtm.GlbService) {
	setString(&object.Basic.Algorithm, d, "algorithm")
	setBool(&object.Basic.AllMonitorsNeeded, d, "all_monitors_needed")
	setBool(&object.Basic.Autorecovery, d, "autorecovery")
	setBool(&object.Basic.ChainedAutoFailback, d, "chained_auto_failback")

	if _, ok := d.GetOk("chained_location_order"); ok {
		setStringList(&object.Basic.ChainedLocationOrder, d, "chained_location_order")
	} else {
		object.Basic.ChainedLocationOrder = &[]string{}
		d.Set("chained_location_order", []string(*object.Basic.ChainedLocationOrder))
	}
	setBool(&object.Basic.DisableOnFailure, d, "disable_on_failure")

	if _, ok := d.GetOk("domains"); ok {
		setStringSet(&object.Basic.Domains, d, "domains")
	} else {
		object.Basic.Domains = &[]string{}
		d.Set("domains", []string(*object.Basic.Domains))
	}
	setBool(&object.Basic.Enabled, d, "enabled")
	setInt(&object.Basic.GeoEffect, d, "geo_effect")

	if _, ok := d.GetOk("last_resort_response"); ok {
		setStringSet(&object.Basic.LastResortResponse, d, "last_resort_response")
	} else {
		object.Basic.LastResortResponse = &[]string{}
		d.Set("last_resort_response", []string(*object.Basic.LastResortResponse))
	}

	if _, ok := d.GetOk("location_draining"); ok {
		setStringSet(&object.Basic.LocationDraining, d, "location_draining")
	} else {
		object.Basic.LocationDraining = &[]string{}
		d.Set("location_draining", []string(*object.Basic.LocationDraining))
	}
	setBool(&object.Basic.ReturnIpsOnFail, d, "return_ips_on_fail")

	if _, ok := d.GetOk("rules"); ok {
		setStringList(&object.Basic.Rules, d, "rules")
	} else {
		object.Basic.Rules = &[]string{}
		d.Set("rules", []string(*object.Basic.Rules))
	}
	setInt(&object.Basic.Ttl, d, "ttl")

	object.Basic.DnssecKeys = &vtm.GlbServiceDnssecKeysTable{}
	if dnssecKeysJson, ok := d.GetOk("dnssec_keys_json"); ok {
		_ = json.Unmarshal([]byte(dnssecKeysJson.(string)), object.Basic.DnssecKeys)
	} else if dnssecKeys, ok := d.GetOk("dnssec_keys"); ok {
		for _, row := range dnssecKeys.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.GlbServiceDnssecKeys{}
			VtmObject.Domain = getStringAddr(itemTerraform["domain"].(string))
			VtmObject.SslKey = getStringSetAddr(expandStringSet(itemTerraform["ssl_key"].(*schema.Set)))
			*object.Basic.DnssecKeys = append(*object.Basic.DnssecKeys, VtmObject)
		}
		d.Set("dnssec_keys", dnssecKeys)
	} else {
		d.Set("dnssec_keys", make([]map[string]interface{}, 0, len(*object.Basic.DnssecKeys)))
	}

	object.Basic.LocationSettings = &vtm.GlbServiceLocationSettingsTable{}
	if locationSettingsJson, ok := d.GetOk("location_settings_json"); ok {
		_ = json.Unmarshal([]byte(locationSettingsJson.(string)), object.Basic.LocationSettings)
	} else if locationSettings, ok := d.GetOk("location_settings"); ok {
		for _, row := range locationSettings.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.GlbServiceLocationSettings{}
			VtmObject.Ips = getStringSetAddr(expandStringSet(itemTerraform["ips"].(*schema.Set)))
			VtmObject.Location = getStringAddr(itemTerraform["location"].(string))
			VtmObject.Monitors = getStringSetAddr(expandStringSet(itemTerraform["monitors"].(*schema.Set)))
			VtmObject.Weight = getIntAddr(itemTerraform["weight"].(int))
			*object.Basic.LocationSettings = append(*object.Basic.LocationSettings, VtmObject)
		}
		d.Set("location_settings", locationSettings)
	} else {
		d.Set("location_settings", make([]map[string]interface{}, 0, len(*object.Basic.LocationSettings)))
	}
	setBool(&object.Log.Enabled, d, "log_enabled")
	setString(&object.Log.Filename, d, "log_filename")
	setString(&object.Log.Format, d, "log_format")
}

func resourceGlbServiceDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteGlbService(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_glb_service '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
