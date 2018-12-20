// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func resourceBgpneighbor() *schema.Resource {
	return &schema.Resource{
		Read:   resourceBgpneighborRead,
		Exists: resourceBgpneighborExists,
		Create: resourceBgpneighborCreate,
		Update: resourceBgpneighborUpdate,
		Delete: resourceBgpneighborDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceBgpneighborSchema(),
	}
}

func getResourceBgpneighborSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The IP address of the BGP neighbor
		"address": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The minimum interval between the sending of BGP routing updates
		//  to neighbors. Note that as a result of jitter, as defined for
		//  BGP, the interval during which no advertisements are sent will
		//  be between 75% and 100% of this value.
		"advertisement_interval": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 65535),
			Default:      5,
		},

		// The AS number for the BGP neighbor
		"as_number": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 4294967295),
			Default:      65534,
		},

		// The password to be used for authentication of sessions with neighbors
		"authentication_password": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The period after which the BGP session with the neighbor is deemed
		//  to have become idle - and requires re-establishment - if the
		//  neighbor falls silent.
		"holdtime": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 65535),
			Default:      90,
		},

		// The interval at which messages are sent to the BGP neighbor to
		//  keep the mutual BGP session established.
		"keepalive": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 65535),
			Default:      30,
		},

		// The traffic managers that are to use this neighbor
		"machines": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},
	}
}

func resourceBgpneighborRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetBgpneighbor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_bgpneighbor '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "address"
	d.Set("address", string(*object.Basic.Address))
	lastAssignedField = "advertisement_interval"
	d.Set("advertisement_interval", int(*object.Basic.AdvertisementInterval))
	lastAssignedField = "as_number"
	d.Set("as_number", int(*object.Basic.AsNumber))
	lastAssignedField = "authentication_password"
	d.Set("authentication_password", string(*object.Basic.AuthenticationPassword))
	lastAssignedField = "holdtime"
	d.Set("holdtime", int(*object.Basic.Holdtime))
	lastAssignedField = "keepalive"
	d.Set("keepalive", int(*object.Basic.Keepalive))
	lastAssignedField = "machines"
	d.Set("machines", []string(*object.Basic.Machines))
	d.SetId(objectName)
	return nil
}

func resourceBgpneighborExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetBgpneighbor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceBgpneighborCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewBgpneighbor(objectName)
	resourceBgpneighborObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_bgpneighbor '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceBgpneighborUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetBgpneighbor(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_bgpneighbor '%v': %v", objectName, err)
	}
	resourceBgpneighborObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_bgpneighbor '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceBgpneighborObjectFieldAssignments(d *schema.ResourceData, object *vtm.Bgpneighbor) {
	setString(&object.Basic.Address, d, "address")
	setInt(&object.Basic.AdvertisementInterval, d, "advertisement_interval")
	setInt(&object.Basic.AsNumber, d, "as_number")
	setString(&object.Basic.AuthenticationPassword, d, "authentication_password")
	setInt(&object.Basic.Holdtime, d, "holdtime")
	setInt(&object.Basic.Keepalive, d, "keepalive")

	if _, ok := d.GetOk("machines"); ok {
		setStringSet(&object.Basic.Machines, d, "machines")
	} else {
		object.Basic.Machines = &[]string{}
		d.Set("machines", []string(*object.Basic.Machines))
	}
}

func resourceBgpneighborDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteBgpneighbor(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_bgpneighbor '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
