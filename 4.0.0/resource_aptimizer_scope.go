// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func resourceAptimizerScope() *schema.Resource {
	return &schema.Resource{
		Read:   resourceAptimizerScopeRead,
		Exists: resourceAptimizerScopeExists,
		Create: resourceAptimizerScopeCreate,
		Update: resourceAptimizerScopeUpdate,
		Delete: resourceAptimizerScopeDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// If the hostnames for this scope are aliases of each other, the
			//  canonical hostname will be used for requests to the server.
			"canonical_hostname": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The hostnames to limit acceleration to.
			"hostnames": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The root path of the application defined by this application
			//  scope.
			"root": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "/",
			},
		},
	}
}

func resourceAptimizerScopeRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerScope(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_scope '%v': %v", objectName, err.ErrorText)
	}
	d.Set("canonical_hostname", string(*object.Basic.CanonicalHostname))
	d.Set("hostnames", []string(*object.Basic.Hostnames))
	d.Set("root", string(*object.Basic.Root))

	d.SetId(objectName)
	return nil
}

func resourceAptimizerScopeExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	_, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerScope(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceAptimizerScopeCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewAptimizerScope(objectName)
	setString(&object.Basic.CanonicalHostname, d, "canonical_hostname")

	if _, ok := d.GetOk("hostnames"); ok {
		setStringList(&object.Basic.Hostnames, d, "hostnames")
	} else {
		object.Basic.Hostnames = &[]string{}
		d.Set("hostnames", []string(*object.Basic.Hostnames))
	}
	setString(&object.Basic.Root, d, "root")

	object.Apply()
	d.SetId(objectName)
	return nil
}

func resourceAptimizerScopeUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerScope(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_scope '%v': %v", objectName, err)
	}
	setString(&object.Basic.CanonicalHostname, d, "canonical_hostname")

	if _, ok := d.GetOk("hostnames"); ok {
		setStringList(&object.Basic.Hostnames, d, "hostnames")
	} else {
		object.Basic.Hostnames = &[]string{}
		d.Set("hostnames", []string(*object.Basic.Hostnames))
	}
	setString(&object.Basic.Root, d, "root")

	object.Apply()
	d.SetId(objectName)
	return nil
}

func resourceAptimizerScopeDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteAptimizerScope(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_scope '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
