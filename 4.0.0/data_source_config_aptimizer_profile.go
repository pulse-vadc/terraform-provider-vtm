// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceAptimizerProfile() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceAptimizerProfileRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// If Web Accelerator can finish optimizing the resource within
			//  this time limit then serve the optimized content to the client,
			//  otherwise complete the optimization in the background and return
			//  the original content to the client. If set to 0, Web Accelerator
			//  will always wait for the optimization to complete before sending
			//  a response to the client.
			"background_after": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      0,
			},

			// If a web page contains resources that have not yet been optimized,
			//  fetch and optimize those resources in the background and send
			//  a partially optimized web page to clients until all resources
			//  on that page are ready.
			"background_on_additional_resources": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Set the Web Accelerator mode to turn acceleration on or off.
			"mode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"active", "idle", "stealth"}, false),
				Default:      "active",
			},

			// Show the Web Accelerator information bar on optimized web pages.
			//  This requires HTML optimization to be enabled in the acceleration
			//  settings.
			"show_info_bar": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

func dataSourceAptimizerProfileRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetAptimizerProfile(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_aptimizer_profile '%v': %v", objectName, err.ErrorText)
	}
	d.Set("background_after", int(*object.Basic.BackgroundAfter))
	d.Set("background_on_additional_resources", bool(*object.Basic.BackgroundOnAdditionalResources))
	d.Set("mode", string(*object.Basic.Mode))
	d.Set("show_info_bar", bool(*object.Basic.ShowInfoBar))

	d.SetId(objectName)
	return nil
}
