// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceBgpneighbor() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceBgpneighborRead,

		Schema: map[string]*schema.Schema{

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
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceBgpneighborRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetBgpneighbor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_bgpneighbor '%v': %v", objectName, err.ErrorText)
	}
	d.Set("address", string(*object.Basic.Address))
	d.Set("advertisement_interval", int(*object.Basic.AdvertisementInterval))
	d.Set("as_number", int(*object.Basic.AsNumber))
	d.Set("authentication_password", string(*object.Basic.AuthenticationPassword))
	d.Set("holdtime", int(*object.Basic.Holdtime))
	d.Set("keepalive", int(*object.Basic.Keepalive))
	d.Set("machines", []string(*object.Basic.Machines))

	d.SetId(objectName)
	return nil
}
