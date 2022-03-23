// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceTrafficManagerIfTable() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerIfTableRead,

		Schema: map[string]*schema.Schema{
			// JSON output string
			"json": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			// autoneg
			"autoneg": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// bmode
			"bmode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"802_3ad", "balance_alb"}, false),
				Default:      "802_3ad",
			},

			// bond
			"bond": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// duplex
			"duplex": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// mode
			"mode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"dhcp", "static"}, false),
				Default:      "static",
			},

			// mtu
			"mtu": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(68, 9216),
				Default:      1500,
			},

			// name
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			// speed
			"speed": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"10", "100", "1000", "10000", "100000", "40000"}, false),
				Default:      "1000",
			},
		},
	}
}

func dataSourceTrafficManagerIfTableRead(d *schema.ResourceData, tm interface{}) error {
	table := &vtm.TrafficManagerIf{
		Autoneg: getBoolAddr(d.Get("autoneg").(bool)),
		Bmode:   getStringAddr(d.Get("bmode").(string)),
		Bond:    getStringAddr(d.Get("bond").(string)),
		Duplex:  getBoolAddr(d.Get("duplex").(bool)),
		Mode:    getStringAddr(d.Get("mode").(string)),
		Mtu:     getIntAddr(d.Get("mtu").(int)),
		Name:    getStringAddr(d.Get("name").(string)),
		Speed:   getStringAddr(d.Get("speed").(string)),
	}
	jsonString, err := json.Marshal(table)
	if err != nil {
		return fmt.Errorf("Failed to marshal table to JSON: %s", err)
	}
	d.Set("json", string(jsonString))
	d.SetId("TrafficManagerIf")
	return nil
}
