// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object Bandwidth
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceBandwidthStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceBandwidthStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Bytes dropped by this bandwidth class.
			"bytes_drop": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes output by connections assigned to this bandwidth class.
			"bytes_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Guaranteed bandwidth class limit (kbits/s).  Currently unused.
			"guarantee": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Maximum bandwidth class limit (kbits/s).
			"maximum": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of packets dropped by this bandwidth class.
			"pkts_drop": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceBandwidthStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetBandwidthStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_bandwidth '%v': %v", objectName, err.ErrorText)
	}
	d.Set("bytes_drop", int(*object.Statistics.BytesDrop))
	d.Set("bytes_out", int(*object.Statistics.BytesOut))
	d.Set("guarantee", int(*object.Statistics.Guarantee))
	d.Set("maximum", int(*object.Statistics.Maximum))
	d.Set("pkts_drop", int(*object.Statistics.PktsDrop))
	d.SetId(objectName)
	return nil
}
