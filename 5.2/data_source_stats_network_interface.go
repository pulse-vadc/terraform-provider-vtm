// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object NetworkInterface
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceNetworkInterfaceStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceNetworkInterfaceStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The number of collisions reported by this interface.
			"collisions": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes received by this interface.
			"rx_bytes": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of receive errors reported by this interface.
			"rx_errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of packets received by this interface.
			"rx_packets": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes transmitted by this interface.
			"tx_bytes": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of transmit errors reported by this interface.
			"tx_errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of packets transmitted by this interface.
			"tx_packets": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceNetworkInterfaceStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetNetworkInterfaceStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_network_interface '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "collisions"
	d.Set("collisions", int(*object.Statistics.Collisions))

	lastAssignedField = "rx_bytes"
	d.Set("rx_bytes", int(*object.Statistics.RxBytes))

	lastAssignedField = "rx_errors"
	d.Set("rx_errors", int(*object.Statistics.RxErrors))

	lastAssignedField = "rx_packets"
	d.Set("rx_packets", int(*object.Statistics.RxPackets))

	lastAssignedField = "tx_bytes"
	d.Set("tx_bytes", int(*object.Statistics.TxBytes))

	lastAssignedField = "tx_errors"
	d.Set("tx_errors", int(*object.Statistics.TxErrors))

	lastAssignedField = "tx_packets"
	d.Set("tx_packets", int(*object.Statistics.TxPackets))
	d.SetId(objectName)
	return nil
}
