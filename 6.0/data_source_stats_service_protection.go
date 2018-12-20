// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object ServiceProtection
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func dataSourceServiceProtectionStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceServiceProtectionStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The time (in hundredths of a second) since this service protection
			//  class last refused a connection (this value will wrap if no connections
			//  are refused in more than 497 days).
			"last_refusal_time": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  request contained disallowed binary content.
			"refusal_binary": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  top 10 source IP addresses issued too many concurrent connections.
			"refusal_conc10_ip": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  source IP address issued too many concurrent connections.
			"refusal_conc1_ip": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  source IP address issued too many connections within 60
			//  seconds.
			"refusal_conn_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  source IP address was banned.
			"refusal_ip": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  HTTP request was not RFC 2396 compliant.
			"refusal_rfc2396": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class because
			//  the  request was larger than the defined limits allowed.
			"refusal_size": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections refused by this service protection class.
			"total_refusal": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceServiceProtectionStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetServiceProtectionStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_service_protection '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "last_refusal_time"
	d.Set("last_refusal_time", int(*object.Statistics.LastRefusalTime))

	lastAssignedField = "refusal_binary"
	d.Set("refusal_binary", int(*object.Statistics.RefusalBinary))

	lastAssignedField = "refusal_conc10_ip"
	d.Set("refusal_conc10_ip", int(*object.Statistics.RefusalConc10Ip))

	lastAssignedField = "refusal_conc1_ip"
	d.Set("refusal_conc1_ip", int(*object.Statistics.RefusalConc1Ip))

	lastAssignedField = "refusal_conn_rate"
	d.Set("refusal_conn_rate", int(*object.Statistics.RefusalConnRate))

	lastAssignedField = "refusal_ip"
	d.Set("refusal_ip", int(*object.Statistics.RefusalIp))

	lastAssignedField = "refusal_rfc2396"
	d.Set("refusal_rfc2396", int(*object.Statistics.RefusalRfc2396))

	lastAssignedField = "refusal_size"
	d.Set("refusal_size", int(*object.Statistics.RefusalSize))

	lastAssignedField = "total_refusal"
	d.Set("total_refusal", int(*object.Statistics.TotalRefusal))
	d.SetId(objectName)
	return nil
}
