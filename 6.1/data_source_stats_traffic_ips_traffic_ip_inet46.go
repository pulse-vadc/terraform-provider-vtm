// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object TrafficIpsTrafficIpInet46
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceTrafficIpsTrafficIpInet46Statistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficIpsTrafficIpInet46StatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Whether this traffic IP address is currently being hosted by
			//  this traffic manager.
			"state": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The time (in hundredths of a second) since trafficIPState last
			//  changed (this value will wrap if the state hasn't changed for
			//  497 days).
			"time": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceTrafficIpsTrafficIpInet46StatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetTrafficIpsTrafficIpInet46Statistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_traffic_ip_inet46 '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "state"
	d.Set("state", string(*object.Statistics.State))

	lastAssignedField = "time"
	d.Set("time", int(*object.Statistics.Time))
	d.SetId(objectName)
	return nil
}
