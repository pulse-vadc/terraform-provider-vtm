// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object GlbService
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.3"
)

func dataSourceGlbServiceStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceGlbServiceStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Number of A records this GLB Service has discarded.
			"discarded": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of A records this GLB Service has altered.
			"responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of A records this GLB Service has passed through unmodified.
			"unmodified": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceGlbServiceStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetGlbServiceStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_glb_services '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "discarded"
	d.Set("discarded", int(*object.Statistics.Discarded))

	lastAssignedField = "responses"
	d.Set("responses", int(*object.Statistics.Responses))

	lastAssignedField = "unmodified"
	d.Set("unmodified", int(*object.Statistics.Unmodified))
	d.SetId(objectName)
	return nil
}
