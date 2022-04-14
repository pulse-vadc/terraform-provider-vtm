// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object CloudApiCredential
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceCloudApiCredentialStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCloudApiCredentialStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The number of instance creation API requests made with this set
			//  of cloud credentials.
			"node_creations": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of instance destruction API requests made with this
			//  set of cloud credentials.
			"node_deletions": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of status API requests made with this set of cloud
			//  credentials.
			"status_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceCloudApiCredentialStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetCloudApiCredentialStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_cloud_api_credentials '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "node_creations"
	d.Set("node_creations", int(*object.Statistics.NodeCreations))

	lastAssignedField = "node_deletions"
	d.Set("node_deletions", int(*object.Statistics.NodeDeletions))

	lastAssignedField = "status_requests"
	d.Set("status_requests", int(*object.Statistics.StatusRequests))
	d.SetId(objectName)
	return nil
}
