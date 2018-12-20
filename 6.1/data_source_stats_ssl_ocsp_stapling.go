// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object SslOcspStapling
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceSslOcspStaplingStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSslOcspStaplingStatisticsRead,
		Schema: map[string]*schema.Schema{

			// The number of entries in the OCSP stapling cache.
			"cache_count": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of outgoing OCSP requests for OCSP stapling.
			"counter": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of failed outgoing OCSP requests for OCSP stapling.
			"failure_count": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of 'good' OCSP responses for OCSP stapling.
			"good_count": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of 'revoked' OCSP responses for OCSP stapling.
			"revoked_count": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of successful outgoing OCSP requests for OCSP stapling.
			"success_count": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of 'unknown' OCSP requests for OCSP stapling.
			"unknown_count": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceSslOcspStaplingStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslOcspStaplingStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_ssl_ocsp_stapling: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "cache_count"
	d.Set("cache_count", int(*object.Statistics.CacheCount))

	lastAssignedField = "counter"
	d.Set("counter", int(*object.Statistics.Count))

	lastAssignedField = "failure_count"
	d.Set("failure_count", int(*object.Statistics.FailureCount))

	lastAssignedField = "good_count"
	d.Set("good_count", int(*object.Statistics.GoodCount))

	lastAssignedField = "revoked_count"
	d.Set("revoked_count", int(*object.Statistics.RevokedCount))

	lastAssignedField = "success_count"
	d.Set("success_count", int(*object.Statistics.SuccessCount))

	lastAssignedField = "unknown_count"
	d.Set("unknown_count", int(*object.Statistics.UnknownCount))
	d.SetId("ssl_ocsp_stapling")
	return nil
}
