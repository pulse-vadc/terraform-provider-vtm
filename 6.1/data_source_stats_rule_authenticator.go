// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object RuleAuthenticator
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceRuleAuthenticatorStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRuleAuthenticatorStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Number of connection errors that have occurred when trying to
			//  connect to an authentication server.
			"errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this Authenticator has failed to authenticate.
			"fails": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this Authenticator has successfully authenticated.
			"passes": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times this Authenticator has been asked to authenticate.
			"requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceRuleAuthenticatorStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetRuleAuthenticatorStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rule_authenticators '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "errors"
	d.Set("errors", int(*object.Statistics.Errors))

	lastAssignedField = "fails"
	d.Set("fails", int(*object.Statistics.Fails))

	lastAssignedField = "passes"
	d.Set("passes", int(*object.Statistics.Passes))

	lastAssignedField = "requests"
	d.Set("requests", int(*object.Statistics.Requests))
	d.SetId(objectName)
	return nil
}
