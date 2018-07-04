// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceCloudApiCredential() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCloudApiCredentialRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The vCenter server hostname or IP address.
			"api_server": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The traffic manager creates and destroys nodes via API calls.
			//  This setting specifies (in seconds) how long to wait for such
			//  calls to complete.
			"cloud_api_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      200,
			},

			// The first part of the credentials for the cloud user.  Typically
			//  this is some variation on the username concept.
			"cred1": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The second part of the credentials for the cloud user.  Typically
			//  this is some variation on the password concept.
			"cred2": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The third part of the credentials for the cloud user.  Typically
			//  this is some variation on the authentication token concept.
			"cred3": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The script to call for communication with the cloud API.
			"script": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The traffic manager will periodically check the status of the
			//  cloud through an API call. This setting specifies the interval
			//  between such updates.
			"update_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      30,
			},
		},
	}
}

func dataSourceCloudApiCredentialRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetCloudApiCredential(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_cloud_api_credential '%v': %v", objectName, err.ErrorText)
	}
	d.Set("api_server", string(*object.Basic.ApiServer))
	d.Set("cloud_api_timeout", int(*object.Basic.CloudApiTimeout))
	d.Set("cred1", string(*object.Basic.Cred1))
	d.Set("cred2", string(*object.Basic.Cred2))
	d.Set("cred3", string(*object.Basic.Cred3))
	d.Set("script", string(*object.Basic.Script))
	d.Set("update_interval", int(*object.Basic.UpdateInterval))

	d.SetId(objectName)
	return nil
}
