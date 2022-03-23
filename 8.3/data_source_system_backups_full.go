// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.3"
)

func dataSourceSystemBackupsFull() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceSystemBackupsFullRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Description of the backup
			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Time the backup was created. Expressed as a UTC value.
			"time_stamp": &schema.Schema{
				Type:         schema.TypeInt,
				Optional: true,
				Computed: true,
			},

			// Version of the traffic manager used to create the backup
			"version": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				Computed: true,
			},
		},
	}
}

func dataSourceSystemBackupsFullRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSystemBackupsFull(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_backups_full '%v': %v", objectName, err.ErrorText)
	}
	d.Set("description", string(*object.Backup.Description))
	d.Set("time_stamp", int(*object.Backup.TimeStamp))
	d.Set("version", string(*object.Backup.Version))

	d.SetId(objectName)
	return nil
}
