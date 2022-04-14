// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.0"
)

func resourceSystemBackupsFull() *schema.Resource {
	return &schema.Resource{
		Read:   resourceSystemBackupsFullRead,
		Exists: resourceSystemBackupsFullExists,
		Create: resourceSystemBackupsFullCreate,
		Update: resourceSystemBackupsFullUpdate,
		Delete: resourceSystemBackupsFullDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

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

func resourceSystemBackupsFullRead(d *schema.ResourceData, tm interface{}) error {
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

func resourceSystemBackupsFullExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	_, err := tm.(*vtm.VirtualTrafficManager).GetSystemBackupsFull(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceSystemBackupsFullCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewSystemBackupsFull(objectName)
	setString(&object.Backup.Description, d, "description")
	setInt(&object.Backup.TimeStamp, d, "time_stamp")
	setString(&object.Backup.Version, d, "version")

	object.Apply()
	d.SetId(objectName)
	return nil
}

func resourceSystemBackupsFullUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSystemBackupsFull(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_backups_full '%v': %v", objectName, err)
	}
	setString(&object.Backup.Description, d, "description")
	setInt(&object.Backup.TimeStamp, d, "time_stamp")
	setString(&object.Backup.Version, d, "version")

	object.Apply()
	d.SetId(objectName)
	return nil
}

func resourceSystemBackupsFullDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteSystemBackupsFull(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_backups_full '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
