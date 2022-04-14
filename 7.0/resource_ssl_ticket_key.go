// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
)

func resourceSslTicketKey() *schema.Resource {
	return &schema.Resource{
		Read:   resourceSslTicketKeyRead,
		Exists: resourceSslTicketKeyExists,
		Create: resourceSslTicketKeyCreate,
		Update: resourceSslTicketKeyUpdate,
		Delete: resourceSslTicketKeyDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceSslTicketKeySchema(),
	}
}

func getResourceSslTicketKeySchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The algorithm used to encrypt session tickets.  The algorithm
		//  determines the length of the key that must be provided.
		"algorithm": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"aes_256_cbc_hmac_sha256"}, false),
			Default:      "aes_256_cbc_hmac_sha256",
		},

		// A 16-byte key identifier, with each byte encoded as two hexadecimal
		//  digits. Key identifiers are transmitted in plaintext at the beginning
		//  of a TLS session ticket, and are used to identify the ticket
		//  encryption key that was used to encrypt a ticket. (They correspond
		//  to the 'key_name' field in RFC 5077.) They are required to be
		//  unique across the set of SSL ticket encryption keys.
		"identifier": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// The session ticket encryption key, with each byte encoded as
		//  two hexadecimal digits. The required key length is determined
		//  by the chosen key algorithm. See the documentation for the 'algorithm'
		//  field for more details.
		"key": &schema.Schema{
			Type:     schema.TypeString,
			Required: true,
		},

		// The latest time at which this key may be used to encrypt new
		//  session tickets. Given as number of seconds since the epoch (1970-01-01T00:00:00Z).
		"validity_end": &schema.Schema{
			Type:         schema.TypeInt,
			Required:     true,
			ValidateFunc: validation.IntAtLeast(0),
		},

		// The earliest time at which this key may be used to encrypt new
		//  session tickets. Given as number of seconds since the epoch (1970-01-01T00:00:00Z).
		"validity_start": &schema.Schema{
			Type:         schema.TypeInt,
			Required:     true,
			ValidateFunc: validation.IntAtLeast(0),
		},
	}
}

func resourceSslTicketKeyRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslTicketKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_ticket_key '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "algorithm"
	d.Set("algorithm", string(*object.Basic.Algorithm))
	lastAssignedField = "identifier"
	d.Set("identifier", string(*object.Basic.Id))
	lastAssignedField = "key"
	d.Set("key", string(*object.Basic.Key))
	lastAssignedField = "validity_end"
	d.Set("validity_end", int(*object.Basic.ValidityEnd))
	lastAssignedField = "validity_start"
	d.Set("validity_start", int(*object.Basic.ValidityStart))
	d.SetId(objectName)
	return nil
}

func resourceSslTicketKeyExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetSslTicketKey(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceSslTicketKeyCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewSslTicketKey(objectName, d.Get("identifier").(string), d.Get("key").(string), d.Get("validity_end").(int), d.Get("validity_start").(int))
	resourceSslTicketKeyObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_ticket_key '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSslTicketKeyUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetSslTicketKey(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_ticket_key '%v': %v", objectName, err)
	}
	resourceSslTicketKeyObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_ticket_key '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceSslTicketKeyObjectFieldAssignments(d *schema.ResourceData, object *vtm.SslTicketKey) {
	setString(&object.Basic.Algorithm, d, "algorithm")
	setString(&object.Basic.Id, d, "identifier")
	setString(&object.Basic.Key, d, "key")
	setInt(&object.Basic.ValidityEnd, d, "validity_end")
	setInt(&object.Basic.ValidityStart, d, "validity_start")
}

func resourceSslTicketKeyDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteSslTicketKey(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_ticket_key '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
