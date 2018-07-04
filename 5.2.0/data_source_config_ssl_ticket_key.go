// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceSslTicketKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSslTicketKeyRead,

		Schema: map[string]*schema.Schema{

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
				Optional: true,
			},

			// The session ticket encryption key, with each byte encoded as
			//  two hexadecimal digits. The required key length is determined
			//  by the chosen key algorithm. See the documentation for the 'algorithm'
			//  field for more details.
			"key": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The latest time at which this key may be used to encrypt new
			//  session tickets. Given as number of seconds since the epoch (1970-01-01T00:00:00Z).
			"validity_end": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
			},

			// The earliest time at which this key may be used to encrypt new
			//  session tickets. Given as number of seconds since the epoch (1970-01-01T00:00:00Z).
			"validity_start": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
			},
		},
	}
}

func dataSourceSslTicketKeyRead(d *schema.ResourceData, tm interface{}) error {
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
		return fmt.Errorf("Failed to read vtm_ssl_ticket_key '%v': %v", objectName, err.ErrorText)
	}
	d.Set("algorithm", string(*object.Basic.Algorithm))
	d.Set("identifier", string(*object.Basic.Id))
	d.Set("key", string(*object.Basic.Key))
	d.Set("validity_end", int(*object.Basic.ValidityEnd))
	d.Set("validity_start", int(*object.Basic.ValidityStart))

	d.SetId(objectName)
	return nil
}
