// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceKerberosPrincipal() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceKerberosPrincipalRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// A list of "<hostname/ip>:<port>" pairs for Kerberos key distribution
			//  center (KDC) services to be explicitly used for the realm of
			//  the principal.  If no KDCs are explicitly configured, DNS will
			//  be used to discover the KDC(s) to use.
			"kdcs": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The name of the Kerberos keytab file containing suitable credentials
			//  to authenticate as the specified Kerberos principal.
			"keytab": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The name of an optional Kerberos configuration file (krb5.conf).
			"krb5conf": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The Kerberos realm where the principal belongs.
			"realm": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The service name part of the Kerberos principal name the traffic
			//  manager should use to authenticate itself.
			"service": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceKerberosPrincipalRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetKerberosPrincipal(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_kerberos_principal '%v': %v", objectName, err.ErrorText)
	}
	d.Set("kdcs", []string(*object.Basic.Kdcs))
	d.Set("keytab", string(*object.Basic.Keytab))
	d.Set("krb5conf", string(*object.Basic.Krb5Conf))
	d.Set("realm", string(*object.Basic.Realm))
	d.Set("service", string(*object.Basic.Service))

	d.SetId(objectName)
	return nil
}
