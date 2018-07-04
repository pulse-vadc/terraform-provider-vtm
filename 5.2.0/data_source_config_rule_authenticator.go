// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceRuleAuthenticator() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceRuleAuthenticatorRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The hostname or IP address of the remote authenticator.
			"host": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A description of the authenticator.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The port on which the remote authenticator should be contacted.
			"port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      389,
			},

			// A list of attributes to return from the search. If blank, no
			//  attributes will be returned. If set to '*' then all user attributes
			//  will be returned.
			"ldap_attributes": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The distinguished name (DN) of the 'bind' user. The traffic manager
			//  will connect to the LDAP server as this user when searching for
			//  user records.
			"ldap_bind_dn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The password for the bind user.
			"ldap_bind_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The filter used to locate the LDAP record for the user being
			//  authenticated. Any occurrences of '"%u"' in the filter will be
			//  replaced by the name of the user being authenticated.
			"ldap_filter": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The base distinguished name (DN) under which user records are
			//  located on the server.
			"ldap_filter_base_dn": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The SSL certificate that the traffic manager should use to validate
			//  the remote server. If no certificate is specified then no signature
			//  validation will be performed.
			"ldap_ssl_cert": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not to enable SSL encryption to the LDAP server.
			"ldap_ssl_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The type of LDAP SSL encryption to use.
			"ldap_ssl_type": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"ldaps", "starttls"}, false),
				Default:      "ldaps",
			},
		},
	}
}

func dataSourceRuleAuthenticatorRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetRuleAuthenticator(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_rule_authenticator '%v': %v", objectName, err.ErrorText)
	}
	d.Set("host", string(*object.Basic.Host))
	d.Set("note", string(*object.Basic.Note))
	d.Set("port", int(*object.Basic.Port))
	d.Set("ldap_attributes", []string(*object.Ldap.Attributes))
	d.Set("ldap_bind_dn", string(*object.Ldap.BindDn))
	d.Set("ldap_bind_password", string(*object.Ldap.BindPassword))
	d.Set("ldap_filter", string(*object.Ldap.Filter))
	d.Set("ldap_filter_base_dn", string(*object.Ldap.FilterBaseDn))
	d.Set("ldap_ssl_cert", string(*object.Ldap.SslCert))
	d.Set("ldap_ssl_enabled", bool(*object.Ldap.SslEnabled))
	d.Set("ldap_ssl_type", string(*object.Ldap.SslType))

	d.SetId(objectName)
	return nil
}
