// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func resourceSecurity() *schema.Resource {
	return &schema.Resource{
		Read:   resourceSecurityRead,
		Create: resourceSecurityUpdate,
		Update: resourceSecurityUpdate,
		Delete: resourceSecurityDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceSecuritySchema(),
	}
}

func getResourceSecuritySchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		// Access to the admin server and REST API is restricted by usernames
		//  and passwords. You can further restrict access to just trusted
		//  IP addresses, CIDR IP subnets or DNS wildcards. These access
		//  restrictions are also used when another traffic manager initially
		//  joins the cluster, after joining the cluster these restrictions
		//  are no longer used. Care must be taken when changing this setting,
		//  as it can cause the administration server to become inaccessible.</br>Access
		//  to the admin UI will not be affected until it is restarted.
		"access": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The amount of time in seconds to ban an offending host for.
		"ssh_intrusion_bantime": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 2147483647),
			Default:      600,
		},

		// The list of hosts to permanently ban, identified by IP address
		//  or DNS hostname in a space-separated list.
		"ssh_intrusion_blacklist": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Whether or not the SSH Intrusion Prevention tool is enabled.
		"ssh_intrusion_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The window of time in seconds the maximum number of connection
		//  attempts applies to. More than (maxretry) failed attempts in
		//  this time span will trigger a ban.
		"ssh_intrusion_findtime": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 2147483647),
			Default:      600,
		},

		// The number of failed connection attempts a host can make before
		//  being banned.
		"ssh_intrusion_maxretry": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 2147483647),
			Default:      6,
		},

		// The list of hosts to never ban, identified by IP address, DNS
		//  hostname or subnet mask, in a space-separated list.
		"ssh_intrusion_whitelist": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},
	}
}

func resourceSecurityRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetSecurity()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_security: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "access"
	d.Set("access", []string(*object.Basic.Access))
	lastAssignedField = "ssh_intrusion_bantime"
	d.Set("ssh_intrusion_bantime", int(*object.SshIntrusion.Bantime))
	lastAssignedField = "ssh_intrusion_blacklist"
	d.Set("ssh_intrusion_blacklist", []string(*object.SshIntrusion.Blacklist))
	lastAssignedField = "ssh_intrusion_enabled"
	d.Set("ssh_intrusion_enabled", bool(*object.SshIntrusion.Enabled))
	lastAssignedField = "ssh_intrusion_findtime"
	d.Set("ssh_intrusion_findtime", int(*object.SshIntrusion.Findtime))
	lastAssignedField = "ssh_intrusion_maxretry"
	d.Set("ssh_intrusion_maxretry", int(*object.SshIntrusion.Maxretry))
	lastAssignedField = "ssh_intrusion_whitelist"
	d.Set("ssh_intrusion_whitelist", []string(*object.SshIntrusion.Whitelist))
	d.SetId("security")
	return nil
}

func resourceSecurityUpdate(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetSecurity()
	if err != nil {
		return fmt.Errorf("Failed to update vtm_security: %v", err)
	}

	if _, ok := d.GetOk("access"); ok {
		setStringSet(&object.Basic.Access, d, "access")
	} else {
		object.Basic.Access = &[]string{}
		d.Set("access", []string(*object.Basic.Access))
	}
	setInt(&object.SshIntrusion.Bantime, d, "ssh_intrusion_bantime")

	if _, ok := d.GetOk("ssh_intrusion_blacklist"); ok {
		setStringSet(&object.SshIntrusion.Blacklist, d, "ssh_intrusion_blacklist")
	} else {
		object.SshIntrusion.Blacklist = &[]string{}
		d.Set("ssh_intrusion_blacklist", []string(*object.SshIntrusion.Blacklist))
	}
	setBool(&object.SshIntrusion.Enabled, d, "ssh_intrusion_enabled")
	setInt(&object.SshIntrusion.Findtime, d, "ssh_intrusion_findtime")
	setInt(&object.SshIntrusion.Maxretry, d, "ssh_intrusion_maxretry")

	if _, ok := d.GetOk("ssh_intrusion_whitelist"); ok {
		setStringSet(&object.SshIntrusion.Whitelist, d, "ssh_intrusion_whitelist")
	} else {
		object.SshIntrusion.Whitelist = &[]string{}
		d.Set("ssh_intrusion_whitelist", []string(*object.SshIntrusion.Whitelist))
	}

	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_security: %s %s", applyErr.ErrorText, info)
	}
	d.SetId("security")
	return nil
}

func resourceSecurityDelete(d *schema.ResourceData, tm interface{}) error {
	d.SetId("")
	return nil
}
