// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceAction() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceActionRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// A description of the action.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Maximum length in bytes of a message sent to the remote syslog.
			//  Messages longer than this will be truncated before they are sent.
			"syslog_msg_len_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(480, 65535),
				Default:      1024,
			},

			// How long the action can run for before it is stopped automatically
			//  (set to 0 to disable timeouts).
			"timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      60,
			},

			// The action type.
			"type": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"email", "log", "program", "soap", "syslog", "trap"}, false),
			},

			// Enable or disable verbose logging for this action.
			"verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The SMTP server to which messages should be sent. This must be
			//  a valid IPv4 address or resolvable hostname (with optional port).
			"email_server": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A set of e-mail addresses to which messages will be sent.
			"email_to": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The full path of the file to log to. The text "%zeushome%" will
			//  be replaced with the location where the software is installed.
			"log_file": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The e-mail address from which messages will appear to originate.
			"log_from": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "vTM@%hostname%",
			},

			// A table containing arguments and argument values to be passed
			//  to the event handling program.
			"program_arguments": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// description
						"description": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// value
						"value": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// The program to run.
			"program_program": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Additional information to send with the SOAP call.
			"soap_additional_data": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The password for HTTP basic authentication.
			"soap_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The address of the server implementing the SOAP interface (For
			//  example, https://example.com).
			"soap_proxy": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Username for HTTP basic authentication. Leave blank if you do
			//  not wish to use authentication.
			"soap_username": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The host and optional port to send syslog messages to (if empty,
			//  messages will be sent to localhost).
			"syslog_sysloghost": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The authentication password for sending a Notify over SNMPv3.
			//  Blank to send unauthenticated traps.
			"trap_auth_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The community string to use when sending a Trap over SNMPv1 or
			//  a Notify over SNMPv2c.
			"trap_community": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The hash algorithm for SNMPv3 authentication.
			"trap_hash_algorithm": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"md5", "sha1"}, false),
				Default:      "md5",
			},

			// The encryption password to encrypt a Notify message for SNMPv3.
			//  Requires that authentication also be configured. Blank to send
			//  unencrypted traps.
			"trap_priv_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The hostname or IPv4 address and optional port number that should
			//  receive traps.
			"trap_traphost": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The SNMP username to use to send the Notify over SNMPv3.
			"trap_username": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The SNMP version to use to send the Trap/Notify.
			"trap_version": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"snmpv1", "snmpv2c", "snmpv3"}, false),
				Default:      "snmpv1",
			},
		},
	}
}

func dataSourceActionRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetAction(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_action '%v': %v", objectName, err.ErrorText)
	}
	d.Set("note", string(*object.Basic.Note))
	d.Set("syslog_msg_len_limit", int(*object.Basic.SyslogMsgLenLimit))
	d.Set("timeout", int(*object.Basic.Timeout))
	d.Set("type", string(*object.Basic.Type))
	d.Set("verbose", bool(*object.Basic.Verbose))
	d.Set("email_server", string(*object.Email.Server))
	d.Set("email_to", []string(*object.Email.To))
	d.Set("log_file", string(*object.Log.File))
	d.Set("log_from", string(*object.Log.From))

	programArguments := make([]map[string]interface{}, 0, len(*object.Program.Arguments))
	for _, item := range *object.Program.Arguments {
		itemTerraform := make(map[string]interface{})
		if item.Description != nil {
			itemTerraform["description"] = string(*item.Description)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Value != nil {
			itemTerraform["value"] = string(*item.Value)
		}
		programArguments = append(programArguments, itemTerraform)
	}
	d.Set("program_arguments", programArguments)
	programArgumentsJson, _ := json.Marshal(programArguments)
	d.Set("program_arguments_json", programArgumentsJson)
	d.Set("program_program", string(*object.Program.Program))
	d.Set("soap_additional_data", string(*object.Soap.AdditionalData))
	d.Set("soap_password", string(*object.Soap.Password))
	d.Set("soap_proxy", string(*object.Soap.Proxy))
	d.Set("soap_username", string(*object.Soap.Username))
	d.Set("syslog_sysloghost", string(*object.Syslog.Sysloghost))
	d.Set("trap_auth_password", string(*object.Trap.AuthPassword))
	d.Set("trap_community", string(*object.Trap.Community))
	d.Set("trap_hash_algorithm", string(*object.Trap.HashAlgorithm))
	d.Set("trap_priv_password", string(*object.Trap.PrivPassword))
	d.Set("trap_traphost", string(*object.Trap.Traphost))
	d.Set("trap_username", string(*object.Trap.Username))
	d.Set("trap_version", string(*object.Trap.Version))

	d.SetId(objectName)
	return nil
}
