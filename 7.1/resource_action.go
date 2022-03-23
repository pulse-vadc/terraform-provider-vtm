// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/7.1"
)

func resourceAction() *schema.Resource {
	return &schema.Resource{
		Read:   resourceActionRead,
		Exists: resourceActionExists,
		Create: resourceActionCreate,
		Update: resourceActionUpdate,
		Delete: resourceActionDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceActionSchema(),
	}
}

func getResourceActionSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

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
			Default:      2048,
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
			Required:     true,
			ValidateFunc: validation.StringInSlice([]string{"email", "log", "program", "soap", "syslog", "trap"}, false),
		},

		// Enable or disable verbose logging for this action.
		"verbose": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The e-mail address from which messages will appear to originate.
		"email_from": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "vTM@%hostname%",
		},

		// The SMTP server to which messages should be sent. This must be
		//  a valid IPv4 address or resolvable hostname (with optional port).
		"email_server": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// A set of e-mail addresses to which messages will be sent.
		"email_to": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The full path of the file to log to. The text "%zeushome%" will
		//  be replaced with the location where the software is installed.
		"log_file": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
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
	}
}

func resourceActionRead(d *schema.ResourceData, tm interface{}) (readError error) {
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

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "syslog_msg_len_limit"
	d.Set("syslog_msg_len_limit", int(*object.Basic.SyslogMsgLenLimit))
	lastAssignedField = "timeout"
	d.Set("timeout", int(*object.Basic.Timeout))
	lastAssignedField = "type"
	d.Set("type", string(*object.Basic.Type))
	lastAssignedField = "verbose"
	d.Set("verbose", bool(*object.Basic.Verbose))
	lastAssignedField = "email_from"
	d.Set("email_from", string(*object.Email.From))
	lastAssignedField = "email_server"
	d.Set("email_server", string(*object.Email.Server))
	lastAssignedField = "email_to"
	d.Set("email_to", []string(*object.Email.To))
	lastAssignedField = "log_file"
	d.Set("log_file", string(*object.Log.File))
	lastAssignedField = "program_arguments"
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
	lastAssignedField = "program_program"
	d.Set("program_program", string(*object.Program.Program))
	lastAssignedField = "soap_additional_data"
	d.Set("soap_additional_data", string(*object.Soap.AdditionalData))
	lastAssignedField = "soap_password"
	d.Set("soap_password", string(*object.Soap.Password))
	lastAssignedField = "soap_proxy"
	d.Set("soap_proxy", string(*object.Soap.Proxy))
	lastAssignedField = "soap_username"
	d.Set("soap_username", string(*object.Soap.Username))
	lastAssignedField = "syslog_sysloghost"
	d.Set("syslog_sysloghost", string(*object.Syslog.Sysloghost))
	lastAssignedField = "trap_auth_password"
	d.Set("trap_auth_password", string(*object.Trap.AuthPassword))
	lastAssignedField = "trap_community"
	d.Set("trap_community", string(*object.Trap.Community))
	lastAssignedField = "trap_hash_algorithm"
	d.Set("trap_hash_algorithm", string(*object.Trap.HashAlgorithm))
	lastAssignedField = "trap_priv_password"
	d.Set("trap_priv_password", string(*object.Trap.PrivPassword))
	lastAssignedField = "trap_traphost"
	d.Set("trap_traphost", string(*object.Trap.Traphost))
	lastAssignedField = "trap_username"
	d.Set("trap_username", string(*object.Trap.Username))
	lastAssignedField = "trap_version"
	d.Set("trap_version", string(*object.Trap.Version))
	d.SetId(objectName)
	return nil
}

func resourceActionExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetAction(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceActionCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewAction(objectName, d.Get("type").(string))
	resourceActionObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_action '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceActionUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetAction(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_action '%v': %v", objectName, err)
	}
	resourceActionObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_action '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceActionObjectFieldAssignments(d *schema.ResourceData, object *vtm.Action) {
	setString(&object.Basic.Note, d, "note")
	setInt(&object.Basic.SyslogMsgLenLimit, d, "syslog_msg_len_limit")
	setInt(&object.Basic.Timeout, d, "timeout")
	setString(&object.Basic.Type, d, "type")
	setBool(&object.Basic.Verbose, d, "verbose")
	setString(&object.Email.From, d, "email_from")
	setString(&object.Email.Server, d, "email_server")

	if _, ok := d.GetOk("email_to"); ok {
		setStringSet(&object.Email.To, d, "email_to")
	} else {
		object.Email.To = &[]string{}
		d.Set("email_to", []string(*object.Email.To))
	}
	setString(&object.Log.File, d, "log_file")

	object.Program.Arguments = &vtm.ActionArgumentsTable{}
	if programArgumentsJson, ok := d.GetOk("program_arguments_json"); ok {
		_ = json.Unmarshal([]byte(programArgumentsJson.(string)), object.Program.Arguments)
	} else if programArguments, ok := d.GetOk("program_arguments"); ok {
		for _, row := range programArguments.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.ActionArguments{}
			VtmObject.Description = getStringAddr(itemTerraform["description"].(string))
			VtmObject.Name = getStringAddr(itemTerraform["name"].(string))
			VtmObject.Value = getStringAddr(itemTerraform["value"].(string))
			*object.Program.Arguments = append(*object.Program.Arguments, VtmObject)
		}
		d.Set("program_arguments", programArguments)
	} else {
		d.Set("program_arguments", make([]map[string]interface{}, 0, len(*object.Program.Arguments)))
	}
	setString(&object.Program.Program, d, "program_program")
	setString(&object.Soap.AdditionalData, d, "soap_additional_data")
	setString(&object.Soap.Password, d, "soap_password")
	setString(&object.Soap.Proxy, d, "soap_proxy")
	setString(&object.Soap.Username, d, "soap_username")
	setString(&object.Syslog.Sysloghost, d, "syslog_sysloghost")
	setString(&object.Trap.AuthPassword, d, "trap_auth_password")
	setString(&object.Trap.Community, d, "trap_community")
	setString(&object.Trap.HashAlgorithm, d, "trap_hash_algorithm")
	setString(&object.Trap.PrivPassword, d, "trap_priv_password")
	setString(&object.Trap.Traphost, d, "trap_traphost")
	setString(&object.Trap.Username, d, "trap_username")
	setString(&object.Trap.Version, d, "trap_version")
}

func resourceActionDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteAction(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_action '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
