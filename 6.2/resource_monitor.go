// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func resourceMonitor() *schema.Resource {
	return &schema.Resource{
		Read:   resourceMonitorRead,
		Exists: resourceMonitorExists,
		Create: resourceMonitorCreate,
		Update: resourceMonitorUpdate,
		Delete: resourceMonitorDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceMonitorSchema(),
	}
}

func getResourceMonitorSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Should the monitor slowly increase the delay after it has failed?
		"back_off": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The minimum time between calls to a monitor.
		"delay": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 999990),
			Default:      3,
		},

		// The number of times in a row that a node must fail execution
		//  of the monitor before it is classed as unavailable.
		"failures": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 99999),
			Default:      3,
		},

		// Should this monitor only report health (ignore load)?
		"health_only": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The machine to monitor, where relevant this should be in the
		//  form "<hostname>:<port>", for "ping" monitors the ":<port>" part
		//  must not be specified.
		"machine": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// A description of the monitor.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// A monitor can either monitor each node in the pool separately
		//  and disable an individual node if it fails, or it can monitor
		//  a specific machine and disable the entire pool if that machine
		//  fails. GLB location monitors must monitor a specific machine.
		"scope": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"pernode", "poolwide"}, false),
			Default:      "pernode",
		},

		// The maximum runtime for an individual instance of the monitor.
		"timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 99999),
			Default:      3,
		},

		// The internal monitor implementation of this monitor.
		"type": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"connect", "http", "ping", "program", "rtsp", "sip", "tcp_transaction"}, false),
			Default:      "ping",
		},

		// Whether or not the monitor should connect using SSL.
		"use_ssl": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not the monitor should emit verbose logging. This
		//  is useful for diagnosing problems.
		"verbose": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The HTTP basic-auth "<user>:<password>" to use for the test HTTP
		//  request.
		"http_authentication": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// A regular expression that the HTTP response body must match.
		//   If the response body content doesn't matter then set this to
		//  ".*" (match anything).
		"http_body_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The host header to use in the test HTTP request.
		"http_host_header": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The path to use in the test HTTP request.  This must be a string
		//  beginning with a "/" (forward slash).
		"http_path": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "/",
		},

		// A regular expression that the HTTP status code must match.  If
		//  the status code doesn't matter then set this to ".*" (match anything).
		"http_status_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "^[234][0-9][0-9]$",
		},

		// The regular expression that the RTSP response body must match.
		"rtsp_body_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The path to use in the RTSP request (some servers will return
		//  500 Internal Server Error unless this is a valid media file).
		"rtsp_path": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "/",
		},

		// The regular expression that the RTSP response status code must
		//  match.
		"rtsp_status_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "^[234][0-9][0-9]$",
		},

		// A table containing arguments and argument values to be passed
		//  to the monitor program.
		"script_arguments": &schema.Schema{
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

		// The program to run.  This must be an executable file, either
		//  within the monitor scripts directory or specified as an absolute
		//  path to some other location on the filesystem.
		"script_program": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The regular expression that the SIP response body must match.
		"sip_body_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The regular expression that the SIP response status code must
		//  match.
		"sip_status_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "^[234][0-9][0-9]$",
		},

		// Which transport protocol the SIP monitor will use to query the
		//  server.
		"sip_transport": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"tcp", "udp"}, false),
			Default:      "udp",
		},

		// An optional string to write to the server before closing the
		//  connection.
		"tcp_close_string": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The maximum amount of data to read back from a server, use 0
		//  for unlimited. Applies to TCP and HTTP monitors.
		"tcp_max_response_len": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      2048,
		},

		// A regular expression to match against the response from the server.
		//  Applies to TCP monitors only.
		"tcp_response_regex": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  ".+",
		},

		// The string to write down the TCP connection.
		"tcp_write_string": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// If this monitor uses UDP, should it accept responses from any
		//  IP and port?
		"udp_accept_all": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},
	}
}

func resourceMonitorRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetMonitor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_monitor '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "back_off"
	d.Set("back_off", bool(*object.Basic.BackOff))
	lastAssignedField = "delay"
	d.Set("delay", int(*object.Basic.Delay))
	lastAssignedField = "failures"
	d.Set("failures", int(*object.Basic.Failures))
	lastAssignedField = "health_only"
	d.Set("health_only", bool(*object.Basic.HealthOnly))
	lastAssignedField = "machine"
	d.Set("machine", string(*object.Basic.Machine))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "scope"
	d.Set("scope", string(*object.Basic.Scope))
	lastAssignedField = "timeout"
	d.Set("timeout", int(*object.Basic.Timeout))
	lastAssignedField = "type"
	d.Set("type", string(*object.Basic.Type))
	lastAssignedField = "use_ssl"
	d.Set("use_ssl", bool(*object.Basic.UseSsl))
	lastAssignedField = "verbose"
	d.Set("verbose", bool(*object.Basic.Verbose))
	lastAssignedField = "http_authentication"
	d.Set("http_authentication", string(*object.Http.Authentication))
	lastAssignedField = "http_body_regex"
	d.Set("http_body_regex", string(*object.Http.BodyRegex))
	lastAssignedField = "http_host_header"
	d.Set("http_host_header", string(*object.Http.HostHeader))
	lastAssignedField = "http_path"
	d.Set("http_path", string(*object.Http.Path))
	lastAssignedField = "http_status_regex"
	d.Set("http_status_regex", string(*object.Http.StatusRegex))
	lastAssignedField = "rtsp_body_regex"
	d.Set("rtsp_body_regex", string(*object.Rtsp.BodyRegex))
	lastAssignedField = "rtsp_path"
	d.Set("rtsp_path", string(*object.Rtsp.Path))
	lastAssignedField = "rtsp_status_regex"
	d.Set("rtsp_status_regex", string(*object.Rtsp.StatusRegex))
	lastAssignedField = "script_arguments"
	scriptArguments := make([]map[string]interface{}, 0, len(*object.Script.Arguments))
	for _, item := range *object.Script.Arguments {
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
		scriptArguments = append(scriptArguments, itemTerraform)
	}
	d.Set("script_arguments", scriptArguments)
	scriptArgumentsJson, _ := json.Marshal(scriptArguments)
	d.Set("script_arguments_json", scriptArgumentsJson)
	lastAssignedField = "script_program"
	d.Set("script_program", string(*object.Script.Program))
	lastAssignedField = "sip_body_regex"
	d.Set("sip_body_regex", string(*object.Sip.BodyRegex))
	lastAssignedField = "sip_status_regex"
	d.Set("sip_status_regex", string(*object.Sip.StatusRegex))
	lastAssignedField = "sip_transport"
	d.Set("sip_transport", string(*object.Sip.Transport))
	lastAssignedField = "tcp_close_string"
	d.Set("tcp_close_string", string(*object.Tcp.CloseString))
	lastAssignedField = "tcp_max_response_len"
	d.Set("tcp_max_response_len", int(*object.Tcp.MaxResponseLen))
	lastAssignedField = "tcp_response_regex"
	d.Set("tcp_response_regex", string(*object.Tcp.ResponseRegex))
	lastAssignedField = "tcp_write_string"
	d.Set("tcp_write_string", string(*object.Tcp.WriteString))
	lastAssignedField = "udp_accept_all"
	d.Set("udp_accept_all", bool(*object.Udp.AcceptAll))
	d.SetId(objectName)
	return nil
}

func resourceMonitorExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetMonitor(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceMonitorCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewMonitor(objectName)
	resourceMonitorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_monitor '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceMonitorUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetMonitor(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_monitor '%v': %v", objectName, err)
	}
	resourceMonitorObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_monitor '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceMonitorObjectFieldAssignments(d *schema.ResourceData, object *vtm.Monitor) {
	setBool(&object.Basic.BackOff, d, "back_off")
	setInt(&object.Basic.Delay, d, "delay")
	setInt(&object.Basic.Failures, d, "failures")
	setBool(&object.Basic.HealthOnly, d, "health_only")
	setString(&object.Basic.Machine, d, "machine")
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Scope, d, "scope")
	setInt(&object.Basic.Timeout, d, "timeout")
	setString(&object.Basic.Type, d, "type")
	setBool(&object.Basic.UseSsl, d, "use_ssl")
	setBool(&object.Basic.Verbose, d, "verbose")
	setString(&object.Http.Authentication, d, "http_authentication")
	setString(&object.Http.BodyRegex, d, "http_body_regex")
	setString(&object.Http.HostHeader, d, "http_host_header")
	setString(&object.Http.Path, d, "http_path")
	setString(&object.Http.StatusRegex, d, "http_status_regex")
	setString(&object.Rtsp.BodyRegex, d, "rtsp_body_regex")
	setString(&object.Rtsp.Path, d, "rtsp_path")
	setString(&object.Rtsp.StatusRegex, d, "rtsp_status_regex")

	object.Script.Arguments = &vtm.MonitorArgumentsTable{}
	if scriptArgumentsJson, ok := d.GetOk("script_arguments_json"); ok {
		_ = json.Unmarshal([]byte(scriptArgumentsJson.(string)), object.Script.Arguments)
	} else if scriptArguments, ok := d.GetOk("script_arguments"); ok {
		for _, row := range scriptArguments.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.MonitorArguments{}
			VtmObject.Description = getStringAddr(itemTerraform["description"].(string))
			VtmObject.Name = getStringAddr(itemTerraform["name"].(string))
			VtmObject.Value = getStringAddr(itemTerraform["value"].(string))
			*object.Script.Arguments = append(*object.Script.Arguments, VtmObject)
		}
		d.Set("script_arguments", scriptArguments)
	} else {
		d.Set("script_arguments", make([]map[string]interface{}, 0, len(*object.Script.Arguments)))
	}
	setString(&object.Script.Program, d, "script_program")
	setString(&object.Sip.BodyRegex, d, "sip_body_regex")
	setString(&object.Sip.StatusRegex, d, "sip_status_regex")
	setString(&object.Sip.Transport, d, "sip_transport")
	setString(&object.Tcp.CloseString, d, "tcp_close_string")
	setInt(&object.Tcp.MaxResponseLen, d, "tcp_max_response_len")
	setString(&object.Tcp.ResponseRegex, d, "tcp_response_regex")
	setString(&object.Tcp.WriteString, d, "tcp_write_string")
	setBool(&object.Udp.AcceptAll, d, "udp_accept_all")
}

func resourceMonitorDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteMonitor(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_monitor '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
