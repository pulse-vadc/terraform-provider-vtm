// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceMonitor() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceMonitorRead,

		Schema: map[string]*schema.Schema{

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
		},
	}
}

func dataSourceMonitorRead(d *schema.ResourceData, tm interface{}) error {
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
	d.Set("back_off", bool(*object.Basic.BackOff))
	d.Set("delay", int(*object.Basic.Delay))
	d.Set("failures", int(*object.Basic.Failures))
	d.Set("health_only", bool(*object.Basic.HealthOnly))
	d.Set("machine", string(*object.Basic.Machine))
	d.Set("note", string(*object.Basic.Note))
	d.Set("scope", string(*object.Basic.Scope))
	d.Set("timeout", int(*object.Basic.Timeout))
	d.Set("type", string(*object.Basic.Type))
	d.Set("use_ssl", bool(*object.Basic.UseSsl))
	d.Set("verbose", bool(*object.Basic.Verbose))
	d.Set("http_authentication", string(*object.Http.Authentication))
	d.Set("http_body_regex", string(*object.Http.BodyRegex))
	d.Set("http_host_header", string(*object.Http.HostHeader))
	d.Set("http_path", string(*object.Http.Path))
	d.Set("http_status_regex", string(*object.Http.StatusRegex))
	d.Set("rtsp_body_regex", string(*object.Rtsp.BodyRegex))
	d.Set("rtsp_path", string(*object.Rtsp.Path))
	d.Set("rtsp_status_regex", string(*object.Rtsp.StatusRegex))

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
	d.Set("script_program", string(*object.Script.Program))
	d.Set("sip_body_regex", string(*object.Sip.BodyRegex))
	d.Set("sip_status_regex", string(*object.Sip.StatusRegex))
	d.Set("sip_transport", string(*object.Sip.Transport))
	d.Set("tcp_close_string", string(*object.Tcp.CloseString))
	d.Set("tcp_max_response_len", int(*object.Tcp.MaxResponseLen))
	d.Set("tcp_response_regex", string(*object.Tcp.ResponseRegex))
	d.Set("tcp_write_string", string(*object.Tcp.WriteString))
	d.Set("udp_accept_all", bool(*object.Udp.AcceptAll))

	d.SetId(objectName)
	return nil
}
