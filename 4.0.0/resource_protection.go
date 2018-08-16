// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func resourceProtection() *schema.Resource {
	return &schema.Resource{
		Read:   resourceProtectionRead,
		Exists: resourceProtectionExists,
		Create: resourceProtectionCreate,
		Update: resourceProtectionUpdate,
		Delete: resourceProtectionDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceProtectionSchema(),
	}
}

func getResourceProtectionSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// Whether or not to output verbose logging.
		"debug": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Enable or disable this service protection class.
		"enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Log service protection messages at these intervals. If set to
		//  "0" no messages will be logged and no alerts will be sent.
		"log_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      60,
		},

		// A description of the service protection class.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether simultaneous connection counting and limits are per-process.
		//  (Each Traffic Manager typically has several processes: one process
		//  per available CPU core.)   If "Yes", a connecting IP address
		//  may make that many connections to each process within a Traffic
		//  Manager. If "No", a connecting IP address may make that many
		//  connections to each Traffic Manager as a whole.
		"per_process_connection_count": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// A TrafficScript rule that will be run on the connection after
		//  the service protection criteria have been evaluated.  This rule
		//  will be executed prior to normal rules configured for the virtual
		//  server.
		"rule": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Place the service protection class into testing mode. (Log when
		//  this class would have dropped a connection, but allow all connections
		//  through).
		"testing": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Always allow access to these IP addresses. This overrides the
		//  connection limits for these machines, but does not stop other
		//  restrictions such as HTTP validity checks.
		"access_restriction_allowed": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Disallow access to these IP addresses.
		"access_restriction_banned": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Additional limit on maximum simultaneous connections from the
		//  top 10 busiest connecting IP addresses combined.  The value should
		//  be between 1 and 10 times the "max_1_connections" limit.   (This
		//  limit is disabled if "per_process_connection_count" is "No",
		//  or "max_1_connections" is "0", or "min_connections" is "0".)
		"connection_limiting_max_10_connections": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      200,
		},

		// Maximum simultaneous connections each connecting IP address is
		//  allowed. Set to "0" to disable this limit.
		"connection_limiting_max_1_connections": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      30,
		},

		// Maximum number of new connections each connecting IP address
		//  is allowed to make in the "rate_timer" interval.  Set to "0"
		//  to disable this limit. If applied to an HTTP Virtual Server each
		//  request sent on a connection that is kept alive counts as a new
		//  connection.  The rate limit is per process: each process within
		//  a Traffic Manager accepts new connections from the connecting
		//  IP address at this rate. (Each Traffic Manager typically has
		//  several processes: one process per available CPU core).
		"connection_limiting_max_connection_rate": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// Entry threshold for the "max_10_connections" limit: the "max_10_connections"
		//  limit is not applied to connecting IP addresses with this many
		//  or fewer simultaneous connections.   Setting to "0" disables
		//  both the "max_1_connections" and "max_10_connections" limits,
		//  if "per_process_connection_count" is "Yes". (If "per_process_connection_count"
		//  is "No", this setting is ignored.)
		"connection_limiting_min_connections": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      4,
		},

		// How frequently the "max_connection_rate" is assessed. For example,
		//  a value of "1" (second) will impose a limit of "max_connection_rate"
		//  connections per second; a value of "60" will impose a limit of
		//  "max_connection_rate" connections per minute. The valid range
		//  is 1-99999 seconds.
		"connection_limiting_rate_timer": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 99999),
			Default:      60,
		},

		// Whether or not requests with poorly-formed URLs be should be
		//  rejected. This tests URL compliance as defined in RFC2396.  Note
		//  that enabling this may block some older, non-conforming web browsers.
		"http_check_rfc2396": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Maximum permitted length of HTTP request body data, set to "0"
		//  to disable the limit.
		"http_max_body_length": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// Maximum permitted length of a single HTTP request header (key
		//  and value), set to "0" to disable the limit.
		"http_max_header_length": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// Maximum permitted size of all the HTTP request headers, set to
		//  "0" to disable the limit.
		"http_max_request_length": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// Maximum permitted URL length, set to "0" to disable the limit.
		"http_max_url_length": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// Whether or not URLs and HTTP request headers that contain binary
		//  data (after decoding) should be rejected.
		"http_reject_binary": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// This setting tells the traffic manager to send an HTTP error
		//  message if a connection fails the service protection tests, instead
		//  of just dropping it. Details of which HTTP response will be sent
		//  when particular tests fail can be found in the Help section for
		//  this page.
		"http_send_error_page": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},
	}
}

func resourceProtectionRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetProtection(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_protection '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "debug"
	d.Set("debug", bool(*object.Basic.Debug))
	lastAssignedField = "enabled"
	d.Set("enabled", bool(*object.Basic.Enabled))
	lastAssignedField = "log_time"
	d.Set("log_time", int(*object.Basic.LogTime))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "per_process_connection_count"
	d.Set("per_process_connection_count", bool(*object.Basic.PerProcessConnectionCount))
	lastAssignedField = "rule"
	d.Set("rule", string(*object.Basic.Rule))
	lastAssignedField = "testing"
	d.Set("testing", bool(*object.Basic.Testing))
	lastAssignedField = "access_restriction_allowed"
	d.Set("access_restriction_allowed", []string(*object.AccessRestriction.Allowed))
	lastAssignedField = "access_restriction_banned"
	d.Set("access_restriction_banned", []string(*object.AccessRestriction.Banned))
	lastAssignedField = "connection_limiting_max_10_connections"
	d.Set("connection_limiting_max_10_connections", int(*object.ConnectionLimiting.Max10Connections))
	lastAssignedField = "connection_limiting_max_1_connections"
	d.Set("connection_limiting_max_1_connections", int(*object.ConnectionLimiting.Max1Connections))
	lastAssignedField = "connection_limiting_max_connection_rate"
	d.Set("connection_limiting_max_connection_rate", int(*object.ConnectionLimiting.MaxConnectionRate))
	lastAssignedField = "connection_limiting_min_connections"
	d.Set("connection_limiting_min_connections", int(*object.ConnectionLimiting.MinConnections))
	lastAssignedField = "connection_limiting_rate_timer"
	d.Set("connection_limiting_rate_timer", int(*object.ConnectionLimiting.RateTimer))
	lastAssignedField = "http_check_rfc2396"
	d.Set("http_check_rfc2396", bool(*object.Http.CheckRfc2396))
	lastAssignedField = "http_max_body_length"
	d.Set("http_max_body_length", int(*object.Http.MaxBodyLength))
	lastAssignedField = "http_max_header_length"
	d.Set("http_max_header_length", int(*object.Http.MaxHeaderLength))
	lastAssignedField = "http_max_request_length"
	d.Set("http_max_request_length", int(*object.Http.MaxRequestLength))
	lastAssignedField = "http_max_url_length"
	d.Set("http_max_url_length", int(*object.Http.MaxUrlLength))
	lastAssignedField = "http_reject_binary"
	d.Set("http_reject_binary", bool(*object.Http.RejectBinary))
	lastAssignedField = "http_send_error_page"
	d.Set("http_send_error_page", bool(*object.Http.SendErrorPage))
	d.SetId(objectName)
	return nil
}

func resourceProtectionExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetProtection(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceProtectionCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewProtection(objectName)
	resourceProtectionObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_protection '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceProtectionUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetProtection(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_protection '%v': %v", objectName, err)
	}
	resourceProtectionObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_protection '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceProtectionObjectFieldAssignments(d *schema.ResourceData, object *vtm.Protection) {
	setBool(&object.Basic.Debug, d, "debug")
	setBool(&object.Basic.Enabled, d, "enabled")
	setInt(&object.Basic.LogTime, d, "log_time")
	setString(&object.Basic.Note, d, "note")
	setBool(&object.Basic.PerProcessConnectionCount, d, "per_process_connection_count")
	setString(&object.Basic.Rule, d, "rule")
	setBool(&object.Basic.Testing, d, "testing")

	if _, ok := d.GetOk("access_restriction_allowed"); ok {
		setStringSet(&object.AccessRestriction.Allowed, d, "access_restriction_allowed")
	} else {
		object.AccessRestriction.Allowed = &[]string{}
		d.Set("access_restriction_allowed", []string(*object.AccessRestriction.Allowed))
	}

	if _, ok := d.GetOk("access_restriction_banned"); ok {
		setStringSet(&object.AccessRestriction.Banned, d, "access_restriction_banned")
	} else {
		object.AccessRestriction.Banned = &[]string{}
		d.Set("access_restriction_banned", []string(*object.AccessRestriction.Banned))
	}
	setInt(&object.ConnectionLimiting.Max10Connections, d, "connection_limiting_max_10_connections")
	setInt(&object.ConnectionLimiting.Max1Connections, d, "connection_limiting_max_1_connections")
	setInt(&object.ConnectionLimiting.MaxConnectionRate, d, "connection_limiting_max_connection_rate")
	setInt(&object.ConnectionLimiting.MinConnections, d, "connection_limiting_min_connections")
	setInt(&object.ConnectionLimiting.RateTimer, d, "connection_limiting_rate_timer")
	setBool(&object.Http.CheckRfc2396, d, "http_check_rfc2396")
	setInt(&object.Http.MaxBodyLength, d, "http_max_body_length")
	setInt(&object.Http.MaxHeaderLength, d, "http_max_header_length")
	setInt(&object.Http.MaxRequestLength, d, "http_max_request_length")
	setInt(&object.Http.MaxUrlLength, d, "http_max_url_length")
	setBool(&object.Http.RejectBinary, d, "http_reject_binary")
	setBool(&object.Http.SendErrorPage, d, "http_send_error_page")
}

func resourceProtectionDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteProtection(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_protection '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
