// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func dataSourceProtection() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceProtectionRead,

		Schema: map[string]*schema.Schema{

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
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Disallow access to these IP addresses.
			"access_restriction_banned": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Additional limit on maximum concurrent connections from the top
			//  10 busiest connecting IP addresses combined.  The value should
			//  be between 1 and 10 times the "max_1_connections" limit.   (This
			//  limit is disabled if "per_process_connection_count" is "No",
			//  or "max_1_connections" is "0", or "min_connections" is "0".)
			"concurrent_connections_max_10_connections": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      200,
			},

			// Maximum concurrent connections each connecting IP address is
			//  allowed. Set to "0" to disable this limit.
			"concurrent_connections_max_1_connections": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      30,
			},

			// Entry threshold for the "max_10_connections" limit: the "max_10_connections"
			//  limit is not applied to connecting IP addresses with this many
			//  or fewer concurrent connections.   Setting to "0" disables both
			//  the "max_1_connections" and "max_10_connections" limits, if "per_process_connection_count"
			//  is "Yes". (If "per_process_connection_count" is "No", this setting
			//  is ignored.)
			"concurrent_connections_min_connections": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      4,
			},

			// Whether concurrent connection counting and limits are per-process.
			//  (Each Traffic Manager typically has several processes: one process
			//  per available CPU core.)   If "Yes", a connecting IP address
			//  may make that many connections to each process within a Traffic
			//  Manager. If "No", a connecting IP address may make that many
			//  connections to each Traffic Manager as a whole.
			"concurrent_connections_per_process_connection_count": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Maximum number of new connections each connecting IP address
			//  is allowed to make in the "rate_timer" interval.  Set to "0"
			//  to disable this limit. If applied to an HTTP Virtual Server each
			//  request sent on a connection that is kept alive counts as a new
			//  connection.  The rate limit is per process: each process within
			//  a Traffic Manager accepts new connections from the connecting
			//  IP address at this rate. (Each Traffic Manager typically has
			//  several processes: one process per available CPU core).
			"connection_rate_max_connection_rate": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// How frequently the "max_connection_rate" is assessed. For example,
			//  a value of "1" (second) will impose a limit of "max_connection_rate"
			//  connections per second; a value of "60" will impose a limit of
			//  "max_connection_rate" connections per minute. The valid range
			//  is 1-99999 seconds.
			"connection_rate_rate_timer": &schema.Schema{
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
		},
	}
}

func dataSourceProtectionRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetProtection(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_protection '%v': %v", objectName, err.ErrorText)
	}
	d.Set("debug", bool(*object.Basic.Debug))
	d.Set("enabled", bool(*object.Basic.Enabled))
	d.Set("log_time", int(*object.Basic.LogTime))
	d.Set("note", string(*object.Basic.Note))
	d.Set("rule", string(*object.Basic.Rule))
	d.Set("testing", bool(*object.Basic.Testing))
	d.Set("access_restriction_allowed", []string(*object.AccessRestriction.Allowed))
	d.Set("access_restriction_banned", []string(*object.AccessRestriction.Banned))
	d.Set("concurrent_connections_max_10_connections", int(*object.ConcurrentConnections.Max10Connections))
	d.Set("concurrent_connections_max_1_connections", int(*object.ConcurrentConnections.Max1Connections))
	d.Set("concurrent_connections_min_connections", int(*object.ConcurrentConnections.MinConnections))
	d.Set("concurrent_connections_per_process_connection_count", bool(*object.ConcurrentConnections.PerProcessConnectionCount))
	d.Set("connection_rate_max_connection_rate", int(*object.ConnectionRate.MaxConnectionRate))
	d.Set("connection_rate_rate_timer", int(*object.ConnectionRate.RateTimer))
	d.Set("http_check_rfc2396", bool(*object.Http.CheckRfc2396))
	d.Set("http_max_body_length", int(*object.Http.MaxBodyLength))
	d.Set("http_max_header_length", int(*object.Http.MaxHeaderLength))
	d.Set("http_max_request_length", int(*object.Http.MaxRequestLength))
	d.Set("http_max_url_length", int(*object.Http.MaxUrlLength))
	d.Set("http_reject_binary", bool(*object.Http.RejectBinary))
	d.Set("http_send_error_page", bool(*object.Http.SendErrorPage))

	d.SetId(objectName)
	return nil
}
