// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object TrafficIpsIpGateway
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func dataSourceTrafficIpsIpGatewayStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficIpsIpGatewayStatisticsRead,
		Schema: map[string]*schema.Schema{

			// Number of ARP messages sent for raised Traffic IP Addresses.
			"arp_message": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ping requests sent to the gateway machine.
			"gateway_ping_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ping responses received from the gateway machine.
			"gateway_ping_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ping requests sent to the backend nodes.
			"node_ping_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ping responses received from the backend nodes.
			"node_ping_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of traffic IP addresses on this system (includes IPv4
			//  and IPv6 addresses).
			"number_inet46": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of traffic IP addresses currently raised on this system
			//  (includes IPv4 and IPv6 addresses).
			"number_raised_inet46": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ping response errors.
			"ping_response_errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceTrafficIpsIpGatewayStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetTrafficIpsIpGatewayStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_ip_gateway: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "arp_message"
	d.Set("arp_message", int(*object.Statistics.ArpMessage))

	lastAssignedField = "gateway_ping_requests"
	d.Set("gateway_ping_requests", int(*object.Statistics.GatewayPingRequests))

	lastAssignedField = "gateway_ping_responses"
	d.Set("gateway_ping_responses", int(*object.Statistics.GatewayPingResponses))

	lastAssignedField = "node_ping_requests"
	d.Set("node_ping_requests", int(*object.Statistics.NodePingRequests))

	lastAssignedField = "node_ping_responses"
	d.Set("node_ping_responses", int(*object.Statistics.NodePingResponses))

	lastAssignedField = "number_inet46"
	d.Set("number_inet46", int(*object.Statistics.NumberInet46))

	lastAssignedField = "number_raised_inet46"
	d.Set("number_raised_inet46", int(*object.Statistics.NumberRaisedInet46))

	lastAssignedField = "ping_response_errors"
	d.Set("ping_response_errors", int(*object.Statistics.PingResponseErrors))
	d.SetId("ip_gateway")
	return nil
}
