// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object VirtualServer
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceVirtualServerStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVirtualServerStatisticsRead,
		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Number of bytes dropped by this virtual server due to BW Limits.
			"bw_limit_bytes_drop": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of packets dropped by this virtual server due to BW Limits.
			"bw_limit_pkts_drop": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes received by this virtual server from clients.
			"bytes_in": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes sent by this virtual server to clients.
			"bytes_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of incoming TLS handshakes for this virtual server with
			//  certificate status requests.
			"cert_status_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of incoming TLS handshakes for this virtual server to
			//  which certificate status responses were attached.
			"cert_status_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections closed by this virtual server because the 'connect_timeout'
			//  interval was exceeded.
			"connect_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of transaction or protocol errors in this virtual server.
			"connection_errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of connection failures in this virtual server.
			"connection_failures": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// TCP connections currently established to this virtual server.
			"current_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections closed by this virtual server because the 'timeout'
			//  interval was exceeded.
			"data_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Direct replies from this virtual server, without forwarding to
			//  a node.
			"direct_replies": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections discarded by this virtual server.
			"discard": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Responses which have been compressed by content compression.
			"gzip": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes of network traffic saved by content compression.
			"gzip_bytes_saved": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Percentage hit rate of the web cache for this virtual server.
			"http_cache_hit_rate": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP responses sent directly from the web cache by this virtual
			//  server.
			"http_cache_hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP requests that are looked up in the web cache by this virtual
			//  server.
			"http_cache_lookups": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP Set-Cookie headers, supplied by a node, that have been rewritten.
			"http_rewrite_cookie": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP Location headers, supplied by a node, that have been rewritten.
			"http_rewrite_location": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections closed by this virtual server because the 'keepalive_timeout'
			//  interval was exceeded.
			"keepalive_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Maximum number of simultaneous TCP connections this virtual server
			//  has processed at any one time.
			"max_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections closed by this virtual server because the 'max_transaction_duration'
			//  interval was exceeded.
			"max_duration_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Packets received by this virtual server from clients.
			"pkts_in": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Packets sent by this virtual server to clients.
			"pkts_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The port the virtual server listens on.
			"port": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections closed by this virtual server because the 'timeout'
			//  interval was exceeded while waiting for rules or external processing.
			"processing_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The protocol the virtual server is operating.
			"protocol": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Number of SIP requests rejected due to them exceeding the maximum
			//  amount of memory allocated to the connection.
			"sip_rejected_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of SIP INVITE requests seen by this virtual server.
			"sip_total_calls": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// UDP datagrams processed by this virtual server.
			"total_dgram": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP/1.x Requests received by this virtual server.
			"total_http1_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP/2 Requests received by this virtual server.
			"total_http2_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// HTTP Requests received by this virtual server.
			"total_http_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests received by this virtual server.
			"total_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of TCP connections reset by this virtual server because
			//  the forward traffic cannot be processed.
			"total_tcp_reset": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ICMP error responses sent to the client by this virtual
			//  server because the forward traffic cannot be processed.
			"total_udp_unreachables": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Connections closed by this virtual server because the 'udp_timeout'
			//  interval was exceeded.
			"udp_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceVirtualServerStatisticsRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetVirtualServerStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_virtual_servers '%v': %v", objectName, err.ErrorText)
	}
	d.Set("bw_limit_bytes_drop", int(*object.Statistics.BwLimitBytesDrop))
	d.Set("bw_limit_pkts_drop", int(*object.Statistics.BwLimitPktsDrop))
	d.Set("bytes_in", int(*object.Statistics.BytesIn))
	d.Set("bytes_out", int(*object.Statistics.BytesOut))
	d.Set("cert_status_requests", int(*object.Statistics.CertStatusRequests))
	d.Set("cert_status_responses", int(*object.Statistics.CertStatusResponses))
	d.Set("connect_timed_out", int(*object.Statistics.ConnectTimedOut))
	d.Set("connection_errors", int(*object.Statistics.ConnectionErrors))
	d.Set("connection_failures", int(*object.Statistics.ConnectionFailures))
	d.Set("current_conn", int(*object.Statistics.CurrentConn))
	d.Set("data_timed_out", int(*object.Statistics.DataTimedOut))
	d.Set("direct_replies", int(*object.Statistics.DirectReplies))
	d.Set("discard", int(*object.Statistics.Discard))
	d.Set("gzip", int(*object.Statistics.Gzip))
	d.Set("gzip_bytes_saved", int(*object.Statistics.GzipBytesSaved))
	d.Set("http_cache_hit_rate", int(*object.Statistics.HttpCacheHitRate))
	d.Set("http_cache_hits", int(*object.Statistics.HttpCacheHits))
	d.Set("http_cache_lookups", int(*object.Statistics.HttpCacheLookups))
	d.Set("http_rewrite_cookie", int(*object.Statistics.HttpRewriteCookie))
	d.Set("http_rewrite_location", int(*object.Statistics.HttpRewriteLocation))
	d.Set("keepalive_timed_out", int(*object.Statistics.KeepaliveTimedOut))
	d.Set("max_conn", int(*object.Statistics.MaxConn))
	d.Set("max_duration_timed_out", int(*object.Statistics.MaxDurationTimedOut))
	d.Set("pkts_in", int(*object.Statistics.PktsIn))
	d.Set("pkts_out", int(*object.Statistics.PktsOut))
	d.Set("port", int(*object.Statistics.Port))
	d.Set("processing_timed_out", int(*object.Statistics.ProcessingTimedOut))
	d.Set("protocol", string(*object.Statistics.Protocol))
	d.Set("sip_rejected_requests", int(*object.Statistics.SipRejectedRequests))
	d.Set("sip_total_calls", int(*object.Statistics.SipTotalCalls))
	d.Set("total_dgram", int(*object.Statistics.TotalDgram))
	d.Set("total_http1_requests", int(*object.Statistics.TotalHttp1Requests))
	d.Set("total_http2_requests", int(*object.Statistics.TotalHttp2Requests))
	d.Set("total_http_requests", int(*object.Statistics.TotalHttpRequests))
	d.Set("total_requests", int(*object.Statistics.TotalRequests))
	d.Set("total_tcp_reset", int(*object.Statistics.TotalTcpReset))
	d.Set("total_udp_unreachables", int(*object.Statistics.TotalUdpUnreachables))
	d.Set("udp_timed_out", int(*object.Statistics.UdpTimedOut))
	d.SetId(objectName)
	return nil
}
