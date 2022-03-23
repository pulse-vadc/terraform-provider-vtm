// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object VirtualServer
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/8.0"
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

			// Number of times a user agent was redirected to SAML Identity
			//  Provider.
			"auth_saml_redirects": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a SAML Response was processed.
			"auth_saml_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a SAML Response was accepted.
			"auth_saml_responses_accepted": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a SAML Response was rejected.
			"auth_saml_responses_rejected": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times an authentication session was created.
			"auth_sessions_created": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times an authentication session was rejected.
			"auth_sessions_rejected": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times an authentication session was used.
			"auth_sessions_used": &schema.Schema{
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

			// Number of HTTP 1xx responses returned by this virtual server.
			"http1xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 2xx responses returned by this virtual server.
			"http2xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 3xx responses returned by this virtual server.
			"http3xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 4xx responses returned by this virtual server.
			"http4xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 5xx responses returned by this virtual server.
			"http5xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 2xx responses returned from webcache by this virtual
			//  server.
			"http_cache2xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 3xx responses returned from webcache by this virtual
			//  server.
			"http_cache3xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 4xx responses returned from webcache by this virtual
			//  server.
			"http_cache4xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 5xx responses returned from webcache by this virtual
			//  server.
			"http_cache5xx_responses": &schema.Schema{
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

			// Number of HTTP 2xx responses generated by this virtual server.
			"http_generated2xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 3xx responses generated by this virtual server.
			"http_generated3xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 4xx responses generated by this virtual server.
			"http_generated4xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 5xx responses generated by this virtual server.
			"http_generated5xx_responses": &schema.Schema{
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

			// Number of HTTP 1xx responses returned from a backend server or
			//  TrafficScript rule by this virtual server.
			"http_server1xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 2xx responses returned from a backend server or
			//  TrafficScript rule by this virtual server.
			"http_server2xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 3xx responses returned from a backend server or
			//  TrafficScript rule by this virtual server.
			"http_server3xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 4xx responses returned from a backend server or
			//  TrafficScript rule by this virtual server.
			"http_server4xx_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of HTTP 5xx responses returned from a backend server or
			//  TrafficScript rule by this virtual server.
			"http_server5xx_responses": &schema.Schema{
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

			// Number of times a lookup for an existing SSL session was performed.
			"ssl_cache_lookup": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a lookup failed to find an existing SSL session.
			"ssl_cache_miss": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times an SSL session was found in the cache but rejected
			//  and not resumed.
			"ssl_cache_rejected": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times an SSL session was resumed from the cache.
			"ssl_cache_resumed": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times an SSL session was saved to the cache.
			"ssl_cache_saved": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a HelloRetryRequest message was sent to TLS clients.
			"ssl_hello_retry_requested": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a new SSL session was created.
			"ssl_new_session": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL session tickets that were rejected because they
			//  had expired.
			"ssl_ticket_expired": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL session tickets that were issued to clients.
			"ssl_ticket_issued": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL session tickets that could not be decrypted because
			//  the ticket key they referenced could not be found.
			"ssl_ticket_key_not_found": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL session tickets received.
			"ssl_ticket_received": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL session tickets that were rejected for a reason
			//  other than because they had expired.
			"ssl_ticket_rejected": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL session tickets that were successfully used to
			//  resume a session.
			"ssl_ticket_resumed": &schema.Schema{
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

			// Connections closed by this virtual server because the 'udp_timeout'
			//  interval was exceeded.
			"udp_timed_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceVirtualServerStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetVirtualServerStatistics(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_virtual_servers '%v': %v", objectName, err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "auth_saml_redirects"
	d.Set("auth_saml_redirects", int(*object.Statistics.AuthSamlRedirects))

	lastAssignedField = "auth_saml_responses"
	d.Set("auth_saml_responses", int(*object.Statistics.AuthSamlResponses))

	lastAssignedField = "auth_saml_responses_accepted"
	d.Set("auth_saml_responses_accepted", int(*object.Statistics.AuthSamlResponsesAccepted))

	lastAssignedField = "auth_saml_responses_rejected"
	d.Set("auth_saml_responses_rejected", int(*object.Statistics.AuthSamlResponsesRejected))

	lastAssignedField = "auth_sessions_created"
	d.Set("auth_sessions_created", int(*object.Statistics.AuthSessionsCreated))

	lastAssignedField = "auth_sessions_rejected"
	d.Set("auth_sessions_rejected", int(*object.Statistics.AuthSessionsRejected))

	lastAssignedField = "auth_sessions_used"
	d.Set("auth_sessions_used", int(*object.Statistics.AuthSessionsUsed))

	lastAssignedField = "bytes_in"
	d.Set("bytes_in", int(*object.Statistics.BytesIn))

	lastAssignedField = "bytes_out"
	d.Set("bytes_out", int(*object.Statistics.BytesOut))

	lastAssignedField = "cert_status_requests"
	d.Set("cert_status_requests", int(*object.Statistics.CertStatusRequests))

	lastAssignedField = "cert_status_responses"
	d.Set("cert_status_responses", int(*object.Statistics.CertStatusResponses))

	lastAssignedField = "connect_timed_out"
	d.Set("connect_timed_out", int(*object.Statistics.ConnectTimedOut))

	lastAssignedField = "connection_errors"
	d.Set("connection_errors", int(*object.Statistics.ConnectionErrors))

	lastAssignedField = "connection_failures"
	d.Set("connection_failures", int(*object.Statistics.ConnectionFailures))

	lastAssignedField = "current_conn"
	d.Set("current_conn", int(*object.Statistics.CurrentConn))

	lastAssignedField = "data_timed_out"
	d.Set("data_timed_out", int(*object.Statistics.DataTimedOut))

	lastAssignedField = "direct_replies"
	d.Set("direct_replies", int(*object.Statistics.DirectReplies))

	lastAssignedField = "discard"
	d.Set("discard", int(*object.Statistics.Discard))

	lastAssignedField = "gzip"
	d.Set("gzip", int(*object.Statistics.Gzip))

	lastAssignedField = "gzip_bytes_saved"
	d.Set("gzip_bytes_saved", int(*object.Statistics.GzipBytesSaved))

	lastAssignedField = "http1xx_responses"
	d.Set("http1xx_responses", int(*object.Statistics.Http1XxResponses))

	lastAssignedField = "http2xx_responses"
	d.Set("http2xx_responses", int(*object.Statistics.Http2XxResponses))

	lastAssignedField = "http3xx_responses"
	d.Set("http3xx_responses", int(*object.Statistics.Http3XxResponses))

	lastAssignedField = "http4xx_responses"
	d.Set("http4xx_responses", int(*object.Statistics.Http4XxResponses))

	lastAssignedField = "http5xx_responses"
	d.Set("http5xx_responses", int(*object.Statistics.Http5XxResponses))

	lastAssignedField = "http_cache2xx_responses"
	d.Set("http_cache2xx_responses", int(*object.Statistics.HttpCache2XxResponses))

	lastAssignedField = "http_cache3xx_responses"
	d.Set("http_cache3xx_responses", int(*object.Statistics.HttpCache3XxResponses))

	lastAssignedField = "http_cache4xx_responses"
	d.Set("http_cache4xx_responses", int(*object.Statistics.HttpCache4XxResponses))

	lastAssignedField = "http_cache5xx_responses"
	d.Set("http_cache5xx_responses", int(*object.Statistics.HttpCache5XxResponses))

	lastAssignedField = "http_cache_hit_rate"
	d.Set("http_cache_hit_rate", int(*object.Statistics.HttpCacheHitRate))

	lastAssignedField = "http_cache_hits"
	d.Set("http_cache_hits", int(*object.Statistics.HttpCacheHits))

	lastAssignedField = "http_cache_lookups"
	d.Set("http_cache_lookups", int(*object.Statistics.HttpCacheLookups))

	lastAssignedField = "http_generated2xx_responses"
	d.Set("http_generated2xx_responses", int(*object.Statistics.HttpGenerated2XxResponses))

	lastAssignedField = "http_generated3xx_responses"
	d.Set("http_generated3xx_responses", int(*object.Statistics.HttpGenerated3XxResponses))

	lastAssignedField = "http_generated4xx_responses"
	d.Set("http_generated4xx_responses", int(*object.Statistics.HttpGenerated4XxResponses))

	lastAssignedField = "http_generated5xx_responses"
	d.Set("http_generated5xx_responses", int(*object.Statistics.HttpGenerated5XxResponses))

	lastAssignedField = "http_rewrite_cookie"
	d.Set("http_rewrite_cookie", int(*object.Statistics.HttpRewriteCookie))

	lastAssignedField = "http_rewrite_location"
	d.Set("http_rewrite_location", int(*object.Statistics.HttpRewriteLocation))

	lastAssignedField = "http_server1xx_responses"
	d.Set("http_server1xx_responses", int(*object.Statistics.HttpServer1XxResponses))

	lastAssignedField = "http_server2xx_responses"
	d.Set("http_server2xx_responses", int(*object.Statistics.HttpServer2XxResponses))

	lastAssignedField = "http_server3xx_responses"
	d.Set("http_server3xx_responses", int(*object.Statistics.HttpServer3XxResponses))

	lastAssignedField = "http_server4xx_responses"
	d.Set("http_server4xx_responses", int(*object.Statistics.HttpServer4XxResponses))

	lastAssignedField = "http_server5xx_responses"
	d.Set("http_server5xx_responses", int(*object.Statistics.HttpServer5XxResponses))

	lastAssignedField = "keepalive_timed_out"
	d.Set("keepalive_timed_out", int(*object.Statistics.KeepaliveTimedOut))

	lastAssignedField = "max_conn"
	d.Set("max_conn", int(*object.Statistics.MaxConn))

	lastAssignedField = "max_duration_timed_out"
	d.Set("max_duration_timed_out", int(*object.Statistics.MaxDurationTimedOut))

	lastAssignedField = "port"
	d.Set("port", int(*object.Statistics.Port))

	lastAssignedField = "processing_timed_out"
	d.Set("processing_timed_out", int(*object.Statistics.ProcessingTimedOut))

	lastAssignedField = "protocol"
	d.Set("protocol", string(*object.Statistics.Protocol))

	lastAssignedField = "sip_rejected_requests"
	d.Set("sip_rejected_requests", int(*object.Statistics.SipRejectedRequests))

	lastAssignedField = "sip_total_calls"
	d.Set("sip_total_calls", int(*object.Statistics.SipTotalCalls))

	lastAssignedField = "ssl_cache_lookup"
	d.Set("ssl_cache_lookup", int(*object.Statistics.SslCacheLookup))

	lastAssignedField = "ssl_cache_miss"
	d.Set("ssl_cache_miss", int(*object.Statistics.SslCacheMiss))

	lastAssignedField = "ssl_cache_rejected"
	d.Set("ssl_cache_rejected", int(*object.Statistics.SslCacheRejected))

	lastAssignedField = "ssl_cache_resumed"
	d.Set("ssl_cache_resumed", int(*object.Statistics.SslCacheResumed))

	lastAssignedField = "ssl_cache_saved"
	d.Set("ssl_cache_saved", int(*object.Statistics.SslCacheSaved))

	lastAssignedField = "ssl_hello_retry_requested"
	d.Set("ssl_hello_retry_requested", int(*object.Statistics.SslHelloRetryRequested))

	lastAssignedField = "ssl_new_session"
	d.Set("ssl_new_session", int(*object.Statistics.SslNewSession))

	lastAssignedField = "ssl_ticket_expired"
	d.Set("ssl_ticket_expired", int(*object.Statistics.SslTicketExpired))

	lastAssignedField = "ssl_ticket_issued"
	d.Set("ssl_ticket_issued", int(*object.Statistics.SslTicketIssued))

	lastAssignedField = "ssl_ticket_key_not_found"
	d.Set("ssl_ticket_key_not_found", int(*object.Statistics.SslTicketKeyNotFound))

	lastAssignedField = "ssl_ticket_received"
	d.Set("ssl_ticket_received", int(*object.Statistics.SslTicketReceived))

	lastAssignedField = "ssl_ticket_rejected"
	d.Set("ssl_ticket_rejected", int(*object.Statistics.SslTicketRejected))

	lastAssignedField = "ssl_ticket_resumed"
	d.Set("ssl_ticket_resumed", int(*object.Statistics.SslTicketResumed))

	lastAssignedField = "total_dgram"
	d.Set("total_dgram", int(*object.Statistics.TotalDgram))

	lastAssignedField = "total_http1_requests"
	d.Set("total_http1_requests", int(*object.Statistics.TotalHttp1Requests))

	lastAssignedField = "total_http2_requests"
	d.Set("total_http2_requests", int(*object.Statistics.TotalHttp2Requests))

	lastAssignedField = "total_http_requests"
	d.Set("total_http_requests", int(*object.Statistics.TotalHttpRequests))

	lastAssignedField = "total_requests"
	d.Set("total_requests", int(*object.Statistics.TotalRequests))

	lastAssignedField = "udp_timed_out"
	d.Set("udp_timed_out", int(*object.Statistics.UdpTimedOut))
	d.SetId(objectName)
	return nil
}
