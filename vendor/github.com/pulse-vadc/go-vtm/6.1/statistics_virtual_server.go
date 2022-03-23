// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type VirtualServerStatistics struct {
	Statistics struct {
		AuthSamlRedirects         *int    `json:"auth_saml_redirects"`
		AuthSamlResponses         *int    `json:"auth_saml_responses"`
		AuthSamlResponsesAccepted *int    `json:"auth_saml_responses_accepted"`
		AuthSamlResponsesRejected *int    `json:"auth_saml_responses_rejected"`
		AuthSessionsCreated       *int    `json:"auth_sessions_created"`
		AuthSessionsRejected      *int    `json:"auth_sessions_rejected"`
		AuthSessionsUsed          *int    `json:"auth_sessions_used"`
		BytesIn                   *int    `json:"bytes_in"`
		BytesOut                  *int    `json:"bytes_out"`
		CertStatusRequests        *int    `json:"cert_status_requests"`
		CertStatusResponses       *int    `json:"cert_status_responses"`
		ConnectTimedOut           *int    `json:"connect_timed_out"`
		ConnectionErrors          *int    `json:"connection_errors"`
		ConnectionFailures        *int    `json:"connection_failures"`
		CurrentConn               *int    `json:"current_conn"`
		DataTimedOut              *int    `json:"data_timed_out"`
		DirectReplies             *int    `json:"direct_replies"`
		Discard                   *int    `json:"discard"`
		Gzip                      *int    `json:"gzip"`
		GzipBytesSaved            *int    `json:"gzip_bytes_saved"`
		Http1XxResponses          *int    `json:"http1xx_responses"`
		Http2XxResponses          *int    `json:"http2xx_responses"`
		Http3XxResponses          *int    `json:"http3xx_responses"`
		Http4XxResponses          *int    `json:"http4xx_responses"`
		Http5XxResponses          *int    `json:"http5xx_responses"`
		HttpCache2XxResponses     *int    `json:"http_cache2xx_responses"`
		HttpCache3XxResponses     *int    `json:"http_cache3xx_responses"`
		HttpCache4XxResponses     *int    `json:"http_cache4xx_responses"`
		HttpCache5XxResponses     *int    `json:"http_cache5xx_responses"`
		HttpCacheHitRate          *int    `json:"http_cache_hit_rate"`
		HttpCacheHits             *int    `json:"http_cache_hits"`
		HttpCacheLookups          *int    `json:"http_cache_lookups"`
		HttpGenerated2XxResponses *int    `json:"http_generated2xx_responses"`
		HttpGenerated3XxResponses *int    `json:"http_generated3xx_responses"`
		HttpGenerated4XxResponses *int    `json:"http_generated4xx_responses"`
		HttpGenerated5XxResponses *int    `json:"http_generated5xx_responses"`
		HttpRewriteCookie         *int    `json:"http_rewrite_cookie"`
		HttpRewriteLocation       *int    `json:"http_rewrite_location"`
		HttpServer1XxResponses    *int    `json:"http_server1xx_responses"`
		HttpServer2XxResponses    *int    `json:"http_server2xx_responses"`
		HttpServer3XxResponses    *int    `json:"http_server3xx_responses"`
		HttpServer4XxResponses    *int    `json:"http_server4xx_responses"`
		HttpServer5XxResponses    *int    `json:"http_server5xx_responses"`
		KeepaliveTimedOut         *int    `json:"keepalive_timed_out"`
		MaxConn                   *int    `json:"max_conn"`
		MaxDurationTimedOut       *int    `json:"max_duration_timed_out"`
		Port                      *int    `json:"port"`
		ProcessingTimedOut        *int    `json:"processing_timed_out"`
		Protocol                  *string `json:"protocol"`
		SipRejectedRequests       *int    `json:"sip_rejected_requests"`
		SipTotalCalls             *int    `json:"sip_total_calls"`
		SslCacheLookup            *int    `json:"ssl_cache_lookup"`
		SslCacheMiss              *int    `json:"ssl_cache_miss"`
		SslCacheRejected          *int    `json:"ssl_cache_rejected"`
		SslCacheResumed           *int    `json:"ssl_cache_resumed"`
		SslCacheSaved             *int    `json:"ssl_cache_saved"`
		SslHelloRetryRequested    *int    `json:"ssl_hello_retry_requested"`
		SslNewSession             *int    `json:"ssl_new_session"`
		SslTicketExpired          *int    `json:"ssl_ticket_expired"`
		SslTicketIssued           *int    `json:"ssl_ticket_issued"`
		SslTicketKeyNotFound      *int    `json:"ssl_ticket_key_not_found"`
		SslTicketReceived         *int    `json:"ssl_ticket_received"`
		SslTicketRejected         *int    `json:"ssl_ticket_rejected"`
		SslTicketResumed          *int    `json:"ssl_ticket_resumed"`
		TotalDgram                *int    `json:"total_dgram"`
		TotalHttp1Requests        *int    `json:"total_http1_requests"`
		TotalHttp2Requests        *int    `json:"total_http2_requests"`
		TotalHttpRequests         *int    `json:"total_http_requests"`
		TotalRequests             *int    `json:"total_requests"`
		UdpTimedOut               *int    `json:"udp_timed_out"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetVirtualServerStatistics(name string) (*VirtualServerStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/status/local_tm/statistics/virtual_servers/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(VirtualServerStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
