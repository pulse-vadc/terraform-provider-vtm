// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type VirtualServerStatistics struct {
	Statistics struct {
		AuthSamlRedirects           *int    `json:"auth_saml_redirects"`
		AuthSamlRedirectsHi         *int    `json:"auth_saml_redirects_hi"`
		AuthSamlRedirectsLo         *int    `json:"auth_saml_redirects_lo"`
		AuthSamlResponses           *int    `json:"auth_saml_responses"`
		AuthSamlResponsesAccepted   *int    `json:"auth_saml_responses_accepted"`
		AuthSamlResponsesAcceptedHi *int    `json:"auth_saml_responses_accepted_hi"`
		AuthSamlResponsesAcceptedLo *int    `json:"auth_saml_responses_accepted_lo"`
		AuthSamlResponsesHi         *int    `json:"auth_saml_responses_hi"`
		AuthSamlResponsesLo         *int    `json:"auth_saml_responses_lo"`
		AuthSamlResponsesRejected   *int    `json:"auth_saml_responses_rejected"`
		AuthSamlResponsesRejectedHi *int    `json:"auth_saml_responses_rejected_hi"`
		AuthSamlResponsesRejectedLo *int    `json:"auth_saml_responses_rejected_lo"`
		AuthSessionsCreated         *int    `json:"auth_sessions_created"`
		AuthSessionsCreatedHi       *int    `json:"auth_sessions_created_hi"`
		AuthSessionsCreatedLo       *int    `json:"auth_sessions_created_lo"`
		AuthSessionsRejected        *int    `json:"auth_sessions_rejected"`
		AuthSessionsRejectedHi      *int    `json:"auth_sessions_rejected_hi"`
		AuthSessionsRejectedLo      *int    `json:"auth_sessions_rejected_lo"`
		AuthSessionsUsed            *int    `json:"auth_sessions_used"`
		AuthSessionsUsedHi          *int    `json:"auth_sessions_used_hi"`
		AuthSessionsUsedLo          *int    `json:"auth_sessions_used_lo"`
		BwLimitBytesDrop            *int    `json:"bw_limit_bytes_drop"`
		BwLimitBytesDropHi          *int    `json:"bw_limit_bytes_drop_hi"`
		BwLimitBytesDropLo          *int    `json:"bw_limit_bytes_drop_lo"`
		BwLimitPktsDrop             *int    `json:"bw_limit_pkts_drop"`
		BwLimitPktsDropHi           *int    `json:"bw_limit_pkts_drop_hi"`
		BwLimitPktsDropLo           *int    `json:"bw_limit_pkts_drop_lo"`
		BytesIn                     *int    `json:"bytes_in"`
		BytesInHi                   *int    `json:"bytes_in_hi"`
		BytesInLo                   *int    `json:"bytes_in_lo"`
		BytesOut                    *int    `json:"bytes_out"`
		BytesOutHi                  *int    `json:"bytes_out_hi"`
		BytesOutLo                  *int    `json:"bytes_out_lo"`
		CertStatusRequests          *int    `json:"cert_status_requests"`
		CertStatusResponses         *int    `json:"cert_status_responses"`
		ConnectTimedOut             *int    `json:"connect_timed_out"`
		ConnectionErrors            *int    `json:"connection_errors"`
		ConnectionFailures          *int    `json:"connection_failures"`
		CurrentConn                 *int    `json:"current_conn"`
		DataTimedOut                *int    `json:"data_timed_out"`
		DirectReplies               *int    `json:"direct_replies"`
		Discard                     *int    `json:"discard"`
		Gzip                        *int    `json:"gzip"`
		GzipBytesSaved              *int    `json:"gzip_bytes_saved"`
		GzipBytesSavedHi            *int    `json:"gzip_bytes_saved_hi"`
		GzipBytesSavedLo            *int    `json:"gzip_bytes_saved_lo"`
		HttpCacheHitRate            *int    `json:"http_cache_hit_rate"`
		HttpCacheHits               *int    `json:"http_cache_hits"`
		HttpCacheLookups            *int    `json:"http_cache_lookups"`
		HttpRewriteCookie           *int    `json:"http_rewrite_cookie"`
		HttpRewriteLocation         *int    `json:"http_rewrite_location"`
		KeepaliveTimedOut           *int    `json:"keepalive_timed_out"`
		MaxConn                     *int    `json:"max_conn"`
		MaxDurationTimedOut         *int    `json:"max_duration_timed_out"`
		PktsIn                      *int    `json:"pkts_in"`
		PktsInHi                    *int    `json:"pkts_in_hi"`
		PktsInLo                    *int    `json:"pkts_in_lo"`
		PktsOut                     *int    `json:"pkts_out"`
		PktsOutHi                   *int    `json:"pkts_out_hi"`
		PktsOutLo                   *int    `json:"pkts_out_lo"`
		Port                        *int    `json:"port"`
		ProcessingTimedOut          *int    `json:"processing_timed_out"`
		Protocol                    *string `json:"protocol"`
		SipRejectedRequests         *int    `json:"sip_rejected_requests"`
		SipTotalCalls               *int    `json:"sip_total_calls"`
		SslCacheLookup              *int    `json:"ssl_cache_lookup"`
		SslCacheLookupHi            *int    `json:"ssl_cache_lookup_hi"`
		SslCacheLookupLo            *int    `json:"ssl_cache_lookup_lo"`
		SslCacheMiss                *int    `json:"ssl_cache_miss"`
		SslCacheMissHi              *int    `json:"ssl_cache_miss_hi"`
		SslCacheMissLo              *int    `json:"ssl_cache_miss_lo"`
		SslCacheRejected            *int    `json:"ssl_cache_rejected"`
		SslCacheRejectedHi          *int    `json:"ssl_cache_rejected_hi"`
		SslCacheRejectedLo          *int    `json:"ssl_cache_rejected_lo"`
		SslCacheResumed             *int    `json:"ssl_cache_resumed"`
		SslCacheResumedHi           *int    `json:"ssl_cache_resumed_hi"`
		SslCacheResumedLo           *int    `json:"ssl_cache_resumed_lo"`
		SslCacheSaved               *int    `json:"ssl_cache_saved"`
		SslCacheSavedHi             *int    `json:"ssl_cache_saved_hi"`
		SslCacheSavedLo             *int    `json:"ssl_cache_saved_lo"`
		SslNewSession               *int    `json:"ssl_new_session"`
		SslNewSessionHi             *int    `json:"ssl_new_session_hi"`
		SslNewSessionLo             *int    `json:"ssl_new_session_lo"`
		SslTicketExpired            *int    `json:"ssl_ticket_expired"`
		SslTicketExpiredHi          *int    `json:"ssl_ticket_expired_hi"`
		SslTicketExpiredLo          *int    `json:"ssl_ticket_expired_lo"`
		SslTicketIssued             *int    `json:"ssl_ticket_issued"`
		SslTicketIssuedHi           *int    `json:"ssl_ticket_issued_hi"`
		SslTicketIssuedLo           *int    `json:"ssl_ticket_issued_lo"`
		SslTicketKeyNotFound        *int    `json:"ssl_ticket_key_not_found"`
		SslTicketKeyNotFoundHi      *int    `json:"ssl_ticket_key_not_found_hi"`
		SslTicketKeyNotFoundLo      *int    `json:"ssl_ticket_key_not_found_lo"`
		SslTicketReceived           *int    `json:"ssl_ticket_received"`
		SslTicketReceivedHi         *int    `json:"ssl_ticket_received_hi"`
		SslTicketReceivedLo         *int    `json:"ssl_ticket_received_lo"`
		SslTicketRejected           *int    `json:"ssl_ticket_rejected"`
		SslTicketRejectedHi         *int    `json:"ssl_ticket_rejected_hi"`
		SslTicketRejectedLo         *int    `json:"ssl_ticket_rejected_lo"`
		SslTicketResumed            *int    `json:"ssl_ticket_resumed"`
		SslTicketResumedHi          *int    `json:"ssl_ticket_resumed_hi"`
		SslTicketResumedLo          *int    `json:"ssl_ticket_resumed_lo"`
		TotalConn                   *int    `json:"total_conn"`
		TotalDgram                  *int    `json:"total_dgram"`
		TotalHttp1Requests          *int    `json:"total_http1_requests"`
		TotalHttp1RequestsHi        *int    `json:"total_http1_requests_hi"`
		TotalHttp1RequestsLo        *int    `json:"total_http1_requests_lo"`
		TotalHttp2Requests          *int    `json:"total_http2_requests"`
		TotalHttp2RequestsHi        *int    `json:"total_http2_requests_hi"`
		TotalHttp2RequestsLo        *int    `json:"total_http2_requests_lo"`
		TotalHttpRequests           *int    `json:"total_http_requests"`
		TotalHttpRequestsHi         *int    `json:"total_http_requests_hi"`
		TotalHttpRequestsLo         *int    `json:"total_http_requests_lo"`
		TotalRequests               *int    `json:"total_requests"`
		TotalRequestsHi             *int    `json:"total_requests_hi"`
		TotalRequestsLo             *int    `json:"total_requests_lo"`
		TotalTcpReset               *int    `json:"total_tcp_reset"`
		TotalUdpUnreachables        *int    `json:"total_udp_unreachables"`
		UdpTimedOut                 *int    `json:"udp_timed_out"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetVirtualServerStatistics(name string) (*VirtualServerStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/status/local_tm/statistics/virtual_servers/" + name)
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
