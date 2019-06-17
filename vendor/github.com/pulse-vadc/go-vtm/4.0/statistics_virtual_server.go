// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 4.0.
package vtm

import (
	"encoding/json"
)

type VirtualServerStatistics struct {
	Statistics struct {
		BwLimitBytesDrop     *int    `json:"bw_limit_bytes_drop"`
		BwLimitBytesDropHi   *int    `json:"bw_limit_bytes_drop_hi"`
		BwLimitBytesDropLo   *int    `json:"bw_limit_bytes_drop_lo"`
		BwLimitPktsDrop      *int    `json:"bw_limit_pkts_drop"`
		BwLimitPktsDropHi    *int    `json:"bw_limit_pkts_drop_hi"`
		BwLimitPktsDropLo    *int    `json:"bw_limit_pkts_drop_lo"`
		BytesIn              *int    `json:"bytes_in"`
		BytesInHi            *int    `json:"bytes_in_hi"`
		BytesInLo            *int    `json:"bytes_in_lo"`
		BytesOut             *int    `json:"bytes_out"`
		BytesOutHi           *int    `json:"bytes_out_hi"`
		BytesOutLo           *int    `json:"bytes_out_lo"`
		CertStatusRequests   *int    `json:"cert_status_requests"`
		CertStatusResponses  *int    `json:"cert_status_responses"`
		ConnectTimedOut      *int    `json:"connect_timed_out"`
		ConnectionErrors     *int    `json:"connection_errors"`
		ConnectionFailures   *int    `json:"connection_failures"`
		CurrentConn          *int    `json:"current_conn"`
		DataTimedOut         *int    `json:"data_timed_out"`
		DirectReplies        *int    `json:"direct_replies"`
		Discard              *int    `json:"discard"`
		Gzip                 *int    `json:"gzip"`
		GzipBytesSaved       *int    `json:"gzip_bytes_saved"`
		GzipBytesSavedHi     *int    `json:"gzip_bytes_saved_hi"`
		GzipBytesSavedLo     *int    `json:"gzip_bytes_saved_lo"`
		HttpCacheHitRate     *int    `json:"http_cache_hit_rate"`
		HttpCacheHits        *int    `json:"http_cache_hits"`
		HttpCacheLookups     *int    `json:"http_cache_lookups"`
		HttpRewriteCookie    *int    `json:"http_rewrite_cookie"`
		HttpRewriteLocation  *int    `json:"http_rewrite_location"`
		KeepaliveTimedOut    *int    `json:"keepalive_timed_out"`
		MaxConn              *int    `json:"max_conn"`
		MaxDurationTimedOut  *int    `json:"max_duration_timed_out"`
		PktsIn               *int    `json:"pkts_in"`
		PktsInHi             *int    `json:"pkts_in_hi"`
		PktsInLo             *int    `json:"pkts_in_lo"`
		PktsOut              *int    `json:"pkts_out"`
		PktsOutHi            *int    `json:"pkts_out_hi"`
		PktsOutLo            *int    `json:"pkts_out_lo"`
		Port                 *int    `json:"port"`
		ProcessingTimedOut   *int    `json:"processing_timed_out"`
		Protocol             *string `json:"protocol"`
		SipRejectedRequests  *int    `json:"sip_rejected_requests"`
		SipTotalCalls        *int    `json:"sip_total_calls"`
		TotalConn            *int    `json:"total_conn"`
		TotalDgram           *int    `json:"total_dgram"`
		TotalHttp1Requests   *int    `json:"total_http1_requests"`
		TotalHttp1RequestsHi *int    `json:"total_http1_requests_hi"`
		TotalHttp1RequestsLo *int    `json:"total_http1_requests_lo"`
		TotalHttp2Requests   *int    `json:"total_http2_requests"`
		TotalHttp2RequestsHi *int    `json:"total_http2_requests_hi"`
		TotalHttp2RequestsLo *int    `json:"total_http2_requests_lo"`
		TotalHttpRequests    *int    `json:"total_http_requests"`
		TotalHttpRequestsHi  *int    `json:"total_http_requests_hi"`
		TotalHttpRequestsLo  *int    `json:"total_http_requests_lo"`
		TotalRequests        *int    `json:"total_requests"`
		TotalRequestsHi      *int    `json:"total_requests_hi"`
		TotalRequestsLo      *int    `json:"total_requests_lo"`
		TotalTcpReset        *int    `json:"total_tcp_reset"`
		TotalUdpUnreachables *int    `json:"total_udp_unreachables"`
		UdpTimedOut          *int    `json:"udp_timed_out"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetVirtualServerStatistics(name string) (*VirtualServerStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/4.0/status/local_tm/statistics/virtual_servers/" + name)
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
