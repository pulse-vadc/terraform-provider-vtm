// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Data Source Object Globals
package main

import (
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
)

func dataSourceGlobalsStatistics() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceGlobalsStatisticsRead,
		Schema: map[string]*schema.Schema{

			// Count of transaction metadata records that have been dropped
			"analytics_transactions_dropped": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Count of transaction metadata records that have been exported
			"analytics_transactions_exported": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of bytes queued in the transaction export transmit buffers.
			"analytics_transactions_memory_usage": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of entries in the TrafficScript data.get()/set() storage.
			"data_entries": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of bytes used in the TrafficScript data.get()/set() storage.
			"data_memory_usage": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Events seen by the traffic Manager's event handling process.
			"events_seen": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The peak bytes received from clients per second in the last hour.
			"hourly_peak_bytes_in_per_second": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The peak bytes sent to clients per second in the last hour.
			"hourly_peak_bytes_out_per_second": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The peak requests per second in the last hour.
			"hourly_peak_requests_per_second": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The peak ssl connections per second in the last hour.
			"hourly_peak_ssl_connections_per_second": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of idle HTTP connections to all nodes (used for
			//  future HTTP requests).
			"num_idle_connections": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The number of traffic manager child processes.
			"number_child_processes": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests for DNS A records resolved from the traffic manager's
			//  local cache.
			"number_dnsa_cache_hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests for DNS A records (hostname->IP address) made by the
			//  traffic manager.
			"number_dnsa_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests for DNS PTR records resolved from the traffic manager's
			//  local cache.
			"number_dnsptr_cache_hits": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Requests for DNS PTR records (IP address->hostname) made by the
			//  traffic manager.
			"number_dnsptr_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Malformed SNMP requests received.
			"number_snmp_bad_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// SNMP GetBulkRequests received.
			"number_snmp_get_bulk_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// SNMP GetNextRequests received.
			"number_snmp_get_next_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// SNMP GetRequests received.
			"number_snmp_get_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// SNMP requests dropped due to access restrictions.
			"number_snmp_unauthorised_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes decrypted with 3DES.
			"ssl_cipher_3des_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes encrypted with 3DES.
			"ssl_cipher_3des_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes decrypted with AES.
			"ssl_cipher_aes_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes encrypted with AES.
			"ssl_cipher_aes_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes decrypted with AES-GCM.
			"ssl_cipher_aes_gcm_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes encrypted with AES-GCM.
			"ssl_cipher_aes_gcm_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes decrypted with a symmetric cipher.
			"ssl_cipher_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes decrypted with DES.
			"ssl_cipher_des_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes encrypted with DES.
			"ssl_cipher_des_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of Diffie Hellman key agreements.
			"ssl_cipher_dh_agreements": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of Diffie Hellman keys generated.
			"ssl_cipher_dh_generates": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of DSA signing operations.
			"ssl_cipher_dsa_signs": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of DSA verifications.
			"ssl_cipher_dsa_verifies": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of Elliptic Curve Diffie Hellman key agreements.
			"ssl_cipher_ecdh_agreements": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of Elliptic Curve Diffie Hellman keys generated.
			"ssl_cipher_ecdh_generates": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ECDSA signing operations.
			"ssl_cipher_ecdsa_signs": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of ECDSA verifications.
			"ssl_cipher_ecdsa_verifies": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes encrypted with a symmetric cipher.
			"ssl_cipher_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes decrypted with RC4.
			"ssl_cipher_rc4_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes encrypted with RC4.
			"ssl_cipher_rc4_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of RSA decrypts.
			"ssl_cipher_rsa_decrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of external RSA decrypts.
			"ssl_cipher_rsa_decrypts_external": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of RSA encrypts.
			"ssl_cipher_rsa_encrypts": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of external RSA encrypts.
			"ssl_cipher_rsa_encrypts_external": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a client certificate has expired.
			"ssl_client_cert_expired": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a client certificate was invalid.
			"ssl_client_cert_invalid": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a client certificate was required but not supplied.
			"ssl_client_cert_not_sent": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times a client certificate was revoked.
			"ssl_client_cert_revoked": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSL connections negotiated.
			"ssl_connections": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of SSLv3 handshakes.
			"ssl_handshake_sslv3": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of TLSv1.0 handshakes.
			"ssl_handshake_tlsv1": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of TLSv1.1 handshakes.
			"ssl_handshake_tlsv11": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of TLSv1.2 handshakes.
			"ssl_handshake_tlsv12": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of TLSv1.3 handshakes.
			"ssl_handshake_tlsv13": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times the SSL session id was found in the cache and
			//  reused.
			"ssl_session_id_mem_cache_hit": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of times the SSL session id was not found in the cache.
			"ssl_session_id_mem_cache_miss": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Percentage of time that the CPUs are busy.
			"sys_cpu_busy_percent": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Percentage of time that the CPUs are idle.
			"sys_cpu_idle_percent": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Percentage of time that the CPUs are busy running system code.
			"sys_cpu_system_busy_percent": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Percentage of time that the CPUs are busy running user-space
			//  code.
			"sys_cpu_user_busy_percent": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of free file descriptors.
			"sys_fds_free": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Buffer memory (MBytes).
			"sys_mem_buffered": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Free memory (MBytes).
			"sys_mem_free": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Memory used (MBytes).
			"sys_mem_in_use": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total swap space (MBytes).
			"sys_mem_swap_total": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Amount of swap space in use (MBytes).
			"sys_mem_swapped": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total memory (MBytes).
			"sys_mem_total": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The time (in hundredths of a second) since the configuration
			//  of traffic manager was updated (this value will wrap if no configuration
			//  changes are made for 497 days).
			"time_last_config_update": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total errors returned from the backend servers.
			"total_backend_server_errors": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of malformed DNS response packets encountered from
			//  the backend servers.
			"total_bad_dns_packets": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes received by the traffic manager from clients.
			"total_bytes_in": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Bytes sent by the traffic manager to clients.
			"total_bytes_out": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of TCP connections received.
			"total_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Number of TCP connections currently established.
			"total_current_conn": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of DNS response packets handled.
			"total_dns_responses": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of TCP requests received.
			"total_requests": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// Total number of TCP requests being processed, after applying
			//  TPS limits.
			"total_transactions": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},

			// The time (in hundredths of a second) that vTM software has been
			//  operational for (this value will wrap if it has been running
			//  for more than 497 days).
			"up_time": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
		},
	}
}

func dataSourceGlobalsStatisticsRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetGlobalsStatistics()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_globals: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "analytics_transactions_dropped"
	d.Set("analytics_transactions_dropped", int(*object.Statistics.AnalyticsTransactionsDropped))

	lastAssignedField = "analytics_transactions_exported"
	d.Set("analytics_transactions_exported", int(*object.Statistics.AnalyticsTransactionsExported))

	lastAssignedField = "analytics_transactions_memory_usage"
	d.Set("analytics_transactions_memory_usage", int(*object.Statistics.AnalyticsTransactionsMemoryUsage))

	lastAssignedField = "data_entries"
	d.Set("data_entries", int(*object.Statistics.DataEntries))

	lastAssignedField = "data_memory_usage"
	d.Set("data_memory_usage", int(*object.Statistics.DataMemoryUsage))

	lastAssignedField = "events_seen"
	d.Set("events_seen", int(*object.Statistics.EventsSeen))

	lastAssignedField = "hourly_peak_bytes_in_per_second"
	d.Set("hourly_peak_bytes_in_per_second", int(*object.Statistics.HourlyPeakBytesInPerSecond))

	lastAssignedField = "hourly_peak_bytes_out_per_second"
	d.Set("hourly_peak_bytes_out_per_second", int(*object.Statistics.HourlyPeakBytesOutPerSecond))

	lastAssignedField = "hourly_peak_requests_per_second"
	d.Set("hourly_peak_requests_per_second", int(*object.Statistics.HourlyPeakRequestsPerSecond))

	lastAssignedField = "hourly_peak_ssl_connections_per_second"
	d.Set("hourly_peak_ssl_connections_per_second", int(*object.Statistics.HourlyPeakSslConnectionsPerSecond))

	lastAssignedField = "num_idle_connections"
	d.Set("num_idle_connections", int(*object.Statistics.NumIdleConnections))

	lastAssignedField = "number_child_processes"
	d.Set("number_child_processes", int(*object.Statistics.NumberChildProcesses))

	lastAssignedField = "number_dnsa_cache_hits"
	d.Set("number_dnsa_cache_hits", int(*object.Statistics.NumberDnsaCacheHits))

	lastAssignedField = "number_dnsa_requests"
	d.Set("number_dnsa_requests", int(*object.Statistics.NumberDnsaRequests))

	lastAssignedField = "number_dnsptr_cache_hits"
	d.Set("number_dnsptr_cache_hits", int(*object.Statistics.NumberDnsptrCacheHits))

	lastAssignedField = "number_dnsptr_requests"
	d.Set("number_dnsptr_requests", int(*object.Statistics.NumberDnsptrRequests))

	lastAssignedField = "number_snmp_bad_requests"
	d.Set("number_snmp_bad_requests", int(*object.Statistics.NumberSnmpBadRequests))

	lastAssignedField = "number_snmp_get_bulk_requests"
	d.Set("number_snmp_get_bulk_requests", int(*object.Statistics.NumberSnmpGetBulkRequests))

	lastAssignedField = "number_snmp_get_next_requests"
	d.Set("number_snmp_get_next_requests", int(*object.Statistics.NumberSnmpGetNextRequests))

	lastAssignedField = "number_snmp_get_requests"
	d.Set("number_snmp_get_requests", int(*object.Statistics.NumberSnmpGetRequests))

	lastAssignedField = "number_snmp_unauthorised_requests"
	d.Set("number_snmp_unauthorised_requests", int(*object.Statistics.NumberSnmpUnauthorisedRequests))

	lastAssignedField = "ssl_cipher_3des_decrypts"
	d.Set("ssl_cipher_3des_decrypts", int(*object.Statistics.SslCipher3DesDecrypts))

	lastAssignedField = "ssl_cipher_3des_encrypts"
	d.Set("ssl_cipher_3des_encrypts", int(*object.Statistics.SslCipher3DesEncrypts))

	lastAssignedField = "ssl_cipher_aes_decrypts"
	d.Set("ssl_cipher_aes_decrypts", int(*object.Statistics.SslCipherAesDecrypts))

	lastAssignedField = "ssl_cipher_aes_encrypts"
	d.Set("ssl_cipher_aes_encrypts", int(*object.Statistics.SslCipherAesEncrypts))

	lastAssignedField = "ssl_cipher_aes_gcm_decrypts"
	d.Set("ssl_cipher_aes_gcm_decrypts", int(*object.Statistics.SslCipherAesGcmDecrypts))

	lastAssignedField = "ssl_cipher_aes_gcm_encrypts"
	d.Set("ssl_cipher_aes_gcm_encrypts", int(*object.Statistics.SslCipherAesGcmEncrypts))

	lastAssignedField = "ssl_cipher_decrypts"
	d.Set("ssl_cipher_decrypts", int(*object.Statistics.SslCipherDecrypts))

	lastAssignedField = "ssl_cipher_des_decrypts"
	d.Set("ssl_cipher_des_decrypts", int(*object.Statistics.SslCipherDesDecrypts))

	lastAssignedField = "ssl_cipher_des_encrypts"
	d.Set("ssl_cipher_des_encrypts", int(*object.Statistics.SslCipherDesEncrypts))

	lastAssignedField = "ssl_cipher_dh_agreements"
	d.Set("ssl_cipher_dh_agreements", int(*object.Statistics.SslCipherDhAgreements))

	lastAssignedField = "ssl_cipher_dh_generates"
	d.Set("ssl_cipher_dh_generates", int(*object.Statistics.SslCipherDhGenerates))

	lastAssignedField = "ssl_cipher_dsa_signs"
	d.Set("ssl_cipher_dsa_signs", int(*object.Statistics.SslCipherDsaSigns))

	lastAssignedField = "ssl_cipher_dsa_verifies"
	d.Set("ssl_cipher_dsa_verifies", int(*object.Statistics.SslCipherDsaVerifies))

	lastAssignedField = "ssl_cipher_ecdh_agreements"
	d.Set("ssl_cipher_ecdh_agreements", int(*object.Statistics.SslCipherEcdhAgreements))

	lastAssignedField = "ssl_cipher_ecdh_generates"
	d.Set("ssl_cipher_ecdh_generates", int(*object.Statistics.SslCipherEcdhGenerates))

	lastAssignedField = "ssl_cipher_ecdsa_signs"
	d.Set("ssl_cipher_ecdsa_signs", int(*object.Statistics.SslCipherEcdsaSigns))

	lastAssignedField = "ssl_cipher_ecdsa_verifies"
	d.Set("ssl_cipher_ecdsa_verifies", int(*object.Statistics.SslCipherEcdsaVerifies))

	lastAssignedField = "ssl_cipher_encrypts"
	d.Set("ssl_cipher_encrypts", int(*object.Statistics.SslCipherEncrypts))

	lastAssignedField = "ssl_cipher_rc4_decrypts"
	d.Set("ssl_cipher_rc4_decrypts", int(*object.Statistics.SslCipherRc4Decrypts))

	lastAssignedField = "ssl_cipher_rc4_encrypts"
	d.Set("ssl_cipher_rc4_encrypts", int(*object.Statistics.SslCipherRc4Encrypts))

	lastAssignedField = "ssl_cipher_rsa_decrypts"
	d.Set("ssl_cipher_rsa_decrypts", int(*object.Statistics.SslCipherRsaDecrypts))

	lastAssignedField = "ssl_cipher_rsa_decrypts_external"
	d.Set("ssl_cipher_rsa_decrypts_external", int(*object.Statistics.SslCipherRsaDecryptsExternal))

	lastAssignedField = "ssl_cipher_rsa_encrypts"
	d.Set("ssl_cipher_rsa_encrypts", int(*object.Statistics.SslCipherRsaEncrypts))

	lastAssignedField = "ssl_cipher_rsa_encrypts_external"
	d.Set("ssl_cipher_rsa_encrypts_external", int(*object.Statistics.SslCipherRsaEncryptsExternal))

	lastAssignedField = "ssl_client_cert_expired"
	d.Set("ssl_client_cert_expired", int(*object.Statistics.SslClientCertExpired))

	lastAssignedField = "ssl_client_cert_invalid"
	d.Set("ssl_client_cert_invalid", int(*object.Statistics.SslClientCertInvalid))

	lastAssignedField = "ssl_client_cert_not_sent"
	d.Set("ssl_client_cert_not_sent", int(*object.Statistics.SslClientCertNotSent))

	lastAssignedField = "ssl_client_cert_revoked"
	d.Set("ssl_client_cert_revoked", int(*object.Statistics.SslClientCertRevoked))

	lastAssignedField = "ssl_connections"
	d.Set("ssl_connections", int(*object.Statistics.SslConnections))

	lastAssignedField = "ssl_handshake_sslv3"
	d.Set("ssl_handshake_sslv3", int(*object.Statistics.SslHandshakeSslv3))

	lastAssignedField = "ssl_handshake_tlsv1"
	d.Set("ssl_handshake_tlsv1", int(*object.Statistics.SslHandshakeTlsv1))

	lastAssignedField = "ssl_handshake_tlsv11"
	d.Set("ssl_handshake_tlsv11", int(*object.Statistics.SslHandshakeTlsv11))

	lastAssignedField = "ssl_handshake_tlsv12"
	d.Set("ssl_handshake_tlsv12", int(*object.Statistics.SslHandshakeTlsv12))

	lastAssignedField = "ssl_handshake_tlsv13"
	d.Set("ssl_handshake_tlsv13", int(*object.Statistics.SslHandshakeTlsv13))

	lastAssignedField = "ssl_session_id_mem_cache_hit"
	d.Set("ssl_session_id_mem_cache_hit", int(*object.Statistics.SslSessionIdMemCacheHit))

	lastAssignedField = "ssl_session_id_mem_cache_miss"
	d.Set("ssl_session_id_mem_cache_miss", int(*object.Statistics.SslSessionIdMemCacheMiss))

	lastAssignedField = "sys_cpu_busy_percent"
	d.Set("sys_cpu_busy_percent", int(*object.Statistics.SysCpuBusyPercent))

	lastAssignedField = "sys_cpu_idle_percent"
	d.Set("sys_cpu_idle_percent", int(*object.Statistics.SysCpuIdlePercent))

	lastAssignedField = "sys_cpu_system_busy_percent"
	d.Set("sys_cpu_system_busy_percent", int(*object.Statistics.SysCpuSystemBusyPercent))

	lastAssignedField = "sys_cpu_user_busy_percent"
	d.Set("sys_cpu_user_busy_percent", int(*object.Statistics.SysCpuUserBusyPercent))

	lastAssignedField = "sys_fds_free"
	d.Set("sys_fds_free", int(*object.Statistics.SysFdsFree))

	lastAssignedField = "sys_mem_buffered"
	d.Set("sys_mem_buffered", int(*object.Statistics.SysMemBuffered))

	lastAssignedField = "sys_mem_free"
	d.Set("sys_mem_free", int(*object.Statistics.SysMemFree))

	lastAssignedField = "sys_mem_in_use"
	d.Set("sys_mem_in_use", int(*object.Statistics.SysMemInUse))

	lastAssignedField = "sys_mem_swap_total"
	d.Set("sys_mem_swap_total", int(*object.Statistics.SysMemSwapTotal))

	lastAssignedField = "sys_mem_swapped"
	d.Set("sys_mem_swapped", int(*object.Statistics.SysMemSwapped))

	lastAssignedField = "sys_mem_total"
	d.Set("sys_mem_total", int(*object.Statistics.SysMemTotal))

	lastAssignedField = "time_last_config_update"
	d.Set("time_last_config_update", int(*object.Statistics.TimeLastConfigUpdate))

	lastAssignedField = "total_backend_server_errors"
	d.Set("total_backend_server_errors", int(*object.Statistics.TotalBackendServerErrors))

	lastAssignedField = "total_bad_dns_packets"
	d.Set("total_bad_dns_packets", int(*object.Statistics.TotalBadDnsPackets))

	lastAssignedField = "total_bytes_in"
	d.Set("total_bytes_in", int(*object.Statistics.TotalBytesIn))

	lastAssignedField = "total_bytes_out"
	d.Set("total_bytes_out", int(*object.Statistics.TotalBytesOut))

	lastAssignedField = "total_conn"
	d.Set("total_conn", int(*object.Statistics.TotalConn))

	lastAssignedField = "total_current_conn"
	d.Set("total_current_conn", int(*object.Statistics.TotalCurrentConn))

	lastAssignedField = "total_dns_responses"
	d.Set("total_dns_responses", int(*object.Statistics.TotalDnsResponses))

	lastAssignedField = "total_requests"
	d.Set("total_requests", int(*object.Statistics.TotalRequests))

	lastAssignedField = "total_transactions"
	d.Set("total_transactions", int(*object.Statistics.TotalTransactions))

	lastAssignedField = "up_time"
	d.Set("up_time", int(*object.Statistics.UpTime))
	d.SetId("globals")
	return nil
}
