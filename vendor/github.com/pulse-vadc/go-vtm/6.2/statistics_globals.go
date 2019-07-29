// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.2.
package vtm

import (
	"encoding/json"
)

type GlobalsStatistics struct {
	Statistics struct {
		AnalyticsTransactionsDropped      *int `json:"analytics_transactions_dropped"`
		AnalyticsTransactionsExported     *int `json:"analytics_transactions_exported"`
		AnalyticsTransactionsMemoryUsage  *int `json:"analytics_transactions_memory_usage"`
		DataEntries                       *int `json:"data_entries"`
		DataMemoryUsage                   *int `json:"data_memory_usage"`
		EventsSeen                        *int `json:"events_seen"`
		HourlyPeakBytesInPerSecond        *int `json:"hourly_peak_bytes_in_per_second"`
		HourlyPeakBytesOutPerSecond       *int `json:"hourly_peak_bytes_out_per_second"`
		HourlyPeakRequestsPerSecond       *int `json:"hourly_peak_requests_per_second"`
		HourlyPeakSslConnectionsPerSecond *int `json:"hourly_peak_ssl_connections_per_second"`
		NumIdleConnections                *int `json:"num_idle_connections"`
		NumberChildProcesses              *int `json:"number_child_processes"`
		NumberDnsaCacheHits               *int `json:"number_dnsa_cache_hits"`
		NumberDnsaRequests                *int `json:"number_dnsa_requests"`
		NumberDnsptrCacheHits             *int `json:"number_dnsptr_cache_hits"`
		NumberDnsptrRequests              *int `json:"number_dnsptr_requests"`
		NumberSnmpBadRequests             *int `json:"number_snmp_bad_requests"`
		NumberSnmpGetBulkRequests         *int `json:"number_snmp_get_bulk_requests"`
		NumberSnmpGetNextRequests         *int `json:"number_snmp_get_next_requests"`
		NumberSnmpGetRequests             *int `json:"number_snmp_get_requests"`
		NumberSnmpUnauthorisedRequests    *int `json:"number_snmp_unauthorised_requests"`
		SslCipher3DesDecrypts             *int `json:"ssl_cipher_3des_decrypts"`
		SslCipher3DesEncrypts             *int `json:"ssl_cipher_3des_encrypts"`
		SslCipherAesDecrypts              *int `json:"ssl_cipher_aes_decrypts"`
		SslCipherAesEncrypts              *int `json:"ssl_cipher_aes_encrypts"`
		SslCipherAesGcmDecrypts           *int `json:"ssl_cipher_aes_gcm_decrypts"`
		SslCipherAesGcmEncrypts           *int `json:"ssl_cipher_aes_gcm_encrypts"`
		SslCipherDecrypts                 *int `json:"ssl_cipher_decrypts"`
		SslCipherDesDecrypts              *int `json:"ssl_cipher_des_decrypts"`
		SslCipherDesEncrypts              *int `json:"ssl_cipher_des_encrypts"`
		SslCipherDhAgreements             *int `json:"ssl_cipher_dh_agreements"`
		SslCipherDhGenerates              *int `json:"ssl_cipher_dh_generates"`
		SslCipherDsaSigns                 *int `json:"ssl_cipher_dsa_signs"`
		SslCipherDsaVerifies              *int `json:"ssl_cipher_dsa_verifies"`
		SslCipherEcdhAgreements           *int `json:"ssl_cipher_ecdh_agreements"`
		SslCipherEcdhGenerates            *int `json:"ssl_cipher_ecdh_generates"`
		SslCipherEcdsaSigns               *int `json:"ssl_cipher_ecdsa_signs"`
		SslCipherEcdsaVerifies            *int `json:"ssl_cipher_ecdsa_verifies"`
		SslCipherEncrypts                 *int `json:"ssl_cipher_encrypts"`
		SslCipherRc4Decrypts              *int `json:"ssl_cipher_rc4_decrypts"`
		SslCipherRc4Encrypts              *int `json:"ssl_cipher_rc4_encrypts"`
		SslCipherRsaDecrypts              *int `json:"ssl_cipher_rsa_decrypts"`
		SslCipherRsaDecryptsExternal      *int `json:"ssl_cipher_rsa_decrypts_external"`
		SslCipherRsaEncrypts              *int `json:"ssl_cipher_rsa_encrypts"`
		SslCipherRsaEncryptsExternal      *int `json:"ssl_cipher_rsa_encrypts_external"`
		SslClientCertExpired              *int `json:"ssl_client_cert_expired"`
		SslClientCertInvalid              *int `json:"ssl_client_cert_invalid"`
		SslClientCertNotSent              *int `json:"ssl_client_cert_not_sent"`
		SslClientCertRevoked              *int `json:"ssl_client_cert_revoked"`
		SslConnections                    *int `json:"ssl_connections"`
		SslHandshakeSslv3                 *int `json:"ssl_handshake_sslv3"`
		SslHandshakeTlsv1                 *int `json:"ssl_handshake_tlsv1"`
		SslHandshakeTlsv11                *int `json:"ssl_handshake_tlsv11"`
		SslHandshakeTlsv12                *int `json:"ssl_handshake_tlsv12"`
		SslHandshakeTlsv13                *int `json:"ssl_handshake_tlsv13"`
		SslSessionIdMemCacheHit           *int `json:"ssl_session_id_mem_cache_hit"`
		SslSessionIdMemCacheMiss          *int `json:"ssl_session_id_mem_cache_miss"`
		SysCpuBusyPercent                 *int `json:"sys_cpu_busy_percent"`
		SysCpuIdlePercent                 *int `json:"sys_cpu_idle_percent"`
		SysCpuSystemBusyPercent           *int `json:"sys_cpu_system_busy_percent"`
		SysCpuUserBusyPercent             *int `json:"sys_cpu_user_busy_percent"`
		SysFdsFree                        *int `json:"sys_fds_free"`
		SysMemBuffered                    *int `json:"sys_mem_buffered"`
		SysMemFree                        *int `json:"sys_mem_free"`
		SysMemInUse                       *int `json:"sys_mem_in_use"`
		SysMemSwapTotal                   *int `json:"sys_mem_swap_total"`
		SysMemSwapped                     *int `json:"sys_mem_swapped"`
		SysMemTotal                       *int `json:"sys_mem_total"`
		TimeLastConfigUpdate              *int `json:"time_last_config_update"`
		TotalBackendServerErrors          *int `json:"total_backend_server_errors"`
		TotalBadDnsPackets                *int `json:"total_bad_dns_packets"`
		TotalBytesIn                      *int `json:"total_bytes_in"`
		TotalBytesOut                     *int `json:"total_bytes_out"`
		TotalConn                         *int `json:"total_conn"`
		TotalCurrentConn                  *int `json:"total_current_conn"`
		TotalDnsResponses                 *int `json:"total_dns_responses"`
		TotalRequests                     *int `json:"total_requests"`
		TotalTransactions                 *int `json:"total_transactions"`
		UpTime                            *int `json:"up_time"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetGlobalsStatistics() (*GlobalsStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.2/status/local_tm/statistics/globals")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(GlobalsStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
