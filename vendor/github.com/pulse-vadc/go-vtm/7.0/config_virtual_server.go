// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 7.0.
package vtm

import (
	"encoding/json"
)

type VirtualServer struct {
	connector               *vtmConnector
	VirtualServerProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetVirtualServer(name string) (*VirtualServer, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetVirtualServer(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/7.0/config/active/virtual_servers/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(VirtualServer)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object VirtualServer) Apply() (*VirtualServer, *vtmErrorResponse) {
	marshalled, err := json.Marshal(object)
	if err != nil {
		panic(err)
	}
	data, ok := object.connector.put(string(marshalled), STANDARD_OBJ)
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	if err := json.NewDecoder(data).Decode(&object); err != nil {
		panic(err)
	}
	return &object, nil
}

func (vtm VirtualTrafficManager) NewVirtualServer(name string, pool string, port int) *VirtualServer {
	object := new(VirtualServer)
	object.Basic.Pool = &pool
	object.Basic.Port = &port
	conn := vtm.connector.getChildConnector("/tm/7.0/config/active/virtual_servers/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteVirtualServer(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/7.0/config/active/virtual_servers/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListVirtualServers() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.0/config/active/virtual_servers")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	objectList := new(vtmObjectChildren)
	if err := json.NewDecoder(data).Decode(objectList); err != nil {
		panic(err)
	}
	var stringList []string
	for _, obj := range objectList.Children {
		stringList = append(stringList, obj.Name)
	}
	return &stringList, nil
}

type VirtualServerProperties struct {
	Aptimizer struct {
		// Whether the virtual server should optimize web content.
		Enabled *bool `json:"enabled,omitempty"`

		// A table of Aptimizer profiles and the application scopes that
		//  apply to them.
		Profile *VirtualServerProfileTable `json:"profile,omitempty"`
	} `json:"aptimizer"`

	Auth struct {
		// Name of the Trusted Identity Provider configuration to use. To
		//  create Identity Providers, please visit section <a href="?section=SAML%3aTrusted%20Identity%20Providers">Trusted
		//  Identity Providers</a>
		SamlIdp *string `json:"saml_idp,omitempty"`

		// The NameID format to request and expect from the identity provider.
		SamlNameidFormat *string `json:"saml_nameid_format,omitempty"`

		// The 'Assertion Consumer Service' endpoint for the SAML service
		//  provider on this virtual server, ie the endpoint to which the
		//  identity provider will cause the user agent to send SAML assertions.
		//  This should be an HTTPS URL, must be in the same cookie domain
		//  as all hostnames used by the end user to access the virtual server
		//  (see cookie configuration) and the port must be the port on which
		//  this virtual server is listening. It must match the URI placed
		//  by the identity provider in the 'Recipient' attribute in the
		//  SAML assertion, if present.
		SamlSpAcsUrl *string `json:"saml_sp_acs_url,omitempty"`

		// The entity ID to be used by the SAML service provider function
		//  on this virtual server. This should usually be a URL, or a URN,
		//  however it may be any string. It must match the entity ID placed
		//   by the identity provider in the 'Audience' field in the SAML
		//  assertion.
		SamlSpEntityId *string `json:"saml_sp_entity_id,omitempty"`

		// Time tolerance on authentication checks. When checking time-stamps
		//  and expiry dates against the current time on the system, allow
		//  a tolerance of this many seconds. For example, if a SAML response
		//  contains a 'NotOnOrAfter' that is 4 seconds in the past according
		//  to the local time, and the tolerance is set to 5 seconds, it
		//  will still be accepted. This is to prevent a lack of clock synchronization
		//  from resulting in rejection of SAML responses.
		SamlTimeTolerance *int `json:"saml_time_tolerance,omitempty"`

		// Attributes of cookie used for authentication session.
		SessionCookieAttributes *string `json:"session_cookie_attributes,omitempty"`

		// Name of cookie used for authentication session.
		SessionCookieName *string `json:"session_cookie_name,omitempty"`

		// Whether or not to include state of authentication sessions stored
		//  encrypted on the client as plaintext in the logs.
		SessionLogExternalState *bool `json:"session_log_external_state,omitempty"`

		// Timeout on authentication session.
		SessionTimeout *int `json:"session_timeout,omitempty"`

		// Type of authentication to apply to requests to the virtual server.
		Type *string `json:"type,omitempty"`

		// Whether or not detailed messages about virtual server authentication
		//  should be written to the error log.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"auth"`

	Basic struct {
		// The bandwidth management class that this server should use, if
		//  any.
		BandwidthClass *string `json:"bandwidth_class,omitempty"`

		// Rules that are run at the end of a transaction, in order, comma
		//  separated.
		CompletionRules *[]string `json:"completion_rules,omitempty"`

		// The time, in seconds, for which an established connection can
		//  remain idle waiting for some initial data to be received from
		//  the client. The initial data is defined as a complete set of
		//  request headers for HTTP, SIP and RTSP services, or the first
		//  byte of data for all other services. A value of "0" will disable
		//  the timeout.
		ConnectTimeout *int `json:"connect_timeout,omitempty"`

		// Whether the virtual server is enabled.
		Enabled *bool `json:"enabled,omitempty"`

		// The associated GLB services for this DNS virtual server.
		GlbServices *[]string `json:"glb_services,omitempty"`

		// Whether to listen on all IP addresses
		ListenOnAny *bool `json:"listen_on_any,omitempty"`

		// Hostnames and IP addresses to listen on
		ListenOnHosts *[]string `json:"listen_on_hosts,omitempty"`

		// Traffic IP Groups to listen on
		ListenOnTrafficIps *[]string `json:"listen_on_traffic_ips,omitempty"`

		// The maximum number of concurrent TCP connections that will be
		//  handled by this virtual server. If set to a non-zero value, the
		//  traffic manager will limit the number of concurrent TCP connections
		//  that this virtual server will accept to the value specified.
		//  When the limit is reached, new connections to this virtual server
		//  will not be accepted. If set to "0" the number of concurrent
		//  TCP connections will not be limited.
		MaxConcurrentConnections *int `json:"max_concurrent_connections,omitempty"`

		// A description for the virtual server.
		Note *string `json:"note,omitempty"`

		// The default pool to use for traffic.
		Pool *string `json:"pool,omitempty"`

		// The port on which to listen for incoming connections.
		Port *int `json:"port,omitempty"`

		// The service protection class that should be used to protect this
		//  server, if any.
		ProtectionClass *string `json:"protection_class,omitempty"`

		// The protocol that the virtual server is using.
		Protocol *string `json:"protocol,omitempty"`

		// Expect connections to the traffic manager to be prefixed with
		//  a PROXY protocol header. If enabled, the information contained
		//  in the PROXY header will be available in TrafficScript. Connections
		//  that are not prefixed with a valid PROXY protocol header will
		//  be discarded.
		ProxyProtocol *bool `json:"proxy_protocol,omitempty"`

		// Connections which do not include a PROXY protocol header are
		//  not rejected, but are treated as ordinary non-PROXY protocol
		//  connections.
		ProxyProtocolOptional *bool `json:"proxy_protocol_optional,omitempty"`

		// Rules to be applied to incoming requests, in order, comma separated.
		RequestRules *[]string `json:"request_rules,omitempty"`

		// Rules to be applied to responses, in order, comma separated.
		ResponseRules *[]string `json:"response_rules,omitempty"`

		// Only applicable for Client First Generic Protocol. Allows Virtual
		//  Traffic Manager to execute rules on a client connects without
		//  waiting for data from the client.
		RulesOnConnect *bool `json:"rules_on_connect,omitempty"`

		// The service level monitoring class that this server should use,
		//  if any.
		SlmClass *string `json:"slm_class,omitempty"`

		// Whether or not the virtual server should decrypt incoming SSL
		//  traffic.
		SslDecrypt *bool `json:"ssl_decrypt,omitempty"`

		// Whether or not bound sockets should be configured for transparent
		//  proxying.
		Transparent *bool `json:"transparent,omitempty"`
	} `json:"basic"`

	Connection struct {
		// Whether or not the virtual server should use keepalive connections
		//  with the remote clients.
		Keepalive *bool `json:"keepalive,omitempty"`

		// The length of time that the virtual server should keep an idle
		//  keepalive connection before discarding it.  A value of "0" (zero)
		//  will mean that the keepalives are never closed by the traffic
		//  manager.
		KeepaliveTimeout *int `json:"keepalive_timeout,omitempty"`

		// The amount of memory, in bytes, that the virtual server should
		//  use to store data sent by the client. Larger values will use
		//  more memory, but will minimise the number of "read()" and "write()"
		//  system calls that the traffic manager must perform.
		MaxClientBuffer *int `json:"max_client_buffer,omitempty"`

		// The amount of memory, in bytes, that the virtual server should
		//  use to store data returned by the server.  Larger values will
		//  use more memory, but will minimise the number of "read()" and
		//  "write()" system calls that the traffic manager must perform.
		MaxServerBuffer *int `json:"max_server_buffer,omitempty"`

		// The total amount of time a transaction can take, counted from
		//  the first byte being received until the transaction is complete.
		//   For HTTP, this can mean all data has been written in both directions,
		//  or the connection has been closed; in most other cases it is
		//  the same as the connection being closed.<br> The default value
		//  of "0" means there is no maximum duration, i.e., transactions
		//  can take arbitrarily long if none of the other timeouts occur.
		MaxTransactionDuration *int `json:"max_transaction_duration,omitempty"`

		// If specified, the traffic manager will use the value as the banner
		//  to send for server-first protocols such as FTP, POP, SMTP and
		//  IMAP. This allows rules to use the first part of the client data
		//  (such as the username) to select a pool. The banner should be
		//  in the correct format for the protocol, e.g. for FTP it should
		//  start with "220 "
		ServerFirstBanner *string `json:"server_first_banner,omitempty"`

		// A connection should be closed if no additional data has been
		//  received for this period of time.  A value of "0" (zero) will
		//  disable this timeout.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"connection"`

	ConnectionErrors struct {
		// The error message to be sent to the client when the traffic manager
		//  detects an internal or backend error for the virtual server.
		ErrorFile *string `json:"error_file,omitempty"`
	} `json:"connection_errors"`

	Cookie struct {
		// The way in which the traffic manager should rewrite the domain
		//  portion of any cookies set by a back-end web server.
		Domain *string `json:"domain,omitempty"`

		// The domain to use when rewriting a cookie's domain to a named
		//  value.
		NewDomain *string `json:"new_domain,omitempty"`

		// If you wish to rewrite the path portion of any cookies set by
		//  a back-end web server, provide a regular expression to match
		//  the path:
		PathRegex *string `json:"path_regex,omitempty"`

		// If cookie path regular expression matches, it will be replaced
		//  by this substitution.  Parameters $1-$9 can be used to represent
		//  bracketed parts of the regular expression.
		PathReplace *string `json:"path_replace,omitempty"`

		// Whether or not the traffic manager should modify the "secure"
		//  tag of any cookies set by a back-end web server.
		Secure *string `json:"secure,omitempty"`
	} `json:"cookie"`

	Dns struct {
		// Enable/Disable use of EDNS client subnet option
		EdnsClientSubnet *bool `json:"edns_client_subnet,omitempty"`

		// EDNS UDP size advertised in responses.
		EdnsUdpsize *int `json:"edns_udpsize,omitempty"`

		// Maximum UDP answer size.
		MaxUdpsize *int `json:"max_udpsize,omitempty"`

		// Response record ordering.
		RrsetOrder *string `json:"rrset_order,omitempty"`

		// Whether or not the DNS Server should emit verbose logging. This
		//  is useful for diagnosing problems.
		Verbose *bool `json:"verbose,omitempty"`

		// The DNS zones
		Zones *[]string `json:"zones,omitempty"`
	} `json:"dns"`

	Ftp struct {
		// The source port to be used for active-mode FTP data connections.
		//   If 0, a random high port will be used, otherwise the specified
		//  port will be used. If a port below 1024 is required you must
		//  first explicitly permit use of low ports with the "data_bind_low"
		//  global setting.
		DataSourcePort *int `json:"data_source_port,omitempty"`

		// Whether or not the virtual server should require that incoming
		//  FTP data connections from the client originate from the same
		//  IP address as the corresponding client control connection.
		ForceClientSecure *bool `json:"force_client_secure,omitempty"`

		// Whether or not the virtual server should require that incoming
		//  FTP data connections from the nodes originate from the same IP
		//  address as the node.
		ForceServerSecure *bool `json:"force_server_secure,omitempty"`

		// If non-zero, then this controls the upper bound of the port range
		//  to use for FTP data connections.
		PortRangeHigh *int `json:"port_range_high,omitempty"`

		// If non-zero, then this controls the lower bound of the port range
		//  to use for FTP data connections.
		PortRangeLow *int `json:"port_range_low,omitempty"`

		// Use SSL on the data connection as well as the control connection
		//  (if not enabled it is left to the client and server to negotiate
		//  this).
		SslData *bool `json:"ssl_data,omitempty"`
	} `json:"ftp"`

	Gzip struct {
		// Use HTTP chunking to deliver data to the client. If this is turned
		//  off, we won't use chunking when gzipping server data. This would
		//  mean that the response couldn't be kept-alive.
		Chunk *bool `json:"chunk,omitempty"`

		// Compression level (1-9, 1=low, 9=high).
		CompressLevel *int `json:"compress_level,omitempty"`

		// Compress web pages sent back by the server.
		Enabled *bool `json:"enabled,omitempty"`

		// How the ETag header should be manipulated when compressing content.
		EtagRewrite *string `json:"etag_rewrite,omitempty"`

		// MIME types to compress. Complete MIME types can be used, or a
		//  type can end in a '*' to match multiple types.
		IncludeMime *[]string `json:"include_mime,omitempty"`

		// Maximum document size to compress (0 means unlimited).
		MaxSize *int `json:"max_size,omitempty"`

		// Minimum document size to compress.
		MinSize *int `json:"min_size,omitempty"`

		// Compress documents with no given size.
		NoSize *bool `json:"no_size,omitempty"`
	} `json:"gzip"`

	Http struct {
		// Whether or not the virtual server should add an "X-Cluster-Client-Ip"
		//  header to the request that contains the remote client's IP address.
		AddClusterIp *bool `json:"add_cluster_ip,omitempty"`

		// Whether or not the virtual server should append the remote client's
		//  IP address to the X-Forwarded-For header. If the header does
		//  not exist, it will be added.
		AddXForwardedFor *bool `json:"add_x_forwarded_for,omitempty"`

		// Whether or not the virtual server should add an "X-Forwarded-Proto"
		//  header to the request that contains the original protocol used
		//  by the client to connect to the traffic manager.
		AddXForwardedProto *bool `json:"add_x_forwarded_proto,omitempty"`

		// A case-insensitive list of HTTP "Upgrade" header values that
		//  will trigger the HTTP connection upgrade auto-detection.
		AutoUpgradeProtocols *[]string `json:"auto_upgrade_protocols,omitempty"`

		// Whether the traffic manager should check for HTTP responses that
		//  confirm an HTTP connection is transitioning to the WebSockets
		//  protocol.  If that such a response is detected, the traffic manager
		//  will cease any protocol-specific processing on the connection
		//  and just pass incoming data to the client/server as appropriate.
		AutodetectUpgradeHeaders *bool `json:"autodetect_upgrade_headers,omitempty"`

		// Handling of HTTP chunk overhead.  When vTM receives data from
		//  a server or client that consists purely of protocol overhead
		//  (contains no payload), forwarding of such segments is delayed
		//  until useful payload data arrives (setting "lazy").  Changing
		//  this key to "eager" will make vTM incur the overhead of immediately
		//  passing such data on; it should only be used with HTTP peers
		//  whose chunk handling requires it.
		ChunkOverheadForwarding *string `json:"chunk_overhead_forwarding,omitempty"`

		// If the 'Location' header matches this regular expression, rewrite
		//  the header using the 'location_replace' pattern.
		LocationRegex *string `json:"location_regex,omitempty"`

		// If the 'Location' header matches the 'location_regex' regular
		//  expression, rewrite the header with this pattern (parameters
		//  such as $1-$9 can be used to match parts of the regular expression):
		LocationReplace *string `json:"location_replace,omitempty"`

		// The action the virtual server should take if the "Location" header
		//  does not match the "location_regex" regular expression.
		LocationRewrite *string `json:"location_rewrite,omitempty"`

		// Auto-correct MIME types if the server sends the "default" MIME
		//  type for files.
		MimeDefault *string `json:"mime_default,omitempty"`

		// Auto-detect MIME types if the server does not provide them.
		MimeDetect *bool `json:"mime_detect,omitempty"`

		// Whether or not the virtual server should strip the 'X-Forwarded-Proto'
		//  header from incoming requests.
		StripXForwardedProto *bool `json:"strip_x_forwarded_proto,omitempty"`
	} `json:"http"`

	Http2 struct {
		// The time, in seconds, to wait for a request on a new HTTP/2 connection.
		//   If no request is received within this time, the connection will
		//  be closed. This setting overrides the "connect_timeout" setting.
		//  If set to "0" (zero), the value of "connect_timeout" will be
		//  used instead.
		ConnectTimeout *int `json:"connect_timeout,omitempty"`

		// This setting controls the preferred frame size used when sending
		//  body data to the client. If the client specifies a smaller maximum
		//  size than this setting, the client's maximum size will be used.
		//  Every data frame sent has at least a 9-byte header, in addition
		//  to this frame size, prepended to it.
		DataFrameSize *int `json:"data_frame_size,omitempty"`

		// This setting allows the HTTP/2 protocol to be used by a HTTP
		//  virtual server. Unless use of HTTP/2 is negotiated by the client,
		//  the virtual server will fall back to HTTP 1.x automatically.
		Enabled *bool `json:"enabled,omitempty"`

		// This setting controls the amount of memory allowed for header
		//  compression on each HTTP/2 connection.
		HeaderTableSize *int `json:"header_table_size,omitempty"`

		// A list of header names that should never be compressed using
		//  indexing.
		HeadersIndexBlacklist *[]string `json:"headers_index_blacklist,omitempty"`

		// The HTTP/2 HPACK compression scheme allows for HTTP headers to
		//  be compressed using indexing. Sensitive headers can be marked
		//  as "never index", which prevents them from being compressed using
		//  indexing. When this setting is "Yes", only headers included in
		//  "http2!headers_index_blacklist" are marked as "never index".
		//  When this setting is "No", all headers will be marked as "never
		//  index" unless they are included in "http2!headers_index_whitelist".
		HeadersIndexDefault *bool `json:"headers_index_default,omitempty"`

		// A list of header names that can be compressed using indexing
		//  when the value of "http2!headers_index_default" is set to "No".
		HeadersIndexWhitelist *[]string `json:"headers_index_whitelist,omitempty"`

		// The maximum size, in bytes, of decompressed headers for an HTTP/2
		//  request. If the limit is exceeded, the connection on which the
		//  request was sent will be dropped. A value of 0 disables the limit
		//  check. If a service protection class with "http!max_header_length"
		//  configured is associated with this service then that setting
		//  will take precedence.
		HeadersSizeLimit *int `json:"headers_size_limit,omitempty"`

		// The time, in seconds, to wait for a new HTTP/2 request on a previously
		//  used HTTP/2 connection that has no open HTTP/2 streams. If an
		//  HTTP/2 request is not received within this time, the connection
		//  will be closed. A value of "0" (zero) will disable the timeout.
		IdleTimeoutNoStreams *int `json:"idle_timeout_no_streams,omitempty"`

		// The time, in seconds, to wait for data on an idle HTTP/2 connection,
		//  which has open streams, when no data has been sent recently (e.g.
		//  for long-polled requests). If data is not sent within this time,
		//  all open streams and the HTTP/2 connection will be closed. A
		//  value of "0" (zero) will disable the timeout.
		IdleTimeoutOpenStreams *int `json:"idle_timeout_open_streams,omitempty"`

		// This setting controls the number of streams a client is permitted
		//  to open concurrently on a single connection.
		MaxConcurrentStreams *int `json:"max_concurrent_streams,omitempty"`

		// This setting controls the maximum HTTP/2 frame size clients are
		//  permitted to send to the traffic manager.
		MaxFrameSize *int `json:"max_frame_size,omitempty"`

		// The maximum size, in bytes, of the random-length padding to add
		//  to HTTP/2 header frames. The padding, a random number of zero
		//  bytes up to the maximum specified.
		MaxHeaderPadding *int `json:"max_header_padding,omitempty"`

		// Whether Cookie headers received from an HTTP/2 client should
		//  be merged into a single Cookie header using RFC6265 rules before
		//  forwarding to an HTTP/1.1 server. Some web applications do not
		//  handle multiple Cookie headers correctly.
		MergeCookieHeaders *bool `json:"merge_cookie_headers,omitempty"`

		// This setting controls the flow control window for each HTTP/2
		//  stream. This will limit the memory used for buffering when the
		//  client is sending body data faster than the pool node is reading
		//  it.
		StreamWindowSize *int `json:"stream_window_size,omitempty"`
	} `json:"http2"`

	KerberosProtocolTransition struct {
		// Whether or not the virtual server should use Kerberos Protocol
		//  Transition.
		Enabled *bool `json:"enabled,omitempty"`

		// The Kerberos principal this virtual server should use to perform
		//  Kerberos Protocol Transition.
		Principal *string `json:"principal,omitempty"`

		// The Kerberos principal name of the service this virtual server
		//  targets.
		Target *string `json:"target,omitempty"`
	} `json:"kerberos_protocol_transition"`

	Log struct {
		// Write log data to disk immediately, rather than buffering data.
		AlwaysFlush *bool `json:"always_flush,omitempty"`

		// Should the virtual server log failures occurring on connections
		//  to clients.
		ClientConnectionFailures *bool `json:"client_connection_failures,omitempty"`

		// Whether or not to log connections to the virtual server to a
		//  disk on the file system.
		Enabled *bool `json:"enabled,omitempty"`

		// The name of the file in which to store the request logs. The
		//  filename can contain macros which will be expanded by the traffic
		//  manager to generate the full filename.
		Filename *string `json:"filename,omitempty"`

		// The log file format. This specifies the line of text that will
		//  be written to the log file when a connection to the traffic manager
		//  is completed.  Many parameters from the connection can be recorded
		//  using macros.
		Format *string `json:"format,omitempty"`

		// Whether to log all connections by default, or log no connections
		//  by default. Specific connections can be selected for addition
		//  to or exclusion from the log using the TrafficScript function
		//  "requestlog.include()".
		SaveAll *bool `json:"save_all,omitempty"`

		// Should the virtual server log failures occurring on connections
		//  to nodes.
		ServerConnectionFailures *bool `json:"server_connection_failures,omitempty"`

		// Should the virtual server log session persistence events.
		SessionPersistenceVerbose *bool `json:"session_persistence_verbose,omitempty"`

		// Should the virtual server log failures occurring on SSL secure
		//  negotiation.
		SslFailures *bool `json:"ssl_failures,omitempty"`

		// Should the virtual server log messages when attempts to resume
		//  SSL sessions (either from the session cache or a session ticket)
		//  fail. Note that failure to resume an SSL session does not result
		//  in the SSL connection being closed, but it does cause a full
		//  SSL handshake to take place.
		SslResumptionFailures *bool `json:"ssl_resumption_failures,omitempty"`
	} `json:"log"`

	RecentConnections struct {
		// Whether or not connections handled by this virtual server should
		//  be shown on the Activity > Connections page.
		Enabled *bool `json:"enabled,omitempty"`

		// Whether or not all connections handled by this virtual server
		//  should be shown on the Connections page. Individual connections
		//  can be selectively shown on the Connections page using the "recentconns.include()"
		//  TrafficScript function.
		SaveAll *bool `json:"save_all,omitempty"`
	} `json:"recent_connections"`

	RequestTracing struct {
		// Record a trace of major connection processing events for each
		//  request and response.
		Enabled *bool `json:"enabled,omitempty"`

		// Include details of individual I/O events in request and response
		//  traces.  Requires request tracing to be enabled.
		TraceIo *bool `json:"trace_io,omitempty"`
	} `json:"request_tracing"`

	Rtsp struct {
		// If non-zero this controls the upper bound of the port range to
		//  use for streaming data connections.
		StreamingPortRangeHigh *int `json:"streaming_port_range_high,omitempty"`

		// If non-zero this controls the lower bound of the port range to
		//  use for streaming data connections.
		StreamingPortRangeLow *int `json:"streaming_port_range_low,omitempty"`

		// If non-zero data-streams associated with RTSP connections will
		//  timeout if no data is transmitted for this many seconds.
		StreamingTimeout *int `json:"streaming_timeout,omitempty"`
	} `json:"rtsp"`

	Sip struct {
		// The action to take when a SIP request with body data arrives
		//  that should be routed to an external IP.
		DangerousRequests *string `json:"dangerous_requests,omitempty"`

		// Should the virtual server follow routing information contained
		//  in SIP requests. If set to "No" requests will be routed to the
		//  chosen back-end node regardless of their URI or Route header.
		FollowRoute *bool `json:"follow_route,omitempty"`

		// SIP clients can have several pending requests at one time. To
		//  protect the traffic manager against DoS attacks, this setting
		//  limits the amount of memory each client can use.  When the limit
		//  is reached new requests will be sent a 413 response. If the value
		//  is set to "0" (zero) the memory limit is disabled.
		MaxConnectionMem *int `json:"max_connection_mem,omitempty"`

		// The mode that this SIP virtual server should operate in.
		Mode *string `json:"mode,omitempty"`

		// Replace the Request-URI of SIP requests with the address of the
		//  selected back-end node.
		RewriteUri *bool `json:"rewrite_uri,omitempty"`

		// If non-zero this controls the upper bound of the port range to
		//  use for streaming data connections.
		StreamingPortRangeHigh *int `json:"streaming_port_range_high,omitempty"`

		// If non-zero, then this controls the lower bound of the port range
		//  to use for streaming data connections.
		StreamingPortRangeLow *int `json:"streaming_port_range_low,omitempty"`

		// If non-zero a UDP stream will timeout when no data has been seen
		//  within this time.
		StreamingTimeout *int `json:"streaming_timeout,omitempty"`

		// When timing out a SIP transaction, send a 'timed out' response
		//  to the client and, in the case of an INVITE transaction, a CANCEL
		//  request to the server.
		TimeoutMessages *bool `json:"timeout_messages,omitempty"`

		// The virtual server should discard a SIP transaction when no further
		//  messages have been seen within this time.
		TransactionTimeout *int `json:"transaction_timeout,omitempty"`

		// Require that SIP datagrams which are part of the same transaction
		//  are received from the same address and port.
		UdpAssociateBySource *bool `json:"udp_associate_by_source,omitempty"`
	} `json:"sip"`

	Smtp struct {
		// Whether or not the traffic manager should expect the connection
		//  to start off in plain text and then upgrade to SSL using STARTTLS
		//  when handling SMTP traffic.
		ExpectStarttls *bool `json:"expect_starttls,omitempty"`
	} `json:"smtp"`

	Ssl struct {
		// Whether or not the virtual server should add HTTP headers to
		//  each request to show the SSL connection parameters.
		AddHttpHeaders *bool `json:"add_http_headers,omitempty"`

		// The SSL/TLS cipher suites to allow for connections to this virtual
		//  server.  Leaving this empty will make the virtual server use
		//  the globally configured cipher suites, see configuration key
		//  <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!cipher_suites">
		//  "ssl!cipher_suites"</a> in the Global Settings section of the
		//  System tab.  See there for how to specify SSL/TLS cipher suites.
		CipherSuites *string `json:"cipher_suites,omitempty"`

		// The certificate authorities that this virtual server should trust
		//  to validate client certificates. If no certificate authorities
		//  are selected, and client certificates are requested, then all
		//  client certificates will be accepted.
		ClientCertCas *[]string `json:"client_cert_cas,omitempty"`

		// What HTTP headers the virtual server should add to each request
		//  to show the data in the client certificate.
		ClientCertHeaders *string `json:"client_cert_headers,omitempty"`

		// The SSL elliptic curve preference list for SSL connections to
		//  this virtual server using TLS version 1.0 or higher. Leaving
		//  this empty will make the virtual server use the globally configured
		//  curve preference list. The named curves P256, P384 and P521 may
		//  be configured.
		EllipticCurves *[]string `json:"elliptic_curves,omitempty"`

		// Whether or not the Fallback SCSV sent by TLS clients is honored
		//  by this virtual server. Choosing the global setting means the
		//  value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!honor_fallback_scsv">
		//  "ssl!honor_fallback_scsv"</a> from the Global Settings section
		//  of the System tab will be enforced.
		HonorFallbackScsv *string `json:"honor_fallback_scsv,omitempty"`

		// When the virtual server verifies certificates signed by these
		//  certificate authorities, it doesn't check the 'not after' date,
		//  i.e., they are considered valid even after their expiration date
		//  has passed (but not if they have been revoked).
		IssuedCertsNeverExpire *[]string `json:"issued_certs_never_expire,omitempty"`

		// This setting gives the number of certificates in a certificate
		//  chain beyond those listed as issued_certs_never_expire whose
		//  certificate expiry will not be checked. For example "0" will
		//  result in the expiry checks being made for certificates issued
		//  by issued_certs_never_expire certificates, "1" will result in
		//  no expiry checks being performed for the certificates directly
		//  issued by issued_certs_never_expire certificates, "2" will avoid
		//  checking expiry for certificates issued by certificates issued
		//  by the issued_certs_never_expire certificates as well, and so
		//  on.
		IssuedCertsNeverExpireDepth *int `json:"issued_certs_never_expire_depth,omitempty"`

		// The maximum client RSA/DSA certificate key size that the virtual
		//  server should accept.
		MaxKeySize *int `json:"max_key_size,omitempty"`

		// The minimum client RSA/DSA certificate key size that the virtual
		//  server should accept.
		MinKeySize *int `json:"min_key_size,omitempty"`

		// Whether or not the traffic manager should use OCSP to check the
		//  revocation status of client certificates.
		OcspEnable *bool `json:"ocsp_enable,omitempty"`

		// A table of certificate issuer specific OCSP settings.
		OcspIssuers *VirtualServerOcspIssuersTable `json:"ocsp_issuers,omitempty"`

		// The number of seconds for which an OCSP response is considered
		//  valid if it has not yet exceeded the time specified in the 'nextUpdate'
		//  field. If set to "0" (zero) then OCSP responses are considered
		//  valid until the time specified in their 'nextUpdate' field.
		OcspMaxResponseAge *int `json:"ocsp_max_response_age,omitempty"`

		// If OCSP URIs are present in certificates used by this virtual
		//  server, then enabling this option will allow the traffic manager
		//  to provide OCSP responses for these certificates as part of the
		//  handshake, if the client sends a TLS status_request extension
		//  in the ClientHello.
		OcspStapling *bool `json:"ocsp_stapling,omitempty"`

		// The number of seconds outside the permitted range for which the
		//  'thisUpdate' and 'nextUpdate' fields of an OCSP response are
		//  still considered valid.
		OcspTimeTolerance *int `json:"ocsp_time_tolerance,omitempty"`

		// The number of seconds after which OCSP requests will be timed
		//  out.
		OcspTimeout *int `json:"ocsp_timeout,omitempty"`

		// Whether or not the virtual server should request an identifying
		//  SSL certificate from each client.
		RequestClientCert *string `json:"request_client_cert,omitempty"`

		// Whether or not to send an SSL/TLS "close alert" when the traffic
		//  manager is initiating an SSL socket disconnection.
		SendCloseAlerts *bool `json:"send_close_alerts,omitempty"`

		// The SSL certificates and corresponding private keys.
		ServerCertAltCertificates *[]string `json:"server_cert_alt_certificates,omitempty"`

		// The default SSL certificate to use for this virtual server.
		ServerCertDefault *string `json:"server_cert_default,omitempty"`

		// Host specific SSL server certificate mappings.
		ServerCertHostMapping *VirtualServerServerCertHostMappingTable `json:"server_cert_host_mapping,omitempty"`

		// Whether or not use of the session cache is enabled for this virtual
		//  server. Choosing the global setting means the value of configuration
		//  key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!cache!enabled">
		//  "ssl!session_cache_enabled"</a> from the Global Settings section
		//  of the System tab will be enforced.
		SessionCacheEnabled *string `json:"session_cache_enabled,omitempty"`

		// Whether or not use of session tickets is enabled for this virtual
		//  server. Choosing the global setting means the value of configuration
		//  key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!tickets!enabled">
		//  "ssl!tickets!enabled"</a> from the Global Settings section of
		//  the System tab will be enforced.
		SessionTicketsEnabled *string `json:"session_tickets_enabled,omitempty"`

		// The SSL signature algorithms preference list for SSL connections
		//  to this virtual server using TLS version 1.2 or higher. Leaving
		//  this empty will make the virtual server use the globally configured
		//  preference list, "signature_algorithms" in the "ssl" section
		//  of the "global_settings" resource.  See there and in the online
		//  help for how to specify SSL signature algorithms.
		SignatureAlgorithms *string `json:"signature_algorithms,omitempty"`

		// Whether or not SSLv3 is enabled for this virtual server.  Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_ssl3">
		//  "ssl!support_ssl3"</a> from the Global Settings section of the
		//  System tab will be enforced.
		SupportSsl3 *string `json:"support_ssl3,omitempty"`

		// Whether or not TLSv1.0 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1">
		//  "ssl!support_tls1"</a> from the Global Settings section of the
		//  System tab will be enforced.
		SupportTls1 *string `json:"support_tls1,omitempty"`

		// Whether or not TLSv1.1 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_1">
		//  "ssl!support_tls1_1"</a> from the Global Settings section of
		//  the System tab will be enforced.
		SupportTls11 *string `json:"support_tls1_1,omitempty"`

		// Whether or not TLSv1.2 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_2">
		//  "ssl!support_tls1_2"</a> from the Global Settings section of
		//  the System tab will be enforced.
		SupportTls12 *string `json:"support_tls1_2,omitempty"`

		// Whether or not TLSv1.3 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_3">
		//  "ssl!support_tls1_3"</a> from the Global Settings section of
		//  the System tab will be enforced.
		SupportTls13 *string `json:"support_tls1_3,omitempty"`

		// If the traffic manager is receiving traffic sent from another
		//  traffic manager, then enabling this option will allow it to decode
		//  extra information on the true origin of the SSL connection. This
		//  information is supplied by the first traffic manager.
		TrustMagic *bool `json:"trust_magic,omitempty"`
	} `json:"ssl"`

	Syslog struct {
		// Whether or not to log connections to the virtual server to a
		//  remote syslog host.
		Enabled *bool `json:"enabled,omitempty"`

		// The log format for the remote syslog.  This specifies the line
		//  of text that will be sent to the remote syslog  when a connection
		//  to the traffic manager is completed. Many parameters from the
		//  connection can be recorded using macros.
		Format *string `json:"format,omitempty"`

		// The remote host and port (default is 514) to send request log
		//  lines to.
		IpEndPoint *string `json:"ip_end_point,omitempty"`

		// Maximum length in bytes of a message sent to the remote syslog.
		//  Messages longer than this will be truncated before they are sent.
		MsgLenLimit *int `json:"msg_len_limit,omitempty"`
	} `json:"syslog"`

	Tcp struct {
		// Whether or not connections from clients should be closed with
		//  a RST packet, rather than a FIN packet. This avoids the TIME_WAIT
		//  state, which on rare occasions allows wandering duplicate packets
		//  to be safely ignored.
		CloseWithRst *bool `json:"close_with_rst,omitempty"`

		// The maximum TCP segment size. This will place a maximum on the
		//  size of TCP segments that are sent by this machine, and will
		//  advertise to the client this value as the maximum size of TCP
		//  segment to send to this machine. Setting this to zero causes
		//  the default maximum TCP segment size to be advertised and used.
		Mss *int `json:"mss,omitempty"`

		// Whether or not Nagle's algorithm should be used for TCP connections.
		Nagle *bool `json:"nagle,omitempty"`

		// If set to "Yes" the traffic manager will send the client FIN
		//  to the back-end server and wait for a server response instead
		//  of closing the connection immediately.  This is only necessary
		//  for protocols that require half-close support to function correctly,
		//  such as "rsh".  If the traffic manager is responding to the request
		//  itself, setting this key to Yes will cause the traffic manager
		//  to continue writing the response even after it has received a
		//  FIN from the client.
		ProxyClose *bool `json:"proxy_close,omitempty"`
	} `json:"tcp"`

	TransactionExport struct {
		// Whether to export a restricted set of metadata about transactions
		//  processed by this virtual server. If enabled, more verbose information
		//  such as client and server headers and request tracing events
		//  will be omitted from the exported data.
		Brief *bool `json:"brief,omitempty"`

		// Export metadata about transactions handled by this service to
		//  the globally configured endpoint. Data will be exported only
		//  if the global "transaction_export!enabled" setting is enabled.
		Enabled *bool `json:"enabled,omitempty"`

		// Whether the transaction processing timeline included in the metadata
		//  export is recorded with a high, microsecond, resolution. If set
		//  to "No", timestamps will be recorded with a resolution of milliseconds.
		HiRes *bool `json:"hi_res,omitempty"`

		// The set of HTTP header names for which corresponding values should
		//  be redacted from the metadata exported by this virtual server.
		HttpHeaderBlacklist *[]string `json:"http_header_blacklist,omitempty"`
	} `json:"transaction_export"`

	Udp struct {
		// Whether UDP datagrams received from the same IP address and port
		//  are sent to the same pool node if they match an existing UDP
		//  session. Sessions are defined by the protocol being handled,
		//  for example SIP datagrams are grouped based on the value of the
		//  Call-ID header.
		EndPointPersistence *bool `json:"end_point_persistence,omitempty"`

		// Whether or not UDP datagrams should be distributed across all
		//  traffic manager processes. This setting is not recommended if
		//  the traffic manager will be handling connection-based UDP protocols.
		PortSmp *bool `json:"port_smp,omitempty"`

		// The virtual server should discard any UDP connection and reclaim
		//  resources when the node has responded with this number of datagrams.
		//   For simple request/response protocols this can be often set
		//  to "1".  If set to "-1", the connection will not be discarded
		//  until the "timeout" is reached.
		ResponseDatagramsExpected *int `json:"response_datagrams_expected,omitempty"`

		// The virtual server should discard any UDP connection and reclaim
		//  resources when no further UDP traffic has been seen within this
		//  time.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"udp"`

	WebCache struct {
		// The "Cache-Control" header to add to every cached HTTP response,
		//  "no-cache" or "max-age=600" for example.
		ControlOut *string `json:"control_out,omitempty"`

		// If set to "Yes" the traffic manager will attempt to cache web
		//  server responses.
		Enabled *bool `json:"enabled,omitempty"`

		// Time period to cache error pages for.
		ErrorPageTime *int `json:"error_page_time,omitempty"`

		// Maximum time period to cache web pages for.
		MaxTime *int `json:"max_time,omitempty"`

		// If a cached page is about to expire within this time, the traffic
		//  manager will start to forward some new requests on to the web
		//  servers. A maximum of one request per second will be forwarded;
		//  the remainder will continue to be served from the cache. This
		//  prevents "bursts" of traffic to your web servers when an item
		//  expires from the cache. Setting this value to "0" will stop the
		//  traffic manager updating the cache before it expires.
		RefreshTime *int `json:"refresh_time,omitempty"`
	} `json:"web_cache"`
}

type VirtualServerProfile struct {
	// The name of an Aptimizer acceleration profile.
	Name *string `json:"name,omitempty"`

	// The application scopes which apply to the acceleration profile.
	Urls *[]string `json:"urls,omitempty"`
}

type VirtualServerProfileTable []VirtualServerProfile

type VirtualServerOcspIssuers struct {
	// Whether the traffic manager should use AIA information contained
	//  in a client certificate to determine which OCSP responder to
	//  contact.
	Aia *bool `json:"aia,omitempty"`

	// The name of an issuer (or DEFAULT for default OCSP settings).
	Issuer *string `json:"issuer,omitempty"`

	// How to use the OCSP nonce extension, which protects against OCSP
	//  replay attacks. Some OCSP servers do not support nonces.
	Nonce *string `json:"nonce,omitempty"`

	// Whether we should do an OCSP check for this issuer, and whether
	//  it is required or optional.
	Required *string `json:"required,omitempty"`

	// The expected responder certificate.
	ResponderCert *string `json:"responder_cert,omitempty"`

	// The certificate with which to sign the request, if any.
	Signer *string `json:"signer,omitempty"`

	// Which OCSP responders this virtual server should use to verify
	//  client certificates.
	Url *string `json:"url,omitempty"`
}

type VirtualServerOcspIssuersTable []VirtualServerOcspIssuers

type VirtualServerServerCertHostMapping struct {
	// The SSL server certificates for a particular destination site
	//  IP.
	AltCertificates *[]string `json:"alt_certificates,omitempty"`

	// The SSL server certificate for a particular destination site
	//  IP.
	Certificate *string `json:"certificate,omitempty"`

	// Host which this entry refers to.
	Host *string `json:"host,omitempty"`
}

type VirtualServerServerCertHostMappingTable []VirtualServerServerCertHostMapping
