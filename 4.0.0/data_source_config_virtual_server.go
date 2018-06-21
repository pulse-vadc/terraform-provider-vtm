// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/4.0"
)

func dataSourceVirtualServer() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVirtualServerRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// Whether or not the virtual server should add an "X-Cluster-Client-Ip"
			//  header to the request that contains the remote client's IP address.
			"add_cluster_ip": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the virtual server should append the remote client's
			//  IP address to the X-Forwarded-For header. If the header does
			//  not exist, it will be added.
			"add_x_forwarded_for": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the virtual server should add an "X-Forwarded-Proto"
			//  header to the request that contains the original protocol used
			//  by the client to connect to the traffic manager.
			"add_x_forwarded_proto": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether the traffic manager should check for HTTP responses that
			//  confirm an HTTP connection is transitioning to the WebSockets
			//  protocol.  If that such a response is detected, the traffic manager
			//  will cease any protocol-specific processing on the connection
			//  and just pass incoming data to the client/server as appropriate.
			"autodetect_upgrade_headers": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The bandwidth management class that this server should use, if
			//  any.
			"bandwidth_class": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether this service should, where possible, bypass data plane
			//  acceleration mechanisms.
			"bypass_data_plane_acceleration": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not connections from clients should be closed with
			//  a RST packet, rather than a FIN packet. This avoids the TIME_WAIT
			//  state, which on rare occasions allows wandering duplicate packets
			//  to be safely ignored.
			"close_with_rst": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Rules that are run at the end of a transaction, in order, comma
			//  separated.
			"completionrules": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The time, in seconds, to wait for data from a new connection.
			//   If no data is received within this time, the connection will
			//  be closed.  A value of "0" (zero) will disable the timeout.
			"connect_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      10,
			},

			// Whether the virtual server is enabled.
			"enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the virtual server should require that incoming
			//  FTP data connections from the nodes originate from the same IP
			//  address as the node.
			"ftp_force_server_secure": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The associated GLB services for this DNS virtual server.
			"glb_services": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Whether to listen on all IP addresses
			"listen_on_any": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Hostnames and IP addresses to listen on
			"listen_on_hosts": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Traffic IP Groups to listen on
			"listen_on_traffic_ips": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The maximum number of concurrent TCP connections that will be
			//  handled by this virtual server. If set to a non-zero value, the
			//  traffic manager will limit the number of concurrent TCP connections
			//  that this virtual server will accept to the value specified.
			//  When the limit is reached, new connections to this virtual server
			//  will not be accepted. If set to "0" the number of concurrent
			//  TCP connections will not be limited.
			"max_concurrent_connections": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// A description for the virtual server.
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The default pool to use for traffic.
			"pool": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The port on which to listen for incoming connections.
			"port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			// The service protection class that should be used to protect this
			//  server, if any.
			"protection_class": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The protocol that the virtual server is using.
			"protocol": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"client_first", "dns", "dns_tcp", "ftp", "http", "https", "imaps", "imapv2", "imapv3", "imapv4", "l4accel_dns", "l4accel_generic", "l4accel_stateless", "l4accel_tcp", "l4accel_udp", "ldap", "ldaps", "pop3", "pop3s", "rtsp", "server_first", "siptcp", "sipudp", "smtp", "ssl", "stream", "telnet", "udp", "udpstreaming"}, false),
				Default:      "http",
			},

			// Expect connections to the traffic manager to be prefixed with
			//  a PROXY protocol header. If enabled, the information contained
			//  in the PROXY header will be available in TrafficScript. Connections
			//  that are not prefixed with a valid PROXY protocol header will
			//  be discarded.
			"proxy_protocol": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Rules to be applied to incoming requests, in order, comma separated.
			"request_rules": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Rules to be applied to responses, in order, comma separated.
			"response_rules": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The service level monitoring class that this server should use,
			//  if any.
			"slm_class": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not Nagle's algorithm should be used for TCP connections.
			"so_nagle": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// What HTTP headers the virtual server should add to each request
			//  to show the data in the client certificate.
			"ssl_client_cert_headers": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"all", "none", "simple"}, false),
				Default:      "none",
			},

			// Whether or not the virtual server should decrypt incoming SSL
			//  traffic.
			"ssl_decrypt": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the Fallback SCSV sent by TLS clients is honored
			//  by this virtual server. Choosing the global setting means the
			//  value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!honor_fallback_scsv">
			//  "ssl!honor_fallback_scsv"</a> from the Global Settings section
			//  of the System tab will be enforced.
			"ssl_honor_fallback_scsv": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not the virtual server should strip the 'X-Forwarded-Proto'
			//  header from incoming requests.
			"strip_x_forwarded_proto": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not bound sockets should be configured for transparent
			//  proxying.
			"transparent": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// When the traffic manager should consider a UDP transaction to
			//  have ended.
			"udp_end_transaction": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"match_requests", "one_response", "timeout"}, false),
				Default:      "one_response",
			},

			// Whether the virtual server should optimize web content.
			"aptimizer_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// A table of Aptimizer profiles and the application scopes that
			//  apply to them.
			"aptimizer_profile": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// urls
						"urls": &schema.Schema{
							Type:     schema.TypeList,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},

			// Whether or not the virtual server should use keepalive connections
			//  with the remote clients.
			"connection_keepalive": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The length of time that the virtual server should keep an idle
			//  keepalive connection before discarding it.  A value of "0" (zero)
			//  will mean that the keepalives are never closed by the traffic
			//  manager.
			"connection_keepalive_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      10,
			},

			// The amount of memory, in bytes, that the virtual server should
			//  use to store data sent by the client. Larger values will use
			//  more memory, but will minimise the number of "read()" and "write()"
			//  system calls that the traffic manager must perform.
			"connection_max_client_buffer": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1024, 16777216),
				Default:      65536,
			},

			// The amount of memory, in bytes, that the virtual server should
			//  use to store data returned by the server.  Larger values will
			//  use more memory, but will minimise the number of "read()" and
			//  "write()" system calls that the traffic manager must perform.
			"connection_max_server_buffer": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1024, 16777216),
				Default:      65536,
			},

			// The total amount of time a transaction can take, counted from
			//  the first byte being received until the transaction is complete.
			//   For HTTP, this can mean all data has been written in both directions,
			//  or the connection has been closed; in most other cases it is
			//  the same as the connection being closed.<br> The default value
			//  of "0" means there is no maximum duration, i.e., transactions
			//  can take arbitrarily long if none of the other timeouts occur.
			"connection_max_transaction_duration": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      0,
			},

			// If specified, the traffic manager will use the value as the banner
			//  to send for server-first protocols such as FTP, POP, SMTP and
			//  IMAP. This allows rules to use the first part of the client data
			//  (such as the username) to select a pool. The banner should be
			//  in the correct format for the protocol, e.g. for FTP it should
			//  start with "220 "
			"connection_server_first_banner": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A connection should be closed if no additional data has been
			//  received for this period of time.  A value of "0" (zero) will
			//  disable this timeout.
			"connection_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      300,
			},

			// The error message to be sent to the client when the traffic manager
			//  detects an internal or backend error for the virtual server.
			"connection_errors_error_file": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "Default",
			},

			// The way in which the traffic manager should rewrite the domain
			//  portion of any cookies set by a back-end web server.
			"cookie_domain": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"no_rewrite", "set_to_named", "set_to_request"}, false),
				Default:      "no_rewrite",
			},

			// The domain to use when rewriting a cookie's domain to a named
			//  value.
			"cookie_new_domain": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// If you wish to rewrite the path portion of any cookies set by
			//  a back-end web server, provide a regular expression to match
			//  the path:
			"cookie_path_regex": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// If cookie path regular expression matches, it will be replaced
			//  by this substitution.  Parameters $1-$9 can be used to represent
			//  bracketed parts of the regular expression.
			"cookie_path_replace": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not the traffic manager should modify the "secure"
			//  tag of any cookies set by a back-end web server.
			"cookie_secure": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"no_modify", "set_secure", "unset_secure"}, false),
				Default:      "no_modify",
			},

			// Enable/Disable use of EDNS client subnet option
			"dns_edns_client_subnet": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// EDNS UDP size advertised in responses.
			"dns_edns_udpsize": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(512, 4096),
				Default:      4096,
			},

			// Maximum UDP answer size.
			"dns_max_udpsize": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(512, 4096),
				Default:      4096,
			},

			// Response record ordering.
			"dns_rrset_order": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"cyclic", "fixed"}, false),
				Default:      "fixed",
			},

			// Whether or not the DNS Server should emit verbose logging. This
			//  is useful for diagnosing problems.
			"dns_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The DNS zones
			"dns_zones": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The source port to be used for active-mode FTP data connections.
			//   If 0, a random high port will be used, otherwise the specified
			//  port will be used. If a port below 1024 is required you must
			//  first explicitly permit use of low ports with the "data_bind_low"
			//  global setting.
			"ftp_data_source_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// Whether or not the virtual server should require that incoming
			//  FTP data connections from the client originate from the same
			//  IP address as the corresponding client control connection.
			"ftp_force_client_secure": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// If non-zero, then this controls the upper bound of the port range
			//  to use for FTP data connections.
			"ftp_port_range_high": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// If non-zero, then this controls the lower bound of the port range
			//  to use for FTP data connections.
			"ftp_port_range_low": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// Use SSL on the data connection as well as the control connection
			//  (if not enabled it is left to the client and server to negotiate
			//  this).
			"ftp_ssl_data": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Compression level (1-9, 1=low, 9=high).
			"gzip_compress_level": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 9),
				Default:      1,
			},

			// Compress web pages sent back by the server.
			"gzip_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// How the ETag header should be manipulated when compressing content.
			"gzip_etag_rewrite": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"delete", "ignore", "weaken", "wrap"}, false),
				Default:      "wrap",
			},

			// MIME types to compress. Complete MIME types can be used, or a
			//  type can end in a '*' to match multiple types.
			"gzip_include_mime": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// Maximum document size to compress (0 means unlimited).
			"gzip_max_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      10000000,
			},

			// Minimum document size to compress.
			"gzip_min_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      1000,
			},

			// Compress documents with no given size.
			"gzip_no_size": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Handling of HTTP chunk overhead.  When vTM receives data from
			//  a server or client that consists purely of protocol overhead
			//  (contains no payload), forwarding of such segments is delayed
			//  until useful payload data arrives (setting "lazy").  Changing
			//  this key to "eager" will make vTM incur the overhead of immediately
			//  passing such data on; it should only be used with HTTP peers
			//  whose chunk handling requires it.
			"http_chunk_overhead_forwarding": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"eager", "lazy"}, false),
				Default:      "lazy",
			},

			// If the 'Location' header matches this regular expression, rewrite
			//  the header using the 'location_replace' pattern.
			"http_location_regex": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// If the 'Location' header matches the 'location_regex' regular
			//  expression, rewrite the header with this pattern (parameters
			//  such as $1-$9 can be used to match parts of the regular expression):
			"http_location_replace": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The action the virtual server should take if the "Location" header
			//  does not match the "location_regex" regular expression.
			"http_location_rewrite": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"always", "if_host_matches", "never"}, false),
				Default:      "if_host_matches",
			},

			// Auto-correct MIME types if the server sends the "default" MIME
			//  type for files.
			"http_mime_default": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "text/plain",
			},

			// Auto-detect MIME types if the server does not provide them.
			"http_mime_detect": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The time, in seconds, to wait for a request on a new HTTP/2 connection.
			//   If no request is received within this time, the connection will
			//  be closed. This setting overrides the "connect_timeout" setting.
			//  If set to "0" (zero), the value of "connect_timeout" will be
			//  used instead.
			"http2_connect_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      0,
			},

			// This setting controls the preferred frame size used when sending
			//  body data to the client. If the client specifies a smaller maximum
			//  size than this setting, the client's maximum size will be used.
			//  Every data frame sent has at least a 9-byte header, in addition
			//  to this frame size, prepended to it.
			"http2_data_frame_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(100, 16777206),
				Default:      4096,
			},

			// This setting allows the HTTP/2 protocol to be used by a HTTP
			//  virtual server. Unless use of HTTP/2 is negotiated by the client,
			//  the virtual server will fall back to HTTP 1.x automatically.
			"http2_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// This setting controls the amount of memory allowed for header
			//  compression on each HTTP/2 connection.
			"http2_header_table_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(4096, 1048576),
				Default:      4096,
			},

			// A list of header names that should never be compressed using
			//  indexing.
			"http2_headers_index_blacklist": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The HTTP/2 HPACK compression scheme allows for HTTP headers to
			//  be compressed using indexing. Sensitive headers can be marked
			//  as "never index", which prevents them from being compressed using
			//  indexing. When this setting is "Yes", only headers included in
			//  "http2!headers_index_blacklist" are marked as "never index".
			//  When this setting is "No", all headers will be marked as "never
			//  index" unless they are included in "http2!headers_index_whitelist".
			"http2_headers_index_default": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// A list of header names that can be compressed using indexing
			//  when the value of "http2!headers_index_default" is set to "No".
			"http2_headers_index_whitelist": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The maximum size, in bytes, of decompressed headers for an HTTP/2
			//  request. If the limit is exceeded, the connection on which the
			//  request was sent will be dropped. A value of 0 disables the limit
			//  check. If a service protection class with "http!max_header_length"
			//  configured is associated with this service then that setting
			//  will take precedence.
			"http2_headers_size_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      262144,
			},

			// The time, in seconds, to wait for a new HTTP/2 request on a previously
			//  used HTTP/2 connection that has no open HTTP/2 streams. If an
			//  HTTP/2 request is not received within this time, the connection
			//  will be closed. A value of "0" (zero) will disable the timeout.
			"http2_idle_timeout_no_streams": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      120,
			},

			// The time, in seconds, to wait for data on an idle HTTP/2 connection,
			//  which has open streams, when no data has been sent recently (e.g.
			//  for long-polled requests). If data is not sent within this time,
			//  all open streams and the HTTP/2 connection will be closed. A
			//  value of "0" (zero) will disable the timeout.
			"http2_idle_timeout_open_streams": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      600,
			},

			// This setting controls the number of streams a client is permitted
			//  to open concurrently on a single connection.
			"http2_max_concurrent_streams": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      200,
			},

			// This setting controls the maximum HTTP/2 frame size clients are
			//  permitted to send to the traffic manager.
			"http2_max_frame_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(16384, 16777215),
				Default:      16384,
			},

			// The maximum size, in bytes, of the random-length padding to add
			//  to HTTP/2 header frames. The padding, a random number of zero
			//  bytes up to the maximum specified.
			"http2_max_header_padding": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 256),
				Default:      0,
			},

			// Whether Cookie headers received from an HTTP/2 client should
			//  be merged into a single Cookie header using RFC6265 rules before
			//  forwarding to an HTTP/1.1 server. Some web applications do not
			//  handle multiple Cookie headers correctly.
			"http2_merge_cookie_headers": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// This setting controls the flow control window for each HTTP/2
			//  stream. This will limit the memory used for buffering when the
			//  client is sending body data faster than the pool node is reading
			//  it.
			"http2_stream_window_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      65535,
			},

			// Whether or not the virtual server should use Kerberos Protocol
			//  Transition.
			"kerberos_protocol_transition_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The Kerberos principal this virtual server should use to perform
			//  Kerberos Protocol Transition.
			"kerberos_protocol_transition_principal": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The Kerberos principal name of the service this virtual server
			//  targets.
			"kerberos_protocol_transition_target": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether the virtual server should send a TCP RST packet or ICMP
			//  error message if a service is unavailable, or if an established
			//  connection to a node fails.
			"l4accel_rst_on_service_failure": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not backend connections should be configured to use
			//  the ingress service IP as the source IP for the back-end connection
			//  when Source NAT is enabled for the pool used by the service.
			//  Requires l4accel!state_sync to be enabled.
			"l4accel_service_ip_snat": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether the state of active connections will be synchronized
			//  across the cluster for L4Accel services, such that connections
			//  will persist in the event of a failover. Note that the service
			//  must listen only on Traffic IP groups for this setting to be
			//  enabled.
			"l4accel_state_sync": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The maximum segment lifetime, in seconds, of a TCP segment being
			//  handled by the traffic manager. This setting determines for how
			//  long information about a connection will be retained after receiving
			//  a two-way FIN or RST.
			"l4accel_tcp_msl": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 60),
				Default:      8,
			},

			// The number of seconds after which a connection will be closed
			//  if no further packets have been received on it.
			"l4accel_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(120, 3600),
				Default:      1800,
			},

			// Whether a connection should be closed when the number of UDP
			//  response datagrams received from the server is equal to the number
			//  of request datagrams that have been sent by the client. If set
			//  to "No" the connection will be closed after the first response
			//  has been received from the server. This setting takes precedence
			//  over "l4accel!optimized_aging" setting.
			"l4accel_udp_count_requests": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Should the virtual server log failures occurring on connections
			//  to clients.
			"log_client_connection_failures": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not to log connections to the virtual server to a
			//  disk on the file system.
			"log_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The name of the file in which to store the request logs. The
			//  filename can contain macros which will be expanded by the traffic
			//  manager to generate the full filename.
			"log_filename": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "%zeushome%/zxtm/log/%v.log",
			},

			// The log file format. This specifies the line of text that will
			//  be written to the log file when a connection to the traffic manager
			//  is completed.  Many parameters from the connection can be recorded
			//  using macros.
			"log_format": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"",
			},

			// Whether to log all connections by default, or log no connections
			//  by default. Specific connections can be selected for addition
			//  to or exclusion from the log using the TrafficScript function
			//  "requestlog.include()".
			"log_save_all": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Should the virtual server log failures occurring on connections
			//  to nodes.
			"log_server_connection_failures": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Should the virtual server log session persistence events.
			"log_session_persistence_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Should the virtual server log failures occurring on SSL secure
			//  negotiation.
			"log_ssl_failures": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not connections handled by this virtual server should
			//  be shown on the Activity > Connections page.
			"recent_connections_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not all connections handled by this virtual server
			//  should be shown on the Connections page. Individual connections
			//  can be selectively shown on the Connections page using the "recentconns.include()"
			//  TrafficScript function.
			"recent_connections_save_all": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Record a trace of major connection processing events for each
			//  request and response.
			"request_tracing_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Include details of individual I/O events in request and response
			//  traces.  Requires request tracing to be enabled.
			"request_tracing_trace_io": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// If non-zero this controls the upper bound of the port range to
			//  use for streaming data connections.
			"rtsp_streaming_port_range_high": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// If non-zero this controls the lower bound of the port range to
			//  use for streaming data connections.
			"rtsp_streaming_port_range_low": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// If non-zero data-streams associated with RTSP connections will
			//  timeout if no data is transmitted for this many seconds.
			"rtsp_streaming_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      30,
			},

			// The action to take when a SIP request with body data arrives
			//  that should be routed to an external IP.
			"sip_dangerous_requests": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"forbid", "forward", "node"}, false),
				Default:      "node",
			},

			// Should the virtual server follow routing information contained
			//  in SIP requests. If set to "No" requests will be routed to the
			//  chosen back-end node regardless of their URI or Route header.
			"sip_follow_route": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// SIP clients can have several pending requests at one time. To
			//  protect the traffic manager against DoS attacks, this setting
			//  limits the amount of memory each client can use.  When the limit
			//  is reached new requests will be sent a 413 response. If the value
			//  is set to "0" (zero) the memory limit is disabled.
			"sip_max_connection_mem": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 16777216),
				Default:      65536,
			},

			// The mode that this SIP virtual server should operate in.
			"sip_mode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"full_gateway", "route", "sip_gateway"}, false),
				Default:      "sip_gateway",
			},

			// Replace the Request-URI of SIP requests with the address of the
			//  selected back-end node.
			"sip_rewrite_uri": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// If non-zero this controls the upper bound of the port range to
			//  use for streaming data connections.
			"sip_streaming_port_range_high": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// If non-zero, then this controls the lower bound of the port range
			//  to use for streaming data connections.
			"sip_streaming_port_range_low": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 65535),
				Default:      0,
			},

			// If non-zero a UDP stream will timeout when no data has been seen
			//  within this time.
			"sip_streaming_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      60,
			},

			// When timing out a SIP transaction, send a 'timed out' response
			//  to the client and, in the case of an INVITE transaction, a CANCEL
			//  request to the server.
			"sip_timeout_messages": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The virtual server should discard a SIP transaction when no further
			//  messages have been seen within this time.
			"sip_transaction_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      30,
			},

			// Whether or not the traffic manager should expect the connection
			//  to start off in plain text and then upgrade to SSL using STARTTLS
			//  when handling SMTP traffic.
			"smtp_expect_starttls": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the virtual server should add HTTP headers to
			//  each request to show the SSL connection parameters.
			"ssl_add_http_headers": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The certificate authorities that this virtual server should trust
			//  to validate client certificates. If no certificate authorities
			//  are selected, and client certificates are requested, then all
			//  client certificates will be accepted.
			"ssl_client_cert_cas": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The SSL elliptic curve preference list for SSL connections to
			//  this virtual server using TLS version 1.0 or higher. Leaving
			//  this empty will make the virtual server use the globally configured
			//  curve preference list. The named curves P256, P384 and P521 may
			//  be configured.
			"ssl_elliptic_curves": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// When the virtual server verifies certificates signed by these
			//  certificate authorities, it doesn't check the 'not after' date,
			//  i.e., they are considered valid even after their expiration date
			//  has passed (but not if they have been revoked).
			"ssl_issued_certs_never_expire": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

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
			"ssl_issued_certs_never_expire_depth": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      1,
			},

			// Whether or not the traffic manager should use OCSP to check the
			//  revocation status of client certificates.
			"ssl_ocsp_enable": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// A table of certificate issuer specific OCSP settings.
			"ssl_ocsp_issuers": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// aia
						"aia": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},

						// issuer
						"issuer": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// nonce
						"nonce": &schema.Schema{
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice([]string{"off", "on", "strict"}, false),
							Default:      "off",
						},

						// required
						"required": &schema.Schema{
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice([]string{"none", "optional", "strict"}, false),
							Default:      "optional",
						},

						// responder_cert
						"responder_cert": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// signer
						"signer": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// url
						"url": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},

			// The number of seconds for which an OCSP response is considered
			//  valid if it has not yet exceeded the time specified in the 'nextUpdate'
			//  field. If set to "0" (zero) then OCSP responses are considered
			//  valid until the time specified in their 'nextUpdate' field.
			"ssl_ocsp_max_response_age": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// If OCSP URIs are present in certificates used by this virtual
			//  server, then enabling this option will allow the traffic manager
			//  to provide OCSP responses for these certificates as part of the
			//  handshake, if the client sends a TLS status_request extension
			//  in the ClientHello.
			"ssl_ocsp_stapling": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The number of seconds outside the permitted range for which the
			//  'thisUpdate' and 'nextUpdate' fields of an OCSP response are
			//  still considered valid.
			"ssl_ocsp_time_tolerance": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      30,
			},

			// The number of seconds after which OCSP requests will be timed
			//  out.
			"ssl_ocsp_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      10,
			},

			// Deprecated. Formerly allowed a preference for SSLv3 for performance
			//  reasons.
			"ssl_prefer_sslv3": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the virtual server should request an identifying
			//  SSL certificate from each client.
			"ssl_request_client_cert": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"dont_request", "request", "require"}, false),
				Default:      "dont_request",
			},

			// Whether or not to send an SSL/TLS "close alert" when the traffic
			//  manager is initiating an SSL socket disconnection.
			"ssl_send_close_alerts": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The SSL certificates and corresponding private keys.
			"ssl_server_cert_alt_certificates": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The default SSL certificate to use for this virtual server.
			"ssl_server_cert_default": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Host specific SSL server certificate mappings.
			"ssl_server_cert_host_mapping": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// alt_certificates
						"alt_certificates": &schema.Schema{
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Default:  nil,
						},

						// certificate
						"certificate": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// host
						"host": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// The SSL signature algorithms preference list for SSL connections
			//  to this virtual server using TLS version 1.2 or higher. Leaving
			//  this empty will make the virtual server use the globally configured
			//  preference list, "signature_algorithms" in the "ssl" section
			//  of the "global_settings" resource.  See there and in the online
			//  help for how to specify SSL signature algorithms.
			"ssl_signature_algorithms": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The SSL/TLS ciphers to allow for connections to this virtual
			//  server.  Leaving this empty will make the virtual server use
			//  the globally configured ciphers, see configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!ssl3_ciphers">
			//  "ssl!ssl3_ciphers"</a> in the Global Settings section of the
			//  System tab.  See there for how to specify SSL/TLS ciphers.
			"ssl_ssl_ciphers": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// No longer supported. Formerly controlled whether SSLv2 could
			//  be used for SSL connections to this virtual server.
			"ssl_ssl_support_ssl2": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not SSLv3 is enabled for this virtual server.  Choosing
			//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_ssl3">
			//  "ssl!support_ssl3"</a> from the Global Settings section of the
			//  System tab will be enforced.
			"ssl_ssl_support_ssl3": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not TLSv1.0 is enabled for this virtual server. Choosing
			//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1">
			//  "ssl!support_tls1"</a> from the Global Settings section of the
			//  System tab will be enforced.
			"ssl_ssl_support_tls1": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not TLSv1.1 is enabled for this virtual server. Choosing
			//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1.1">
			//  "ssl!support_tls1.1"</a> from the Global Settings section of
			//  the System tab will be enforced.
			"ssl_ssl_support_tls1_1": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not TLSv1.2 is enabled for this virtual server. Choosing
			//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1.2">
			//  "ssl!support_tls1.2"</a> from the Global Settings section of
			//  the System tab will be enforced.
			"ssl_ssl_support_tls1_2": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// If the traffic manager is receiving traffic sent from another
			//  traffic manager, then enabling this option will allow it to decode
			//  extra information on the true origin of the SSL connection. This
			//  information is supplied by the first traffic manager.
			"ssl_trust_magic": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not to log connections to the virtual server to a
			//  remote syslog host.
			"syslog_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The log format for the remote syslog.  This specifies the line
			//  of text that will be sent to the remote syslog  when a connection
			//  to the traffic manager is completed. Many parameters from the
			//  connection can be recorded using macros.
			"syslog_format": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"",
			},

			// The remote host and port (default is 514) to send request log
			//  lines to.
			"syslog_ip_end_point": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Maximum length in bytes of a message sent to the remote syslog.
			//  Messages longer than this will be truncated before they are sent.
			"syslog_msg_len_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(480, 65535),
				Default:      1024,
			},

			// If set to "Yes" the traffic manager will send the client FIN
			//  to the back-end server and wait for a server response instead
			//  of closing the connection immediately.  This is only necessary
			//  for protocols that require half-close support to function correctly,
			//  such as "rsh".  If the traffic manager is responding to the request
			//  itself, setting this key to Yes will cause the traffic manager
			//  to continue writing the response even after it has received a
			//  FIN from the client.
			"tcp_proxy_close": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether to export a restricted set of metadata about transactions
			//  processed by this virtual server. If enabled, more verbose information
			//  such as client and server headers and request tracing events
			//  will be omitted from the exported data.
			"transaction_export_brief": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Export metadata about transactions handled by this service to
			//  the globally configured endpoint. Data will be exported only
			//  if the global "transaction_export!enabled" setting is enabled.
			"transaction_export_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether the transaction processing timeline included in the metadata
			//  export is recorded with a high, microsecond, resolution. If set
			//  to "No", timestamps will be recorded with a resolution of milliseconds.
			"transaction_export_hi_res": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The set of HTTP header names for which corresponding values should
			//  be redacted from the metadata exported by this virtual server.
			"transaction_export_http_header_blacklist": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// Whether UDP datagrams received from the same IP address and port
			//  are sent to the same pool node if they match an existing UDP
			//  session. Sessions are defined by the protocol being handled,
			//  for example SIP datagrams are grouped based on the value of the
			//  Call-ID header.
			"udp_end_point_persistence": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not UDP datagrams should be distributed across all
			//  traffic manager processes. This setting is not recommended if
			//  the traffic manager will be handling connection-based UDP protocols.
			"udp_port_smp": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The virtual server should discard any UDP connection and reclaim
			//  resources when the node has responded with this number of datagrams.
			//   For simple request/response protocols this can be often set
			//  to "1".  If set to "-1", the connection will not be discarded
			//  until the "timeout" is reached.
			"udp_response_datagrams_expected": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				Default:  1,
			},

			// The virtual server should discard any UDP connection and reclaim
			//  resources when no further UDP traffic has been seen within this
			//  time.
			"udp_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      7,
			},

			// The "Cache-Control" header to add to every cached HTTP response,
			//  "no-cache" or "max-age=600" for example.
			"web_cache_control_out": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// If set to "Yes" the traffic manager will attempt to cache web
			//  server responses.
			"web_cache_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Time period to cache error pages for.
			"web_cache_error_page_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      30,
			},

			// Maximum time period to cache web pages for.
			"web_cache_max_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      600,
			},

			// If a cached page is about to expire within this time, the traffic
			//  manager will start to forward some new requests on to the web
			//  servers. A maximum of one request per second will be forwarded;
			//  the remainder will continue to be served from the cache. This
			//  prevents "bursts" of traffic to your web servers when an item
			//  expires from the cache. Setting this value to "0" will stop the
			//  traffic manager updating the cache before it expires.
			"web_cache_refresh_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      2,
			},
		},
	}
}

func dataSourceVirtualServerRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetVirtualServer(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_virtual_server '%v': %v", objectName, err.ErrorText)
	}
	d.Set("add_cluster_ip", bool(*object.Basic.AddClusterIp))
	d.Set("add_x_forwarded_for", bool(*object.Basic.AddXForwardedFor))
	d.Set("add_x_forwarded_proto", bool(*object.Basic.AddXForwardedProto))
	d.Set("autodetect_upgrade_headers", bool(*object.Basic.AutodetectUpgradeHeaders))
	d.Set("bandwidth_class", string(*object.Basic.BandwidthClass))
	d.Set("bypass_data_plane_acceleration", bool(*object.Basic.BypassDataPlaneAcceleration))
	d.Set("close_with_rst", bool(*object.Basic.CloseWithRst))
	d.Set("completionrules", []string(*object.Basic.Completionrules))
	d.Set("connect_timeout", int(*object.Basic.ConnectTimeout))
	d.Set("enabled", bool(*object.Basic.Enabled))
	d.Set("ftp_force_server_secure", bool(*object.Basic.FtpForceServerSecure))
	d.Set("glb_services", []string(*object.Basic.GlbServices))
	d.Set("listen_on_any", bool(*object.Basic.ListenOnAny))
	d.Set("listen_on_hosts", []string(*object.Basic.ListenOnHosts))
	d.Set("listen_on_traffic_ips", []string(*object.Basic.ListenOnTrafficIps))
	d.Set("max_concurrent_connections", int(*object.Basic.MaxConcurrentConnections))
	d.Set("note", string(*object.Basic.Note))
	d.Set("pool", string(*object.Basic.Pool))
	d.Set("port", int(*object.Basic.Port))
	d.Set("protection_class", string(*object.Basic.ProtectionClass))
	d.Set("protocol", string(*object.Basic.Protocol))
	d.Set("proxy_protocol", bool(*object.Basic.ProxyProtocol))
	d.Set("request_rules", []string(*object.Basic.RequestRules))
	d.Set("response_rules", []string(*object.Basic.ResponseRules))
	d.Set("slm_class", string(*object.Basic.SlmClass))
	d.Set("so_nagle", bool(*object.Basic.SoNagle))
	d.Set("ssl_client_cert_headers", string(*object.Basic.SslClientCertHeaders))
	d.Set("ssl_decrypt", bool(*object.Basic.SslDecrypt))
	d.Set("ssl_honor_fallback_scsv", string(*object.Basic.SslHonorFallbackScsv))
	d.Set("strip_x_forwarded_proto", bool(*object.Basic.StripXForwardedProto))
	d.Set("transparent", bool(*object.Basic.Transparent))
	d.Set("udp_end_transaction", string(*object.Basic.UdpEndTransaction))
	d.Set("aptimizer_enabled", bool(*object.Aptimizer.Enabled))

	aptimizerProfile := make([]map[string]interface{}, 0, len(*object.Aptimizer.Profile))
	for _, item := range *object.Aptimizer.Profile {
		itemTerraform := make(map[string]interface{})
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Urls != nil {
			itemTerraform["urls"] = []string(*item.Urls)
		}
		aptimizerProfile = append(aptimizerProfile, itemTerraform)
	}
	d.Set("aptimizer_profile", aptimizerProfile)
	aptimizerProfileJson, _ := json.Marshal(aptimizerProfile)
	d.Set("aptimizer_profile_json", aptimizerProfileJson)
	d.Set("connection_keepalive", bool(*object.Connection.Keepalive))
	d.Set("connection_keepalive_timeout", int(*object.Connection.KeepaliveTimeout))
	d.Set("connection_max_client_buffer", int(*object.Connection.MaxClientBuffer))
	d.Set("connection_max_server_buffer", int(*object.Connection.MaxServerBuffer))
	d.Set("connection_max_transaction_duration", int(*object.Connection.MaxTransactionDuration))
	d.Set("connection_server_first_banner", string(*object.Connection.ServerFirstBanner))
	d.Set("connection_timeout", int(*object.Connection.Timeout))
	d.Set("connection_errors_error_file", string(*object.ConnectionErrors.ErrorFile))
	d.Set("cookie_domain", string(*object.Cookie.Domain))
	d.Set("cookie_new_domain", string(*object.Cookie.NewDomain))
	d.Set("cookie_path_regex", string(*object.Cookie.PathRegex))
	d.Set("cookie_path_replace", string(*object.Cookie.PathReplace))
	d.Set("cookie_secure", string(*object.Cookie.Secure))
	d.Set("dns_edns_client_subnet", bool(*object.Dns.EdnsClientSubnet))
	d.Set("dns_edns_udpsize", int(*object.Dns.EdnsUdpsize))
	d.Set("dns_max_udpsize", int(*object.Dns.MaxUdpsize))
	d.Set("dns_rrset_order", string(*object.Dns.RrsetOrder))
	d.Set("dns_verbose", bool(*object.Dns.Verbose))
	d.Set("dns_zones", []string(*object.Dns.Zones))
	d.Set("ftp_data_source_port", int(*object.Ftp.DataSourcePort))
	d.Set("ftp_force_client_secure", bool(*object.Ftp.ForceClientSecure))
	d.Set("ftp_port_range_high", int(*object.Ftp.PortRangeHigh))
	d.Set("ftp_port_range_low", int(*object.Ftp.PortRangeLow))
	d.Set("ftp_ssl_data", bool(*object.Ftp.SslData))
	d.Set("gzip_compress_level", int(*object.Gzip.CompressLevel))
	d.Set("gzip_enabled", bool(*object.Gzip.Enabled))
	d.Set("gzip_etag_rewrite", string(*object.Gzip.EtagRewrite))
	d.Set("gzip_include_mime", []string(*object.Gzip.IncludeMime))
	d.Set("gzip_max_size", int(*object.Gzip.MaxSize))
	d.Set("gzip_min_size", int(*object.Gzip.MinSize))
	d.Set("gzip_no_size", bool(*object.Gzip.NoSize))
	d.Set("http_chunk_overhead_forwarding", string(*object.Http.ChunkOverheadForwarding))
	d.Set("http_location_regex", string(*object.Http.LocationRegex))
	d.Set("http_location_replace", string(*object.Http.LocationReplace))
	d.Set("http_location_rewrite", string(*object.Http.LocationRewrite))
	d.Set("http_mime_default", string(*object.Http.MimeDefault))
	d.Set("http_mime_detect", bool(*object.Http.MimeDetect))
	d.Set("http2_connect_timeout", int(*object.Http2.ConnectTimeout))
	d.Set("http2_data_frame_size", int(*object.Http2.DataFrameSize))
	d.Set("http2_enabled", bool(*object.Http2.Enabled))
	d.Set("http2_header_table_size", int(*object.Http2.HeaderTableSize))
	d.Set("http2_headers_index_blacklist", []string(*object.Http2.HeadersIndexBlacklist))
	d.Set("http2_headers_index_default", bool(*object.Http2.HeadersIndexDefault))
	d.Set("http2_headers_index_whitelist", []string(*object.Http2.HeadersIndexWhitelist))
	d.Set("http2_headers_size_limit", int(*object.Http2.HeadersSizeLimit))
	d.Set("http2_idle_timeout_no_streams", int(*object.Http2.IdleTimeoutNoStreams))
	d.Set("http2_idle_timeout_open_streams", int(*object.Http2.IdleTimeoutOpenStreams))
	d.Set("http2_max_concurrent_streams", int(*object.Http2.MaxConcurrentStreams))
	d.Set("http2_max_frame_size", int(*object.Http2.MaxFrameSize))
	d.Set("http2_max_header_padding", int(*object.Http2.MaxHeaderPadding))
	d.Set("http2_merge_cookie_headers", bool(*object.Http2.MergeCookieHeaders))
	d.Set("http2_stream_window_size", int(*object.Http2.StreamWindowSize))
	d.Set("kerberos_protocol_transition_enabled", bool(*object.KerberosProtocolTransition.Enabled))
	d.Set("kerberos_protocol_transition_principal", string(*object.KerberosProtocolTransition.Principal))
	d.Set("kerberos_protocol_transition_target", string(*object.KerberosProtocolTransition.Target))
	d.Set("l4accel_rst_on_service_failure", bool(*object.L4Accel.RstOnServiceFailure))
	d.Set("l4accel_service_ip_snat", bool(*object.L4Accel.ServiceIpSnat))
	d.Set("l4accel_state_sync", bool(*object.L4Accel.StateSync))
	d.Set("l4accel_tcp_msl", int(*object.L4Accel.TcpMsl))
	d.Set("l4accel_timeout", int(*object.L4Accel.Timeout))
	d.Set("l4accel_udp_count_requests", bool(*object.L4Accel.UdpCountRequests))
	d.Set("log_client_connection_failures", bool(*object.Log.ClientConnectionFailures))
	d.Set("log_enabled", bool(*object.Log.Enabled))
	d.Set("log_filename", string(*object.Log.Filename))
	d.Set("log_format", string(*object.Log.Format))
	d.Set("log_save_all", bool(*object.Log.SaveAll))
	d.Set("log_server_connection_failures", bool(*object.Log.ServerConnectionFailures))
	d.Set("log_session_persistence_verbose", bool(*object.Log.SessionPersistenceVerbose))
	d.Set("log_ssl_failures", bool(*object.Log.SslFailures))
	d.Set("recent_connections_enabled", bool(*object.RecentConnections.Enabled))
	d.Set("recent_connections_save_all", bool(*object.RecentConnections.SaveAll))
	d.Set("request_tracing_enabled", bool(*object.RequestTracing.Enabled))
	d.Set("request_tracing_trace_io", bool(*object.RequestTracing.TraceIo))
	d.Set("rtsp_streaming_port_range_high", int(*object.Rtsp.StreamingPortRangeHigh))
	d.Set("rtsp_streaming_port_range_low", int(*object.Rtsp.StreamingPortRangeLow))
	d.Set("rtsp_streaming_timeout", int(*object.Rtsp.StreamingTimeout))
	d.Set("sip_dangerous_requests", string(*object.Sip.DangerousRequests))
	d.Set("sip_follow_route", bool(*object.Sip.FollowRoute))
	d.Set("sip_max_connection_mem", int(*object.Sip.MaxConnectionMem))
	d.Set("sip_mode", string(*object.Sip.Mode))
	d.Set("sip_rewrite_uri", bool(*object.Sip.RewriteUri))
	d.Set("sip_streaming_port_range_high", int(*object.Sip.StreamingPortRangeHigh))
	d.Set("sip_streaming_port_range_low", int(*object.Sip.StreamingPortRangeLow))
	d.Set("sip_streaming_timeout", int(*object.Sip.StreamingTimeout))
	d.Set("sip_timeout_messages", bool(*object.Sip.TimeoutMessages))
	d.Set("sip_transaction_timeout", int(*object.Sip.TransactionTimeout))
	d.Set("smtp_expect_starttls", bool(*object.Smtp.ExpectStarttls))
	d.Set("ssl_add_http_headers", bool(*object.Ssl.AddHttpHeaders))
	d.Set("ssl_client_cert_cas", []string(*object.Ssl.ClientCertCas))
	d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	d.Set("ssl_issued_certs_never_expire", []string(*object.Ssl.IssuedCertsNeverExpire))
	d.Set("ssl_issued_certs_never_expire_depth", int(*object.Ssl.IssuedCertsNeverExpireDepth))
	d.Set("ssl_ocsp_enable", bool(*object.Ssl.OcspEnable))

	sslOcspIssuers := make([]map[string]interface{}, 0, len(*object.Ssl.OcspIssuers))
	for _, item := range *object.Ssl.OcspIssuers {
		itemTerraform := make(map[string]interface{})
		if item.Aia != nil {
			itemTerraform["aia"] = bool(*item.Aia)
		}
		if item.Issuer != nil {
			itemTerraform["issuer"] = string(*item.Issuer)
		}
		if item.Nonce != nil {
			itemTerraform["nonce"] = string(*item.Nonce)
		}
		if item.Required != nil {
			itemTerraform["required"] = string(*item.Required)
		}
		if item.ResponderCert != nil {
			itemTerraform["responder_cert"] = string(*item.ResponderCert)
		}
		if item.Signer != nil {
			itemTerraform["signer"] = string(*item.Signer)
		}
		if item.Url != nil {
			itemTerraform["url"] = string(*item.Url)
		}
		sslOcspIssuers = append(sslOcspIssuers, itemTerraform)
	}
	d.Set("ssl_ocsp_issuers", sslOcspIssuers)
	sslOcspIssuersJson, _ := json.Marshal(sslOcspIssuers)
	d.Set("ssl_ocsp_issuers_json", sslOcspIssuersJson)
	d.Set("ssl_ocsp_max_response_age", int(*object.Ssl.OcspMaxResponseAge))
	d.Set("ssl_ocsp_stapling", bool(*object.Ssl.OcspStapling))
	d.Set("ssl_ocsp_time_tolerance", int(*object.Ssl.OcspTimeTolerance))
	d.Set("ssl_ocsp_timeout", int(*object.Ssl.OcspTimeout))
	d.Set("ssl_prefer_sslv3", bool(*object.Ssl.PreferSslv3))
	d.Set("ssl_request_client_cert", string(*object.Ssl.RequestClientCert))
	d.Set("ssl_send_close_alerts", bool(*object.Ssl.SendCloseAlerts))
	d.Set("ssl_server_cert_alt_certificates", []string(*object.Ssl.ServerCertAltCertificates))
	d.Set("ssl_server_cert_default", string(*object.Ssl.ServerCertDefault))

	sslServerCertHostMapping := make([]map[string]interface{}, 0, len(*object.Ssl.ServerCertHostMapping))
	for _, item := range *object.Ssl.ServerCertHostMapping {
		itemTerraform := make(map[string]interface{})
		if item.AltCertificates != nil {
			itemTerraform["alt_certificates"] = []string(*item.AltCertificates)
		}
		if item.Certificate != nil {
			itemTerraform["certificate"] = string(*item.Certificate)
		}
		if item.Host != nil {
			itemTerraform["host"] = string(*item.Host)
		}
		sslServerCertHostMapping = append(sslServerCertHostMapping, itemTerraform)
	}
	d.Set("ssl_server_cert_host_mapping", sslServerCertHostMapping)
	sslServerCertHostMappingJson, _ := json.Marshal(sslServerCertHostMapping)
	d.Set("ssl_server_cert_host_mapping_json", sslServerCertHostMappingJson)
	d.Set("ssl_signature_algorithms", string(*object.Ssl.SignatureAlgorithms))
	d.Set("ssl_ssl_ciphers", string(*object.Ssl.SslCiphers))
	d.Set("ssl_ssl_support_ssl2", string(*object.Ssl.SslSupportSsl2))
	d.Set("ssl_ssl_support_ssl3", string(*object.Ssl.SslSupportSsl3))
	d.Set("ssl_ssl_support_tls1", string(*object.Ssl.SslSupportTls1))
	d.Set("ssl_ssl_support_tls1_1", string(*object.Ssl.SslSupportTls11))
	d.Set("ssl_ssl_support_tls1_2", string(*object.Ssl.SslSupportTls12))
	d.Set("ssl_trust_magic", bool(*object.Ssl.TrustMagic))
	d.Set("syslog_enabled", bool(*object.Syslog.Enabled))
	d.Set("syslog_format", string(*object.Syslog.Format))
	d.Set("syslog_ip_end_point", string(*object.Syslog.IpEndPoint))
	d.Set("syslog_msg_len_limit", int(*object.Syslog.MsgLenLimit))
	d.Set("tcp_proxy_close", bool(*object.Tcp.ProxyClose))
	d.Set("transaction_export_brief", bool(*object.TransactionExport.Brief))
	d.Set("transaction_export_enabled", bool(*object.TransactionExport.Enabled))
	d.Set("transaction_export_hi_res", bool(*object.TransactionExport.HiRes))
	d.Set("transaction_export_http_header_blacklist", []string(*object.TransactionExport.HttpHeaderBlacklist))
	d.Set("udp_end_point_persistence", bool(*object.Udp.EndPointPersistence))
	d.Set("udp_port_smp", bool(*object.Udp.PortSmp))
	d.Set("udp_response_datagrams_expected", int(*object.Udp.ResponseDatagramsExpected))
	d.Set("udp_timeout", int(*object.Udp.Timeout))
	d.Set("web_cache_control_out", string(*object.WebCache.ControlOut))
	d.Set("web_cache_enabled", bool(*object.WebCache.Enabled))
	d.Set("web_cache_error_page_time", int(*object.WebCache.ErrorPageTime))
	d.Set("web_cache_max_time", int(*object.WebCache.MaxTime))
	d.Set("web_cache_refresh_time", int(*object.WebCache.RefreshTime))

	d.SetId(objectName)
	return nil
}
