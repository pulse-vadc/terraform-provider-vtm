// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func resourceVirtualServer() *schema.Resource {
	return &schema.Resource{
		Read:   resourceVirtualServerRead,
		Exists: resourceVirtualServerExists,
		Create: resourceVirtualServerCreate,
		Update: resourceVirtualServerUpdate,
		Delete: resourceVirtualServerDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceVirtualServerSchema(),
	}
}

func getResourceVirtualServerSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
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

		// Rules that are run at the end of a transaction, in order, comma
		//  separated.
		"completion_rules": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The time, in seconds, for which an established connection can
		//  remain idle waiting for some initial data to be received from
		//  the client. The initial data is defined as a complete set of
		//  request headers for HTTP, SIP and RTSP services, or the first
		//  byte of data for all other services. A value of "0" will disable
		//  the timeout.
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

		// The associated GLB services for this DNS virtual server.
		"glb_services": &schema.Schema{
			Type:     schema.TypeSet,
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
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Traffic IP Groups to listen on
		"listen_on_traffic_ips": &schema.Schema{
			Type:     schema.TypeSet,
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
			Required: true,
		},

		// The port on which to listen for incoming connections.
		"port": &schema.Schema{
			Type:         schema.TypeInt,
			Required:     true,
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

		// Whether or not the virtual server should decrypt incoming SSL
		//  traffic.
		"ssl_decrypt": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not bound sockets should be configured for transparent
		//  proxying.
		"transparent": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
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
						Type:     schema.TypeSet,
						Required: true,
						Elem:     &schema.Schema{Type: schema.TypeString},
					},
				},
			},
		},

		// Name of the Trusted Identity Provider configuration to use. To
		//  create Identity Providers, please visit section <a href="?section=SAML%3aTrusted%20Identity%20Providers">Trusted
		//  Identity Providers</a>
		"auth_saml_idp": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The NameID format to request and expect from the identity provider.
		"auth_saml_nameid_format": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"emailaddress", "none", "unspecified"}, false),
			Default:      "none",
		},

		// The 'Assertion Consumer Service' endpoint for the SAML service
		//  provider on this virtual server, ie the endpoint to which the
		//  identity provider will cause the user agent to send SAML assertions.
		//  This should be an HTTPS URL, must be in the same cookie domain
		//  as all hostnames used by the end user to access the virtual server
		//  (see cookie configuration) and the port must be the port on which
		//  this virtual server is listening. It must match the URI placed
		//  by the identity provider in the 'Recipient' attribute in the
		//  SAML assertion, if present.
		"auth_saml_sp_acs_url": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The entity ID to be used by the SAML service provider function
		//  on this virtual server. This should usually be a URL, or a URN,
		//  however it may be any string. It must match the entity ID placed
		//   by the identity provider in the 'Audience' field in the SAML
		//  assertion.
		"auth_saml_sp_entity_id": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Time tolerance on authentication checks. When checking time-stamps
		//  and expiry dates against the current time on the system, allow
		//  a tolerance of this many seconds. For example, if a SAML response
		//  contains a 'NotOnOrAfter' that is 4 seconds in the past according
		//  to the local time, and the tolerance is set to 5 seconds, it
		//  will still be accepted. This is to prevent a lack of clock synchronization
		//  from resulting in rejection of SAML responses.
		"auth_saml_time_tolerance": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 3600),
			Default:      5,
		},

		// Attributes of cookie used for authentication session.
		"auth_session_cookie_attributes": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "HttpOnly; SameSite=Strict",
		},

		// Name of cookie used for authentication session.
		"auth_session_cookie_name": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "VS_SamlSP_Auth",
		},

		// Whether or not to include state of authentication sessions stored
		//  encrypted on the client as plaintext in the logs.
		"auth_session_log_external_state": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Timeout on authentication session.
		"auth_session_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(60, 31535940),
			Default:      7200,
		},

		// Type of authentication to apply to requests to the virtual server.
		"auth_type": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"none", "saml_sp"}, false),
			Default:      "none",
		},

		// Whether or not detailed messages about virtual server authentication
		//  should be written to the error log.
		"auth_verbose": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
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
			Type:     schema.TypeSet,
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

		// Whether or not the virtual server should require that incoming
		//  FTP data connections from the nodes originate from the same IP
		//  address as the node.
		"ftp_force_server_secure": &schema.Schema{
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
			Type:     schema.TypeSet,
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

		// Whether or not the virtual server should add an "X-Cluster-Client-Ip"
		//  header to the request that contains the remote client's IP address.
		"http_add_cluster_ip": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Whether or not the virtual server should append the remote client's
		//  IP address to the X-Forwarded-For header. If the header does
		//  not exist, it will be added.
		"http_add_x_forwarded_for": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not the virtual server should add an "X-Forwarded-Proto"
		//  header to the request that contains the original protocol used
		//  by the client to connect to the traffic manager.
		"http_add_x_forwarded_proto": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether the traffic manager should check for HTTP responses that
		//  confirm an HTTP connection is transitioning to the WebSockets
		//  protocol.  If that such a response is detected, the traffic manager
		//  will cease any protocol-specific processing on the connection
		//  and just pass incoming data to the client/server as appropriate.
		"http_autodetect_upgrade_headers": &schema.Schema{
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

		// Whether or not the virtual server should strip the 'X-Forwarded-Proto'
		//  header from incoming requests.
		"http_strip_x_forwarded_proto": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
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
			Type:     schema.TypeSet,
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
			Type:     schema.TypeSet,
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

		// Should the virtual server log messages when attempts to resume
		//  SSL sessions (either from the session cache or a session ticket)
		//  fail. Note that failure to resume an SSL session does not result
		//  in the SSL connection being closed, but it does cause a full
		//  SSL handshake to take place.
		"log_ssl_resumption_failures": &schema.Schema{
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

		// The SSL/TLS cipher suites to allow for connections to this virtual
		//  server.  Leaving this empty will make the virtual server use
		//  the globally configured cipher suites, see configuration key
		//  <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!cipher_suites">
		//  "ssl!cipher_suites"</a> in the Global Settings section of the
		//  System tab.  See there for how to specify SSL/TLS cipher suites.
		"ssl_cipher_suites": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The certificate authorities that this virtual server should trust
		//  to validate client certificates. If no certificate authorities
		//  are selected, and client certificates are requested, then all
		//  client certificates will be accepted.
		"ssl_client_cert_cas": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// What HTTP headers the virtual server should add to each request
		//  to show the data in the client certificate.
		"ssl_client_cert_headers": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"all", "none", "simple"}, false),
			Default:      "none",
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

		// When the virtual server verifies certificates signed by these
		//  certificate authorities, it doesn't check the 'not after' date,
		//  i.e., they are considered valid even after their expiration date
		//  has passed (but not if they have been revoked).
		"ssl_issued_certs_never_expire": &schema.Schema{
			Type:     schema.TypeSet,
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

		// Whether or not use of the session cache is enabled for this virtual
		//  server. Choosing the global setting means the value of configuration
		//  key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!cache!enabled">
		//  "ssl!session_cache_enabled"</a> from the Global Settings section
		//  of the System tab will be enforced.
		"ssl_session_cache_enabled": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not use of session tickets is enabled for this virtual
		//  server. Choosing the global setting means the value of configuration
		//  key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!tickets!enabled">
		//  "ssl!tickets!enabled"</a> from the Global Settings section of
		//  the System tab will be enforced.
		"ssl_session_tickets_enabled": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
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

		// Whether or not SSLv3 is enabled for this virtual server.  Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_ssl3">
		//  "ssl!support_ssl3"</a> from the Global Settings section of the
		//  System tab will be enforced.
		"ssl_support_ssl3": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not TLSv1.0 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1">
		//  "ssl!support_tls1"</a> from the Global Settings section of the
		//  System tab will be enforced.
		"ssl_support_tls1": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not TLSv1.1 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_1">
		//  "ssl!support_tls1_1"</a> from the Global Settings section of
		//  the System tab will be enforced.
		"ssl_support_tls1_1": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not TLSv1.2 is enabled for this virtual server. Choosing
		//  the global setting means the value of configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_2">
		//  "ssl!support_tls1_2"</a> from the Global Settings section of
		//  the System tab will be enforced.
		"ssl_support_tls1_2": &schema.Schema{
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

		// Whether or not connections from clients should be closed with
		//  a RST packet, rather than a FIN packet. This avoids the TIME_WAIT
		//  state, which on rare occasions allows wandering duplicate packets
		//  to be safely ignored.
		"tcp_close_with_rst": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not Nagle's algorithm should be used for TCP connections.
		"tcp_nagle": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
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
			Type:     schema.TypeSet,
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

		// When the traffic manager should consider a UDP transaction to
		//  have ended.
		"udp_udp_end_transaction": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"match_requests", "one_response", "timeout"}, false),
			Default:      "one_response",
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
	}
}

func resourceVirtualServerRead(d *schema.ResourceData, tm interface{}) (readError error) {
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

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "bandwidth_class"
	d.Set("bandwidth_class", string(*object.Basic.BandwidthClass))
	lastAssignedField = "bypass_data_plane_acceleration"
	d.Set("bypass_data_plane_acceleration", bool(*object.Basic.BypassDataPlaneAcceleration))
	lastAssignedField = "completion_rules"
	d.Set("completion_rules", []string(*object.Basic.CompletionRules))
	lastAssignedField = "connect_timeout"
	d.Set("connect_timeout", int(*object.Basic.ConnectTimeout))
	lastAssignedField = "enabled"
	d.Set("enabled", bool(*object.Basic.Enabled))
	lastAssignedField = "glb_services"
	d.Set("glb_services", []string(*object.Basic.GlbServices))
	lastAssignedField = "listen_on_any"
	d.Set("listen_on_any", bool(*object.Basic.ListenOnAny))
	lastAssignedField = "listen_on_hosts"
	d.Set("listen_on_hosts", []string(*object.Basic.ListenOnHosts))
	lastAssignedField = "listen_on_traffic_ips"
	d.Set("listen_on_traffic_ips", []string(*object.Basic.ListenOnTrafficIps))
	lastAssignedField = "max_concurrent_connections"
	d.Set("max_concurrent_connections", int(*object.Basic.MaxConcurrentConnections))
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "pool"
	d.Set("pool", string(*object.Basic.Pool))
	lastAssignedField = "port"
	d.Set("port", int(*object.Basic.Port))
	lastAssignedField = "protection_class"
	d.Set("protection_class", string(*object.Basic.ProtectionClass))
	lastAssignedField = "protocol"
	d.Set("protocol", string(*object.Basic.Protocol))
	lastAssignedField = "proxy_protocol"
	d.Set("proxy_protocol", bool(*object.Basic.ProxyProtocol))
	lastAssignedField = "request_rules"
	d.Set("request_rules", []string(*object.Basic.RequestRules))
	lastAssignedField = "response_rules"
	d.Set("response_rules", []string(*object.Basic.ResponseRules))
	lastAssignedField = "slm_class"
	d.Set("slm_class", string(*object.Basic.SlmClass))
	lastAssignedField = "ssl_decrypt"
	d.Set("ssl_decrypt", bool(*object.Basic.SslDecrypt))
	lastAssignedField = "transparent"
	d.Set("transparent", bool(*object.Basic.Transparent))
	lastAssignedField = "aptimizer_enabled"
	d.Set("aptimizer_enabled", bool(*object.Aptimizer.Enabled))
	lastAssignedField = "aptimizer_profile"
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
	lastAssignedField = "auth_saml_idp"
	d.Set("auth_saml_idp", string(*object.Auth.SamlIdp))
	lastAssignedField = "auth_saml_nameid_format"
	d.Set("auth_saml_nameid_format", string(*object.Auth.SamlNameidFormat))
	lastAssignedField = "auth_saml_sp_acs_url"
	d.Set("auth_saml_sp_acs_url", string(*object.Auth.SamlSpAcsUrl))
	lastAssignedField = "auth_saml_sp_entity_id"
	d.Set("auth_saml_sp_entity_id", string(*object.Auth.SamlSpEntityId))
	lastAssignedField = "auth_saml_time_tolerance"
	d.Set("auth_saml_time_tolerance", int(*object.Auth.SamlTimeTolerance))
	lastAssignedField = "auth_session_cookie_attributes"
	d.Set("auth_session_cookie_attributes", string(*object.Auth.SessionCookieAttributes))
	lastAssignedField = "auth_session_cookie_name"
	d.Set("auth_session_cookie_name", string(*object.Auth.SessionCookieName))
	lastAssignedField = "auth_session_log_external_state"
	d.Set("auth_session_log_external_state", bool(*object.Auth.SessionLogExternalState))
	lastAssignedField = "auth_session_timeout"
	d.Set("auth_session_timeout", int(*object.Auth.SessionTimeout))
	lastAssignedField = "auth_type"
	d.Set("auth_type", string(*object.Auth.Type))
	lastAssignedField = "auth_verbose"
	d.Set("auth_verbose", bool(*object.Auth.Verbose))
	lastAssignedField = "connection_keepalive"
	d.Set("connection_keepalive", bool(*object.Connection.Keepalive))
	lastAssignedField = "connection_keepalive_timeout"
	d.Set("connection_keepalive_timeout", int(*object.Connection.KeepaliveTimeout))
	lastAssignedField = "connection_max_client_buffer"
	d.Set("connection_max_client_buffer", int(*object.Connection.MaxClientBuffer))
	lastAssignedField = "connection_max_server_buffer"
	d.Set("connection_max_server_buffer", int(*object.Connection.MaxServerBuffer))
	lastAssignedField = "connection_max_transaction_duration"
	d.Set("connection_max_transaction_duration", int(*object.Connection.MaxTransactionDuration))
	lastAssignedField = "connection_server_first_banner"
	d.Set("connection_server_first_banner", string(*object.Connection.ServerFirstBanner))
	lastAssignedField = "connection_timeout"
	d.Set("connection_timeout", int(*object.Connection.Timeout))
	lastAssignedField = "connection_errors_error_file"
	d.Set("connection_errors_error_file", string(*object.ConnectionErrors.ErrorFile))
	lastAssignedField = "cookie_domain"
	d.Set("cookie_domain", string(*object.Cookie.Domain))
	lastAssignedField = "cookie_new_domain"
	d.Set("cookie_new_domain", string(*object.Cookie.NewDomain))
	lastAssignedField = "cookie_path_regex"
	d.Set("cookie_path_regex", string(*object.Cookie.PathRegex))
	lastAssignedField = "cookie_path_replace"
	d.Set("cookie_path_replace", string(*object.Cookie.PathReplace))
	lastAssignedField = "cookie_secure"
	d.Set("cookie_secure", string(*object.Cookie.Secure))
	lastAssignedField = "dns_edns_client_subnet"
	d.Set("dns_edns_client_subnet", bool(*object.Dns.EdnsClientSubnet))
	lastAssignedField = "dns_edns_udpsize"
	d.Set("dns_edns_udpsize", int(*object.Dns.EdnsUdpsize))
	lastAssignedField = "dns_max_udpsize"
	d.Set("dns_max_udpsize", int(*object.Dns.MaxUdpsize))
	lastAssignedField = "dns_rrset_order"
	d.Set("dns_rrset_order", string(*object.Dns.RrsetOrder))
	lastAssignedField = "dns_verbose"
	d.Set("dns_verbose", bool(*object.Dns.Verbose))
	lastAssignedField = "dns_zones"
	d.Set("dns_zones", []string(*object.Dns.Zones))
	lastAssignedField = "ftp_data_source_port"
	d.Set("ftp_data_source_port", int(*object.Ftp.DataSourcePort))
	lastAssignedField = "ftp_force_client_secure"
	d.Set("ftp_force_client_secure", bool(*object.Ftp.ForceClientSecure))
	lastAssignedField = "ftp_force_server_secure"
	d.Set("ftp_force_server_secure", bool(*object.Ftp.ForceServerSecure))
	lastAssignedField = "ftp_port_range_high"
	d.Set("ftp_port_range_high", int(*object.Ftp.PortRangeHigh))
	lastAssignedField = "ftp_port_range_low"
	d.Set("ftp_port_range_low", int(*object.Ftp.PortRangeLow))
	lastAssignedField = "ftp_ssl_data"
	d.Set("ftp_ssl_data", bool(*object.Ftp.SslData))
	lastAssignedField = "gzip_compress_level"
	d.Set("gzip_compress_level", int(*object.Gzip.CompressLevel))
	lastAssignedField = "gzip_enabled"
	d.Set("gzip_enabled", bool(*object.Gzip.Enabled))
	lastAssignedField = "gzip_etag_rewrite"
	d.Set("gzip_etag_rewrite", string(*object.Gzip.EtagRewrite))
	lastAssignedField = "gzip_include_mime"
	d.Set("gzip_include_mime", []string(*object.Gzip.IncludeMime))
	lastAssignedField = "gzip_max_size"
	d.Set("gzip_max_size", int(*object.Gzip.MaxSize))
	lastAssignedField = "gzip_min_size"
	d.Set("gzip_min_size", int(*object.Gzip.MinSize))
	lastAssignedField = "gzip_no_size"
	d.Set("gzip_no_size", bool(*object.Gzip.NoSize))
	lastAssignedField = "http_add_cluster_ip"
	d.Set("http_add_cluster_ip", bool(*object.Http.AddClusterIp))
	lastAssignedField = "http_add_x_forwarded_for"
	d.Set("http_add_x_forwarded_for", bool(*object.Http.AddXForwardedFor))
	lastAssignedField = "http_add_x_forwarded_proto"
	d.Set("http_add_x_forwarded_proto", bool(*object.Http.AddXForwardedProto))
	lastAssignedField = "http_autodetect_upgrade_headers"
	d.Set("http_autodetect_upgrade_headers", bool(*object.Http.AutodetectUpgradeHeaders))
	lastAssignedField = "http_chunk_overhead_forwarding"
	d.Set("http_chunk_overhead_forwarding", string(*object.Http.ChunkOverheadForwarding))
	lastAssignedField = "http_location_regex"
	d.Set("http_location_regex", string(*object.Http.LocationRegex))
	lastAssignedField = "http_location_replace"
	d.Set("http_location_replace", string(*object.Http.LocationReplace))
	lastAssignedField = "http_location_rewrite"
	d.Set("http_location_rewrite", string(*object.Http.LocationRewrite))
	lastAssignedField = "http_mime_default"
	d.Set("http_mime_default", string(*object.Http.MimeDefault))
	lastAssignedField = "http_mime_detect"
	d.Set("http_mime_detect", bool(*object.Http.MimeDetect))
	lastAssignedField = "http_strip_x_forwarded_proto"
	d.Set("http_strip_x_forwarded_proto", bool(*object.Http.StripXForwardedProto))
	lastAssignedField = "http2_connect_timeout"
	d.Set("http2_connect_timeout", int(*object.Http2.ConnectTimeout))
	lastAssignedField = "http2_data_frame_size"
	d.Set("http2_data_frame_size", int(*object.Http2.DataFrameSize))
	lastAssignedField = "http2_enabled"
	d.Set("http2_enabled", bool(*object.Http2.Enabled))
	lastAssignedField = "http2_header_table_size"
	d.Set("http2_header_table_size", int(*object.Http2.HeaderTableSize))
	lastAssignedField = "http2_headers_index_blacklist"
	d.Set("http2_headers_index_blacklist", []string(*object.Http2.HeadersIndexBlacklist))
	lastAssignedField = "http2_headers_index_default"
	d.Set("http2_headers_index_default", bool(*object.Http2.HeadersIndexDefault))
	lastAssignedField = "http2_headers_index_whitelist"
	d.Set("http2_headers_index_whitelist", []string(*object.Http2.HeadersIndexWhitelist))
	lastAssignedField = "http2_headers_size_limit"
	d.Set("http2_headers_size_limit", int(*object.Http2.HeadersSizeLimit))
	lastAssignedField = "http2_idle_timeout_no_streams"
	d.Set("http2_idle_timeout_no_streams", int(*object.Http2.IdleTimeoutNoStreams))
	lastAssignedField = "http2_idle_timeout_open_streams"
	d.Set("http2_idle_timeout_open_streams", int(*object.Http2.IdleTimeoutOpenStreams))
	lastAssignedField = "http2_max_concurrent_streams"
	d.Set("http2_max_concurrent_streams", int(*object.Http2.MaxConcurrentStreams))
	lastAssignedField = "http2_max_frame_size"
	d.Set("http2_max_frame_size", int(*object.Http2.MaxFrameSize))
	lastAssignedField = "http2_max_header_padding"
	d.Set("http2_max_header_padding", int(*object.Http2.MaxHeaderPadding))
	lastAssignedField = "http2_merge_cookie_headers"
	d.Set("http2_merge_cookie_headers", bool(*object.Http2.MergeCookieHeaders))
	lastAssignedField = "http2_stream_window_size"
	d.Set("http2_stream_window_size", int(*object.Http2.StreamWindowSize))
	lastAssignedField = "kerberos_protocol_transition_enabled"
	d.Set("kerberos_protocol_transition_enabled", bool(*object.KerberosProtocolTransition.Enabled))
	lastAssignedField = "kerberos_protocol_transition_principal"
	d.Set("kerberos_protocol_transition_principal", string(*object.KerberosProtocolTransition.Principal))
	lastAssignedField = "kerberos_protocol_transition_target"
	d.Set("kerberos_protocol_transition_target", string(*object.KerberosProtocolTransition.Target))
	lastAssignedField = "l4accel_rst_on_service_failure"
	d.Set("l4accel_rst_on_service_failure", bool(*object.L4Accel.RstOnServiceFailure))
	lastAssignedField = "l4accel_service_ip_snat"
	d.Set("l4accel_service_ip_snat", bool(*object.L4Accel.ServiceIpSnat))
	lastAssignedField = "l4accel_state_sync"
	d.Set("l4accel_state_sync", bool(*object.L4Accel.StateSync))
	lastAssignedField = "l4accel_tcp_msl"
	d.Set("l4accel_tcp_msl", int(*object.L4Accel.TcpMsl))
	lastAssignedField = "l4accel_timeout"
	d.Set("l4accel_timeout", int(*object.L4Accel.Timeout))
	lastAssignedField = "l4accel_udp_count_requests"
	d.Set("l4accel_udp_count_requests", bool(*object.L4Accel.UdpCountRequests))
	lastAssignedField = "log_client_connection_failures"
	d.Set("log_client_connection_failures", bool(*object.Log.ClientConnectionFailures))
	lastAssignedField = "log_enabled"
	d.Set("log_enabled", bool(*object.Log.Enabled))
	lastAssignedField = "log_filename"
	d.Set("log_filename", string(*object.Log.Filename))
	lastAssignedField = "log_format"
	d.Set("log_format", string(*object.Log.Format))
	lastAssignedField = "log_save_all"
	d.Set("log_save_all", bool(*object.Log.SaveAll))
	lastAssignedField = "log_server_connection_failures"
	d.Set("log_server_connection_failures", bool(*object.Log.ServerConnectionFailures))
	lastAssignedField = "log_session_persistence_verbose"
	d.Set("log_session_persistence_verbose", bool(*object.Log.SessionPersistenceVerbose))
	lastAssignedField = "log_ssl_failures"
	d.Set("log_ssl_failures", bool(*object.Log.SslFailures))
	lastAssignedField = "log_ssl_resumption_failures"
	d.Set("log_ssl_resumption_failures", bool(*object.Log.SslResumptionFailures))
	lastAssignedField = "recent_connections_enabled"
	d.Set("recent_connections_enabled", bool(*object.RecentConnections.Enabled))
	lastAssignedField = "recent_connections_save_all"
	d.Set("recent_connections_save_all", bool(*object.RecentConnections.SaveAll))
	lastAssignedField = "request_tracing_enabled"
	d.Set("request_tracing_enabled", bool(*object.RequestTracing.Enabled))
	lastAssignedField = "request_tracing_trace_io"
	d.Set("request_tracing_trace_io", bool(*object.RequestTracing.TraceIo))
	lastAssignedField = "rtsp_streaming_port_range_high"
	d.Set("rtsp_streaming_port_range_high", int(*object.Rtsp.StreamingPortRangeHigh))
	lastAssignedField = "rtsp_streaming_port_range_low"
	d.Set("rtsp_streaming_port_range_low", int(*object.Rtsp.StreamingPortRangeLow))
	lastAssignedField = "rtsp_streaming_timeout"
	d.Set("rtsp_streaming_timeout", int(*object.Rtsp.StreamingTimeout))
	lastAssignedField = "sip_dangerous_requests"
	d.Set("sip_dangerous_requests", string(*object.Sip.DangerousRequests))
	lastAssignedField = "sip_follow_route"
	d.Set("sip_follow_route", bool(*object.Sip.FollowRoute))
	lastAssignedField = "sip_max_connection_mem"
	d.Set("sip_max_connection_mem", int(*object.Sip.MaxConnectionMem))
	lastAssignedField = "sip_mode"
	d.Set("sip_mode", string(*object.Sip.Mode))
	lastAssignedField = "sip_rewrite_uri"
	d.Set("sip_rewrite_uri", bool(*object.Sip.RewriteUri))
	lastAssignedField = "sip_streaming_port_range_high"
	d.Set("sip_streaming_port_range_high", int(*object.Sip.StreamingPortRangeHigh))
	lastAssignedField = "sip_streaming_port_range_low"
	d.Set("sip_streaming_port_range_low", int(*object.Sip.StreamingPortRangeLow))
	lastAssignedField = "sip_streaming_timeout"
	d.Set("sip_streaming_timeout", int(*object.Sip.StreamingTimeout))
	lastAssignedField = "sip_timeout_messages"
	d.Set("sip_timeout_messages", bool(*object.Sip.TimeoutMessages))
	lastAssignedField = "sip_transaction_timeout"
	d.Set("sip_transaction_timeout", int(*object.Sip.TransactionTimeout))
	lastAssignedField = "smtp_expect_starttls"
	d.Set("smtp_expect_starttls", bool(*object.Smtp.ExpectStarttls))
	lastAssignedField = "ssl_add_http_headers"
	d.Set("ssl_add_http_headers", bool(*object.Ssl.AddHttpHeaders))
	lastAssignedField = "ssl_cipher_suites"
	d.Set("ssl_cipher_suites", string(*object.Ssl.CipherSuites))
	lastAssignedField = "ssl_client_cert_cas"
	d.Set("ssl_client_cert_cas", []string(*object.Ssl.ClientCertCas))
	lastAssignedField = "ssl_client_cert_headers"
	d.Set("ssl_client_cert_headers", string(*object.Ssl.ClientCertHeaders))
	lastAssignedField = "ssl_elliptic_curves"
	d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	lastAssignedField = "ssl_honor_fallback_scsv"
	d.Set("ssl_honor_fallback_scsv", string(*object.Ssl.HonorFallbackScsv))
	lastAssignedField = "ssl_issued_certs_never_expire"
	d.Set("ssl_issued_certs_never_expire", []string(*object.Ssl.IssuedCertsNeverExpire))
	lastAssignedField = "ssl_issued_certs_never_expire_depth"
	d.Set("ssl_issued_certs_never_expire_depth", int(*object.Ssl.IssuedCertsNeverExpireDepth))
	lastAssignedField = "ssl_ocsp_enable"
	d.Set("ssl_ocsp_enable", bool(*object.Ssl.OcspEnable))
	lastAssignedField = "ssl_ocsp_issuers"
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
	lastAssignedField = "ssl_ocsp_max_response_age"
	d.Set("ssl_ocsp_max_response_age", int(*object.Ssl.OcspMaxResponseAge))
	lastAssignedField = "ssl_ocsp_stapling"
	d.Set("ssl_ocsp_stapling", bool(*object.Ssl.OcspStapling))
	lastAssignedField = "ssl_ocsp_time_tolerance"
	d.Set("ssl_ocsp_time_tolerance", int(*object.Ssl.OcspTimeTolerance))
	lastAssignedField = "ssl_ocsp_timeout"
	d.Set("ssl_ocsp_timeout", int(*object.Ssl.OcspTimeout))
	lastAssignedField = "ssl_request_client_cert"
	d.Set("ssl_request_client_cert", string(*object.Ssl.RequestClientCert))
	lastAssignedField = "ssl_send_close_alerts"
	d.Set("ssl_send_close_alerts", bool(*object.Ssl.SendCloseAlerts))
	lastAssignedField = "ssl_server_cert_alt_certificates"
	d.Set("ssl_server_cert_alt_certificates", []string(*object.Ssl.ServerCertAltCertificates))
	lastAssignedField = "ssl_server_cert_default"
	d.Set("ssl_server_cert_default", string(*object.Ssl.ServerCertDefault))
	lastAssignedField = "ssl_server_cert_host_mapping"
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
	lastAssignedField = "ssl_session_cache_enabled"
	d.Set("ssl_session_cache_enabled", string(*object.Ssl.SessionCacheEnabled))
	lastAssignedField = "ssl_session_tickets_enabled"
	d.Set("ssl_session_tickets_enabled", string(*object.Ssl.SessionTicketsEnabled))
	lastAssignedField = "ssl_signature_algorithms"
	d.Set("ssl_signature_algorithms", string(*object.Ssl.SignatureAlgorithms))
	lastAssignedField = "ssl_support_ssl3"
	d.Set("ssl_support_ssl3", string(*object.Ssl.SupportSsl3))
	lastAssignedField = "ssl_support_tls1"
	d.Set("ssl_support_tls1", string(*object.Ssl.SupportTls1))
	lastAssignedField = "ssl_support_tls1_1"
	d.Set("ssl_support_tls1_1", string(*object.Ssl.SupportTls11))
	lastAssignedField = "ssl_support_tls1_2"
	d.Set("ssl_support_tls1_2", string(*object.Ssl.SupportTls12))
	lastAssignedField = "ssl_trust_magic"
	d.Set("ssl_trust_magic", bool(*object.Ssl.TrustMagic))
	lastAssignedField = "syslog_enabled"
	d.Set("syslog_enabled", bool(*object.Syslog.Enabled))
	lastAssignedField = "syslog_format"
	d.Set("syslog_format", string(*object.Syslog.Format))
	lastAssignedField = "syslog_ip_end_point"
	d.Set("syslog_ip_end_point", string(*object.Syslog.IpEndPoint))
	lastAssignedField = "syslog_msg_len_limit"
	d.Set("syslog_msg_len_limit", int(*object.Syslog.MsgLenLimit))
	lastAssignedField = "tcp_close_with_rst"
	d.Set("tcp_close_with_rst", bool(*object.Tcp.CloseWithRst))
	lastAssignedField = "tcp_nagle"
	d.Set("tcp_nagle", bool(*object.Tcp.Nagle))
	lastAssignedField = "tcp_proxy_close"
	d.Set("tcp_proxy_close", bool(*object.Tcp.ProxyClose))
	lastAssignedField = "transaction_export_brief"
	d.Set("transaction_export_brief", bool(*object.TransactionExport.Brief))
	lastAssignedField = "transaction_export_enabled"
	d.Set("transaction_export_enabled", bool(*object.TransactionExport.Enabled))
	lastAssignedField = "transaction_export_hi_res"
	d.Set("transaction_export_hi_res", bool(*object.TransactionExport.HiRes))
	lastAssignedField = "transaction_export_http_header_blacklist"
	d.Set("transaction_export_http_header_blacklist", []string(*object.TransactionExport.HttpHeaderBlacklist))
	lastAssignedField = "udp_end_point_persistence"
	d.Set("udp_end_point_persistence", bool(*object.Udp.EndPointPersistence))
	lastAssignedField = "udp_port_smp"
	d.Set("udp_port_smp", bool(*object.Udp.PortSmp))
	lastAssignedField = "udp_response_datagrams_expected"
	d.Set("udp_response_datagrams_expected", int(*object.Udp.ResponseDatagramsExpected))
	lastAssignedField = "udp_timeout"
	d.Set("udp_timeout", int(*object.Udp.Timeout))
	lastAssignedField = "udp_udp_end_transaction"
	d.Set("udp_udp_end_transaction", string(*object.Udp.UdpEndTransaction))
	lastAssignedField = "web_cache_control_out"
	d.Set("web_cache_control_out", string(*object.WebCache.ControlOut))
	lastAssignedField = "web_cache_enabled"
	d.Set("web_cache_enabled", bool(*object.WebCache.Enabled))
	lastAssignedField = "web_cache_error_page_time"
	d.Set("web_cache_error_page_time", int(*object.WebCache.ErrorPageTime))
	lastAssignedField = "web_cache_max_time"
	d.Set("web_cache_max_time", int(*object.WebCache.MaxTime))
	lastAssignedField = "web_cache_refresh_time"
	d.Set("web_cache_refresh_time", int(*object.WebCache.RefreshTime))
	d.SetId(objectName)
	return nil
}

func resourceVirtualServerExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetVirtualServer(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourceVirtualServerCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewVirtualServer(objectName, d.Get("pool").(string), d.Get("port").(int))
	resourceVirtualServerObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_virtual_server '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceVirtualServerUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetVirtualServer(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_virtual_server '%v': %v", objectName, err)
	}
	resourceVirtualServerObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_virtual_server '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourceVirtualServerObjectFieldAssignments(d *schema.ResourceData, object *vtm.VirtualServer) {
	setString(&object.Basic.BandwidthClass, d, "bandwidth_class")
	setBool(&object.Basic.BypassDataPlaneAcceleration, d, "bypass_data_plane_acceleration")

	if _, ok := d.GetOk("completion_rules"); ok {
		setStringList(&object.Basic.CompletionRules, d, "completion_rules")
	} else {
		object.Basic.CompletionRules = &[]string{}
		d.Set("completion_rules", []string(*object.Basic.CompletionRules))
	}
	setInt(&object.Basic.ConnectTimeout, d, "connect_timeout")
	setBool(&object.Basic.Enabled, d, "enabled")

	if _, ok := d.GetOk("glb_services"); ok {
		setStringSet(&object.Basic.GlbServices, d, "glb_services")
	} else {
		object.Basic.GlbServices = &[]string{}
		d.Set("glb_services", []string(*object.Basic.GlbServices))
	}
	setBool(&object.Basic.ListenOnAny, d, "listen_on_any")

	if _, ok := d.GetOk("listen_on_hosts"); ok {
		setStringSet(&object.Basic.ListenOnHosts, d, "listen_on_hosts")
	} else {
		object.Basic.ListenOnHosts = &[]string{}
		d.Set("listen_on_hosts", []string(*object.Basic.ListenOnHosts))
	}

	if _, ok := d.GetOk("listen_on_traffic_ips"); ok {
		setStringSet(&object.Basic.ListenOnTrafficIps, d, "listen_on_traffic_ips")
	} else {
		object.Basic.ListenOnTrafficIps = &[]string{}
		d.Set("listen_on_traffic_ips", []string(*object.Basic.ListenOnTrafficIps))
	}
	setInt(&object.Basic.MaxConcurrentConnections, d, "max_concurrent_connections")
	setString(&object.Basic.Note, d, "note")
	setString(&object.Basic.Pool, d, "pool")
	setInt(&object.Basic.Port, d, "port")
	setString(&object.Basic.ProtectionClass, d, "protection_class")
	setString(&object.Basic.Protocol, d, "protocol")
	setBool(&object.Basic.ProxyProtocol, d, "proxy_protocol")

	if _, ok := d.GetOk("request_rules"); ok {
		setStringList(&object.Basic.RequestRules, d, "request_rules")
	} else {
		object.Basic.RequestRules = &[]string{}
		d.Set("request_rules", []string(*object.Basic.RequestRules))
	}

	if _, ok := d.GetOk("response_rules"); ok {
		setStringList(&object.Basic.ResponseRules, d, "response_rules")
	} else {
		object.Basic.ResponseRules = &[]string{}
		d.Set("response_rules", []string(*object.Basic.ResponseRules))
	}
	setString(&object.Basic.SlmClass, d, "slm_class")
	setBool(&object.Basic.SslDecrypt, d, "ssl_decrypt")
	setBool(&object.Basic.Transparent, d, "transparent")
	setBool(&object.Aptimizer.Enabled, d, "aptimizer_enabled")

	object.Aptimizer.Profile = &vtm.VirtualServerProfileTable{}
	if aptimizerProfileJson, ok := d.GetOk("aptimizer_profile_json"); ok {
		_ = json.Unmarshal([]byte(aptimizerProfileJson.(string)), object.Aptimizer.Profile)
	} else if aptimizerProfile, ok := d.GetOk("aptimizer_profile"); ok {
		for _, row := range aptimizerProfile.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.VirtualServerProfile{}
			VtmObject.Name = getStringAddr(itemTerraform["name"].(string))
			VtmObject.Urls = getStringSetAddr(expandStringSet(itemTerraform["urls"].(*schema.Set)))
			*object.Aptimizer.Profile = append(*object.Aptimizer.Profile, VtmObject)
		}
		d.Set("aptimizer_profile", aptimizerProfile)
	} else {
		d.Set("aptimizer_profile", make([]map[string]interface{}, 0, len(*object.Aptimizer.Profile)))
	}
	setString(&object.Auth.SamlIdp, d, "auth_saml_idp")
	setString(&object.Auth.SamlNameidFormat, d, "auth_saml_nameid_format")
	setString(&object.Auth.SamlSpAcsUrl, d, "auth_saml_sp_acs_url")
	setString(&object.Auth.SamlSpEntityId, d, "auth_saml_sp_entity_id")
	setInt(&object.Auth.SamlTimeTolerance, d, "auth_saml_time_tolerance")
	setString(&object.Auth.SessionCookieAttributes, d, "auth_session_cookie_attributes")
	setString(&object.Auth.SessionCookieName, d, "auth_session_cookie_name")
	setBool(&object.Auth.SessionLogExternalState, d, "auth_session_log_external_state")
	setInt(&object.Auth.SessionTimeout, d, "auth_session_timeout")
	setString(&object.Auth.Type, d, "auth_type")
	setBool(&object.Auth.Verbose, d, "auth_verbose")
	setBool(&object.Connection.Keepalive, d, "connection_keepalive")
	setInt(&object.Connection.KeepaliveTimeout, d, "connection_keepalive_timeout")
	setInt(&object.Connection.MaxClientBuffer, d, "connection_max_client_buffer")
	setInt(&object.Connection.MaxServerBuffer, d, "connection_max_server_buffer")
	setInt(&object.Connection.MaxTransactionDuration, d, "connection_max_transaction_duration")
	setString(&object.Connection.ServerFirstBanner, d, "connection_server_first_banner")
	setInt(&object.Connection.Timeout, d, "connection_timeout")
	setString(&object.ConnectionErrors.ErrorFile, d, "connection_errors_error_file")
	setString(&object.Cookie.Domain, d, "cookie_domain")
	setString(&object.Cookie.NewDomain, d, "cookie_new_domain")
	setString(&object.Cookie.PathRegex, d, "cookie_path_regex")
	setString(&object.Cookie.PathReplace, d, "cookie_path_replace")
	setString(&object.Cookie.Secure, d, "cookie_secure")
	setBool(&object.Dns.EdnsClientSubnet, d, "dns_edns_client_subnet")
	setInt(&object.Dns.EdnsUdpsize, d, "dns_edns_udpsize")
	setInt(&object.Dns.MaxUdpsize, d, "dns_max_udpsize")
	setString(&object.Dns.RrsetOrder, d, "dns_rrset_order")
	setBool(&object.Dns.Verbose, d, "dns_verbose")

	if _, ok := d.GetOk("dns_zones"); ok {
		setStringSet(&object.Dns.Zones, d, "dns_zones")
	} else {
		object.Dns.Zones = &[]string{}
		d.Set("dns_zones", []string(*object.Dns.Zones))
	}
	setInt(&object.Ftp.DataSourcePort, d, "ftp_data_source_port")
	setBool(&object.Ftp.ForceClientSecure, d, "ftp_force_client_secure")
	setBool(&object.Ftp.ForceServerSecure, d, "ftp_force_server_secure")
	setInt(&object.Ftp.PortRangeHigh, d, "ftp_port_range_high")
	setInt(&object.Ftp.PortRangeLow, d, "ftp_port_range_low")
	setBool(&object.Ftp.SslData, d, "ftp_ssl_data")
	setInt(&object.Gzip.CompressLevel, d, "gzip_compress_level")
	setBool(&object.Gzip.Enabled, d, "gzip_enabled")
	setString(&object.Gzip.EtagRewrite, d, "gzip_etag_rewrite")

	if _, ok := d.GetOk("gzip_include_mime"); ok {
		setStringSet(&object.Gzip.IncludeMime, d, "gzip_include_mime")
	} else {
		object.Gzip.IncludeMime = &[]string{"text/html", "text/plain"}
		d.Set("gzip_include_mime", []string(*object.Gzip.IncludeMime))
	}
	setInt(&object.Gzip.MaxSize, d, "gzip_max_size")
	setInt(&object.Gzip.MinSize, d, "gzip_min_size")
	setBool(&object.Gzip.NoSize, d, "gzip_no_size")
	setBool(&object.Http.AddClusterIp, d, "http_add_cluster_ip")
	setBool(&object.Http.AddXForwardedFor, d, "http_add_x_forwarded_for")
	setBool(&object.Http.AddXForwardedProto, d, "http_add_x_forwarded_proto")
	setBool(&object.Http.AutodetectUpgradeHeaders, d, "http_autodetect_upgrade_headers")
	setString(&object.Http.ChunkOverheadForwarding, d, "http_chunk_overhead_forwarding")
	setString(&object.Http.LocationRegex, d, "http_location_regex")
	setString(&object.Http.LocationReplace, d, "http_location_replace")
	setString(&object.Http.LocationRewrite, d, "http_location_rewrite")
	setString(&object.Http.MimeDefault, d, "http_mime_default")
	setBool(&object.Http.MimeDetect, d, "http_mime_detect")
	setBool(&object.Http.StripXForwardedProto, d, "http_strip_x_forwarded_proto")
	setInt(&object.Http2.ConnectTimeout, d, "http2_connect_timeout")
	setInt(&object.Http2.DataFrameSize, d, "http2_data_frame_size")
	setBool(&object.Http2.Enabled, d, "http2_enabled")
	setInt(&object.Http2.HeaderTableSize, d, "http2_header_table_size")

	if _, ok := d.GetOk("http2_headers_index_blacklist"); ok {
		setStringSet(&object.Http2.HeadersIndexBlacklist, d, "http2_headers_index_blacklist")
	} else {
		object.Http2.HeadersIndexBlacklist = &[]string{}
		d.Set("http2_headers_index_blacklist", []string(*object.Http2.HeadersIndexBlacklist))
	}
	setBool(&object.Http2.HeadersIndexDefault, d, "http2_headers_index_default")

	if _, ok := d.GetOk("http2_headers_index_whitelist"); ok {
		setStringSet(&object.Http2.HeadersIndexWhitelist, d, "http2_headers_index_whitelist")
	} else {
		object.Http2.HeadersIndexWhitelist = &[]string{}
		d.Set("http2_headers_index_whitelist", []string(*object.Http2.HeadersIndexWhitelist))
	}
	setInt(&object.Http2.HeadersSizeLimit, d, "http2_headers_size_limit")
	setInt(&object.Http2.IdleTimeoutNoStreams, d, "http2_idle_timeout_no_streams")
	setInt(&object.Http2.IdleTimeoutOpenStreams, d, "http2_idle_timeout_open_streams")
	setInt(&object.Http2.MaxConcurrentStreams, d, "http2_max_concurrent_streams")
	setInt(&object.Http2.MaxFrameSize, d, "http2_max_frame_size")
	setInt(&object.Http2.MaxHeaderPadding, d, "http2_max_header_padding")
	setBool(&object.Http2.MergeCookieHeaders, d, "http2_merge_cookie_headers")
	setInt(&object.Http2.StreamWindowSize, d, "http2_stream_window_size")
	setBool(&object.KerberosProtocolTransition.Enabled, d, "kerberos_protocol_transition_enabled")
	setString(&object.KerberosProtocolTransition.Principal, d, "kerberos_protocol_transition_principal")
	setString(&object.KerberosProtocolTransition.Target, d, "kerberos_protocol_transition_target")
	setBool(&object.L4Accel.RstOnServiceFailure, d, "l4accel_rst_on_service_failure")
	setBool(&object.L4Accel.ServiceIpSnat, d, "l4accel_service_ip_snat")
	setBool(&object.L4Accel.StateSync, d, "l4accel_state_sync")
	setInt(&object.L4Accel.TcpMsl, d, "l4accel_tcp_msl")
	setInt(&object.L4Accel.Timeout, d, "l4accel_timeout")
	setBool(&object.L4Accel.UdpCountRequests, d, "l4accel_udp_count_requests")
	setBool(&object.Log.ClientConnectionFailures, d, "log_client_connection_failures")
	setBool(&object.Log.Enabled, d, "log_enabled")
	setString(&object.Log.Filename, d, "log_filename")
	setString(&object.Log.Format, d, "log_format")
	setBool(&object.Log.SaveAll, d, "log_save_all")
	setBool(&object.Log.ServerConnectionFailures, d, "log_server_connection_failures")
	setBool(&object.Log.SessionPersistenceVerbose, d, "log_session_persistence_verbose")
	setBool(&object.Log.SslFailures, d, "log_ssl_failures")
	setBool(&object.Log.SslResumptionFailures, d, "log_ssl_resumption_failures")
	setBool(&object.RecentConnections.Enabled, d, "recent_connections_enabled")
	setBool(&object.RecentConnections.SaveAll, d, "recent_connections_save_all")
	setBool(&object.RequestTracing.Enabled, d, "request_tracing_enabled")
	setBool(&object.RequestTracing.TraceIo, d, "request_tracing_trace_io")
	setInt(&object.Rtsp.StreamingPortRangeHigh, d, "rtsp_streaming_port_range_high")
	setInt(&object.Rtsp.StreamingPortRangeLow, d, "rtsp_streaming_port_range_low")
	setInt(&object.Rtsp.StreamingTimeout, d, "rtsp_streaming_timeout")
	setString(&object.Sip.DangerousRequests, d, "sip_dangerous_requests")
	setBool(&object.Sip.FollowRoute, d, "sip_follow_route")
	setInt(&object.Sip.MaxConnectionMem, d, "sip_max_connection_mem")
	setString(&object.Sip.Mode, d, "sip_mode")
	setBool(&object.Sip.RewriteUri, d, "sip_rewrite_uri")
	setInt(&object.Sip.StreamingPortRangeHigh, d, "sip_streaming_port_range_high")
	setInt(&object.Sip.StreamingPortRangeLow, d, "sip_streaming_port_range_low")
	setInt(&object.Sip.StreamingTimeout, d, "sip_streaming_timeout")
	setBool(&object.Sip.TimeoutMessages, d, "sip_timeout_messages")
	setInt(&object.Sip.TransactionTimeout, d, "sip_transaction_timeout")
	setBool(&object.Smtp.ExpectStarttls, d, "smtp_expect_starttls")
	setBool(&object.Ssl.AddHttpHeaders, d, "ssl_add_http_headers")
	setString(&object.Ssl.CipherSuites, d, "ssl_cipher_suites")

	if _, ok := d.GetOk("ssl_client_cert_cas"); ok {
		setStringSet(&object.Ssl.ClientCertCas, d, "ssl_client_cert_cas")
	} else {
		object.Ssl.ClientCertCas = &[]string{}
		d.Set("ssl_client_cert_cas", []string(*object.Ssl.ClientCertCas))
	}
	setString(&object.Ssl.ClientCertHeaders, d, "ssl_client_cert_headers")

	if _, ok := d.GetOk("ssl_elliptic_curves"); ok {
		setStringList(&object.Ssl.EllipticCurves, d, "ssl_elliptic_curves")
	} else {
		object.Ssl.EllipticCurves = &[]string{}
		d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	}
	setString(&object.Ssl.HonorFallbackScsv, d, "ssl_honor_fallback_scsv")

	if _, ok := d.GetOk("ssl_issued_certs_never_expire"); ok {
		setStringSet(&object.Ssl.IssuedCertsNeverExpire, d, "ssl_issued_certs_never_expire")
	} else {
		object.Ssl.IssuedCertsNeverExpire = &[]string{}
		d.Set("ssl_issued_certs_never_expire", []string(*object.Ssl.IssuedCertsNeverExpire))
	}
	setInt(&object.Ssl.IssuedCertsNeverExpireDepth, d, "ssl_issued_certs_never_expire_depth")
	setBool(&object.Ssl.OcspEnable, d, "ssl_ocsp_enable")

	object.Ssl.OcspIssuers = &vtm.VirtualServerOcspIssuersTable{}
	if sslOcspIssuersJson, ok := d.GetOk("ssl_ocsp_issuers_json"); ok {
		_ = json.Unmarshal([]byte(sslOcspIssuersJson.(string)), object.Ssl.OcspIssuers)
	} else if sslOcspIssuers, ok := d.GetOk("ssl_ocsp_issuers"); ok {
		for _, row := range sslOcspIssuers.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.VirtualServerOcspIssuers{}
			VtmObject.Aia = getBoolAddr(itemTerraform["aia"].(bool))
			VtmObject.Issuer = getStringAddr(itemTerraform["issuer"].(string))
			VtmObject.Nonce = getStringAddr(itemTerraform["nonce"].(string))
			VtmObject.Required = getStringAddr(itemTerraform["required"].(string))
			VtmObject.ResponderCert = getStringAddr(itemTerraform["responder_cert"].(string))
			VtmObject.Signer = getStringAddr(itemTerraform["signer"].(string))
			VtmObject.Url = getStringAddr(itemTerraform["url"].(string))
			*object.Ssl.OcspIssuers = append(*object.Ssl.OcspIssuers, VtmObject)
		}
		d.Set("ssl_ocsp_issuers", sslOcspIssuers)
	} else {
		d.Set("ssl_ocsp_issuers", make([]map[string]interface{}, 0, len(*object.Ssl.OcspIssuers)))
	}
	setInt(&object.Ssl.OcspMaxResponseAge, d, "ssl_ocsp_max_response_age")
	setBool(&object.Ssl.OcspStapling, d, "ssl_ocsp_stapling")
	setInt(&object.Ssl.OcspTimeTolerance, d, "ssl_ocsp_time_tolerance")
	setInt(&object.Ssl.OcspTimeout, d, "ssl_ocsp_timeout")
	setString(&object.Ssl.RequestClientCert, d, "ssl_request_client_cert")
	setBool(&object.Ssl.SendCloseAlerts, d, "ssl_send_close_alerts")

	if _, ok := d.GetOk("ssl_server_cert_alt_certificates"); ok {
		setStringList(&object.Ssl.ServerCertAltCertificates, d, "ssl_server_cert_alt_certificates")
	} else {
		object.Ssl.ServerCertAltCertificates = &[]string{}
		d.Set("ssl_server_cert_alt_certificates", []string(*object.Ssl.ServerCertAltCertificates))
	}
	setString(&object.Ssl.ServerCertDefault, d, "ssl_server_cert_default")

	object.Ssl.ServerCertHostMapping = &vtm.VirtualServerServerCertHostMappingTable{}
	if sslServerCertHostMappingJson, ok := d.GetOk("ssl_server_cert_host_mapping_json"); ok {
		_ = json.Unmarshal([]byte(sslServerCertHostMappingJson.(string)), object.Ssl.ServerCertHostMapping)
	} else if sslServerCertHostMapping, ok := d.GetOk("ssl_server_cert_host_mapping"); ok {
		for _, row := range sslServerCertHostMapping.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.VirtualServerServerCertHostMapping{}
			VtmObject.AltCertificates = getStringListAddr(expandStringList(itemTerraform["alt_certificates"].([]interface{})))
			VtmObject.Certificate = getStringAddr(itemTerraform["certificate"].(string))
			VtmObject.Host = getStringAddr(itemTerraform["host"].(string))
			*object.Ssl.ServerCertHostMapping = append(*object.Ssl.ServerCertHostMapping, VtmObject)
		}
		d.Set("ssl_server_cert_host_mapping", sslServerCertHostMapping)
	} else {
		d.Set("ssl_server_cert_host_mapping", make([]map[string]interface{}, 0, len(*object.Ssl.ServerCertHostMapping)))
	}
	setString(&object.Ssl.SessionCacheEnabled, d, "ssl_session_cache_enabled")
	setString(&object.Ssl.SessionTicketsEnabled, d, "ssl_session_tickets_enabled")
	setString(&object.Ssl.SignatureAlgorithms, d, "ssl_signature_algorithms")
	setString(&object.Ssl.SupportSsl3, d, "ssl_support_ssl3")
	setString(&object.Ssl.SupportTls1, d, "ssl_support_tls1")
	setString(&object.Ssl.SupportTls11, d, "ssl_support_tls1_1")
	setString(&object.Ssl.SupportTls12, d, "ssl_support_tls1_2")
	setBool(&object.Ssl.TrustMagic, d, "ssl_trust_magic")
	setBool(&object.Syslog.Enabled, d, "syslog_enabled")
	setString(&object.Syslog.Format, d, "syslog_format")
	setString(&object.Syslog.IpEndPoint, d, "syslog_ip_end_point")
	setInt(&object.Syslog.MsgLenLimit, d, "syslog_msg_len_limit")
	setBool(&object.Tcp.CloseWithRst, d, "tcp_close_with_rst")
	setBool(&object.Tcp.Nagle, d, "tcp_nagle")
	setBool(&object.Tcp.ProxyClose, d, "tcp_proxy_close")
	setBool(&object.TransactionExport.Brief, d, "transaction_export_brief")
	setBool(&object.TransactionExport.Enabled, d, "transaction_export_enabled")
	setBool(&object.TransactionExport.HiRes, d, "transaction_export_hi_res")

	if _, ok := d.GetOk("transaction_export_http_header_blacklist"); ok {
		setStringSet(&object.TransactionExport.HttpHeaderBlacklist, d, "transaction_export_http_header_blacklist")
	} else {
		object.TransactionExport.HttpHeaderBlacklist = &[]string{"Authorization"}
		d.Set("transaction_export_http_header_blacklist", []string(*object.TransactionExport.HttpHeaderBlacklist))
	}
	setBool(&object.Udp.EndPointPersistence, d, "udp_end_point_persistence")
	setBool(&object.Udp.PortSmp, d, "udp_port_smp")
	setInt(&object.Udp.ResponseDatagramsExpected, d, "udp_response_datagrams_expected")
	setInt(&object.Udp.Timeout, d, "udp_timeout")
	setString(&object.Udp.UdpEndTransaction, d, "udp_udp_end_transaction")
	setString(&object.WebCache.ControlOut, d, "web_cache_control_out")
	setBool(&object.WebCache.Enabled, d, "web_cache_enabled")
	setInt(&object.WebCache.ErrorPageTime, d, "web_cache_error_page_time")
	setInt(&object.WebCache.MaxTime, d, "web_cache_max_time")
	setInt(&object.WebCache.RefreshTime, d, "web_cache_refresh_time")
}

func resourceVirtualServerDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeleteVirtualServer(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_virtual_server '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
