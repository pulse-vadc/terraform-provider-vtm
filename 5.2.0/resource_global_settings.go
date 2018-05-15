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

func resourceGlobalSettings() *schema.Resource {
	return &schema.Resource{
		Read:   resourceGlobalSettingsRead,
		Create: resourceGlobalSettingsUpdate,
		Update: resourceGlobalSettingsUpdate,
		Delete: resourceGlobalSettingsDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{

			// How often, in milliseconds, each traffic manager child process
			//  (that isn't listening for new connections) checks to see whether
			//  it should start listening for new connections.
			"accepting_delay": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(5, 999),
				Default:      50,
			},

			// Is the application firewall enabled.
			"afm_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The default chunk size for reading/writing requests.
			"chunk_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      16384,
			},

			// Whether or not your traffic manager should make use of TCP optimisations
			//  to defer the processing of new client-first connections until
			//  the client has sent some data.
			"client_first_opt": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Cluster identifier. Generally supplied by Services Director.
			"cluster_identifier": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The number of CPU cores assigned to assist with data plane acceleration.
			//  These cores are dedicated to reading and writing packets to the
			//  network interface cards and distributing packets between the
			//  traffic manager processes.
			"data_plane_acceleration_cores": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"four", "one", "two"}, false),
				Default:      "one",
			},

			// Whether Data Plane Acceleration Mode is enabled.
			"data_plane_acceleration_mode": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// A list of license servers for FLA licensing.  A license server
			//  should be specified as a "<ip/host>:<port>" pair.
			"license_servers": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The maximum number of file descriptors that your traffic manager
			//  will allocate.
			"max_fds": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(100, 9999999),
				Default:      1048576,
			},

			// The maximum number of each of nodes, pools or locations that
			//  can be monitored. The memory used to store information about
			//  nodes, pools and locations is allocated at start-up, so the traffic
			//  manager must be restarted after changing this setting.
			"monitor_memory_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(4096, 999999),
				Default:      4096,
			},

			// The maximum number of Rate classes that can be created. Approximately
			//  100 bytes will be pre-allocated per Rate class.
			"rate_class_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      25000,
			},

			// The size of the shared memory pool used for shared storage across
			//  worker processes (e.g. bandwidth shared data).This is specified
			//  as either a percentage of system RAM, "5%" for example, or an
			//  absolute size such as "10MB".
			"shared_pool_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "10MB",
			},

			// The maximum number of SLM classes that can be created. Approximately
			//  100 bytes will be pre-allocated per SLM class.
			"slm_class_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      1024,
			},

			// The size of the operating system's read buffer. A value of "0"
			//  (zero) means to use the OS default; in normal circumstances this
			//  is what should be used.
			"so_rbuff_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// The size of the operating system's write buffer. A value of "0"
			//  (zero) means to use the OS default; in normal circumstances this
			//  is what should be used.
			"so_wbuff_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// Whether or not the traffic manager should use potential network
			//  socket optimisations. If set to "auto", a decision will be made
			//  based on the host platform.
			"socket_optimizations": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"auto", "no", "yes"}, false),
				Default:      "auto",
			},

			// The maximum number of Traffic IP Groups that can be created.
			"tip_class_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      10000,
			},

			// Whether or not the admin server, the internal control port and
			//  the config daemon honor the Fallback SCSV to protect connections
			//  against downgrade attacks.
			"admin_honor_fallback_scsv": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not SSL3/TLS re-handshakes should be supported for
			//  admin server and internal connections.
			"admin_ssl3_allow_rehandshake": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"always", "never", "rfc5746", "safe"}, false),
				Default:      "rfc5746",
			},

			// The SSL ciphers to use for admin server and internal connections.
			//  For information on supported ciphers see the online help.
			"admin_ssl3_ciphers": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "SSL_RSA_WITH_AES_128_GCM_SHA256,SSL_RSA_WITH_AES_128_CBC_SHA256,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_GCM_SHA384,SSL_RSA_WITH_AES_256_CBC_SHA256,SSL_RSA_WITH_AES_256_CBC_SHA,SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,SSL_DHE_DSS_WITH_AES_128_CBC_SHA,SSL_DHE_DSS_WITH_AES_256_CBC_SHA,SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
			},

			// The length in bits of the Diffie-Hellman key for ciphers that
			//  use Diffie-Hellman key agreement for admin server and internal
			//  connections.
			"admin_ssl3_diffie_hellman_key_length": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"dh_1024", "dh_2048", "dh_3072", "dh_4096"}, false),
				Default:      "dh_2048",
			},

			// If SSL3/TLS re-handshakes are supported on the admin server,
			//  this defines the minimum time interval (in milliseconds) between
			//  handshakes on a single SSL3/TLS connection that is permitted.
			//   To disable the minimum interval for handshakes the key should
			//  be set to the value "0".
			"admin_ssl3_min_rehandshake_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      1000,
			},

			// The SSL elliptic curve preference list for admin and internal
			//  connections. The named curves P256, P384 and P521 may be configured.
			"admin_ssl_elliptic_curves": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Whether or not SSL3 and TLS1 use one-byte fragments as a BEAST
			//  countermeasure for admin server and internal connections.
			"admin_ssl_insert_extra_fragment": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The maximum size (in bytes) of SSL handshake messages that the
			//  admin server and internal connections will accept. To accept
			//  any size of handshake message the key should be set to the value
			//  "0".
			"admin_ssl_max_handshake_message_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 16777215),
				Default:      10240,
			},

			// Take performance degrading steps to prevent exposing timing side-channels
			//  with SSL3 and TLS used by the admin server and internal connections.
			"admin_ssl_prevent_timing_side_channels": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The SSL signature algorithms preference list for admin and internal
			//  connections using TLS version 1.2 or higher. For information
			//  on supported algorithms see the online help.
			"admin_ssl_signature_algorithms": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not SSL3 support is enabled for admin server and internal
			//  connections.
			"admin_support_ssl3": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not TLS1.0 support is enabled for admin server and
			//  internal connections.
			"admin_support_tls1": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not TLS1.1 support is enabled for admin server and
			//  internal connections.
			"admin_support_tls1_1": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not TLS1.2 support is enabled for admin server and
			//  internal connections.
			"admin_support_tls1_2": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The password used to protect the bootloader. An empty string
			//  means there will be no protection.
			"appliance_bootloader_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not the traffic manager will attempt to route response
			//  packets back to clients via the same route on which the corresponding
			//  request arrived.   Note that this applies only to the last hop
			//  of the route - the behaviour of upstream routers cannot be altered
			//  by the traffic manager.
			"appliance_return_path_routing_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The maximum size of a dependent resource that can undergo Web
			//  Accelerator optimization. Any content larger than this size will
			//  not be optimized. Units of KB and MB can be used, no postfix
			//  denotes bytes. A value of 0 disables the limit.
			"aptimizer_max_dependent_fetch_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "2MB",
			},

			// The maximum size of unoptimized content buffered in the traffic
			//  manager for a single backend response that is undergoing Web
			//  Accelerator optimization. Responses larger than this will not
			//  be optimized. Note that if the backend response is compressed
			//  then this setting pertains to the compressed size, before Web
			//  Accelerator decompresses it. Units of KB and MB can be used,
			//  no postfix denotes bytes. Value range is 1 - 128MB.
			"aptimizer_max_original_content_buffer_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "2MB",
			},

			// The period of time (in seconds) after which a previous failure
			//  will no longer count towards the watchdog limit.
			"aptimizer_watchdog_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      300,
			},

			// The maximum number of times the Web Accelerator sub-process will
			//  be started or restarted within the interval defined by the aptimizer!watchdog_interval
			//  setting. If the process fails this many times, it must be restarted
			//  manually from the Diagnose page.  Zero means no limit.
			"aptimizer_watchdog_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99),
				Default:      3,
			},

			// Whether to mirror the audit log to EventD.
			"auditlog_via_eventd": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether to output audit log message to the syslog.
			"auditlog_via_syslog": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Lifetime in seconds of cryptographic keys used to decrypt SAML
			//  SP sessions stored externally (client-side).
			"auth_saml_key_lifetime": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(120, 31536000),
				Default:      86400,
			},

			// Rotation interval in seconds for cryptographic keys used to encrypt
			//  SAML SP sessions stored externally (client-side).
			"auth_saml_key_rotation_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(60, 31535940),
				Default:      14400,
			},

			// Whether or not detailed messages about the autoscaler's activity
			//  are written to the error log.
			"autoscaler_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The number of the BGP AS in which the traffic manager will operate.
			//  Must be entered in decimal.
			"bgp_as_number": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 4294967295),
				Default:      65534,
			},

			// Whether BGP Route Health Injection is enabled
			"bgp_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The default value of "allow_update" for new cluster members.
			//   If you have cluster members joining from less trusted locations
			//  (such as cloud instances) this can be set to "false" in order
			//  to make them effectively "read-only" cluster members.
			"cluster_comms_allow_update_default": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The hosts that can contact the internal administration port on
			//  each traffic manager.  This should be a list containing IP addresses,
			//  CIDR IP subnets, and "localhost"; or it can be set to "all" to
			//  allow any host to connect.
			"cluster_comms_allowed_update_hosts": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// How often to propagate the session persistence and bandwidth
			//  information to other traffic managers in the same cluster. Set
			//  this to "0" (zero) to disable propagation.<br /> Note that a
			//  cluster using "unicast" heartbeat messages cannot turn off these
			//  messages.
			"cluster_comms_state_sync_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 60),
				Default:      3,
			},

			// The maximum amount of time to wait when propagating session persistence
			//  and bandwidth information to other traffic managers in the same
			//  cluster. Once this timeout is hit the transfer is aborted and
			//  a new connection created.
			"cluster_comms_state_sync_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 60),
				Default:      6,
			},

			// The maximum number of unused HTTP keepalive connections with
			//  back-end nodes that the traffic manager should maintain for re-use.
			//   Setting this to "0" (zero) will cause the traffic manager to
			//  auto-size this parameter based on the available number of file-descriptors.
			"connection_idle_connections_max": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      0,
			},

			// How long an unused HTTP keepalive connection should be kept before
			//  it is discarded.
			"connection_idle_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      10,
			},

			// The listen queue size for managing incoming connections. It may
			//  be necessary to increase the system's listen queue size if this
			//  value is altered.  If the value is set to "0" then the default
			//  system setting will be used.
			"connection_listen_queue_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 10000),
				Default:      0,
			},

			// Number of processes that should accept new connections. Only
			//  this many traffic manager child processes will listen for new
			//  connections at any one time. Setting this to "0" (zero) will
			//  cause your traffic manager to select an appropriate default value
			//  based on the architecture and number of CPUs.
			"connection_max_accepting": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 1000),
				Default:      0,
			},

			// Whether or not the traffic manager should try to read multiple
			//  new connections each time a new client connects. This can improve
			//  performance under some very specific conditions. However, in
			//  general it is recommended that this be set to 'false'.
			"connection_multiple_accept": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The time, in milliseconds, to delay sending a TCP ACK response,
			//  providing an opportunity for additional data to be incorporated
			//  into the response and potentially improving network performance.
			//  The setting affects TCP connections handled by layer 7 services
			//  running in Data Plane Acceleration mode.
			"data_plane_acceleration_tcp_delay_ack": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      200,
			},

			// The TCP window scale option, which configures the size of the
			//  receive window for TCP connections handled by layer 7 services
			//  when running in Data Plane Acceleration mode.
			"data_plane_acceleration_tcp_win_scale": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 7),
				Default:      7,
			},

			// Maximum Time To Live (expiry time) for entries in the DNS cache.
			"dns_max_ttl": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      86400,
			},

			// Minimum Time To Live (expiry time) for entries in the DNS cache.
			"dns_min_ttl": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      86400,
			},

			// Expiry time for failed lookups in the DNS cache.
			"dns_negative_expiry": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      60,
			},

			// Maximum number of entries in the DNS cache.
			"dns_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      10867,
			},

			// Timeout for receiving a response from a DNS server.
			"dns_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 9999),
				Default:      12,
			},

			// Amazon EC2 Access Key ID.
			"ec2_access_key_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The maximum amount of time requests to the AWS Query API can
			//  take before timing out.
			"ec2_awstool_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 3600),
				Default:      10,
			},

			// URL for the EC2 metadata server, "http://169.254.169.254/latest/meta-data"
			//  for example.
			"ec2_metadata_server": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// URL for the Amazon EC2 endpoint, "https://ec2.amazonaws.com/"
			//  for example.
			"ec2_query_server": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Amazon EC2 Secret Access Key.
			"ec2_secret_access_key": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether to verify Amazon EC2 endpoint's certificate using CA(s)
			//  present in SSL Certificate Authorities Catalog.
			"ec2_verify_query_server_cert": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The minimum length of time that must elapse between alert emails
			//  being sent.  Where multiple alerts occur inside this timeframe,
			//  they will be retained and sent within a single email rather than
			//  separately.
			"eventing_mail_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      30,
			},

			// The number of times to attempt to send an alert email before
			//  giving up.
			"eventing_max_attempts": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      10,
			},

			// The number of ARP packets a traffic manager should send when
			//  an IP address is raised.
			"fault_tolerance_arp_count": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      10,
			},

			// Whether or not traffic IPs automatically move back to machines
			//  that have recovered from a failure and have dropped their traffic
			//  IPs.
			"fault_tolerance_auto_failback": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Configure the delay of automatic failback after a previous failover
			//  event. This setting has no effect if autofailback is disabled.
			"fault_tolerance_autofailback_delay": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 86400),
				Default:      10,
			},

			// How long the traffic manager should wait for status updates from
			//  any of the traffic manager's child processes before assuming
			//  one of them is no longer servicing traffic.
			"fault_tolerance_child_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(3, 60),
				Default:      5,
			},

			// The IP addresses used to check front-end connectivity. The text
			//  "%gateway%" will be replaced with the default gateway on each
			//  system. Set this to an empty string if the traffic manager is
			//  on an Intranet with no external connectivity.
			"fault_tolerance_frontend_check_ips": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// The method traffic managers should use to exchange cluster heartbeat
			//  messages.
			"fault_tolerance_heartbeat_method": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"multicast", "unicast"}, false),
				Default:      "unicast",
			},

			// The interval between unsolicited periodic IGMP Membership Report
			//  messages for Multi-Hosted Traffic IP Groups.
			"fault_tolerance_igmp_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 86400),
				Default:      30,
			},

			// When running in Data Plane Acceleration Mode, how long the traffic
			//  manager should wait for a status update from child processes
			//  handling L4Accel services before assuming it is no longer servicing
			//  traffic.
			"fault_tolerance_l4accel_child_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 10),
				Default:      2,
			},

			// The port on which cluster members will transfer state information
			//  for L4Accel services when running in Data Plane Acceleration
			//  Mode.
			"fault_tolerance_l4accel_sync_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      10240,
			},

			// The frequency, in milliseconds, that each traffic manager machine
			//  should check and announce its connectivity.
			"fault_tolerance_monitor_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(100, 59999),
				Default:      500,
			},

			// How long, in seconds, each traffic manager should wait for a
			//  response from its connectivity tests or from other traffic manager
			//  machines before registering a failure.
			"fault_tolerance_monitor_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(3, 60),
				Default:      5,
			},

			// The multicast address and port to use to exchange cluster heartbeat
			//  messages.
			"fault_tolerance_multicast_address": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "239.100.1.1:9090",
			},

			// The unicast UDP port to use to exchange cluster heartbeat messages.
			"fault_tolerance_unicast_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      9090,
			},

			// Whether or not cluster heartbeat messages should only be sent
			//  and received over the management network.
			"fault_tolerance_use_bind_ip": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not a traffic manager should log all connectivity
			//  tests.  This is very verbose, and should only be used for diagnostic
			//  purposes.
			"fault_tolerance_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Enable FIPS Mode (requires software restart).
			"fips_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the traffic manager should permit use of FTP data
			//  connection source ports lower than 1024.  If "No" the traffic
			//  manager can completely drop root privileges, if "Yes" some or
			//  all privileges may be retained in order to bind to low ports.
			"ftp_data_bind_low": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Write a message to the logs for every DNS query that is load
			//  balanced, showing the source IP address and the chosen datacenter.
			"glb_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Number of days to store historical traffic information, if set
			//  to "0" the data will be kept indefinitely.
			"historical_activity_keep_days": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 99999),
				Default:      90,
			},

			// A table of MAC to IP address mappings for each router where return
			//  path routing is required.
			"ip_appliance_returnpath": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// ipv4
						"ipv4": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// ipv6
						"ipv6": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// mac
						"mac": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// CLASSPATH to use when starting the Java runner.
			"java_classpath": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Java command to use when starting the Java runner, including
			//  any additional options.
			"java_command": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "java -server",
			},

			// Whether or not Java support should be enabled.  If this is set
			//  to "No", then your traffic manager will not start any Java processes.
			//  Java support is only required if you are using the TrafficScript
			//  "java.run()" function.
			"java_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Java library directory for additional jar files. The Java runner
			//  will load classes from any ".jar" files stored in this directory,
			//  as well as the * jar files and classes stored in traffic manager's
			//  catalog.
			"java_lib": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Maximum number of simultaneous Java requests. If there are more
			//  than this many requests, then further requests will be queued
			//  until the earlier requests are completed. This setting is per-CPU,
			//  so if your traffic manager is running on a machine with 4 CPU
			//  cores, then each core can make this many requests at one time.
			"java_max_connections": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 1000000),
				Default:      256,
			},

			// Default time to keep a Java session.
			"java_session_age": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 100000000),
				Default:      86400,
			},

			// Whether or not a traffic manager should log all Kerberos related
			//  activity.  This is very verbose, and should only be used for
			//  diagnostic purposes.
			"kerberos_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The maximum number of concurrent connections, in millions, that
			//  can be handled by each L4Accel child process. An appropriate
			//  amount of memory to store this many connections will be allocated
			//  when the traffic manager starts.
			"l4accel_max_concurrent_connections": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 4),
				Default:      1,
			},

			// The minimum severity of events/alerts that should be logged to
			//  disk. "INFO" will log all events; a higher severity setting will
			//  log fewer events.  More fine-grained control can be achieved
			//  using events and actions.
			"log_error_level": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"fatal", "info", "serious", "warn"}, false),
				Default:      "info",
			},

			// How long to wait before flushing the request log files for each
			//  virtual server.
			"log_flush_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      5,
			},

			// The file to log event messages to.
			"log_log_file": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "%zeushome%/zxtm/log/errors",
			},

			// The maximum number of connection errors logged per second when
			//  connection error reporting is enabled.
			"log_rate": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      50,
			},

			// How long to wait before re-opening request log files, this ensures
			//  that log files will be recreated in the case of log rotation.
			"log_reopen": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      30,
			},

			// The minimum time between log messages for log intensive features
			//  such as SLM.
			"log_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      60,
			},

			// The HTTP Event Collector token to use for HTTP authentication
			//  with a Splunk server.
			"log_export_auth_hec_token": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The HTTP authentication method to use when exporting log entries.
			"log_export_auth_http": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"basic", "none", "splunk"}, false),
				Default:      "none",
			},

			// The password to use for HTTP basic authentication.
			"log_export_auth_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The username to use for HTTP basic authentication.
			"log_export_auth_username": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Monitor log files and export entries to the configured endpoint.
			"log_export_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The URL to which log entries should be sent. Entries are sent
			//  using HTTP(S) POST requests.
			"log_export_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The number of seconds after which HTTP requests sent to the configured
			//  endpoint will be considered to have failed if no response is
			//  received. A value of "0" means that HTTP requests will not time
			//  out.
			"log_export_request_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      30,
			},

			// Whether the server certificate should be verified when connecting
			//  to the endpoint. If enabled, server certificates that do not
			//  match the server name, are self-signed, have expired, have been
			//  revoked, or that are signed by an unknown CA will be rejected.
			"log_export_tls_verify": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The OSPF area in which the traffic manager will operate. May
			//  be entered in decimal or IPv4 address format.
			"ospfv2_area": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0.0.0.1",
			},

			// The type of OSPF area in which the traffic manager will operate.
			//  This must be the same for all routers in the area, as required
			//  by OSPF.
			"ospfv2_area_type": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"normal", "nssa", "stub"}, false),
				Default:      "normal",
			},

			// OSPFv2 authentication key ID. If set to 0, which is the default
			//  value, the key is disabled.
			"ospfv2_authentication_key_id_a": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// OSPFv2 authentication key ID. If set to 0, which is the default
			//  value, the key is disabled.
			"ospfv2_authentication_key_id_b": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// OSPFv2 authentication shared secret (MD5). If set to blank, which
			//  is the default value, the key is disabled.
			"ospfv2_authentication_shared_secret_a": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// OSPFv2 authentication shared secret (MD5). If set to blank, which
			//  is the default value, the key is disabled.
			"ospfv2_authentication_shared_secret_b": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The number of seconds before declaring a silent router down.
			"ospfv2_dead_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      40,
			},

			// Whether OSPFv2 Route Health Injection is enabled
			"ospfv2_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The interval at which OSPF "hello" packets are sent to the network.
			"ospfv2_hello_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      10,
			},

			// The amount of shared memory reserved for an inter-process table
			//  of combined connection counts, used by all Service Protection
			//  classes that have "per_process_connection_count" set to "No".
			//   The amount is specified as an absolute size, eg 20MB.
			"protection_conncount_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "20MB",
			},

			// How many recently closed connections each traffic manager process
			//  should save. These saved connections will be shown alongside
			//  currently active connections when viewing the Connections page.
			//  You should set this value to "0" in a benchmarking or performance-critical
			//  environment.
			"recent_connections_max_per_process": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      500,
			},

			// The amount of time for which snapshots will be retained on the
			//  Connections page.
			"recent_connections_retain_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 9999),
				Default:      60,
			},

			// The maximum number of connections each traffic manager process
			//  should show when viewing a snapshot on the Connections page.
			//  This value includes both currently active connections and saved
			//  connections. If set to "0" all active and saved connection will
			//  be displayed on the Connections page.
			"recent_connections_snapshot_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      500,
			},

			// The Owner of a Services Director instance, used for self-registration.
			"remote_licensing_owner": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The secret associated with the Owner.
			"remote_licensing_owner_secret": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The auto-accept Policy ID that this instance should attempt to
			//  use.
			"remote_licensing_policy_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A Services Director address for self-registration. A registration
			//  server should be specified as a "<ip/host>:<port>" pair.
			"remote_licensing_registration_server": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The certificate of a Services Director instance, used for self-registration.
			"remote_licensing_server_certificate": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The length of time after a successful request that the authentication
			//  of a given username and password will be cached for an IP address.
			//  A setting of 0 disables the cache forcing every REST request
			//  to be authenticated which will adversely affect performance.
			"rest_api_auth_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      120,
			},

			// The maximum allowed length in bytes of a HTTP request's headers.
			"rest_api_http_max_header_length": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      4096,
			},

			// Configuration changes will be replicated across the cluster after
			//  this period of time, regardless of whether additional API requests
			//  are being made.
			"rest_api_replicate_absolute": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      20,
			},

			// Configuration changes made via the REST API will be propagated
			//  across the cluster when no further API requests have been made
			//  for this period of time.
			"rest_api_replicate_lull": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      5,
			},

			// The period of time after which configuration replication across
			//  the cluster will be cancelled if it has not completed.
			"rest_api_replicate_timeout": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      10,
			},

			// Banner text displayed on the Admin Server login page and before
			//  logging in to appliance SSH servers.
			"security_login_banner": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not users must explicitly agree to the displayed "login_banner"
			//  text before logging in to the Admin Server.
			"security_login_banner_accept": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The number of seconds before another login attempt can be made
			//  after a failed attempt.
			"security_login_delay": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      4,
			},

			// The number of sequential failed login attempts that will cause
			//  a user account to be suspended.  Setting this to "0" disables
			//  this feature. To apply this to users who have never successfully
			//  logged in, "track_unknown_users" must also be enabled.
			"security_max_login_attempts": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 1000),
				Default:      0,
			},

			// Whether or not usernames blocked due to the "max_login_attempts"
			//  limit should also be blocked from authentication against external
			//  services (such as LDAP and RADIUS).
			"security_max_login_external": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The number of minutes to suspend users who have exceeded the
			//  "max_login_attempts" limit.
			"security_max_login_suspension_time": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 999999),
				Default:      15,
			},

			// Whether or not to allow the same character to appear consecutively
			//  in passwords.
			"security_password_allow_consecutive_chars": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The maximum number of times a password can be changed in a 24-hour
			//  period. Set to "0" to disable this restriction.
			"security_password_changes_per_day": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// Minimum number of alphabetic characters a password must contain.
			//  Set to 0 to disable this restriction.
			"security_password_min_alpha_chars": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// Minimum number of characters a password must contain. Set to
			//  "0" to disable this restriction.
			"security_password_min_length": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// Minimum number of numeric characters a password must contain.
			//  Set to "0" to disable this restriction.
			"security_password_min_numeric_chars": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// Minimum number of special (non-alphanumeric) characters a password
			//  must contain. Set to "0" to disable this restriction.
			"security_password_min_special_chars": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// Minimum number of uppercase characters a password must contain.
			//  Set to "0" to disable this restriction.
			"security_password_min_uppercase_chars": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// The number of times a password must have been changed before
			//  it can be reused. Set to "0" to disable this restriction.
			"security_password_reuse_after": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 255),
				Default:      0,
			},

			// Banner text to be displayed on the appliance console after login.
			"security_post_login_banner": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether to remember past login attempts from usernames that are
			//  not known to exist (should be set to false for an Admin Server
			//  accessible from the public Internet). This does not affect the
			//  audit log.
			"security_track_unknown_users": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Banner text to be displayed on all Admin Server pages.
			"security_ui_page_banner": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The maximum number of entries in the ASP session cache.  This
			//  is used for storing session mappings for ASP session persistence.
			//  Approximately 100 bytes will be pre-allocated per entry.
			"session_asp_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      32768,
			},

			// The maximum number of entries in the IP session cache.  This
			//  is used to provide session persistence based on the source IP
			//  address. Approximately 100 bytes will be pre-allocated per entry.
			"session_ip_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      32768,
			},

			// The maximum number of entries in the J2EE session cache.  This
			//  is used for storing session mappings for J2EE session persistence.
			//  Approximately 100 bytes will be pre-allocated per entry.
			"session_j2ee_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      32768,
			},

			// The maximum number of entries in the SSL session persistence
			//  cache. This is used to provide session persistence based on the
			//  SSL session ID.  Approximately 200 bytes will be pre-allocated
			//  per entry.
			"session_ssl_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      32768,
			},

			// The maximum number of entries in the global universal session
			//  cache.  This is used for storing session mappings for universal
			//  session persistence.  Approximately 100 bytes will be pre-allocated
			//  per entry.
			"session_universal_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      32768,
			},

			// The number of user defined SNMP counters. Approximately 100 bytes
			//  will be pre-allocated at start-up per user defined SNMP counter.
			"snmp_user_counters": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 10000),
				Default:      10,
			},

			// The number of minutes that the SOAP server should remain idle
			//  before exiting.  The SOAP server has a short startup delay the
			//  first time a SOAP request is made, subsequent SOAP requests don't
			//  have this delay.
			"soap_idle_minutes": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 1440),
				Default:      10,
			},

			// The maximum number of Source NAT IP addresses that can be used
			//  across all Traffic IP Groups.
			"source_nat_ip_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 64),
				Default:      16,
			},

			// The upper boundary of the port range reserved for use by the
			//  kernel. Ports above this range will be used by the traffic manager
			//  for establishing outgoing connections.
			"source_nat_ip_local_port_range_high": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(10240, 30720),
				Default:      10240,
			},

			// The size of the Source NAT shared memory pool used for shared
			//  storage across child processes. This value is specified as an
			//  absolute size such as "10MB".
			"source_nat_shared_pool_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(2, 2048),
				Default:      10,
			},

			// Whether or not SSL/TLS re-handshakes should be supported. Enabling
			//  support for re-handshakes can expose services to Man-in-the-Middle
			//  attacks. It is recommended that only "safe" handshakes be permitted,
			//  or none at all.
			"ssl_allow_rehandshake": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"always", "never", "rfc5746", "safe"}, false),
				Default:      "safe",
			},

			// Whether or not the SSL server session cache is enabled, unless
			//  overridden by virtual server settings.
			"ssl_cache_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// How long the SSL session IDs for SSL decryption should be stored
			//  for.
			"ssl_cache_expiry": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      1800,
			},

			// Whether an SSL session created by a given virtual server can
			//  only be resumed by a connection to the same virtual server.
			"ssl_cache_per_virtualserver": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// How many entries the SSL session ID cache should hold. This cache
			//  is used to cache SSL sessions to help speed up SSL handshakes
			//  when performing SSL decryption. Each entry will allocate approximately
			//  1.5kB of metadata.
			"ssl_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      6151,
			},

			// The SSL/TLS cipher suites preference list for SSL/TLS connections,
			//  unless overridden by virtual server or pool settings. For information
			//  on supported cipher suites see the online help.
			"ssl_cipher_suites": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or the SSL client cache will be used, unless overridden
			//  by pool settings.
			"ssl_client_cache_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// How long in seconds SSL sessions should be stored in the client
			//  cache for, by default. Servers returning session tickets may
			//  also provide a lifetime hint, which will be used if it is less
			//  than this value.
			"ssl_client_cache_expiry": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      14400,
			},

			// How many entries the SSL client session cache should hold, per
			//  child. This cache is used to cache SSL sessions to help speed
			//  up SSL handshakes when performing SSL encryption. Each entry
			//  will require approx 100 bytes of memory plus space for either
			//  an SSL session id or an SSL session ticket, which may be as small
			//  as 16 bytes or may be as large as a few kilobytes, depending
			//  upon the server behavior.
			"ssl_client_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      1024,
			},

			// Whether or not session tickets may be requested and stored in
			//  the SSL client cache.
			"ssl_client_cache_tickets_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// How much shared memory to allocate for loading Certificate Revocation
			//  Lists. This should be at least 3 times the total size of all
			//  CRLs on disk. This is specified as either a percentage of system
			//  RAM, "1%" for example, or an absolute size such as "10MB".
			"ssl_crl_mem_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "5MB",
			},

			// The size in bits of the modulus for the domain parameters used
			//  for cipher suites that use finite field Diffie-Hellman key agreement.
			"ssl_diffie_hellman_modulus_size": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"dh_1024", "dh_2048", "dh_3072", "dh_4096"}, false),
				Default:      "dh_2048",
			},

			// The SSL/TLS elliptic curve preference list for SSL/TLS connections
			//  using TLS version 1.0 or higher, unless overridden by virtual
			//  server or pool settings. For information on supported curves
			//  see the online help.
			"ssl_elliptic_curves": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Whether or not ssl-decrypting Virtual Servers honor the Fallback
			//  SCSV to protect connections against downgrade attacks.
			"ssl_honor_fallback_scsv": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not SSL3 and TLS1 use one-byte fragments as a BEAST
			//  countermeasure.
			"ssl_insert_extra_fragment": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The maximum size (in bytes) of SSL handshake messages that SSL
			//  connections will accept. To accept any size of handshake message
			//  the key should be set to the value "0".
			"ssl_max_handshake_message_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 16777215),
				Default:      10240,
			},

			// If SSL3/TLS re-handshakes are supported, this defines the minimum
			//  time interval (in milliseconds) between handshakes on a single
			//  SSL3/TLS connection that is permitted.  To disable the minimum
			//  interval for handshakes the key should be set to the value "0".
			"ssl_min_rehandshake_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      1000,
			},

			// The maximum number of cached client certificate OCSP results
			//  stored. This cache is used to speed up OCSP checks against client
			//  certificates by caching results. Approximately 1040 bytes are
			//  pre-allocated per entry.
			"ssl_ocsp_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      2048,
			},

			// How long to wait before refreshing requests on behalf of the
			//  store of certificate status responses used by OCSP stapling,
			//  if we don't have an up-to-date OCSP response.
			"ssl_ocsp_stapling_default_refresh_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      60,
			},

			// Maximum time to wait before refreshing requests on behalf of
			//  the store of certificate status responses used by OCSP stapling.
			//  (0 means no maximum.)
			"ssl_ocsp_stapling_maximum_refresh_interval": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      864000,
			},

			// How much shared memory to allocate for the store of certificate
			//  status responses for OCSP stapling. This should be at least 2kB
			//  times the number of certificates configured to use OCSP stapling.
			//  This is specified as either a percentage of system RAM, "1%"
			//  for example, or an absolute size such as "10MB".
			"ssl_ocsp_stapling_mem_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "1MB",
			},

			// How many seconds to allow the current time to be outside the
			//  validity time of an OCSP response before considering it invalid.
			"ssl_ocsp_stapling_time_tolerance": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      30,
			},

			// Whether the OCSP response signature should be verified before
			//  the OCSP response is cached.
			"ssl_ocsp_stapling_verify_response": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Take performance degrading steps to prevent exposing timing side-channels
			//  with SSL3 and TLS.
			"ssl_prevent_timing_side_channels": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The SSL/TLS signature algorithms preference list for SSL/TLS
			//  connections using TLS version 1.2 or higher, unless overridden
			//  by virtual server or pool settings. For information on supported
			//  algorithms see the online help.
			"ssl_signature_algorithms": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not SSL3 support is enabled.
			"ssl_support_ssl3": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not TLS1.0 support is enabled.
			"ssl_support_tls1": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not TLS1.1 support is enabled.
			"ssl_support_tls1_1": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not TLS1.2 support is enabled.
			"ssl_support_tls1_2": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not session tickets will be issued to and accepted
			//  from clients that support them, unless overridden by virtual
			//  server settings.
			"ssl_tickets_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// When an SSL session ticket will be reissued (ie when a new ticket
			//  will be generated for the same SSL session).
			"ssl_tickets_reissue_policy": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"always", "never"}, false),
				Default:      "never",
			},

			// The length of time for which an SSL session ticket will be accepted
			//  by a virtual server after the ticket is created. If a ticket
			//  is reissued (if ssl!tickets!reissue_policy is set to 'always')
			//  this time starts at the time when the ticket was reissued.
			"ssl_tickets_ticket_expiry": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(60, 31536000),
				Default:      14400,
			},

			// The length of time for which an auto-generated SSL ticket key
			//  will be used to decrypt old session ticket, before being deleted
			//  from memory. This setting is ignored if there are any entries
			//  in the (REST-only) SSL ticket keys catalog.
			"ssl_tickets_ticket_key_expiry": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(120, 31536000),
				Default:      86400,
			},

			// The length of time for which an auto-generated SSL ticket key
			//  will be used to encrypt new session tickets, before a new SSL
			//  ticket key is generated. The ticket encryption key will be held
			//  in memory for ssl!tickets!ticket_key_expiry, so that tickets
			//  encrypted using the key can still be decrypted and used. This
			//  setting is ignored if there are any entries in the (REST-only)
			//  SSL ticket keys catalog.
			"ssl_tickets_ticket_key_rotation": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(60, 31535940),
				Default:      14400,
			},

			// How many seconds to allow the current time to be outside the
			//  validity time of an SSL ticket before considering it invalid.
			"ssl_tickets_time_tolerance": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      30,
			},

			// Whether the traffic manager should validate that SSL server certificates
			//  form a matching key pair before the certificate gets used on
			//  an SSL decrypting virtual server.
			"ssl_validate_server_certificates_catalog": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the SSL hardware is an "accelerator" (faster than
			//  software). By default the traffic manager will only use the SSL
			//  hardware if a key requires it (i.e. the key is stored on secure
			//  hardware and the traffic manager only has a placeholder/identifier
			//  key). With this option enabled, your traffic manager will instead
			//  try to use hardware for all SSL decrypts.
			"ssl_hardware_accel": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The client identifier used when accessing the Microsoft Azure
			//  Key Vault.
			"ssl_hardware_azure_client_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The client secret used when accessing the Microsoft Azure Key
			//  Vault.
			"ssl_hardware_azure_client_secret": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The URL for the REST API of the Microsoft Azure Key Vault.
			"ssl_hardware_azure_vault_url": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not the Azure Key Vault REST API certificate should
			//  be verified.
			"ssl_hardware_azure_verify_rest_api_cert": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Print verbose information about the PKCS11 hardware security
			//  module to the event log.
			"ssl_hardware_driver_pkcs11_debug": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The location of the PKCS#11 library for your SSL hardware if
			//  it is not in a standard location.  The traffic manager will search
			//  the standard locations by default.
			"ssl_hardware_driver_pkcs11_lib": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The label of the SSL Hardware slot to use. Only required if you
			//  have multiple HW accelerator slots.
			"ssl_hardware_driver_pkcs11_slot_desc": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The type of SSL hardware slot to use.
			"ssl_hardware_driver_pkcs11_slot_type": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"module", "operator", "softcard"}, false),
				Default:      "operator",
			},

			// The User PIN for the PKCS token (PKCS#11 devices only).
			"ssl_hardware_driver_pkcs11_user_pin": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The number of consecutive failures from the SSL hardware that
			//  will be tolerated before the traffic manager assumes its session
			//  with the device is invalid and tries to log in again.  This is
			//  necessary when the device reboots following a power failure.
			"ssl_hardware_failure_count": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 99999),
				Default:      5,
			},

			// The type of SSL hardware to use. The drivers for the SSL hardware
			//  should be installed and accessible to the traffic manager software.
			"ssl_hardware_library": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"azure", "none", "pkcs11"}, false),
				Default:      "none",
			},

			// Allow the reporting of anonymized usage data to Pulse Secure
			//  for product improvement and customer support purposes.
			"telemetry_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The maximum amount of memory available to store TrafficScript
			//  "data.local.set()" information. This can be specified as a percentage
			//  of system RAM, "5%" for example; or an absolute size such as
			//  "200MB".
			"trafficscript_data_local_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "5%",
			},

			// The maximum amount of memory available to store TrafficScript
			//  "data.set()" information.  This can be specified as a percentage
			//  of system RAM, "5%" for example; or an absolute size such as
			//  "200MB".
			"trafficscript_data_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "5%",
			},

			// Raise an event if a TrafficScript rule runs for more than this
			//  number of milliseconds in a single invocation. If you get such
			//  events repeatedly, you may want to consider re-working some of
			//  your TrafficScript rules. A value of 0 means no warnings will
			//  be issued.
			"trafficscript_execution_time_warning": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      500,
			},

			// The maximum number of instructions a TrafficScript rule will
			//  run. A rule will be aborted if it runs more than this number
			//  of instructions without yielding, preventing infinite loops.
			"trafficscript_max_instr": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      100000,
			},

			// Raise an event if a TrafficScript rule requires more than this
			//  amount of buffered network data.  If you get such events repeatedly,
			//  you may want to consider re-working some of your TrafficScript
			//  rules to use less memory or to stream the data that they process
			//  rather than storing it all in memory. This setting also limits
			//  the amount of data that can be returned by "request.GetLine()".
			"trafficscript_memory_warning": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483647),
				Default:      1048576,
			},

			// The maximum number of regular expressions to cache in TrafficScript.
			//  Regular expressions will be compiled in order to speed up their
			//  use in the future.
			"trafficscript_regex_cache_size": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      57,
			},

			// The maximum number of ways TrafficScript will attempt to match
			//  a regular expression at each position in the subject string,
			//  before it aborts the rule and reports a TrafficScript error.
			"trafficscript_regex_match_limit": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 2147483646),
				Default:      10000000,
			},

			// The percentage of "regex_match_limit" at which TrafficScript
			//  reports a performance warning.
			"trafficscript_regex_match_warn_percentage": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 100),
				Default:      5,
			},

			// Allow the "pool.use" and "pool.select" TrafficScript functions
			//  to accept variables instead of requiring literal strings. <br
			//  /> Enabling this feature has the following effects 1. Your traffic
			//  manager may no longer be able to know whether a pool is in use.
			//  2. Errors for pools that aren't in use will not be hidden. 3.
			//  Some settings displayed for a Pool may not be appropriate for
			//  the type of traffic being managed. 4. Pool usage information
			//  on the pool edit pages and config summary may not be accurate.
			//  5. Monitors will run for all pools (with this option disabled
			//  monitors will only run for Pools that are used).
			"trafficscript_variable_pool_use": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Export metadata about transactions processed by the traffic manager
			//  to an external location.
			"transaction_export_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The endpoint to which transaction metadata should be exported.
			//  The endpoint is specified as a hostname or IP address with a
			//  port.
			"transaction_export_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether the connection to the specified endpoint should be encrypted.
			"transaction_export_tls": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether the server certificate presented by the endpoint should
			//  be verified, preventing a connection from being established if
			//  the certificate does not match the server name, is self-signed,
			//  is expired, is revoked, or has an unknown CA.
			"transaction_export_tls_verify": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The estimated average length of the path (including query string)
			//  for resources being cached. An amount of memory equal to this
			//  figure multiplied by max_file_num will be allocated for storing
			//  the paths for cache entries. This setting can be increased if
			//  your web site makes extensive use of long URLs.
			"web_cache_avg_path_length": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      512,
			},

			// Whether or not to use a disk-backed (typically SSD) cache.  If
			//  set to "Yes" cached web pages will be stored in a file on disk.
			//   This enables the traffic manager to use a cache that is larger
			//  than available RAM.  The "size" setting should also be adjusted
			//  to select a suitable maximum size based on your disk space. <br
			//  /> Note that the disk caching is optimized for use with SSD storage.
			"web_cache_disk": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// If disk caching is enabled, this sets the directory where the
			//  disk cache file will be stored.  The traffic manager will create
			//  a file called "webcache.data" in this location. <br /> Note that
			//  the disk caching is optimized for use with SSD storage.
			"web_cache_disk_dir": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "%zeushome%/zxtm/internal",
			},

			// Maximum number of entries in the cache.  Approximately 0.9 KB
			//  will be pre-allocated per entry for metadata, this is in addition
			//  to the memory reserved for the content cache and for storing
			//  the paths of the cached resources.
			"web_cache_max_file_num": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 2147483647),
				Default:      10000,
			},

			// Largest size of a cacheable object in the cache.  This is specified
			//  as either a percentage of the total cache size, "2%" for example,
			//  or an absolute size such as "20MB".
			"web_cache_max_file_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "2%",
			},

			// The maximum length of the path (including query string) for the
			//  resource being cached. If the path exceeds this length then it
			//  will not be added to the cache.
			"web_cache_max_path_length": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(0, 999999),
				Default:      2048,
			},

			// Enable normalization (lexical ordering of the parameter-assignments)
			//  of the query string.
			"web_cache_normalize_query": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The maximum size of the HTTP web page cache.  This is specified
			//  as either a percentage of system RAM, "20%" for example, or an
			//  absolute size such as "200MB".
			"web_cache_size": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "20%",
			},

			// Add an X-Cache-Info header to every HTTP response, showing whether
			//  the request and/or the response was cacheable.
			"web_cache_verbose": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

func resourceGlobalSettingsRead(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetGlobalSettings()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_global_setting: %v", err.ErrorText)
	}
	d.Set("accepting_delay", int(*object.Basic.AcceptingDelay))
	d.Set("afm_enabled", bool(*object.Basic.AfmEnabled))
	d.Set("chunk_size", int(*object.Basic.ChunkSize))
	d.Set("client_first_opt", bool(*object.Basic.ClientFirstOpt))
	d.Set("cluster_identifier", string(*object.Basic.ClusterIdentifier))
	d.Set("data_plane_acceleration_cores", string(*object.Basic.DataPlaneAccelerationCores))
	d.Set("data_plane_acceleration_mode", bool(*object.Basic.DataPlaneAccelerationMode))
	d.Set("license_servers", []string(*object.Basic.LicenseServers))
	d.Set("max_fds", int(*object.Basic.MaxFds))
	d.Set("monitor_memory_size", int(*object.Basic.MonitorMemorySize))
	d.Set("rate_class_limit", int(*object.Basic.RateClassLimit))
	d.Set("shared_pool_size", string(*object.Basic.SharedPoolSize))
	d.Set("slm_class_limit", int(*object.Basic.SlmClassLimit))
	d.Set("so_rbuff_size", int(*object.Basic.SoRbuffSize))
	d.Set("so_wbuff_size", int(*object.Basic.SoWbuffSize))
	d.Set("socket_optimizations", string(*object.Basic.SocketOptimizations))
	d.Set("tip_class_limit", int(*object.Basic.TipClassLimit))
	d.Set("admin_honor_fallback_scsv", bool(*object.Admin.HonorFallbackScsv))
	d.Set("admin_ssl3_allow_rehandshake", string(*object.Admin.Ssl3AllowRehandshake))
	d.Set("admin_ssl3_ciphers", string(*object.Admin.Ssl3Ciphers))
	d.Set("admin_ssl3_diffie_hellman_key_length", string(*object.Admin.Ssl3DiffieHellmanKeyLength))
	d.Set("admin_ssl3_min_rehandshake_interval", int(*object.Admin.Ssl3MinRehandshakeInterval))
	d.Set("admin_ssl_elliptic_curves", []string(*object.Admin.SslEllipticCurves))
	d.Set("admin_ssl_insert_extra_fragment", bool(*object.Admin.SslInsertExtraFragment))
	d.Set("admin_ssl_max_handshake_message_size", int(*object.Admin.SslMaxHandshakeMessageSize))
	d.Set("admin_ssl_prevent_timing_side_channels", bool(*object.Admin.SslPreventTimingSideChannels))
	d.Set("admin_ssl_signature_algorithms", string(*object.Admin.SslSignatureAlgorithms))
	d.Set("admin_support_ssl3", bool(*object.Admin.SupportSsl3))
	d.Set("admin_support_tls1", bool(*object.Admin.SupportTls1))
	d.Set("admin_support_tls1_1", bool(*object.Admin.SupportTls11))
	d.Set("admin_support_tls1_2", bool(*object.Admin.SupportTls12))
	d.Set("appliance_bootloader_password", string(*object.Appliance.BootloaderPassword))
	d.Set("appliance_return_path_routing_enabled", bool(*object.Appliance.ReturnPathRoutingEnabled))
	d.Set("aptimizer_max_dependent_fetch_size", string(*object.Aptimizer.MaxDependentFetchSize))
	d.Set("aptimizer_max_original_content_buffer_size", string(*object.Aptimizer.MaxOriginalContentBufferSize))
	d.Set("aptimizer_watchdog_interval", int(*object.Aptimizer.WatchdogInterval))
	d.Set("aptimizer_watchdog_limit", int(*object.Aptimizer.WatchdogLimit))
	d.Set("auditlog_via_eventd", bool(*object.Auditlog.ViaEventd))
	d.Set("auditlog_via_syslog", bool(*object.Auditlog.ViaSyslog))
	d.Set("auth_saml_key_lifetime", int(*object.Auth.SamlKeyLifetime))
	d.Set("auth_saml_key_rotation_interval", int(*object.Auth.SamlKeyRotationInterval))
	d.Set("autoscaler_verbose", bool(*object.Autoscaler.Verbose))
	d.Set("bgp_as_number", int(*object.Bgp.AsNumber))
	d.Set("bgp_enabled", bool(*object.Bgp.Enabled))
	d.Set("cluster_comms_allow_update_default", bool(*object.ClusterComms.AllowUpdateDefault))
	d.Set("cluster_comms_allowed_update_hosts", []string(*object.ClusterComms.AllowedUpdateHosts))
	d.Set("cluster_comms_state_sync_interval", int(*object.ClusterComms.StateSyncInterval))
	d.Set("cluster_comms_state_sync_timeout", int(*object.ClusterComms.StateSyncTimeout))
	d.Set("connection_idle_connections_max", int(*object.Connection.IdleConnectionsMax))
	d.Set("connection_idle_timeout", int(*object.Connection.IdleTimeout))
	d.Set("connection_listen_queue_size", int(*object.Connection.ListenQueueSize))
	d.Set("connection_max_accepting", int(*object.Connection.MaxAccepting))
	d.Set("connection_multiple_accept", bool(*object.Connection.MultipleAccept))
	d.Set("data_plane_acceleration_tcp_delay_ack", int(*object.DataPlaneAcceleration.TcpDelayAck))
	d.Set("data_plane_acceleration_tcp_win_scale", int(*object.DataPlaneAcceleration.TcpWinScale))
	d.Set("dns_max_ttl", int(*object.Dns.MaxTtl))
	d.Set("dns_min_ttl", int(*object.Dns.MinTtl))
	d.Set("dns_negative_expiry", int(*object.Dns.NegativeExpiry))
	d.Set("dns_size", int(*object.Dns.Size))
	d.Set("dns_timeout", int(*object.Dns.Timeout))
	d.Set("ec2_access_key_id", string(*object.Ec2.AccessKeyId))
	d.Set("ec2_awstool_timeout", int(*object.Ec2.AwstoolTimeout))
	d.Set("ec2_metadata_server", string(*object.Ec2.MetadataServer))
	d.Set("ec2_query_server", string(*object.Ec2.QueryServer))
	d.Set("ec2_secret_access_key", string(*object.Ec2.SecretAccessKey))
	d.Set("ec2_verify_query_server_cert", bool(*object.Ec2.VerifyQueryServerCert))
	d.Set("eventing_mail_interval", int(*object.Eventing.MailInterval))
	d.Set("eventing_max_attempts", int(*object.Eventing.MaxAttempts))
	d.Set("fault_tolerance_arp_count", int(*object.FaultTolerance.ArpCount))
	d.Set("fault_tolerance_auto_failback", bool(*object.FaultTolerance.AutoFailback))
	d.Set("fault_tolerance_autofailback_delay", int(*object.FaultTolerance.AutofailbackDelay))
	d.Set("fault_tolerance_child_timeout", int(*object.FaultTolerance.ChildTimeout))
	d.Set("fault_tolerance_frontend_check_ips", []string(*object.FaultTolerance.FrontendCheckIps))
	d.Set("fault_tolerance_heartbeat_method", string(*object.FaultTolerance.HeartbeatMethod))
	d.Set("fault_tolerance_igmp_interval", int(*object.FaultTolerance.IgmpInterval))
	d.Set("fault_tolerance_l4accel_child_timeout", int(*object.FaultTolerance.L4AccelChildTimeout))
	d.Set("fault_tolerance_l4accel_sync_port", int(*object.FaultTolerance.L4AccelSyncPort))
	d.Set("fault_tolerance_monitor_interval", int(*object.FaultTolerance.MonitorInterval))
	d.Set("fault_tolerance_monitor_timeout", int(*object.FaultTolerance.MonitorTimeout))
	d.Set("fault_tolerance_multicast_address", string(*object.FaultTolerance.MulticastAddress))
	d.Set("fault_tolerance_unicast_port", int(*object.FaultTolerance.UnicastPort))
	d.Set("fault_tolerance_use_bind_ip", bool(*object.FaultTolerance.UseBindIp))
	d.Set("fault_tolerance_verbose", bool(*object.FaultTolerance.Verbose))
	d.Set("fips_enabled", bool(*object.Fips.Enabled))
	d.Set("ftp_data_bind_low", bool(*object.Ftp.DataBindLow))
	d.Set("glb_verbose", bool(*object.Glb.Verbose))
	d.Set("historical_activity_keep_days", int(*object.HistoricalActivity.KeepDays))

	ipApplianceReturnpath := make([]map[string]interface{}, 0, len(*object.Ip.ApplianceReturnpath))
	for _, item := range *object.Ip.ApplianceReturnpath {
		itemTerraform := make(map[string]interface{})
		if item.Ipv4 != nil {
			itemTerraform["ipv4"] = string(*item.Ipv4)
		}
		if item.Ipv6 != nil {
			itemTerraform["ipv6"] = string(*item.Ipv6)
		}
		if item.Mac != nil {
			itemTerraform["mac"] = string(*item.Mac)
		}
		ipApplianceReturnpath = append(ipApplianceReturnpath, itemTerraform)
	}
	d.Set("ip_appliance_returnpath", ipApplianceReturnpath)
	ipApplianceReturnpathJson, _ := json.Marshal(ipApplianceReturnpath)
	d.Set("ip_appliance_returnpath_json", ipApplianceReturnpathJson)
	d.Set("java_classpath", string(*object.Java.Classpath))
	d.Set("java_command", string(*object.Java.Command))
	d.Set("java_enabled", bool(*object.Java.Enabled))
	d.Set("java_lib", string(*object.Java.Lib))
	d.Set("java_max_connections", int(*object.Java.MaxConnections))
	d.Set("java_session_age", int(*object.Java.SessionAge))
	d.Set("kerberos_verbose", bool(*object.Kerberos.Verbose))
	d.Set("l4accel_max_concurrent_connections", int(*object.L4Accel.MaxConcurrentConnections))
	d.Set("log_error_level", string(*object.Log.ErrorLevel))
	d.Set("log_flush_time", int(*object.Log.FlushTime))
	d.Set("log_log_file", string(*object.Log.LogFile))
	d.Set("log_rate", int(*object.Log.Rate))
	d.Set("log_reopen", int(*object.Log.Reopen))
	d.Set("log_time", int(*object.Log.Time))
	d.Set("log_export_auth_hec_token", string(*object.LogExport.AuthHecToken))
	d.Set("log_export_auth_http", string(*object.LogExport.AuthHttp))
	d.Set("log_export_auth_password", string(*object.LogExport.AuthPassword))
	d.Set("log_export_auth_username", string(*object.LogExport.AuthUsername))
	d.Set("log_export_enabled", bool(*object.LogExport.Enabled))
	d.Set("log_export_endpoint", string(*object.LogExport.Endpoint))
	d.Set("log_export_request_timeout", int(*object.LogExport.RequestTimeout))
	d.Set("log_export_tls_verify", bool(*object.LogExport.TlsVerify))
	d.Set("ospfv2_area", string(*object.Ospfv2.Area))
	d.Set("ospfv2_area_type", string(*object.Ospfv2.AreaType))
	d.Set("ospfv2_authentication_key_id_a", int(*object.Ospfv2.AuthenticationKeyIdA))
	d.Set("ospfv2_authentication_key_id_b", int(*object.Ospfv2.AuthenticationKeyIdB))
	d.Set("ospfv2_authentication_shared_secret_a", string(*object.Ospfv2.AuthenticationSharedSecretA))
	d.Set("ospfv2_authentication_shared_secret_b", string(*object.Ospfv2.AuthenticationSharedSecretB))
	d.Set("ospfv2_dead_interval", int(*object.Ospfv2.DeadInterval))
	d.Set("ospfv2_enabled", bool(*object.Ospfv2.Enabled))
	d.Set("ospfv2_hello_interval", int(*object.Ospfv2.HelloInterval))
	d.Set("protection_conncount_size", string(*object.Protection.ConncountSize))
	d.Set("recent_connections_max_per_process", int(*object.RecentConnections.MaxPerProcess))
	d.Set("recent_connections_retain_time", int(*object.RecentConnections.RetainTime))
	d.Set("recent_connections_snapshot_size", int(*object.RecentConnections.SnapshotSize))
	d.Set("remote_licensing_owner", string(*object.RemoteLicensing.Owner))
	d.Set("remote_licensing_owner_secret", string(*object.RemoteLicensing.OwnerSecret))
	d.Set("remote_licensing_policy_id", string(*object.RemoteLicensing.PolicyId))
	d.Set("remote_licensing_registration_server", string(*object.RemoteLicensing.RegistrationServer))
	d.Set("remote_licensing_server_certificate", string(*object.RemoteLicensing.ServerCertificate))
	d.Set("rest_api_auth_timeout", int(*object.RestApi.AuthTimeout))
	d.Set("rest_api_http_max_header_length", int(*object.RestApi.HttpMaxHeaderLength))
	d.Set("rest_api_replicate_absolute", int(*object.RestApi.ReplicateAbsolute))
	d.Set("rest_api_replicate_lull", int(*object.RestApi.ReplicateLull))
	d.Set("rest_api_replicate_timeout", int(*object.RestApi.ReplicateTimeout))
	d.Set("security_login_banner", string(*object.Security.LoginBanner))
	d.Set("security_login_banner_accept", bool(*object.Security.LoginBannerAccept))
	d.Set("security_login_delay", int(*object.Security.LoginDelay))
	d.Set("security_max_login_attempts", int(*object.Security.MaxLoginAttempts))
	d.Set("security_max_login_external", bool(*object.Security.MaxLoginExternal))
	d.Set("security_max_login_suspension_time", int(*object.Security.MaxLoginSuspensionTime))
	d.Set("security_password_allow_consecutive_chars", bool(*object.Security.PasswordAllowConsecutiveChars))
	d.Set("security_password_changes_per_day", int(*object.Security.PasswordChangesPerDay))
	d.Set("security_password_min_alpha_chars", int(*object.Security.PasswordMinAlphaChars))
	d.Set("security_password_min_length", int(*object.Security.PasswordMinLength))
	d.Set("security_password_min_numeric_chars", int(*object.Security.PasswordMinNumericChars))
	d.Set("security_password_min_special_chars", int(*object.Security.PasswordMinSpecialChars))
	d.Set("security_password_min_uppercase_chars", int(*object.Security.PasswordMinUppercaseChars))
	d.Set("security_password_reuse_after", int(*object.Security.PasswordReuseAfter))
	d.Set("security_post_login_banner", string(*object.Security.PostLoginBanner))
	d.Set("security_track_unknown_users", bool(*object.Security.TrackUnknownUsers))
	d.Set("security_ui_page_banner", string(*object.Security.UiPageBanner))
	d.Set("session_asp_cache_size", int(*object.Session.AspCacheSize))
	d.Set("session_ip_cache_size", int(*object.Session.IpCacheSize))
	d.Set("session_j2ee_cache_size", int(*object.Session.J2EeCacheSize))
	d.Set("session_ssl_cache_size", int(*object.Session.SslCacheSize))
	d.Set("session_universal_cache_size", int(*object.Session.UniversalCacheSize))
	d.Set("snmp_user_counters", int(*object.Snmp.UserCounters))
	d.Set("soap_idle_minutes", int(*object.Soap.IdleMinutes))
	d.Set("source_nat_ip_limit", int(*object.SourceNat.IpLimit))
	d.Set("source_nat_ip_local_port_range_high", int(*object.SourceNat.IpLocalPortRangeHigh))
	d.Set("source_nat_shared_pool_size", int(*object.SourceNat.SharedPoolSize))
	d.Set("ssl_allow_rehandshake", string(*object.Ssl.AllowRehandshake))
	d.Set("ssl_cache_enabled", bool(*object.Ssl.CacheEnabled))
	d.Set("ssl_cache_expiry", int(*object.Ssl.CacheExpiry))
	d.Set("ssl_cache_per_virtualserver", bool(*object.Ssl.CachePerVirtualserver))
	d.Set("ssl_cache_size", int(*object.Ssl.CacheSize))
	d.Set("ssl_cipher_suites", string(*object.Ssl.CipherSuites))
	d.Set("ssl_client_cache_enabled", bool(*object.Ssl.ClientCacheEnabled))
	d.Set("ssl_client_cache_expiry", int(*object.Ssl.ClientCacheExpiry))
	d.Set("ssl_client_cache_size", int(*object.Ssl.ClientCacheSize))
	d.Set("ssl_client_cache_tickets_enabled", bool(*object.Ssl.ClientCacheTicketsEnabled))
	d.Set("ssl_crl_mem_size", string(*object.Ssl.CrlMemSize))
	d.Set("ssl_diffie_hellman_modulus_size", string(*object.Ssl.DiffieHellmanModulusSize))
	d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	d.Set("ssl_honor_fallback_scsv", bool(*object.Ssl.HonorFallbackScsv))
	d.Set("ssl_insert_extra_fragment", bool(*object.Ssl.InsertExtraFragment))
	d.Set("ssl_max_handshake_message_size", int(*object.Ssl.MaxHandshakeMessageSize))
	d.Set("ssl_min_rehandshake_interval", int(*object.Ssl.MinRehandshakeInterval))
	d.Set("ssl_ocsp_cache_size", int(*object.Ssl.OcspCacheSize))
	d.Set("ssl_ocsp_stapling_default_refresh_interval", int(*object.Ssl.OcspStaplingDefaultRefreshInterval))
	d.Set("ssl_ocsp_stapling_maximum_refresh_interval", int(*object.Ssl.OcspStaplingMaximumRefreshInterval))
	d.Set("ssl_ocsp_stapling_mem_size", string(*object.Ssl.OcspStaplingMemSize))
	d.Set("ssl_ocsp_stapling_time_tolerance", int(*object.Ssl.OcspStaplingTimeTolerance))
	d.Set("ssl_ocsp_stapling_verify_response", bool(*object.Ssl.OcspStaplingVerifyResponse))
	d.Set("ssl_prevent_timing_side_channels", bool(*object.Ssl.PreventTimingSideChannels))
	d.Set("ssl_signature_algorithms", string(*object.Ssl.SignatureAlgorithms))
	d.Set("ssl_support_ssl3", bool(*object.Ssl.SupportSsl3))
	d.Set("ssl_support_tls1", bool(*object.Ssl.SupportTls1))
	d.Set("ssl_support_tls1_1", bool(*object.Ssl.SupportTls11))
	d.Set("ssl_support_tls1_2", bool(*object.Ssl.SupportTls12))
	d.Set("ssl_tickets_enabled", bool(*object.Ssl.TicketsEnabled))
	d.Set("ssl_tickets_reissue_policy", string(*object.Ssl.TicketsReissuePolicy))
	d.Set("ssl_tickets_ticket_expiry", int(*object.Ssl.TicketsTicketExpiry))
	d.Set("ssl_tickets_ticket_key_expiry", int(*object.Ssl.TicketsTicketKeyExpiry))
	d.Set("ssl_tickets_ticket_key_rotation", int(*object.Ssl.TicketsTicketKeyRotation))
	d.Set("ssl_tickets_time_tolerance", int(*object.Ssl.TicketsTimeTolerance))
	d.Set("ssl_validate_server_certificates_catalog", bool(*object.Ssl.ValidateServerCertificatesCatalog))
	d.Set("ssl_hardware_accel", bool(*object.SslHardware.Accel))
	d.Set("ssl_hardware_azure_client_id", string(*object.SslHardware.AzureClientId))
	d.Set("ssl_hardware_azure_client_secret", string(*object.SslHardware.AzureClientSecret))
	d.Set("ssl_hardware_azure_vault_url", string(*object.SslHardware.AzureVaultUrl))
	d.Set("ssl_hardware_azure_verify_rest_api_cert", bool(*object.SslHardware.AzureVerifyRestApiCert))
	d.Set("ssl_hardware_driver_pkcs11_debug", bool(*object.SslHardware.DriverPkcs11Debug))
	d.Set("ssl_hardware_driver_pkcs11_lib", string(*object.SslHardware.DriverPkcs11Lib))
	d.Set("ssl_hardware_driver_pkcs11_slot_desc", string(*object.SslHardware.DriverPkcs11SlotDesc))
	d.Set("ssl_hardware_driver_pkcs11_slot_type", string(*object.SslHardware.DriverPkcs11SlotType))
	d.Set("ssl_hardware_driver_pkcs11_user_pin", string(*object.SslHardware.DriverPkcs11UserPin))
	d.Set("ssl_hardware_failure_count", int(*object.SslHardware.FailureCount))
	d.Set("ssl_hardware_library", string(*object.SslHardware.Library))
	d.Set("telemetry_enabled", bool(*object.Telemetry.Enabled))
	d.Set("trafficscript_data_local_size", string(*object.Trafficscript.DataLocalSize))
	d.Set("trafficscript_data_size", string(*object.Trafficscript.DataSize))
	d.Set("trafficscript_execution_time_warning", int(*object.Trafficscript.ExecutionTimeWarning))
	d.Set("trafficscript_max_instr", int(*object.Trafficscript.MaxInstr))
	d.Set("trafficscript_memory_warning", int(*object.Trafficscript.MemoryWarning))
	d.Set("trafficscript_regex_cache_size", int(*object.Trafficscript.RegexCacheSize))
	d.Set("trafficscript_regex_match_limit", int(*object.Trafficscript.RegexMatchLimit))
	d.Set("trafficscript_regex_match_warn_percentage", int(*object.Trafficscript.RegexMatchWarnPercentage))
	d.Set("trafficscript_variable_pool_use", bool(*object.Trafficscript.VariablePoolUse))
	d.Set("transaction_export_enabled", bool(*object.TransactionExport.Enabled))
	d.Set("transaction_export_endpoint", string(*object.TransactionExport.Endpoint))
	d.Set("transaction_export_tls", bool(*object.TransactionExport.Tls))
	d.Set("transaction_export_tls_verify", bool(*object.TransactionExport.TlsVerify))
	d.Set("web_cache_avg_path_length", int(*object.WebCache.AvgPathLength))
	d.Set("web_cache_disk", bool(*object.WebCache.Disk))
	d.Set("web_cache_disk_dir", string(*object.WebCache.DiskDir))
	d.Set("web_cache_max_file_num", int(*object.WebCache.MaxFileNum))
	d.Set("web_cache_max_file_size", string(*object.WebCache.MaxFileSize))
	d.Set("web_cache_max_path_length", int(*object.WebCache.MaxPathLength))
	d.Set("web_cache_normalize_query", bool(*object.WebCache.NormalizeQuery))
	d.Set("web_cache_size", string(*object.WebCache.Size))
	d.Set("web_cache_verbose", bool(*object.WebCache.Verbose))

	d.SetId("global_setting")
	return nil
}

func resourceGlobalSettingsUpdate(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetGlobalSettings()
	if err != nil {
		return fmt.Errorf("Failed to update vtm_global_setting: %v", err)
	}
	setInt(&object.Basic.AcceptingDelay, d, "accepting_delay")
	setBool(&object.Basic.AfmEnabled, d, "afm_enabled")
	setInt(&object.Basic.ChunkSize, d, "chunk_size")
	setBool(&object.Basic.ClientFirstOpt, d, "client_first_opt")
	setString(&object.Basic.ClusterIdentifier, d, "cluster_identifier")
	setString(&object.Basic.DataPlaneAccelerationCores, d, "data_plane_acceleration_cores")
	setBool(&object.Basic.DataPlaneAccelerationMode, d, "data_plane_acceleration_mode")

	if _, ok := d.GetOk("license_servers"); ok {
		setStringList(&object.Basic.LicenseServers, d, "license_servers")
	} else {
		object.Basic.LicenseServers = &[]string{}
		d.Set("license_servers", []string(*object.Basic.LicenseServers))
	}
	setInt(&object.Basic.MaxFds, d, "max_fds")
	setInt(&object.Basic.MonitorMemorySize, d, "monitor_memory_size")
	setInt(&object.Basic.RateClassLimit, d, "rate_class_limit")
	setString(&object.Basic.SharedPoolSize, d, "shared_pool_size")
	setInt(&object.Basic.SlmClassLimit, d, "slm_class_limit")
	setInt(&object.Basic.SoRbuffSize, d, "so_rbuff_size")
	setInt(&object.Basic.SoWbuffSize, d, "so_wbuff_size")
	setString(&object.Basic.SocketOptimizations, d, "socket_optimizations")
	setInt(&object.Basic.TipClassLimit, d, "tip_class_limit")
	setBool(&object.Admin.HonorFallbackScsv, d, "admin_honor_fallback_scsv")
	setString(&object.Admin.Ssl3AllowRehandshake, d, "admin_ssl3_allow_rehandshake")
	setString(&object.Admin.Ssl3Ciphers, d, "admin_ssl3_ciphers")
	setString(&object.Admin.Ssl3DiffieHellmanKeyLength, d, "admin_ssl3_diffie_hellman_key_length")
	setInt(&object.Admin.Ssl3MinRehandshakeInterval, d, "admin_ssl3_min_rehandshake_interval")

	if _, ok := d.GetOk("admin_ssl_elliptic_curves"); ok {
		setStringList(&object.Admin.SslEllipticCurves, d, "admin_ssl_elliptic_curves")
	} else {
		object.Admin.SslEllipticCurves = &[]string{}
		d.Set("admin_ssl_elliptic_curves", []string(*object.Admin.SslEllipticCurves))
	}
	setBool(&object.Admin.SslInsertExtraFragment, d, "admin_ssl_insert_extra_fragment")
	setInt(&object.Admin.SslMaxHandshakeMessageSize, d, "admin_ssl_max_handshake_message_size")
	setBool(&object.Admin.SslPreventTimingSideChannels, d, "admin_ssl_prevent_timing_side_channels")
	setString(&object.Admin.SslSignatureAlgorithms, d, "admin_ssl_signature_algorithms")
	setBool(&object.Admin.SupportSsl3, d, "admin_support_ssl3")
	setBool(&object.Admin.SupportTls1, d, "admin_support_tls1")
	setBool(&object.Admin.SupportTls11, d, "admin_support_tls1_1")
	setBool(&object.Admin.SupportTls12, d, "admin_support_tls1_2")
	setString(&object.Appliance.BootloaderPassword, d, "appliance_bootloader_password")
	setBool(&object.Appliance.ReturnPathRoutingEnabled, d, "appliance_return_path_routing_enabled")
	setString(&object.Aptimizer.MaxDependentFetchSize, d, "aptimizer_max_dependent_fetch_size")
	setString(&object.Aptimizer.MaxOriginalContentBufferSize, d, "aptimizer_max_original_content_buffer_size")
	setInt(&object.Aptimizer.WatchdogInterval, d, "aptimizer_watchdog_interval")
	setInt(&object.Aptimizer.WatchdogLimit, d, "aptimizer_watchdog_limit")
	setBool(&object.Auditlog.ViaEventd, d, "auditlog_via_eventd")
	setBool(&object.Auditlog.ViaSyslog, d, "auditlog_via_syslog")
	setInt(&object.Auth.SamlKeyLifetime, d, "auth_saml_key_lifetime")
	setInt(&object.Auth.SamlKeyRotationInterval, d, "auth_saml_key_rotation_interval")
	setBool(&object.Autoscaler.Verbose, d, "autoscaler_verbose")
	setInt(&object.Bgp.AsNumber, d, "bgp_as_number")
	setBool(&object.Bgp.Enabled, d, "bgp_enabled")
	setBool(&object.ClusterComms.AllowUpdateDefault, d, "cluster_comms_allow_update_default")

	if _, ok := d.GetOk("cluster_comms_allowed_update_hosts"); ok {
		setStringList(&object.ClusterComms.AllowedUpdateHosts, d, "cluster_comms_allowed_update_hosts")
	} else {
		object.ClusterComms.AllowedUpdateHosts = &[]string{"all"}
		d.Set("cluster_comms_allowed_update_hosts", []string(*object.ClusterComms.AllowedUpdateHosts))
	}
	setInt(&object.ClusterComms.StateSyncInterval, d, "cluster_comms_state_sync_interval")
	setInt(&object.ClusterComms.StateSyncTimeout, d, "cluster_comms_state_sync_timeout")
	setInt(&object.Connection.IdleConnectionsMax, d, "connection_idle_connections_max")
	setInt(&object.Connection.IdleTimeout, d, "connection_idle_timeout")
	setInt(&object.Connection.ListenQueueSize, d, "connection_listen_queue_size")
	setInt(&object.Connection.MaxAccepting, d, "connection_max_accepting")
	setBool(&object.Connection.MultipleAccept, d, "connection_multiple_accept")
	setInt(&object.DataPlaneAcceleration.TcpDelayAck, d, "data_plane_acceleration_tcp_delay_ack")
	setInt(&object.DataPlaneAcceleration.TcpWinScale, d, "data_plane_acceleration_tcp_win_scale")
	setInt(&object.Dns.MaxTtl, d, "dns_max_ttl")
	setInt(&object.Dns.MinTtl, d, "dns_min_ttl")
	setInt(&object.Dns.NegativeExpiry, d, "dns_negative_expiry")
	setInt(&object.Dns.Size, d, "dns_size")
	setInt(&object.Dns.Timeout, d, "dns_timeout")
	setString(&object.Ec2.AccessKeyId, d, "ec2_access_key_id")
	setInt(&object.Ec2.AwstoolTimeout, d, "ec2_awstool_timeout")
	setString(&object.Ec2.MetadataServer, d, "ec2_metadata_server")
	setString(&object.Ec2.QueryServer, d, "ec2_query_server")
	setString(&object.Ec2.SecretAccessKey, d, "ec2_secret_access_key")
	setBool(&object.Ec2.VerifyQueryServerCert, d, "ec2_verify_query_server_cert")
	setInt(&object.Eventing.MailInterval, d, "eventing_mail_interval")
	setInt(&object.Eventing.MaxAttempts, d, "eventing_max_attempts")
	setInt(&object.FaultTolerance.ArpCount, d, "fault_tolerance_arp_count")
	setBool(&object.FaultTolerance.AutoFailback, d, "fault_tolerance_auto_failback")
	setInt(&object.FaultTolerance.AutofailbackDelay, d, "fault_tolerance_autofailback_delay")
	setInt(&object.FaultTolerance.ChildTimeout, d, "fault_tolerance_child_timeout")

	if _, ok := d.GetOk("fault_tolerance_frontend_check_ips"); ok {
		setStringList(&object.FaultTolerance.FrontendCheckIps, d, "fault_tolerance_frontend_check_ips")
	} else {
		object.FaultTolerance.FrontendCheckIps = &[]string{"%gateway%"}
		d.Set("fault_tolerance_frontend_check_ips", []string(*object.FaultTolerance.FrontendCheckIps))
	}
	setString(&object.FaultTolerance.HeartbeatMethod, d, "fault_tolerance_heartbeat_method")
	setInt(&object.FaultTolerance.IgmpInterval, d, "fault_tolerance_igmp_interval")
	setInt(&object.FaultTolerance.L4AccelChildTimeout, d, "fault_tolerance_l4accel_child_timeout")
	setInt(&object.FaultTolerance.L4AccelSyncPort, d, "fault_tolerance_l4accel_sync_port")
	setInt(&object.FaultTolerance.MonitorInterval, d, "fault_tolerance_monitor_interval")
	setInt(&object.FaultTolerance.MonitorTimeout, d, "fault_tolerance_monitor_timeout")
	setString(&object.FaultTolerance.MulticastAddress, d, "fault_tolerance_multicast_address")
	setInt(&object.FaultTolerance.UnicastPort, d, "fault_tolerance_unicast_port")
	setBool(&object.FaultTolerance.UseBindIp, d, "fault_tolerance_use_bind_ip")
	setBool(&object.FaultTolerance.Verbose, d, "fault_tolerance_verbose")
	setBool(&object.Fips.Enabled, d, "fips_enabled")
	setBool(&object.Ftp.DataBindLow, d, "ftp_data_bind_low")
	setBool(&object.Glb.Verbose, d, "glb_verbose")
	setInt(&object.HistoricalActivity.KeepDays, d, "historical_activity_keep_days")

	object.Ip.ApplianceReturnpath = &vtm.GlobalSettingsApplianceReturnpathTable{}
	if ipApplianceReturnpathJson, ok := d.GetOk("ip_appliance_returnpath_json"); ok {
		_ = json.Unmarshal([]byte(ipApplianceReturnpathJson.(string)), object.Ip.ApplianceReturnpath)
	} else if ipApplianceReturnpath, ok := d.GetOk("ip_appliance_returnpath"); ok {
		for _, row := range ipApplianceReturnpath.(*schema.Set).List() { // VTM-37687: ipApplianceReturnpath.([]interface{}) {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.GlobalSettingsApplianceReturnpath{}
			VtmObject.Ipv4 = getStringAddr(itemTerraform["ipv4"].(string))
			VtmObject.Ipv6 = getStringAddr(itemTerraform["ipv6"].(string))
			VtmObject.Mac = getStringAddr(itemTerraform["mac"].(string))
			*object.Ip.ApplianceReturnpath = append(*object.Ip.ApplianceReturnpath, VtmObject)
		}
		d.Set("ip_appliance_returnpath", ipApplianceReturnpath)
	} else {
		d.Set("ip_appliance_returnpath", make([]map[string]interface{}, 0, len(*object.Ip.ApplianceReturnpath)))
	}
	setString(&object.Java.Classpath, d, "java_classpath")
	setString(&object.Java.Command, d, "java_command")
	setBool(&object.Java.Enabled, d, "java_enabled")
	setString(&object.Java.Lib, d, "java_lib")
	setInt(&object.Java.MaxConnections, d, "java_max_connections")
	setInt(&object.Java.SessionAge, d, "java_session_age")
	setBool(&object.Kerberos.Verbose, d, "kerberos_verbose")
	setInt(&object.L4Accel.MaxConcurrentConnections, d, "l4accel_max_concurrent_connections")
	setString(&object.Log.ErrorLevel, d, "log_error_level")
	setInt(&object.Log.FlushTime, d, "log_flush_time")
	setString(&object.Log.LogFile, d, "log_log_file")
	setInt(&object.Log.Rate, d, "log_rate")
	setInt(&object.Log.Reopen, d, "log_reopen")
	setInt(&object.Log.Time, d, "log_time")
	setString(&object.LogExport.AuthHecToken, d, "log_export_auth_hec_token")
	setString(&object.LogExport.AuthHttp, d, "log_export_auth_http")
	setString(&object.LogExport.AuthPassword, d, "log_export_auth_password")
	setString(&object.LogExport.AuthUsername, d, "log_export_auth_username")
	setBool(&object.LogExport.Enabled, d, "log_export_enabled")
	setString(&object.LogExport.Endpoint, d, "log_export_endpoint")
	setInt(&object.LogExport.RequestTimeout, d, "log_export_request_timeout")
	setBool(&object.LogExport.TlsVerify, d, "log_export_tls_verify")
	setString(&object.Ospfv2.Area, d, "ospfv2_area")
	setString(&object.Ospfv2.AreaType, d, "ospfv2_area_type")
	setInt(&object.Ospfv2.AuthenticationKeyIdA, d, "ospfv2_authentication_key_id_a")
	setInt(&object.Ospfv2.AuthenticationKeyIdB, d, "ospfv2_authentication_key_id_b")
	setString(&object.Ospfv2.AuthenticationSharedSecretA, d, "ospfv2_authentication_shared_secret_a")
	setString(&object.Ospfv2.AuthenticationSharedSecretB, d, "ospfv2_authentication_shared_secret_b")
	setInt(&object.Ospfv2.DeadInterval, d, "ospfv2_dead_interval")
	setBool(&object.Ospfv2.Enabled, d, "ospfv2_enabled")
	setInt(&object.Ospfv2.HelloInterval, d, "ospfv2_hello_interval")
	setString(&object.Protection.ConncountSize, d, "protection_conncount_size")
	setInt(&object.RecentConnections.MaxPerProcess, d, "recent_connections_max_per_process")
	setInt(&object.RecentConnections.RetainTime, d, "recent_connections_retain_time")
	setInt(&object.RecentConnections.SnapshotSize, d, "recent_connections_snapshot_size")
	setString(&object.RemoteLicensing.Owner, d, "remote_licensing_owner")
	setString(&object.RemoteLicensing.OwnerSecret, d, "remote_licensing_owner_secret")
	setString(&object.RemoteLicensing.PolicyId, d, "remote_licensing_policy_id")
	setString(&object.RemoteLicensing.RegistrationServer, d, "remote_licensing_registration_server")
	setString(&object.RemoteLicensing.ServerCertificate, d, "remote_licensing_server_certificate")
	setInt(&object.RestApi.AuthTimeout, d, "rest_api_auth_timeout")
	setInt(&object.RestApi.HttpMaxHeaderLength, d, "rest_api_http_max_header_length")
	setInt(&object.RestApi.ReplicateAbsolute, d, "rest_api_replicate_absolute")
	setInt(&object.RestApi.ReplicateLull, d, "rest_api_replicate_lull")
	setInt(&object.RestApi.ReplicateTimeout, d, "rest_api_replicate_timeout")
	setString(&object.Security.LoginBanner, d, "security_login_banner")
	setBool(&object.Security.LoginBannerAccept, d, "security_login_banner_accept")
	setInt(&object.Security.LoginDelay, d, "security_login_delay")
	setInt(&object.Security.MaxLoginAttempts, d, "security_max_login_attempts")
	setBool(&object.Security.MaxLoginExternal, d, "security_max_login_external")
	setInt(&object.Security.MaxLoginSuspensionTime, d, "security_max_login_suspension_time")
	setBool(&object.Security.PasswordAllowConsecutiveChars, d, "security_password_allow_consecutive_chars")
	setInt(&object.Security.PasswordChangesPerDay, d, "security_password_changes_per_day")
	setInt(&object.Security.PasswordMinAlphaChars, d, "security_password_min_alpha_chars")
	setInt(&object.Security.PasswordMinLength, d, "security_password_min_length")
	setInt(&object.Security.PasswordMinNumericChars, d, "security_password_min_numeric_chars")
	setInt(&object.Security.PasswordMinSpecialChars, d, "security_password_min_special_chars")
	setInt(&object.Security.PasswordMinUppercaseChars, d, "security_password_min_uppercase_chars")
	setInt(&object.Security.PasswordReuseAfter, d, "security_password_reuse_after")
	setString(&object.Security.PostLoginBanner, d, "security_post_login_banner")
	setBool(&object.Security.TrackUnknownUsers, d, "security_track_unknown_users")
	setString(&object.Security.UiPageBanner, d, "security_ui_page_banner")
	setInt(&object.Session.AspCacheSize, d, "session_asp_cache_size")
	setInt(&object.Session.IpCacheSize, d, "session_ip_cache_size")
	setInt(&object.Session.J2EeCacheSize, d, "session_j2ee_cache_size")
	setInt(&object.Session.SslCacheSize, d, "session_ssl_cache_size")
	setInt(&object.Session.UniversalCacheSize, d, "session_universal_cache_size")
	setInt(&object.Snmp.UserCounters, d, "snmp_user_counters")
	setInt(&object.Soap.IdleMinutes, d, "soap_idle_minutes")
	setInt(&object.SourceNat.IpLimit, d, "source_nat_ip_limit")
	setInt(&object.SourceNat.IpLocalPortRangeHigh, d, "source_nat_ip_local_port_range_high")
	setInt(&object.SourceNat.SharedPoolSize, d, "source_nat_shared_pool_size")
	setString(&object.Ssl.AllowRehandshake, d, "ssl_allow_rehandshake")
	setBool(&object.Ssl.CacheEnabled, d, "ssl_cache_enabled")
	setInt(&object.Ssl.CacheExpiry, d, "ssl_cache_expiry")
	setBool(&object.Ssl.CachePerVirtualserver, d, "ssl_cache_per_virtualserver")
	setInt(&object.Ssl.CacheSize, d, "ssl_cache_size")
	setString(&object.Ssl.CipherSuites, d, "ssl_cipher_suites")
	setBool(&object.Ssl.ClientCacheEnabled, d, "ssl_client_cache_enabled")
	setInt(&object.Ssl.ClientCacheExpiry, d, "ssl_client_cache_expiry")
	setInt(&object.Ssl.ClientCacheSize, d, "ssl_client_cache_size")
	setBool(&object.Ssl.ClientCacheTicketsEnabled, d, "ssl_client_cache_tickets_enabled")
	setString(&object.Ssl.CrlMemSize, d, "ssl_crl_mem_size")
	setString(&object.Ssl.DiffieHellmanModulusSize, d, "ssl_diffie_hellman_modulus_size")

	if _, ok := d.GetOk("ssl_elliptic_curves"); ok {
		setStringList(&object.Ssl.EllipticCurves, d, "ssl_elliptic_curves")
	} else {
		object.Ssl.EllipticCurves = &[]string{}
		d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	}
	setBool(&object.Ssl.HonorFallbackScsv, d, "ssl_honor_fallback_scsv")
	setBool(&object.Ssl.InsertExtraFragment, d, "ssl_insert_extra_fragment")
	setInt(&object.Ssl.MaxHandshakeMessageSize, d, "ssl_max_handshake_message_size")
	setInt(&object.Ssl.MinRehandshakeInterval, d, "ssl_min_rehandshake_interval")
	setInt(&object.Ssl.OcspCacheSize, d, "ssl_ocsp_cache_size")
	setInt(&object.Ssl.OcspStaplingDefaultRefreshInterval, d, "ssl_ocsp_stapling_default_refresh_interval")
	setInt(&object.Ssl.OcspStaplingMaximumRefreshInterval, d, "ssl_ocsp_stapling_maximum_refresh_interval")
	setString(&object.Ssl.OcspStaplingMemSize, d, "ssl_ocsp_stapling_mem_size")
	setInt(&object.Ssl.OcspStaplingTimeTolerance, d, "ssl_ocsp_stapling_time_tolerance")
	setBool(&object.Ssl.OcspStaplingVerifyResponse, d, "ssl_ocsp_stapling_verify_response")
	setBool(&object.Ssl.PreventTimingSideChannels, d, "ssl_prevent_timing_side_channels")
	setString(&object.Ssl.SignatureAlgorithms, d, "ssl_signature_algorithms")
	setBool(&object.Ssl.SupportSsl3, d, "ssl_support_ssl3")
	setBool(&object.Ssl.SupportTls1, d, "ssl_support_tls1")
	setBool(&object.Ssl.SupportTls11, d, "ssl_support_tls1_1")
	setBool(&object.Ssl.SupportTls12, d, "ssl_support_tls1_2")
	setBool(&object.Ssl.TicketsEnabled, d, "ssl_tickets_enabled")
	setString(&object.Ssl.TicketsReissuePolicy, d, "ssl_tickets_reissue_policy")
	setInt(&object.Ssl.TicketsTicketExpiry, d, "ssl_tickets_ticket_expiry")
	setInt(&object.Ssl.TicketsTicketKeyExpiry, d, "ssl_tickets_ticket_key_expiry")
	setInt(&object.Ssl.TicketsTicketKeyRotation, d, "ssl_tickets_ticket_key_rotation")
	setInt(&object.Ssl.TicketsTimeTolerance, d, "ssl_tickets_time_tolerance")
	setBool(&object.Ssl.ValidateServerCertificatesCatalog, d, "ssl_validate_server_certificates_catalog")
	setBool(&object.SslHardware.Accel, d, "ssl_hardware_accel")
	setString(&object.SslHardware.AzureClientId, d, "ssl_hardware_azure_client_id")
	setString(&object.SslHardware.AzureClientSecret, d, "ssl_hardware_azure_client_secret")
	setString(&object.SslHardware.AzureVaultUrl, d, "ssl_hardware_azure_vault_url")
	setBool(&object.SslHardware.AzureVerifyRestApiCert, d, "ssl_hardware_azure_verify_rest_api_cert")
	setBool(&object.SslHardware.DriverPkcs11Debug, d, "ssl_hardware_driver_pkcs11_debug")
	setString(&object.SslHardware.DriverPkcs11Lib, d, "ssl_hardware_driver_pkcs11_lib")
	setString(&object.SslHardware.DriverPkcs11SlotDesc, d, "ssl_hardware_driver_pkcs11_slot_desc")
	setString(&object.SslHardware.DriverPkcs11SlotType, d, "ssl_hardware_driver_pkcs11_slot_type")
	setString(&object.SslHardware.DriverPkcs11UserPin, d, "ssl_hardware_driver_pkcs11_user_pin")
	setInt(&object.SslHardware.FailureCount, d, "ssl_hardware_failure_count")
	setString(&object.SslHardware.Library, d, "ssl_hardware_library")
	setBool(&object.Telemetry.Enabled, d, "telemetry_enabled")
	setString(&object.Trafficscript.DataLocalSize, d, "trafficscript_data_local_size")
	setString(&object.Trafficscript.DataSize, d, "trafficscript_data_size")
	setInt(&object.Trafficscript.ExecutionTimeWarning, d, "trafficscript_execution_time_warning")
	setInt(&object.Trafficscript.MaxInstr, d, "trafficscript_max_instr")
	setInt(&object.Trafficscript.MemoryWarning, d, "trafficscript_memory_warning")
	setInt(&object.Trafficscript.RegexCacheSize, d, "trafficscript_regex_cache_size")
	setInt(&object.Trafficscript.RegexMatchLimit, d, "trafficscript_regex_match_limit")
	setInt(&object.Trafficscript.RegexMatchWarnPercentage, d, "trafficscript_regex_match_warn_percentage")
	setBool(&object.Trafficscript.VariablePoolUse, d, "trafficscript_variable_pool_use")
	setBool(&object.TransactionExport.Enabled, d, "transaction_export_enabled")
	setString(&object.TransactionExport.Endpoint, d, "transaction_export_endpoint")
	setBool(&object.TransactionExport.Tls, d, "transaction_export_tls")
	setBool(&object.TransactionExport.TlsVerify, d, "transaction_export_tls_verify")
	setInt(&object.WebCache.AvgPathLength, d, "web_cache_avg_path_length")
	setBool(&object.WebCache.Disk, d, "web_cache_disk")
	setString(&object.WebCache.DiskDir, d, "web_cache_disk_dir")
	setInt(&object.WebCache.MaxFileNum, d, "web_cache_max_file_num")
	setString(&object.WebCache.MaxFileSize, d, "web_cache_max_file_size")
	setInt(&object.WebCache.MaxPathLength, d, "web_cache_max_path_length")
	setBool(&object.WebCache.NormalizeQuery, d, "web_cache_normalize_query")
	setString(&object.WebCache.Size, d, "web_cache_size")
	setBool(&object.WebCache.Verbose, d, "web_cache_verbose")

	object.Apply()
	d.SetId("global_setting")
	return nil
}

func resourceGlobalSettingsDelete(d *schema.ResourceData, tm interface{}) error {
	d.SetId("")
	return nil
}
