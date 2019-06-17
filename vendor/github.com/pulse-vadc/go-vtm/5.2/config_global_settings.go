// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type GlobalSettings struct {
	connector                *vtmConnector
	GlobalSettingsProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetGlobalSettings() (*GlobalSettings, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/global_settings")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(GlobalSettings)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object GlobalSettings) Apply() (*GlobalSettings, *vtmErrorResponse) {
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

type GlobalSettingsProperties struct {
	Admin struct {
		// Whether or not the admin server, the internal control port and
		//  the config daemon honor the Fallback SCSV to protect connections
		//  against downgrade attacks.
		HonorFallbackScsv *bool `json:"honor_fallback_scsv,omitempty"`

		// Whether or not SSL3/TLS re-handshakes should be supported for
		//  admin server and internal connections.
		Ssl3AllowRehandshake *string `json:"ssl3_allow_rehandshake,omitempty"`

		// The SSL ciphers to use for admin server and internal connections.
		//  For information on supported ciphers see the online help.
		Ssl3Ciphers *string `json:"ssl3_ciphers,omitempty"`

		// The length in bits of the Diffie-Hellman key for ciphers that
		//  use Diffie-Hellman key agreement for admin server and internal
		//  connections.
		Ssl3DiffieHellmanKeyLength *string `json:"ssl3_diffie_hellman_key_length,omitempty"`

		// If SSL3/TLS re-handshakes are supported on the admin server,
		//  this defines the minimum time interval (in milliseconds) between
		//  handshakes on a single SSL3/TLS connection that is permitted.
		//   To disable the minimum interval for handshakes the key should
		//  be set to the value "0".
		Ssl3MinRehandshakeInterval *int `json:"ssl3_min_rehandshake_interval,omitempty"`

		// The SSL elliptic curve preference list for admin and internal
		//  connections. The named curves P256, P384 and P521 may be configured.
		SslEllipticCurves *[]string `json:"ssl_elliptic_curves,omitempty"`

		// Whether or not SSL3 and TLS1 use one-byte fragments as a BEAST
		//  countermeasure for admin server and internal connections.
		SslInsertExtraFragment *bool `json:"ssl_insert_extra_fragment,omitempty"`

		// The maximum size (in bytes) of SSL handshake messages that the
		//  admin server and internal connections will accept. To accept
		//  any size of handshake message the key should be set to the value
		//  "0".
		SslMaxHandshakeMessageSize *int `json:"ssl_max_handshake_message_size,omitempty"`

		// Take performance degrading steps to prevent exposing timing side-channels
		//  with SSL3 and TLS used by the admin server and internal connections.
		SslPreventTimingSideChannels *bool `json:"ssl_prevent_timing_side_channels,omitempty"`

		// The SSL signature algorithms preference list for admin and internal
		//  connections using TLS version 1.2 or higher. For information
		//  on supported algorithms see the online help.
		SslSignatureAlgorithms *string `json:"ssl_signature_algorithms,omitempty"`

		// Whether or not SSL3 support is enabled for admin server and internal
		//  connections.
		SupportSsl3 *bool `json:"support_ssl3,omitempty"`

		// Whether or not TLS1.0 support is enabled for admin server and
		//  internal connections.
		SupportTls1 *bool `json:"support_tls1,omitempty"`

		// Whether or not TLS1.1 support is enabled for admin server and
		//  internal connections.
		SupportTls11 *bool `json:"support_tls1_1,omitempty"`

		// Whether or not TLS1.2 support is enabled for admin server and
		//  internal connections.
		SupportTls12 *bool `json:"support_tls1_2,omitempty"`
	} `json:"admin"`

	Appliance struct {
		// The password used to protect the bootloader. An empty string
		//  means there will be no protection.
		BootloaderPassword *string `json:"bootloader_password,omitempty"`

		// Whether or not the traffic manager will attempt to route response
		//  packets back to clients via the same route on which the corresponding
		//  request arrived.   Note that this applies only to the last hop
		//  of the route - the behaviour of upstream routers cannot be altered
		//  by the traffic manager.
		ReturnPathRoutingEnabled *bool `json:"return_path_routing_enabled,omitempty"`
	} `json:"appliance"`

	Aptimizer struct {
		// The period of time (in seconds) that unaccessed cache entries
		//  will be retained by Web Accelerator.
		CacheEntryLifetime *int `json:"cache_entry_lifetime,omitempty"`

		// The maximum number of cache entries that will be retained by
		//  Web Accelerator before removing old entries to make room for
		//  new ones.
		CacheEntryLimit *int `json:"cache_entry_limit,omitempty"`

		// The Profile to use by default if no mappings are configured (or
		//  if Web Accelerator is licensed in Express mode)
		DefaultProfile *string `json:"default_profile,omitempty"`

		// The Scope to use by default if no mappings are configured (or
		//  if Web Accelerator is licensed in Express mode)
		DefaultScope *string `json:"default_scope,omitempty"`

		// How long to wait for dependent resource fetches (default 30 seconds).
		DependentFetchTimeout *int `json:"dependent_fetch_timeout,omitempty"`

		// Whether or not the Web Accelerator state will be dumped if "/aptimizer-state-dump"
		//  is appended to an optimized URL.
		EnableStateDump *bool `json:"enable_state_dump,omitempty"`

		// The time after which connections between the traffic manager
		//  and Web Accelerator processes will be closed, should an optimization
		//  job take considerably longer than expected.
		IpcTimeout *int `json:"ipc_timeout,omitempty"`

		// How many direct jobs can be in progress before optimization jobs
		//  start getting rejected by Web Accelerator.
		MaxConcurrentJobs *int `json:"max_concurrent_jobs,omitempty"`

		// The maximum size of a dependent resource that can undergo Web
		//  Accelerator optimization. Any content larger than this size will
		//  not be optimized. Units of KB and MB can be used, no postfix
		//  denotes bytes. A value of 0 disables the limit.
		MaxDependentFetchSize *string `json:"max_dependent_fetch_size,omitempty"`

		// The maximum size of unoptimized content buffered in the traffic
		//  manager for a single backend response that is undergoing Web
		//  Accelerator optimization. Responses larger than this will not
		//  be optimized. Note that if the backend response is compressed
		//  then this setting pertains to the compressed size, before Web
		//  Accelerator decompresses it. Units of KB and MB can be used,
		//  no postfix denotes bytes. Value range is 1 - 128MB.
		MaxOriginalContentBufferSize *string `json:"max_original_content_buffer_size,omitempty"`

		// The size in bytes of the operating system buffer which is used
		//  to send request URLs and data to Web Accelerator and return optimized
		//  resources from Web Accelerator. A larger buffer will allow a
		//  greater number of simultaneous resources to be optimized, particularly
		//  if a large number of requests are made at the same time, for
		//  example an HTML page containing hundreds of images to optimize.
		//  If this is set to zero, the default operating system buffer size
		//  will be used.
		QueueBufferSize *int `json:"queue_buffer_size,omitempty"`

		// The period of time (in seconds) that resource data is retained
		//  by Web Accelerator after it is no longer actively in use.
		ResourceLifetime *int `json:"resource_lifetime,omitempty"`

		// The maximum amount of memory the cache is allowed to have pinned.
		//  Once it goes over that limit, it starts releasing resource data
		//  in LRU order.
		ResourceMemoryLimit *int `json:"resource_memory_limit,omitempty"`

		// The period of time (in seconds) after which a previous failure
		//  will no longer count towards the watchdog limit.
		WatchdogInterval *int `json:"watchdog_interval,omitempty"`

		// The maximum number of times the Web Accelerator sub-process will
		//  be started or restarted within the interval defined by the aptimizer!watchdog_interval
		//  setting. If the process fails this many times, it must be restarted
		//  manually from the Diagnose page.  Zero means no limit.
		WatchdogLimit *int `json:"watchdog_limit,omitempty"`
	} `json:"aptimizer"`

	Auditlog struct {
		// Whether to mirror the audit log to EventD.
		ViaEventd *bool `json:"via_eventd,omitempty"`

		// Whether to output audit log message to the syslog.
		ViaSyslog *bool `json:"via_syslog,omitempty"`
	} `json:"auditlog"`

	Auth struct {
		// Lifetime in seconds of cryptographic keys used to decrypt SAML
		//  SP sessions stored externally (client-side).
		SamlKeyLifetime *int `json:"saml_key_lifetime,omitempty"`

		// Rotation interval in seconds for cryptographic keys used to encrypt
		//  SAML SP sessions stored externally (client-side).
		SamlKeyRotationInterval *int `json:"saml_key_rotation_interval,omitempty"`
	} `json:"auth"`

	Autoscaler struct {
		// The interval at which the parent sends new SLM status to the
		//  autoscaler.
		SlmInterval *int `json:"slm_interval,omitempty"`

		// Whether or not detailed messages about the autoscaler's activity
		//  are written to the error log.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"autoscaler"`

	Bandwidth struct {
		// For the global BW limits, how the bandwidth allocation should
		//  be shared between consumers. In 'pooled' mode, the allocation
		//  is shared between all consumers, who can write as much data as
		//  they want until the pool of data is exhausted. In 'quota' mode,
		//  bandwidth is divided between consumers, who can write only as
		//  much as they are allocated. Any unused bandwidth will be lost.
		LicenseSharing *string `json:"license_sharing,omitempty"`

		// For the global BW limits using 'pooled' bandwidth allocation
		//  sharing between consumers, when the license limit is reached
		//  the allowance will be evenly distributed between the remaining
		//  consumers. Each consumer will, however be permitted to write
		//  at least this much data.
		PooledMinWrite *int `json:"pooled_min_write,omitempty"`
	} `json:"bandwidth"`

	Basic struct {
		// How often, in milliseconds, each traffic manager child process
		//  (that isn't listening for new connections) checks to see whether
		//  it should start listening for new connections.
		AcceptingDelay *int `json:"accepting_delay,omitempty"`

		// How long in seconds to wait for the application firewall control
		//  script to complete clustering operations for the application
		//  firewall.
		AfmClusterTimeout *int `json:"afm_cluster_timeout,omitempty"`

		// How long in seconds to wait for the application firewall control
		//  script to complete operations such as starting and stopping the
		//  application firewall.
		AfmControlTimeout *int `json:"afm_control_timeout,omitempty"`

		// Is the application firewall enabled.
		AfmEnabled *bool `json:"afm_enabled,omitempty"`

		// Timeout for waiting for child processes to respond to parent
		//  control requests If a child process (zeus.zxtm, zeus.eventd,
		//  zeus.autoscaler, etc) takes longer than this number of seconds
		//  to respond to a parent control command, error messages will be
		//  logged for every multiple of this number of seconds, for example,
		//  if set to 10 seconds, a log message will be logged every 10 seconds,
		//  until the child responds or is automatically killed (see the
		//  child_control_kill_timeout setting).
		ChildControlCommandTimeout *int `json:"child_control_command_timeout,omitempty"`

		// Timeout for waiting for child processes to respond to parent
		//  control requests If a child process (zeus.zxtm, zeus.eventd,
		//  zeus.autoscaler, etc) takes longer than this number of seconds
		//  to respond to a parent control command, then the parent zeus.zxtm
		//  process will assume this process is stuck in an unresponsive
		//  loop and will kill it, log the termination event, and wait for
		//  a new process of the same type to restart. Set this to 0 to disable
		//  killing unresponsive child processes.
		ChildControlKillTimeout *int `json:"child_control_kill_timeout,omitempty"`

		// The default chunk size for reading/writing requests.
		ChunkSize *int `json:"chunk_size,omitempty"`

		// Whether or not your traffic manager should make use of TCP optimisations
		//  to defer the processing of new client-first connections until
		//  the client has sent some data.
		ClientFirstOpt *bool `json:"client_first_opt,omitempty"`

		// Cluster identifier. Generally supplied by Services Director.
		ClusterIdentifier *string `json:"cluster_identifier,omitempty"`

		// How frequently should child processes check for CPU starvation?
		//  A value of 0 disables the detection.
		CpuStarvationCheckInterval *int `json:"cpu_starvation_check_interval,omitempty"`

		// How much delay in milliseconds between starvation checks do we
		//  allow before we assume that the machine or its HyperVisor are
		//  overloaded.
		CpuStarvationCheckTolerance *int `json:"cpu_starvation_check_tolerance,omitempty"`

		// The number of CPU cores assigned to assist with data plane acceleration.
		//  These cores are dedicated to reading and writing packets to the
		//  network interface cards and distributing packets between the
		//  traffic manager processes.
		DataPlaneAccelerationCores *string `json:"data_plane_acceleration_cores,omitempty"`

		// Whether Data Plane Acceleration Mode is enabled.
		DataPlaneAccelerationMode *bool `json:"data_plane_acceleration_mode,omitempty"`

		// Disable the cipher blacklist check in HTTP2 (mainly intended
		//  for testing purposes)
		Http2NoCipherBlacklistCheck *bool `json:"http2_no_cipher_blacklist_check,omitempty"`

		// Whether or not messages pertaining to internal configuration
		//  files should be logged to the event log.
		InternalConfigLogging *bool `json:"internal_config_logging,omitempty"`

		// A list of license servers for FLA licensing.  A license server
		//  should be specified as a "<ip/host>:<port>" pair.
		LicenseServers *[]string `json:"license_servers,omitempty"`

		// The maximum number of file descriptors that your traffic manager
		//  will allocate.
		MaxFds *int `json:"max_fds,omitempty"`

		// The maximum number of each of nodes, pools or locations that
		//  can be monitored. The memory used to store information about
		//  nodes, pools and locations is allocated at start-up, so the traffic
		//  manager must be restarted after changing this setting.
		MonitorMemorySize *int `json:"monitor_memory_size,omitempty"`

		// The maximum number of Rate classes that can be created. Approximately
		//  100 bytes will be pre-allocated per Rate class.
		RateClassLimit *int `json:"rate_class_limit,omitempty"`

		// The size of the shared memory pool used for shared storage across
		//  worker processes (e.g. bandwidth shared data).This is specified
		//  as either a percentage of system RAM, "5%" for example, or an
		//  absolute size such as "10MB".
		SharedPoolSize *string `json:"shared_pool_size,omitempty"`

		// The maximum number of SLM classes that can be created. Approximately
		//  100 bytes will be pre-allocated per SLM class.
		SlmClassLimit *int `json:"slm_class_limit,omitempty"`

		// The size of the operating system's read buffer. A value of "0"
		//  (zero) means to use the OS default; in normal circumstances this
		//  is what should be used.
		SoRbuffSize *int `json:"so_rbuff_size,omitempty"`

		// The size of the operating system's write buffer. A value of "0"
		//  (zero) means to use the OS default; in normal circumstances this
		//  is what should be used.
		SoWbuffSize *int `json:"so_wbuff_size,omitempty"`

		// Whether or not the traffic manager should use potential network
		//  socket optimisations. If set to "auto", a decision will be made
		//  based on the host platform.
		SocketOptimizations *string `json:"socket_optimizations,omitempty"`

		// Whether the storage for the traffic managers' configuration is
		//  shared between cluster members.
		StorageShared *bool `json:"storage_shared,omitempty"`

		// The maximum number of Traffic IP Groups that can be created.
		TipClassLimit *int `json:"tip_class_limit,omitempty"`
	} `json:"basic"`

	Bgp struct {
		// The number of the BGP AS in which the traffic manager will operate.
		//  Must be entered in decimal.
		AsNumber *int `json:"as_number,omitempty"`

		// Whether BGP Route Health Injection is enabled
		Enabled *bool `json:"enabled,omitempty"`
	} `json:"bgp"`

	ClusterComms struct {
		// The default value of "allow_update" for new cluster members.
		//   If you have cluster members joining from less trusted locations
		//  (such as cloud instances) this can be set to "false" in order
		//  to make them effectively "read-only" cluster members.
		AllowUpdateDefault *bool `json:"allow_update_default,omitempty"`

		// The hosts that can contact the internal administration port on
		//  each traffic manager.  This should be a list containing IP addresses,
		//  CIDR IP subnets, and "localhost"; or it can be set to "all" to
		//  allow any host to connect.
		AllowedUpdateHosts *[]string `json:"allowed_update_hosts,omitempty"`

		// How often to propagate the session persistence and bandwidth
		//  information to other traffic managers in the same cluster. Set
		//  this to "0" (zero) to disable propagation.<br /> Note that a
		//  cluster using "unicast" heartbeat messages cannot turn off these
		//  messages.
		StateSyncInterval *int `json:"state_sync_interval,omitempty"`

		// The maximum amount of time to wait when propagating session persistence
		//  and bandwidth information to other traffic managers in the same
		//  cluster. Once this timeout is hit the transfer is aborted and
		//  a new connection created.
		StateSyncTimeout *int `json:"state_sync_timeout,omitempty"`
	} `json:"cluster_comms"`

	Connection struct {
		// The maximum number of unused HTTP keepalive connections with
		//  back-end nodes that the traffic manager should maintain for re-use.
		//   Setting this to "0" (zero) will cause the traffic manager to
		//  auto-size this parameter based on the available number of file-descriptors.
		IdleConnectionsMax *int `json:"idle_connections_max,omitempty"`

		// How long an unused HTTP keepalive connection should be kept before
		//  it is discarded.
		IdleTimeout *int `json:"idle_timeout,omitempty"`

		// The listen queue size for managing incoming connections. It may
		//  be necessary to increase the system's listen queue size if this
		//  value is altered.  If the value is set to "0" then the default
		//  system setting will be used.
		ListenQueueSize *int `json:"listen_queue_size,omitempty"`

		// Number of processes that should accept new connections. Only
		//  this many traffic manager child processes will listen for new
		//  connections at any one time. Setting this to "0" (zero) will
		//  cause your traffic manager to select an appropriate default value
		//  based on the architecture and number of CPUs.
		MaxAccepting *int `json:"max_accepting,omitempty"`

		// Whether or not the traffic manager should try to read multiple
		//  new connections each time a new client connects. This can improve
		//  performance under some very specific conditions. However, in
		//  general it is recommended that this be set to 'false'.
		MultipleAccept *bool `json:"multiple_accept,omitempty"`
	} `json:"connection"`

	DataPlaneAcceleration struct {
		// The time, in milliseconds, to delay sending a TCP ACK response,
		//  providing an opportunity for additional data to be incorporated
		//  into the response and potentially improving network performance.
		//  The setting affects TCP connections handled by layer 7 services
		//  running in Data Plane Acceleration mode.
		TcpDelayAck *int `json:"tcp_delay_ack,omitempty"`

		// The TCP window scale option, which configures the size of the
		//  receive window for TCP connections handled by layer 7 services
		//  when running in Data Plane Acceleration mode.
		TcpWinScale *int `json:"tcp_win_scale,omitempty"`
	} `json:"data_plane_acceleration"`

	Dns struct {
		// How often to check the DNS configuration for changes.
		Checktime *int `json:"checktime,omitempty"`

		// The location of the "hosts" file.
		Hosts *string `json:"hosts,omitempty"`

		// Whether or not to try reading the "dns!hosts" file before calling
		//  gethostbyname(). This config key exists for testing purposes
		//  only.
		Hostsfirst *bool `json:"hostsfirst,omitempty"`

		// Maximum Time To Live (expiry time) for entries in the DNS cache.
		MaxTtl *int `json:"max_ttl,omitempty"`

		// How often to send DNS request packets before giving up.
		Maxasynctries *int `json:"maxasynctries,omitempty"`

		// Minimum Time To Live (expiry time) for entries in the DNS cache.
		MinTtl *int `json:"min_ttl,omitempty"`

		// Expiry time for failed lookups in the DNS cache.
		NegativeExpiry *int `json:"negative_expiry,omitempty"`

		// The location of the "resolv.conf" file.
		Resolv *string `json:"resolv,omitempty"`

		// Maximum number of entries in the DNS cache.
		Size *int `json:"size,omitempty"`

		// Timeout for receiving a response from a DNS server.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"dns"`

	DnsAutoscale struct {
		// The IP address and port number of the DNS server to use for DNS-derived
		//  autoscaling, in the form addr:port. This is intended for test
		//  and debug purposes, and will override the configuration of the
		//  system resolver, which is usually defined in /etc/resolv.conf
		Resolver *string `json:"resolver,omitempty"`
	} `json:"dns_autoscale"`

	Ec2 struct {
		// Amazon EC2 Access Key ID.
		AccessKeyId *string `json:"access_key_id,omitempty"`

		// How long, in seconds, the traffic manager should wait while associating
		//  or disassociating an Elastic IP to the instance.
		ActionTimeout *int `json:"action_timeout,omitempty"`

		// The maximum amount of time requests to the AWS Query API can
		//  take before timing out.
		AwstoolTimeout *int `json:"awstool_timeout,omitempty"`

		// URL for the EC2 metadata server, "http://169.254.169.254/latest/meta-data"
		//  for example.
		MetadataServer *string `json:"metadata_server,omitempty"`

		// The maximum amount of time requests to the EC2 Metadata Server
		//  can take before timing out.
		MetadataTimeout *int `json:"metadata_timeout,omitempty"`

		// URL for the Amazon EC2 endpoint, "https://ec2.amazonaws.com/"
		//  for example.
		QueryServer *string `json:"query_server,omitempty"`

		// Amazon EC2 Secret Access Key.
		SecretAccessKey *string `json:"secret_access_key,omitempty"`

		// Whether to verify Amazon EC2 endpoint's certificate using CA(s)
		//  present in SSL Certificate Authorities Catalog.
		VerifyQueryServerCert *bool `json:"verify_query_server_cert,omitempty"`

		// Whether to decluster the traffic manager running inside vpc when
		//  the instance stops.
		VpcDeclusterOnStop *bool `json:"vpc_decluster_on_stop,omitempty"`
	} `json:"ec2"`

	Eventing struct {
		// The minimum length of time that must elapse between alert emails
		//  being sent.  Where multiple alerts occur inside this timeframe,
		//  they will be retained and sent within a single email rather than
		//  separately.
		MailInterval *int `json:"mail_interval,omitempty"`

		// The number of times to attempt to send an alert email before
		//  giving up.
		MaxAttempts *int `json:"max_attempts,omitempty"`
	} `json:"eventing"`

	FaultTolerance struct {
		// The number of ARP packets a traffic manager should send when
		//  an IP address is raised.
		ArpCount *int `json:"arp_count,omitempty"`

		// Whether or not traffic IPs automatically move back to machines
		//  that have recovered from a failure and have dropped their traffic
		//  IPs.
		AutoFailback *bool `json:"auto_failback,omitempty"`

		// Configure the delay of automatic failback after a previous failover
		//  event. This setting has no effect if autofailback is disabled.
		AutofailbackDelay *int `json:"autofailback_delay,omitempty"`

		// How long the traffic manager should wait for status updates from
		//  any of the traffic manager's child processes before assuming
		//  one of them is no longer servicing traffic.
		ChildTimeout *int `json:"child_timeout,omitempty"`

		// The IP addresses used to check front-end connectivity. The text
		//  "%gateway%" will be replaced with the default gateway on each
		//  system. Set this to an empty string if the traffic manager is
		//  on an Intranet with no external connectivity.
		FrontendCheckIps *[]string `json:"frontend_check_ips,omitempty"`

		// The method traffic managers should use to exchange cluster heartbeat
		//  messages.
		HeartbeatMethod *string `json:"heartbeat_method,omitempty"`

		// The interval between unsolicited periodic IGMP Membership Report
		//  messages for Multi-Hosted Traffic IP Groups.
		IgmpInterval *int `json:"igmp_interval,omitempty"`

		// When running in Data Plane Acceleration Mode, how long the traffic
		//  manager should wait for a status update from child processes
		//  handling L4Accel services before assuming it is no longer servicing
		//  traffic.
		L4AccelChildTimeout *int `json:"l4accel_child_timeout,omitempty"`

		// The port on which cluster members will transfer state information
		//  for L4Accel services when running in Data Plane Acceleration
		//  Mode.
		L4AccelSyncPort *int `json:"l4accel_sync_port,omitempty"`

		// The frequency, in milliseconds, that each traffic manager machine
		//  should check and announce its connectivity.
		MonitorInterval *int `json:"monitor_interval,omitempty"`

		// How long, in seconds, each traffic manager should wait for a
		//  response from its connectivity tests or from other traffic manager
		//  machines before registering a failure.
		MonitorTimeout *int `json:"monitor_timeout,omitempty"`

		// The multicast address and port to use to exchange cluster heartbeat
		//  messages.
		MulticastAddress *string `json:"multicast_address,omitempty"`

		// Whether the ribd routing daemon is to be run. The routing software
		//  needs to be restarted for this change to take effect.
		RoutingSwRunRibd *bool `json:"routing_sw_run_ribd,omitempty"`

		// The period of time in seconds after which a failure will no longer
		//  count towards the watchdog limit.
		RoutingSwWatchdogInterval *int `json:"routing_sw_watchdog_interval,omitempty"`

		// The maximum number of times the routing software suite of processes
		//  will be started or restarted within the interval defined by the
		//  flipper!routing_sw_watchdog_interval setting. If the routing
		//  software fails this many times within the interval, it will be
		//  stopped and can only be restarted manually from the Diagnose
		//  page or by switching OSPF off and on again. Zero means no limit.
		RoutingSwWatchdogLimit *int `json:"routing_sw_watchdog_limit,omitempty"`

		// Mark Traffic IPv6 addresses as "deprecated" to prevent their
		//  use during IPv6 source selection.
		Tipv6RaiseDeprecated *bool `json:"tipv6_raise_deprecated,omitempty"`

		// The unicast UDP port to use to exchange cluster heartbeat messages.
		UnicastPort *int `json:"unicast_port,omitempty"`

		// Whether or not cluster heartbeat messages should only be sent
		//  and received over the management network.
		UseBindIp *bool `json:"use_bind_ip,omitempty"`

		// Whether or not a traffic manager should log all connectivity
		//  tests.  This is very verbose, and should only be used for diagnostic
		//  purposes.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"fault_tolerance"`

	Fips struct {
		// Enable FIPS Mode (requires software restart).
		Enabled *bool `json:"enabled,omitempty"`
	} `json:"fips"`

	Ftp struct {
		// Whether or not the traffic manager should permit use of FTP data
		//  connection source ports lower than 1024.  If "No" the traffic
		//  manager can completely drop root privileges, if "Yes" some or
		//  all privileges may be retained in order to bind to low ports.
		DataBindLow *bool `json:"data_bind_low,omitempty"`
	} `json:"ftp"`

	Glb struct {
		// Write a message to the logs for every DNS query that is load
		//  balanced, showing the source IP address and the chosen datacenter.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"glb"`

	HistoricalActivity struct {
		// Number of days to store historical traffic information, if set
		//  to "0" the data will be kept indefinitely.
		KeepDays *int `json:"keep_days,omitempty"`
	} `json:"historical_activity"`

	Http struct {
		// The maximum length the header line of an HTTP chunk can have
		//  in an upload from the client.  Header lines exceeding this length
		//  will be considered invalid.  The traffic manager buffers the
		//  header line before it can read any payload data in the chunk;
		//  the limit exists to protect against malicious clients that send
		//  very long lines but never any payload data.
		MaxChunkHeaderLength *int `json:"max_chunk_header_length,omitempty"`
	} `json:"http"`

	Ip struct {
		// A table of MAC to IP address mappings for each router where return
		//  path routing is required.
		ApplianceReturnpath *GlobalSettingsApplianceReturnpathTable `json:"appliance_returnpath,omitempty"`
	} `json:"ip"`

	Java struct {
		// CLASSPATH to use when starting the Java runner.
		Classpath *string `json:"classpath,omitempty"`

		// Java command to use when starting the Java runner, including
		//  any additional options.
		Command *string `json:"command,omitempty"`

		// Whether or not Java support should be enabled.  If this is set
		//  to "No", then your traffic manager will not start any Java processes.
		//  Java support is only required if you are using the TrafficScript
		//  "java.run()" function.
		Enabled *bool `json:"enabled,omitempty"`

		// Java library directory for additional jar files. The Java runner
		//  will load classes from any ".jar" files stored in this directory,
		//  as well as the * jar files and classes stored in traffic manager's
		//  catalog.
		Lib *string `json:"lib,omitempty"`

		// Maximum number of simultaneous Java requests. If there are more
		//  than this many requests, then further requests will be queued
		//  until the earlier requests are completed. This setting is per-CPU,
		//  so if your traffic manager is running on a machine with 4 CPU
		//  cores, then each core can make this many requests at one time.
		MaxConnections *int `json:"max_connections,omitempty"`

		// Default time to keep a Java session.
		SessionAge *int `json:"session_age,omitempty"`
	} `json:"java"`

	Kerberos struct {
		// The period of time after which an outstanding Kerberos operation
		//  will be cancelled, generating an error for dependent operations.
		Timeout *int `json:"timeout,omitempty"`

		// Whether or not a traffic manager should log all Kerberos related
		//  activity.  This is very verbose, and should only be used for
		//  diagnostic purposes.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"kerberos"`

	L4Accel struct {
		// The maximum number of concurrent connections, in millions, that
		//  can be handled by each L4Accel child process. An appropriate
		//  amount of memory to store this many connections will be allocated
		//  when the traffic manager starts.
		MaxConcurrentConnections *int `json:"max_concurrent_connections,omitempty"`
	} `json:"l4accel"`

	Log struct {
		// The minimum severity of events/alerts that should be logged to
		//  disk. "INFO" will log all events; a higher severity setting will
		//  log fewer events.  More fine-grained control can be achieved
		//  using events and actions.
		ErrorLevel *string `json:"error_level,omitempty"`

		// How long to wait before flushing the request log files for each
		//  virtual server.
		FlushTime *int `json:"flush_time,omitempty"`

		// The file to log event messages to.
		LogFile *string `json:"log_file,omitempty"`

		// The maximum number of connection errors logged per second when
		//  connection error reporting is enabled.
		Rate *int `json:"rate,omitempty"`

		// How long to wait before re-opening request log files, this ensures
		//  that log files will be recreated in the case of log rotation.
		Reopen *int `json:"reopen,omitempty"`

		// The minimum time between log messages for log intensive features
		//  such as SLM.
		Time *int `json:"time,omitempty"`
	} `json:"log"`

	LogExport struct {
		// The HTTP Event Collector token to use for HTTP authentication
		//  with a Splunk server.
		AuthHecToken *string `json:"auth_hec_token,omitempty"`

		// The HTTP authentication method to use when exporting log entries.
		AuthHttp *string `json:"auth_http,omitempty"`

		// The password to use for HTTP basic authentication.
		AuthPassword *string `json:"auth_password,omitempty"`

		// The username to use for HTTP basic authentication.
		AuthUsername *string `json:"auth_username,omitempty"`

		// Monitor log files and export entries to the configured endpoint.
		Enabled *bool `json:"enabled,omitempty"`

		// The URL to which log entries should be sent. Entries are sent
		//  using HTTP(S) POST requests.
		Endpoint *string `json:"endpoint,omitempty"`

		// The maximum size of any individual log entry to be exported.
		//  Log entries that exceed this size will be truncated. The maximum
		//  individual entry size must be at least "80" characters. A value
		//  of "0" means that no limit is imposed on the length of message
		//  for any individual entry.
		MaxEventMessageSize *int `json:"max_event_message_size,omitempty"`

		// The maximum bandwidth to be used for sending HTTP requests to
		//  the configured endpoint, measured in kilobits per second. A value
		//  of zero means that no bandwidth limit will be imposed.
		MaxRequestBandwidth *int `json:"max_request_bandwidth,omitempty"`

		// The maximum amount of log data to export in a single request.
		//  A value of "0" means no limit.
		MaxRequestSize *int `json:"max_request_size,omitempty"`

		// The maximum permitted size of HTTP responses from the configured
		//  endpoint. Both headers and body data are included in the size
		//  calculation. A response exceeding this size will be treated as
		//  an error response. A value of "0" means that there is no limit
		//  to the size of response that will be considered valid.
		MaxResponseSize *int `json:"max_response_size,omitempty"`

		// An upper limit to the interval for rate limiting all errors raised
		//  by the log exporter.
		MaximumErrorRaisingPeriod *int `json:"maximum_error_raising_period,omitempty"`

		// A lower limit to the interval for rate limiting all errors raised
		//  by the log exporter. The interval can only be shorter than this
		//  limit if the maximum interval is set to be less than this minimum
		//  limit.
		MinimumErrorRaisingPeriod *int `json:"minimum_error_raising_period,omitempty"`

		// The number of seconds after which HTTP requests sent to the configured
		//  endpoint will be considered to have failed if no response is
		//  received. A value of "0" means that HTTP requests will not time
		//  out.
		RequestTimeout *int `json:"request_timeout,omitempty"`

		// Whether the server certificate should be verified when connecting
		//  to the endpoint. If enabled, server certificates that do not
		//  match the server name, are self-signed, have expired, have been
		//  revoked, or that are signed by an unknown CA will be rejected.
		TlsVerify *bool `json:"tls_verify,omitempty"`
	} `json:"log_export"`

	Ospfv2 struct {
		// The OSPF area in which the traffic manager will operate. May
		//  be entered in decimal or IPv4 address format.
		Area *string `json:"area,omitempty"`

		// The type of OSPF area in which the traffic manager will operate.
		//  This must be the same for all routers in the area, as required
		//  by OSPF.
		AreaType *string `json:"area_type,omitempty"`

		// OSPFv2 authentication key ID. If set to 0, which is the default
		//  value, the key is disabled.
		AuthenticationKeyIdA *int `json:"authentication_key_id_a,omitempty"`

		// OSPFv2 authentication key ID. If set to 0, which is the default
		//  value, the key is disabled.
		AuthenticationKeyIdB *int `json:"authentication_key_id_b,omitempty"`

		// OSPFv2 authentication shared secret (MD5). If set to blank, which
		//  is the default value, the key is disabled.
		AuthenticationSharedSecretA *string `json:"authentication_shared_secret_a,omitempty"`

		// OSPFv2 authentication shared secret (MD5). If set to blank, which
		//  is the default value, the key is disabled.
		AuthenticationSharedSecretB *string `json:"authentication_shared_secret_b,omitempty"`

		// The number of seconds before declaring a silent router down.
		DeadInterval *int `json:"dead_interval,omitempty"`

		// Whether OSPFv2 Route Health Injection is enabled
		Enabled *bool `json:"enabled,omitempty"`

		// The interval at which OSPF "hello" packets are sent to the network.
		HelloInterval *int `json:"hello_interval,omitempty"`
	} `json:"ospfv2"`

	PeriodicLog struct {
		// Enable periodic logging
		Enabled *bool `json:"enabled,omitempty"`

		// Time interval in seconds for periodic logging
		Interval *int `json:"interval,omitempty"`

		// Maximum size (in MBytes) for the archive periodic logs. When
		//  combined size of the archives exceeds this value, the oldest
		//  archives will be deleted. Set to 0 to disable archive size limit
		MaxArchiveSetSize *int `json:"max_archive_set_size,omitempty"`

		// Maximum size (in MBytes) for the current set of periodic logs.
		//  If this size is exceeded, the current set will be archived. Set
		//  to zero to disable archiving based on current set size.
		MaxLogSetSize *int `json:"max_log_set_size,omitempty"`

		// Maximum number of archived log sets to keep. When the number
		//  of archived periodic log sets exceeds this, the oldest archives
		//  will be deleted.
		MaxNumArchives *int `json:"max_num_archives,omitempty"`

		// Number of periodic logs which should be archived together as
		//  a run.
		RunCount *int `json:"run_count,omitempty"`
	} `json:"periodic_log"`

	Protection struct {
		// The amount of shared memory reserved for an inter-process table
		//  of combined connection counts, used by all Service Protection
		//  classes that have "per_process_connection_count" set to "No".
		//   The amount is specified as an absolute size, eg 20MB.
		ConncountSize *string `json:"conncount_size,omitempty"`
	} `json:"protection"`

	RecentConnections struct {
		// How many recently closed connections each traffic manager process
		//  should save. These saved connections will be shown alongside
		//  currently active connections when viewing the Connections page.
		//  You should set this value to "0" in a benchmarking or performance-critical
		//  environment.
		MaxPerProcess *int `json:"max_per_process,omitempty"`

		// The amount of time for which snapshots will be retained on the
		//  Connections page.
		RetainTime *int `json:"retain_time,omitempty"`

		// The maximum number of connections each traffic manager process
		//  should show when viewing a snapshot on the Connections page.
		//  This value includes both currently active connections and saved
		//  connections. If set to "0" all active and saved connection will
		//  be displayed on the Connections page.
		SnapshotSize *int `json:"snapshot_size,omitempty"`
	} `json:"recent_connections"`

	RemoteLicensing struct {
		// The Owner of a Services Director instance, used for self-registration.
		Owner *string `json:"owner,omitempty"`

		// The secret associated with the Owner.
		OwnerSecret *string `json:"owner_secret,omitempty"`

		// The auto-accept Policy ID that this instance should attempt to
		//  use.
		PolicyId *string `json:"policy_id,omitempty"`

		// A Services Director address for self-registration. A registration
		//  server should be specified as a "<ip/host>:<port>" pair.
		RegistrationServer *string `json:"registration_server,omitempty"`

		// Time-out value for the self-register script.
		ScriptTimeout *int `json:"script_timeout,omitempty"`

		// The certificate of a Services Director instance, used for self-registration.
		ServerCertificate *string `json:"server_certificate,omitempty"`
	} `json:"remote_licensing"`

	RestApi struct {
		// The length of time after a successful request that the authentication
		//  of a given username and password will be cached for an IP address.
		//  A setting of 0 disables the cache forcing every REST request
		//  to be authenticated which will adversely affect performance.
		AuthTimeout *int `json:"auth_timeout,omitempty"`

		// Maximum amount of time in seconds to block the event queue waiting
		//  for unparallisable events like loading from disk.
		BlockForFutureMax *int `json:"block_for_future_max,omitempty"`

		// Minimum size in bytes a response body needs to be for compression
		//  (e.g. gzip) to be used. Set to 0 to always use compression when
		//  available.
		HttpCompressMin *int `json:"http_compress_min,omitempty"`

		// The length of time in seconds an idle connection will be kept
		//  open before the REST API closes the connection.
		HttpKeepAliveTimeout *int `json:"http_keep_alive_timeout,omitempty"`

		// The maximum allowed length in bytes of a HTTP request's headers.
		HttpMaxHeaderLength *int `json:"http_max_header_length,omitempty"`

		// Maximum size in bytes the body of an HTTP PUT request can be
		//  for a key-value resource (i.e. a JSON request)
		HttpMaxResourceBodyLength *int `json:"http_max_resource_body_length,omitempty"`

		// Maximum size in bytes the per-connection output buffer can grow
		//  to before being paused.
		HttpMaxWriteBuffer *int `json:"http_max_write_buffer,omitempty"`

		// Maximum time in seconds to keep an idle session open for.
		HttpSessionTimeout *int `json:"http_session_timeout,omitempty"`

		// A set of symlinks that the REST API maps to actual directories.
		//  Used to add mirored resources so proxies work correctly.
		ProxyMap *GlobalSettingsProxyMapTable `json:"proxy_map,omitempty"`

		// Configuration changes will be replicated across the cluster after
		//  this period of time, regardless of whether additional API requests
		//  are being made.
		ReplicateAbsolute *int `json:"replicate_absolute,omitempty"`

		// Configuration changes made via the REST API will be propagated
		//  across the cluster when no further API requests have been made
		//  for this period of time.
		ReplicateLull *int `json:"replicate_lull,omitempty"`

		// The period of time after which configuration replication across
		//  the cluster will be cancelled if it has not completed.
		ReplicateTimeout *int `json:"replicate_timeout,omitempty"`
	} `json:"rest_api"`

	Security struct {
		// Banner text displayed on the Admin Server login page and before
		//  logging in to appliance SSH servers.
		LoginBanner *string `json:"login_banner,omitempty"`

		// Whether or not users must explicitly agree to the displayed "login_banner"
		//  text before logging in to the Admin Server.
		LoginBannerAccept *bool `json:"login_banner_accept,omitempty"`

		// The number of seconds before another login attempt can be made
		//  after a failed attempt.
		LoginDelay *int `json:"login_delay,omitempty"`

		// The number of sequential failed login attempts that will cause
		//  a user account to be suspended.  Setting this to "0" disables
		//  this feature. To apply this to users who have never successfully
		//  logged in, "track_unknown_users" must also be enabled.
		MaxLoginAttempts *int `json:"max_login_attempts,omitempty"`

		// Whether or not usernames blocked due to the "max_login_attempts"
		//  limit should also be blocked from authentication against external
		//  services (such as LDAP and RADIUS).
		MaxLoginExternal *bool `json:"max_login_external,omitempty"`

		// The number of minutes to suspend users who have exceeded the
		//  "max_login_attempts" limit.
		MaxLoginSuspensionTime *int `json:"max_login_suspension_time,omitempty"`

		// Whether or not to allow the same character to appear consecutively
		//  in passwords.
		PasswordAllowConsecutiveChars *bool `json:"password_allow_consecutive_chars,omitempty"`

		// The maximum number of times a password can be changed in a 24-hour
		//  period. Set to "0" to disable this restriction.
		PasswordChangesPerDay *int `json:"password_changes_per_day,omitempty"`

		// Minimum number of alphabetic characters a password must contain.
		//  Set to 0 to disable this restriction.
		PasswordMinAlphaChars *int `json:"password_min_alpha_chars,omitempty"`

		// Minimum number of characters a password must contain. Set to
		//  "0" to disable this restriction.
		PasswordMinLength *int `json:"password_min_length,omitempty"`

		// Minimum number of numeric characters a password must contain.
		//  Set to "0" to disable this restriction.
		PasswordMinNumericChars *int `json:"password_min_numeric_chars,omitempty"`

		// Minimum number of special (non-alphanumeric) characters a password
		//  must contain. Set to "0" to disable this restriction.
		PasswordMinSpecialChars *int `json:"password_min_special_chars,omitempty"`

		// Minimum number of uppercase characters a password must contain.
		//  Set to "0" to disable this restriction.
		PasswordMinUppercaseChars *int `json:"password_min_uppercase_chars,omitempty"`

		// The number of times a password must have been changed before
		//  it can be reused. Set to "0" to disable this restriction.
		PasswordReuseAfter *int `json:"password_reuse_after,omitempty"`

		// Banner text to be displayed on the appliance console after login.
		PostLoginBanner *string `json:"post_login_banner,omitempty"`

		// Whether to remember past login attempts from usernames that are
		//  not known to exist (should be set to false for an Admin Server
		//  accessible from the public Internet). This does not affect the
		//  audit log.
		TrackUnknownUsers *bool `json:"track_unknown_users,omitempty"`

		// Banner text to be displayed on all Admin Server pages.
		UiPageBanner *string `json:"ui_page_banner,omitempty"`
	} `json:"security"`

	Session struct {
		// The maximum number of entries in the ASP session cache.  This
		//  is used for storing session mappings for ASP session persistence.
		//  Approximately 100 bytes will be pre-allocated per entry.
		AspCacheSize *int `json:"asp_cache_size,omitempty"`

		// The maximum number of entries in the IP session cache.  This
		//  is used to provide session persistence based on the source IP
		//  address. Approximately 100 bytes will be pre-allocated per entry.
		IpCacheSize *int `json:"ip_cache_size,omitempty"`

		// The maximum number of entries in the J2EE session cache.  This
		//  is used for storing session mappings for J2EE session persistence.
		//  Approximately 100 bytes will be pre-allocated per entry.
		J2EeCacheSize *int `json:"j2ee_cache_size,omitempty"`

		// The maximum number of entries in the SSL session persistence
		//  cache. This is used to provide session persistence based on the
		//  SSL session ID.  Approximately 200 bytes will be pre-allocated
		//  per entry.
		SslCacheSize *int `json:"ssl_cache_size,omitempty"`

		// The maximum number of entries in the global universal session
		//  cache.  This is used for storing session mappings for universal
		//  session persistence.  Approximately 100 bytes will be pre-allocated
		//  per entry.
		UniversalCacheSize *int `json:"universal_cache_size,omitempty"`
	} `json:"session"`

	Snmp struct {
		// The number of user defined SNMP counters. Approximately 100 bytes
		//  will be pre-allocated at start-up per user defined SNMP counter.
		UserCounters *int `json:"user_counters,omitempty"`
	} `json:"snmp"`

	Soap struct {
		// The number of minutes that the SOAP server should remain idle
		//  before exiting.  The SOAP server has a short startup delay the
		//  first time a SOAP request is made, subsequent SOAP requests don't
		//  have this delay.
		IdleMinutes *int `json:"idle_minutes,omitempty"`
	} `json:"soap"`

	SourceNat struct {
		// The maximum locks used for SNAT clists
		ClistLocks *int `json:"clist_locks,omitempty"`

		// The maximum number of Source NAT IP addresses that can be used
		//  across all Traffic IP Groups.
		IpLimit *int `json:"ip_limit,omitempty"`

		// The upper boundary of the port range reserved for use by the
		//  kernel. Ports above this range will be used by the traffic manager
		//  for establishing outgoing connections.
		IpLocalPortRangeHigh *int `json:"ip_local_port_range_high,omitempty"`

		// The maximum locks used for SNAT portmap hash tables
		PortmaphashtableLocks *int `json:"portmaphashtable_locks,omitempty"`

		// The size of the Source NAT shared memory pool used for shared
		//  storage across child processes. This value is specified as an
		//  absolute size such as "10MB".
		SharedPoolSize *int `json:"shared_pool_size,omitempty"`
	} `json:"source_nat"`

	Ssl struct {
		// Whether or not SSL/TLS re-handshakes should be supported. Enabling
		//  support for re-handshakes can expose services to Man-in-the-Middle
		//  attacks. It is recommended that only "safe" handshakes be permitted,
		//  or none at all.
		AllowRehandshake *string `json:"allow_rehandshake,omitempty"`

		// Whether or not the SSL server session cache is enabled, unless
		//  overridden by virtual server settings.
		CacheEnabled *bool `json:"cache_enabled,omitempty"`

		// How long the SSL session IDs for SSL decryption should be stored
		//  for.
		CacheExpiry *int `json:"cache_expiry,omitempty"`

		// Whether an SSL session created by a given virtual server can
		//  only be resumed by a connection to the same virtual server.
		CachePerVirtualserver *bool `json:"cache_per_virtualserver,omitempty"`

		// How many entries the SSL session ID cache should hold. This cache
		//  is used to cache SSL sessions to help speed up SSL handshakes
		//  when performing SSL decryption. Each entry will allocate approximately
		//  1.5kB of metadata.
		CacheSize *int `json:"cache_size,omitempty"`

		// The SSL/TLS cipher suites preference list for SSL/TLS connections,
		//  unless overridden by virtual server or pool settings. For information
		//  on supported cipher suites see the online help.
		CipherSuites *string `json:"cipher_suites,omitempty"`

		// Whether or the SSL client cache will be used, unless overridden
		//  by pool settings.
		ClientCacheEnabled *bool `json:"client_cache_enabled,omitempty"`

		// How long in seconds SSL sessions should be stored in the client
		//  cache for, by default. Servers returning session tickets may
		//  also provide a lifetime hint, which will be used if it is less
		//  than this value.
		ClientCacheExpiry *int `json:"client_cache_expiry,omitempty"`

		// How many entries the SSL client session cache should hold, per
		//  child. This cache is used to cache SSL sessions to help speed
		//  up SSL handshakes when performing SSL encryption. Each entry
		//  will require approx 100 bytes of memory plus space for either
		//  an SSL session id or an SSL session ticket, which may be as small
		//  as 16 bytes or may be as large as a few kilobytes, depending
		//  upon the server behavior.
		ClientCacheSize *int `json:"client_cache_size,omitempty"`

		// Whether or not session tickets may be requested and stored in
		//  the SSL client cache.
		ClientCacheTicketsEnabled *bool `json:"client_cache_tickets_enabled,omitempty"`

		// How much shared memory to allocate for loading Certificate Revocation
		//  Lists. This should be at least 3 times the total size of all
		//  CRLs on disk. This is specified as either a percentage of system
		//  RAM, "1%" for example, or an absolute size such as "10MB".
		CrlMemSize *string `json:"crl_mem_size,omitempty"`

		// The minimum size in bits of the modulus in the domain parameters
		//  that the traffic manager will accept when connecting using finite
		//  field Diffie-Hellman key agreement as a client.
		DiffieHellmanClientMinModulusSize *int `json:"diffie_hellman_client_min_modulus_size,omitempty"`

		// The size in bits of the modulus for the domain parameters used
		//  for cipher suites that use finite field Diffie-Hellman key agreement.
		DiffieHellmanModulusSize *string `json:"diffie_hellman_modulus_size,omitempty"`

		// Enable or disable use of "stitched" CBC/HMAC mode ciphers
		DisableStitchedCbcHmac *bool `json:"disable_stitched_cbc_hmac,omitempty"`

		// The SSL/TLS elliptic curve preference list for SSL/TLS connections
		//  using TLS version 1.0 or higher, unless overridden by virtual
		//  server or pool settings. For information on supported curves
		//  see the online help.
		EllipticCurves *[]string `json:"elliptic_curves,omitempty"`

		// Whether or not ssl-decrypting Virtual Servers honor the Fallback
		//  SCSV to protect connections against downgrade attacks.
		HonorFallbackScsv *bool `json:"honor_fallback_scsv,omitempty"`

		// Whether or not SSL3 and TLS1 use one-byte fragments as a BEAST
		//  countermeasure.
		InsertExtraFragment *bool `json:"insert_extra_fragment,omitempty"`

		// The maximum size (in bytes) of SSL handshake messages that SSL
		//  connections will accept. To accept any size of handshake message
		//  the key should be set to the value "0".
		MaxHandshakeMessageSize *int `json:"max_handshake_message_size,omitempty"`

		// If SSL3/TLS re-handshakes are supported, this defines the minimum
		//  time interval (in milliseconds) between handshakes on a single
		//  SSL3/TLS connection that is permitted.  To disable the minimum
		//  interval for handshakes the key should be set to the value "0".
		MinRehandshakeInterval *int `json:"min_rehandshake_interval,omitempty"`

		// Whether SSL/TLS alert descriptions should be obscured (where
		//  reasonable) when sent to a remote peer. Alert descriptions are
		//  useful for diagnosing SSL/TLS connection issues when connecting
		//  to a remote peer. However those diagnostics may provide information
		//  that an attacker could use to compromise the system (as a concrete
		//  example, see Moeller, B., "Security of CBC Ciphersuites in SSL/TLS:
		//  Problems and Countermeasures"). If not enabled, alert descriptions
		//  that are known to facilitate compromise will still be obscured.
		//   Otherwise, if enabled, alert descriptions that can be safely
		//  mapped to a more general one, will be.
		ObscureAlertDescriptions *bool `json:"obscure_alert_descriptions,omitempty"`

		// The maximum number of cached client certificate OCSP results
		//  stored. This cache is used to speed up OCSP checks against client
		//  certificates by caching results. Approximately 1040 bytes are
		//  pre-allocated per entry.
		OcspCacheSize *int `json:"ocsp_cache_size,omitempty"`

		// Maximum size of OCSP response to accept when verifying client
		//  certificates during SSL decryption. 0 means unlimited.
		OcspMaxResponseSize *int `json:"ocsp_max_response_size,omitempty"`

		// How long to wait before refreshing requests on behalf of the
		//  store of certificate status responses used by OCSP stapling,
		//  if we don't have an up-to-date OCSP response.
		OcspStaplingDefaultRefreshInterval *int `json:"ocsp_stapling_default_refresh_interval,omitempty"`

		// Maximum time to wait before refreshing requests on behalf of
		//  the store of certificate status responses used by OCSP stapling.
		//  (0 means no maximum.)
		OcspStaplingMaximumRefreshInterval *int `json:"ocsp_stapling_maximum_refresh_interval,omitempty"`

		// How much shared memory to allocate for the store of certificate
		//  status responses for OCSP stapling. This should be at least 2kB
		//  times the number of certificates configured to use OCSP stapling.
		//  This is specified as either a percentage of system RAM, "1%"
		//  for example, or an absolute size such as "10MB".
		OcspStaplingMemSize *string `json:"ocsp_stapling_mem_size,omitempty"`

		// The minimum number of seconds to wait between OCSP requests for
		//  the same certificate.
		OcspStaplingMinimumRefreshInterval *int `json:"ocsp_stapling_minimum_refresh_interval,omitempty"`

		// The number of seconds before an OCSP response is stale to make
		//  a new OCSP request.
		OcspStaplingPrefetch *int `json:"ocsp_stapling_prefetch,omitempty"`

		// How many seconds to allow the current time to be outside the
		//  validity time of an OCSP response before considering it invalid.
		OcspStaplingTimeTolerance *int `json:"ocsp_stapling_time_tolerance,omitempty"`

		// Whether the OCSP response signature should be verified before
		//  the OCSP response is cached.
		OcspStaplingVerifyResponse *bool `json:"ocsp_stapling_verify_response,omitempty"`

		// Take performance degrading steps to prevent exposing timing side-channels
		//  with SSL3 and TLS.
		PreventTimingSideChannels *bool `json:"prevent_timing_side_channels,omitempty"`

		// The SSL/TLS signature algorithms preference list for SSL/TLS
		//  connections using TLS version 1.2 or higher, unless overridden
		//  by virtual server or pool settings. For information on supported
		//  algorithms see the online help.
		SignatureAlgorithms *string `json:"signature_algorithms,omitempty"`

		// Whether or not SSL3 support is enabled.
		SupportSsl3 *bool `json:"support_ssl3,omitempty"`

		// Whether or not TLS1.0 support is enabled.
		SupportTls1 *bool `json:"support_tls1,omitempty"`

		// Whether or not TLS1.1 support is enabled.
		SupportTls11 *bool `json:"support_tls1_1,omitempty"`

		// Whether or not TLS1.2 support is enabled.
		SupportTls12 *bool `json:"support_tls1_2,omitempty"`

		// Whether or not session tickets will be issued to and accepted
		//  from clients that support them, unless overridden by virtual
		//  server settings.
		TicketsEnabled *bool `json:"tickets_enabled,omitempty"`

		// When an SSL session ticket will be reissued (ie when a new ticket
		//  will be generated for the same SSL session).
		TicketsReissuePolicy *string `json:"tickets_reissue_policy,omitempty"`

		// The length of time for which an SSL session ticket will be accepted
		//  by a virtual server after the ticket is created. If a ticket
		//  is reissued (if ssl!tickets!reissue_policy is set to 'always')
		//  this time starts at the time when the ticket was reissued.
		TicketsTicketExpiry *int `json:"tickets_ticket_expiry,omitempty"`

		// The length of time for which an auto-generated SSL ticket key
		//  will be used to decrypt old session ticket, before being deleted
		//  from memory. This setting is ignored if there are any entries
		//  in the (REST-only) SSL ticket keys catalog.
		TicketsTicketKeyExpiry *int `json:"tickets_ticket_key_expiry,omitempty"`

		// The length of time for which an auto-generated SSL ticket key
		//  will be used to encrypt new session tickets, before a new SSL
		//  ticket key is generated. The ticket encryption key will be held
		//  in memory for ssl!tickets!ticket_key_expiry, so that tickets
		//  encrypted using the key can still be decrypted and used. This
		//  setting is ignored if there are any entries in the (REST-only)
		//  SSL ticket keys catalog.
		TicketsTicketKeyRotation *int `json:"tickets_ticket_key_rotation,omitempty"`

		// How many seconds to allow the current time to be outside the
		//  validity time of an SSL ticket before considering it invalid.
		TicketsTimeTolerance *int `json:"tickets_time_tolerance,omitempty"`

		// Whether the traffic manager should validate that SSL server certificates
		//  form a matching key pair before the certificate gets used on
		//  an SSL decrypting virtual server.
		ValidateServerCertificatesCatalog *bool `json:"validate_server_certificates_catalog,omitempty"`
	} `json:"ssl"`

	SslHardware struct {
		// Whether or not the SSL hardware is an "accelerator" (faster than
		//  software). By default the traffic manager will only use the SSL
		//  hardware if a key requires it (i.e. the key is stored on secure
		//  hardware and the traffic manager only has a placeholder/identifier
		//  key). With this option enabled, your traffic manager will instead
		//  try to use hardware for all SSL decrypts.
		Accel *bool `json:"accel,omitempty"`

		// The version of the Azure Key Vault REST API.
		AzureApiVersion *string `json:"azure_api_version,omitempty"`

		// The client identifier used when accessing the Microsoft Azure
		//  Key Vault.
		AzureClientId *string `json:"azure_client_id,omitempty"`

		// The client secret used when accessing the Microsoft Azure Key
		//  Vault.
		AzureClientSecret *string `json:"azure_client_secret,omitempty"`

		// Timeout for establishing a connection to the Azure Key Vault
		//  REST API. Using a value of 0 will use libcurl's built-in timeout.
		AzureConnectTimeout *int `json:"azure_connect_timeout,omitempty"`

		// Idle timeout for a connection to the Azure Key Vault REST API.
		//  Using a value of 0 will deactivate the timeout.
		AzureIdleTimeout *int `json:"azure_idle_timeout,omitempty"`

		// The maximum number of concurrent HTTPS connections that will
		//  be used to retrieve the list of keys stored in an Azure Key Vault.
		AzureKeyListConns *int `json:"azure_key_list_conns,omitempty"`

		// The URL for the REST API of the Microsoft Azure Key Vault.
		AzureVaultUrl *string `json:"azure_vault_url,omitempty"`

		// Whether or not the Azure Key Vault REST API certificate should
		//  be verified.
		AzureVerifyRestApiCert *bool `json:"azure_verify_rest_api_cert,omitempty"`

		// Print verbose information about the PKCS11 hardware security
		//  module to the event log.
		DriverPkcs11Debug *bool `json:"driver_pkcs11_debug,omitempty"`

		// The location of the PKCS#11 library for your SSL hardware if
		//  it is not in a standard location.  The traffic manager will search
		//  the standard locations by default.
		DriverPkcs11Lib *string `json:"driver_pkcs11_lib,omitempty"`

		// The label of the SSL Hardware slot to use. Only required if you
		//  have multiple HW accelerator slots.
		DriverPkcs11SlotDesc *string `json:"driver_pkcs11_slot_desc,omitempty"`

		// The type of SSL hardware slot to use.
		DriverPkcs11SlotType *string `json:"driver_pkcs11_slot_type,omitempty"`

		// The User PIN for the PKCS token (PKCS#11 devices only).
		DriverPkcs11UserPin *string `json:"driver_pkcs11_user_pin,omitempty"`

		// The number of consecutive failures from the SSL hardware that
		//  will be tolerated before the traffic manager assumes its session
		//  with the device is invalid and tries to log in again.  This is
		//  necessary when the device reboots following a power failure.
		FailureCount *int `json:"failure_count,omitempty"`

		// The type of SSL hardware to use. The drivers for the SSL hardware
		//  should be installed and accessible to the traffic manager software.
		Library *string `json:"library,omitempty"`

		// The maximum number of concurrent requests the traffic manager
		//  will offload to the accelerator device.
		Nworkers *int `json:"nworkers,omitempty"`

		// The maximum number of requests that will be queued to the accelerator
		//  device.
		Queuelen *int `json:"queuelen,omitempty"`
	} `json:"ssl_hardware"`

	Telemetry struct {
		// Allow the reporting of anonymized usage data to Pulse Secure
		//  for product improvement and customer support purposes.
		Enabled *bool `json:"enabled,omitempty"`

		// Tag exported data with an arbitrary string, to mark is as not
		//  being "real" data
		InternalUse *string `json:"internal_use,omitempty"`

		// Instruct the telemetry system to use a fast schedule for testing
		TestSchedule *bool `json:"test_schedule,omitempty"`

		// Override the default URL for telemetry data export.
		Url *string `json:"url,omitempty"`
	} `json:"telemetry"`

	Trafficscript struct {
		// The maximum amount of memory available to store TrafficScript
		//  "data.local.set()" information. This can be specified as a percentage
		//  of system RAM, "5%" for example; or an absolute size such as
		//  "200MB".
		DataLocalSize *string `json:"data_local_size,omitempty"`

		// The maximum amount of memory available to store TrafficScript
		//  "data.set()" information.  This can be specified as a percentage
		//  of system RAM, "5%" for example; or an absolute size such as
		//  "200MB".
		DataSize *string `json:"data_size,omitempty"`

		// Raise an event if a TrafficScript rule runs for more than this
		//  number of milliseconds in a single invocation. If you get such
		//  events repeatedly, you may want to consider re-working some of
		//  your TrafficScript rules. A value of 0 means no warnings will
		//  be issued.
		ExecutionTimeWarning *int `json:"execution_time_warning,omitempty"`

		// The maximum number of instructions a TrafficScript rule will
		//  run. A rule will be aborted if it runs more than this number
		//  of instructions without yielding, preventing infinite loops.
		MaxInstr *int `json:"max_instr,omitempty"`

		// Raise an event if a TrafficScript rule requires more than this
		//  amount of buffered network data.  If you get such events repeatedly,
		//  you may want to consider re-working some of your TrafficScript
		//  rules to use less memory or to stream the data that they process
		//  rather than storing it all in memory. This setting also limits
		//  the amount of data that can be returned by "request.GetLine()".
		MemoryWarning *int `json:"memory_warning,omitempty"`

		// The maximum number of regular expressions to cache in TrafficScript.
		//  Regular expressions will be compiled in order to speed up their
		//  use in the future.
		RegexCacheSize *int `json:"regex_cache_size,omitempty"`

		// The maximum number of ways TrafficScript will attempt to match
		//  a regular expression at each position in the subject string,
		//  before it aborts the rule and reports a TrafficScript error.
		RegexMatchLimit *int `json:"regex_match_limit,omitempty"`

		// The percentage of "regex_match_limit" at which TrafficScript
		//  reports a performance warning.
		RegexMatchWarnPercentage *int `json:"regex_match_warn_percentage,omitempty"`

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
		VariablePoolUse *bool `json:"variable_pool_use,omitempty"`
	} `json:"trafficscript"`

	TransactionExport struct {
		// The maximum buffering of transaction metadata before events are
		//  switched to brief mode automatically. Each child process is permitted
		//  to buffer this amount of verbose event data, if this buffer size
		//  is exceeded, then events are recorded in brief until space becomes
		//  available. A value of 0 disables this feature.
		AutoBrief *int `json:"auto_brief,omitempty"`

		// Export metadata about transactions processed by the traffic manager
		//  to an external location.
		Enabled *bool `json:"enabled,omitempty"`

		// The endpoint to which transaction metadata should be exported.
		//  The endpoint is specified as a hostname or IP address with a
		//  port.
		Endpoint *string `json:"endpoint,omitempty"`

		// The interval at which reconnection failures will be reported
		//  in the event log.
		FailureInterval *int `json:"failure_interval,omitempty"`

		// The maximum amount of transaction metadata pending export to
		//  buffer. If the buffer size is exceeded, metadata pertaining to
		//  new transactions will be dropped until more buffer space becomes
		//  available.
		Memory *int `json:"memory,omitempty"`

		// The interval at which reconnection will be attempted to the analytics
		//  engine following a disconnection or connection failure.
		ReconnectInterval *int `json:"reconnect_interval,omitempty"`

		// Whether the connection to the specified endpoint should be encrypted.
		Tls *bool `json:"tls,omitempty"`

		// The maximum time allowed to complete a TLS handshake after completing
		//  a TCP connection. If the TLS handshake does not complete in time,
		//  the connection is considered to have failed.
		TlsTimeout *int `json:"tls_timeout,omitempty"`

		// Whether the server certificate presented by the endpoint should
		//  be verified, preventing a connection from being established if
		//  the certificate does not match the server name, is self-signed,
		//  is expired, is revoked, or has an unknown CA.
		TlsVerify *bool `json:"tls_verify,omitempty"`
	} `json:"transaction_export"`

	WebCache struct {
		// The estimated average length of the path (including query string)
		//  for resources being cached. An amount of memory equal to this
		//  figure multiplied by max_file_num will be allocated for storing
		//  the paths for cache entries. This setting can be increased if
		//  your web site makes extensive use of long URLs.
		AvgPathLength *int `json:"avg_path_length,omitempty"`

		// The size of the blocks of shared memory that are allocated for
		//  the content cache.  Every entry in the content cache will use
		//  at least this amount of memory.  You can specify the number of
		//  bytes, kB, or MB.  Unless you know that you are serving almost
		//  exclusively very small or very large files, there is no reason
		//  to change this value.
		Blocksize *string `json:"blocksize,omitempty"`

		// Whether or not to use a disk-backed (typically SSD) cache.  If
		//  set to "Yes" cached web pages will be stored in a file on disk.
		//   This enables the traffic manager to use a cache that is larger
		//  than available RAM.  The "size" setting should also be adjusted
		//  to select a suitable maximum size based on your disk space. <br
		//  /> Note that the disk caching is optimized for use with SSD storage.
		Disk *bool `json:"disk,omitempty"`

		// If disk caching is enabled, this sets the directory where the
		//  disk cache file will be stored.  The traffic manager will create
		//  a file called "webcache.data" in this location. <br /> Note that
		//  the disk caching is optimized for use with SSD storage.
		DiskDir *string `json:"disk_dir,omitempty"`

		// Maximum number of range segments allowed in a range request.
		//   Requests containing more segments than this will get a 416 "Requested
		//  Range Not Satisfiable" response, even if the page actually contains
		//  the requested ranges.  This setting is useful to protect against
		//  byte-range-related DoS attacks.
		MaxByteRangeSegments *int `json:"max_byte_range_segments,omitempty"`

		// Maximum number of entries in the cache.  Approximately 0.9 KB
		//  will be pre-allocated per entry for metadata, this is in addition
		//  to the memory reserved for the content cache and for storing
		//  the paths of the cached resources.
		MaxFileNum *int `json:"max_file_num,omitempty"`

		// Largest size of a cacheable object in the cache.  This is specified
		//  as either a percentage of the total cache size, "2%" for example,
		//  or an absolute size such as "20MB".
		MaxFileSize *string `json:"max_file_size,omitempty"`

		// Maximum number of webcache handles to allow per process. This
		//  is a limit on the maximum number of cached objects being simultaneously
		//  served, not a limit on the maximum that can be in the cache.
		//  A value of 0 indicates that we should use the system per-process
		//  limit on number of FDs.
		MaxHandles *int `json:"max_handles,omitempty"`

		// The maximum length of the path (including query string) for the
		//  resource being cached. If the path exceeds this length then it
		//  will not be added to the cache.
		MaxPathLength *int `json:"max_path_length,omitempty"`

		// If a page is stored in the cache, the traffic manager will add
		//  the header "Accept-Ranges: bytes" to responses that are not chunked,
		//  not compressed and exceed a certain size (and do not have it
		//  yet). This expert tunable specifies the minimum size a page has
		//  to have for the traffic manager to add the Accept-Ranges header.
		MinSizeAcceptRange *int `json:"min_size_accept_range,omitempty"`

		// Enable normalization (lexical ordering of the parameter-assignments)
		//  of the query string.
		NormalizeQuery *bool `json:"normalize_query,omitempty"`

		// The maximum size of the HTTP web page cache.  This is specified
		//  as either a percentage of system RAM, "20%" for example, or an
		//  absolute size such as "200MB".
		Size *string `json:"size,omitempty"`

		// Percentage of space to keep free in the URL store.
		UrlStoreKeepFree *int `json:"url_store_keep_free,omitempty"`

		// How many times to attempt to malloc space for a cache URL before
		//  giving up. 0 means never give up.
		UrlStoreMaxMallocs *int `json:"url_store_max_mallocs,omitempty"`

		// The number of bins to use for the URL store. 0 means no binning.
		UrlStoreNumBins *int `json:"url_store_num_bins,omitempty"`

		// Add an X-Cache-Info header to every HTTP response, showing whether
		//  the request and/or the response was cacheable.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"web_cache"`
}

type GlobalSettingsApplianceReturnpath struct {
	// The MAC address to IPv4 address mapping of a router the software
	//  is connected to. The "*" (asterisk) in the key name is the MAC
	//  address, the value is the IP address.
	Ipv4 *string `json:"ipv4,omitempty"`

	// The MAC address to IPv6 address mapping of a router the software
	//  is connected to. The "*" (asterisk) in the key name is the MAC
	//  address, the value is the IP address.
	Ipv6 *string `json:"ipv6,omitempty"`

	// The MAC address of a router the software is connected to.
	Mac *string `json:"mac,omitempty"`
}

type GlobalSettingsApplianceReturnpathTable []GlobalSettingsApplianceReturnpath

type GlobalSettingsProxyMap struct {
	// The real path to create a symlinked resource to.
	AbsolutePath *string `json:"absolute_path,omitempty"`

	// The path to the symlinked resource. Intermediate resources will
	//  be created. All new resources will be hidden.
	SymlinkPath *string `json:"symlink_path,omitempty"`
}

type GlobalSettingsProxyMapTable []GlobalSettingsProxyMap
