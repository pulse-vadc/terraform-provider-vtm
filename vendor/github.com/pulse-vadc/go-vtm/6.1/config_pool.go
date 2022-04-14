// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type Pool struct {
	connector      *vtmConnector
	PoolProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetPool(name string) (*Pool, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetPool(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/pools/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Pool)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Pool) Apply() (*Pool, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewPool(name string) *Pool {
	object := new(Pool)

	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/pools/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeletePool(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/pools/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListPools() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/config/active/pools")
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

type PoolProperties struct {
	AutoScaling struct {
		// The time in seconds from the creation of the node which the traffic
		//  manager should wait before adding the node to the autoscaled
		//  pool. Set this to allow applications on the newly created node
		//  time to intialize before being sent traffic.
		AddnodeDelaytime *int `json:"addnode_delaytime,omitempty"`

		// The Cloud Credentials object containing authentication credentials
		//  to use in cloud API calls.
		CloudCredentials *string `json:"cloud_credentials,omitempty"`

		// The ESX host or ESX cluster name to put the new virtual machine
		//  instances on.
		Cluster *string `json:"cluster,omitempty"`

		// The name of the logical datacenter on the vCenter server. Virtual
		//  machines will be scaled up and down under the datacenter root
		//  folder.
		DataCenter *string `json:"data_center,omitempty"`

		// The name of the datastore to be used by the newly created virtual
		//  machine.
		DataStore *string `json:"data_store,omitempty"`

		// Are the nodes of this pool subject to autoscaling?  If yes, nodes
		//  will be automatically added and removed from the pool by the
		//  chosen autoscaling mechanism.
		Enabled *bool `json:"enabled,omitempty"`

		// Whether or not autoscaling is being handled by an external system.
		//  Set this value to Yes if all aspects of autoscaling are handled
		//  by an external system, such as RightScale. If set to No, the
		//  traffic manager will determine when to scale the pool and will
		//  communicate with the cloud provider to create and destroy nodes
		//  as necessary.
		External *bool `json:"external,omitempty"`

		// Any extra arguments to the autoscaling API. Each argument can
		//  be separated by comma. E.g in case of EC2, it can take extra
		//  parameters to the Amazon's RunInstance API say DisableApiTermination=false,Placement.Tenancy=default.
		Extraargs *string `json:"extraargs,omitempty"`

		// The time period in seconds for which a change condition must
		//  persist before the change is actually instigated.
		Hysteresis *int `json:"hysteresis,omitempty"`

		// The identifier for the image of the instances to create.
		Imageid *string `json:"imageid,omitempty"`

		// Which type of IP addresses on the node to use.  Choose private
		//  IPs if the traffic manager is in the same cloud as the nodes,
		//  otherwise choose public IPs.
		IpsToUse *string `json:"ips_to_use,omitempty"`

		// The time in seconds for which the last node in an autoscaled
		//  pool must have been idle before it is destroyed.  This is only
		//  relevant if min_nodes is 0.
		LastNodeIdleTime *int `json:"last_node_idle_time,omitempty"`

		// The maximum number of nodes in this autoscaled pool.
		MaxNodes *int `json:"max_nodes,omitempty"`

		// The minimum number of nodes in this autoscaled pool.
		MinNodes *int `json:"min_nodes,omitempty"`

		// The beginning of the name of nodes in the cloud that are part
		//  of this autoscaled pool.
		Name *string `json:"name,omitempty"`

		// The port number to use for each node in this autoscaled pool.
		Port *int `json:"port,omitempty"`

		// The time period in seconds after the instigation of a re-size
		//  during which no further changes will be made to the pool size.
		Refractory *int `json:"refractory,omitempty"`

		// The expected response time of the nodes in ms.  This time is
		//  used as a reference when deciding whether a node's response time
		//  is conforming.  All responses from all the nodes will be compared
		//  to this reference and the percentage of conforming responses
		//  is the base for decisions about scaling the pool up or down.
		ResponseTime *int `json:"response_time,omitempty"`

		// The fraction, in percent, of conforming requests above which
		//  the pool size is decreased.  If the percentage of conforming
		//  requests exceeds this value, the pool is scaled down.
		ScaleDownLevel *int `json:"scale_down_level,omitempty"`

		// The fraction, in percent, of conforming requests below which
		//  the pool size is increased.  If the percentage of conforming
		//  requests drops below this value, the pool is scaled up.
		ScaleUpLevel *int `json:"scale_up_level,omitempty"`

		// List of security group IDs to associate to the new EC2 instance.
		Securitygroupids *[]string `json:"securitygroupids,omitempty"`

		// The identifier for the size of the instances to create.
		SizeId *string `json:"size_id,omitempty"`

		// List of subnet IDs where the new EC2-VPC instance(s) will be
		//  launched. Instances will be evenly distributed among the subnets.
		//  If the list is empty, instances will be launched inside EC2-Classic.
		Subnetids *[]string `json:"subnetids,omitempty"`
	} `json:"auto_scaling"`

	Basic struct {
		// The Bandwidth Management Class this pool uses, if any.
		BandwidthClass *string `json:"bandwidth_class,omitempty"`

		// If all of the nodes in this pool have failed, then requests can
		//  be diverted to another pool.
		FailurePool *string `json:"failure_pool,omitempty"`

		// The size of the LARD cache. This is used when recording unique
		//  URLs to provide request affinity, where the same request is sent
		//  to the same node.
		LardSize *int `json:"lard_size,omitempty"`

		// The maximum number of nodes to which the traffic manager will
		//  attempt to send a request before returning an error to the client.
		//  Requests that are non-retryable will be attempted against only
		//  one node. Zero signifies no limit.
		MaxConnectionAttempts *int `json:"max_connection_attempts,omitempty"`

		// The maximum number of unused HTTP keepalive connections that
		//  should be maintained to an individual node.  Zero signifies no
		//  limit.
		MaxIdleConnectionsPernode *int `json:"max_idle_connections_pernode,omitempty"`

		// The maximum number of connection attempts the traffic manager
		//  will make where the server fails to respond within the time limit
		//  defined by the "max_reply_time" setting. Zero signifies no limit.
		MaxTimedOutConnectionAttempts *int `json:"max_timed_out_connection_attempts,omitempty"`

		// The monitors assigned to this pool, used to detect failures in
		//  the back end nodes.
		Monitors *[]string `json:"monitors,omitempty"`

		// Whether or not connections to the back-end nodes should be closed
		//  with a RST packet, rather than a FIN packet. This avoids the
		//  TIME_WAIT state, which on rare occasions allows wandering duplicate
		//  packets to be safely ignored.
		NodeCloseWithRst *bool `json:"node_close_with_rst,omitempty"`

		// The number of times the software will attempt to connect to the
		//  same back-end node before marking it as failed.  This is only
		//  used when "passive_monitoring" is enabled.
		NodeConnectionAttempts *int `json:"node_connection_attempts,omitempty"`

		// Specify the deletion behavior for nodes in this pool.
		NodeDeleteBehavior *string `json:"node_delete_behavior,omitempty"`

		// The maximum time that a node will be allowed to remain in a draining
		//  state after it has been deleted. A value of 0 means no maximum
		//  time.
		NodeDrainToDeleteTimeout *int `json:"node_drain_to_delete_timeout,omitempty"`

		// A table of all nodes in this pool. A node should be specified
		//  as a "<ip>:<port>" pair, and has a state, weight and priority.
		NodesTable *PoolNodesTableTable `json:"nodes_table,omitempty"`

		// A description of the pool.
		Note *string `json:"note,omitempty"`

		// Whether or not the software should check that 'real' requests
		//  (i.e. not those from monitors) to this pool appear to be working.
		//   This should normally be enabled, so that when a node is refusing
		//  connections, responding too slowly, or sending back invalid data,
		//  it can mark that node as failed, and stop sending requests to
		//  it. <br>If this is disabled, you should ensure that suitable
		//  health monitors are configured to check your servers instead,
		//  otherwise failed requests will not be detected and subsequently
		//  retried.
		PassiveMonitoring *bool `json:"passive_monitoring,omitempty"`

		// The default Session Persistence class this pool uses, if any.
		PersistenceClass *string `json:"persistence_class,omitempty"`

		// Whether or not connections to the back-ends appear to originate
		//  from the source client IP address.
		Transparent *bool `json:"transparent,omitempty"`
	} `json:"basic"`

	Connection struct {
		// How long the pool should wait for a connection to a node to be
		//  established before giving up and trying another node.
		MaxConnectTime *int `json:"max_connect_time,omitempty"`

		// The maximum number of concurrent connections allowed to each
		//  back-end node in this pool per machine. A value of 0 means unlimited
		//  connections.
		MaxConnectionsPerNode *int `json:"max_connections_per_node,omitempty"`

		// The maximum number of connections that can be queued due to connections
		//  limits. A value of 0 means unlimited queue size.
		MaxQueueSize *int `json:"max_queue_size,omitempty"`

		// How long the pool should wait for a response from the node before
		//  either discarding the request or trying another node (retryable
		//  requests only).
		MaxReplyTime *int `json:"max_reply_time,omitempty"`

		// The maximum time to keep a connection queued in seconds.
		QueueTimeout *int `json:"queue_timeout,omitempty"`
	} `json:"connection"`

	DnsAutoscale struct {
		// When enabled, the Traffic Manager will periodically resolve the
		//  hostnames in the "hostnames" list using a DNS query, and use
		//  the results to automatically add, remove or update the IP addresses
		//  of the nodes in the pool.
		Enabled *bool `json:"enabled,omitempty"`

		// A list of hostnames which will be used for DNS-derived autoscaling
		Hostnames *[]string `json:"hostnames,omitempty"`

		// The port number to use for each node when using DNS-derived autoscaling
		Port *int `json:"port,omitempty"`
	} `json:"dns_autoscale"`

	Ftp struct {
		// Whether or not the backend IPv4 nodes understand the EPRT and
		//  EPSV command from RFC 2428.  It is always assumed that IPv6 nodes
		//  support these commands.
		SupportRfc2428 *bool `json:"support_rfc_2428,omitempty"`
	} `json:"ftp"`

	Http struct {
		// Whether or not the pool should maintain HTTP keepalive connections
		//  to the nodes.
		Keepalive *bool `json:"keepalive,omitempty"`

		// Whether or not the pool should maintain HTTP keepalive connections
		//  to the nodes for non-idempotent requests.
		KeepaliveNonIdempotent *bool `json:"keepalive_non_idempotent,omitempty"`
	} `json:"http"`

	KerberosProtocolTransition struct {
		// The Kerberos principal the traffic manager should use when performing
		//  Kerberos Protocol Transition.
		Principal *string `json:"principal,omitempty"`

		// The Kerberos principal name of the service this pool targets.
		Target *string `json:"target,omitempty"`
	} `json:"kerberos_protocol_transition"`

	LoadBalancing struct {
		// The load balancing algorithm that this pool uses to distribute
		//  load across its nodes.
		Algorithm *string `json:"algorithm,omitempty"`

		// Enable priority lists.
		PriorityEnabled *bool `json:"priority_enabled,omitempty"`

		// Minimum number of highest-priority active nodes.
		PriorityNodes *int `json:"priority_nodes,omitempty"`
	} `json:"load_balancing"`

	Node struct {
		// Close all connections to a node once we detect that it has failed.
		CloseOnDeath *bool `json:"close_on_death,omitempty"`

		// The amount of time, in seconds, that a traffic manager will wait
		//  before re-trying a node that has been marked as failed by passive
		//  monitoring.
		RetryFailTime *int `json:"retry_fail_time,omitempty"`
	} `json:"node"`

	ServiceDiscovery struct {
		// Are the nodes of this pool determined by a Service Discovery
		//  plugin? If yes, nodes will be automatically added and removed
		//  from the pool by the traffic manager.
		Enabled *bool `json:"enabled,omitempty"`

		// The minimum time before rerunning the Service Discovery plugin
		Interval *int `json:"interval,omitempty"`

		// The plugin script a Service Discovery autoscaled pool should
		//  use to retrieve the list of nodes.
		Plugin *string `json:"plugin,omitempty"`

		// The arguments for the script specified in "service_discovery!plugin",
		//  e.g. a common instance tag, or name of a managed group of cloud
		//  instances.
		PluginArgs *string `json:"plugin_args,omitempty"`

		// The maximum time a plugin should be allowed to run before timing
		//  out. Set to 0 for no timeout.
		Timeout *int `json:"timeout,omitempty"`
	} `json:"service_discovery"`

	Smtp struct {
		// If we are encrypting traffic for an SMTP connection, should we
		//  upgrade to SSL using STARTTLS.
		SendStarttls *bool `json:"send_starttls,omitempty"`
	} `json:"smtp"`

	Ssl struct {
		// The SSL/TLS cipher suites to allow for connections to a back-end
		//  node. Leaving this empty will make the pool use the globally
		//  configured cipher suites, see configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!cipher_suites">
		//  "ssl!cipher_suites"</a> in the Global Settings section of the
		//  System tab.  See there for how to specify SSL/TLS cipher suites.
		CipherSuites *string `json:"cipher_suites,omitempty"`

		// Whether or not a suitable certificate and private key from the
		//  SSL Client Certificates catalog be used if the back-end server
		//  requests client authentication.
		ClientAuth *bool `json:"client_auth,omitempty"`

		// A list of names against which the 'common name' of the certificate
		//  is matched; these names are used in addition to the node's hostname
		//  or IP address as specified in the config file or added by the
		//  autoscaler process.
		CommonNameMatch *[]string `json:"common_name_match,omitempty"`

		// The SSL elliptic curve preference list for SSL connections from
		//  this pool using TLS version 1.0 or higher. Leaving this empty
		//  will make the pool use the globally configured preference list.
		//  The named curves P256, P384 and P521 may be configured.
		EllipticCurves *[]string `json:"elliptic_curves,omitempty"`

		// Whether or not the pool should encrypt data before sending it
		//  to a back-end node.
		Enable *bool `json:"enable,omitempty"`

		// SSL protocol enhancements allow your traffic manager to prefix
		//  each new SSL connection with information about the client. This
		//  enables Pulse Secure Virtual Traffic Manager virtual servers
		//  referenced by this pool to discover the original client's IP
		//  address. Only enable this if you are using nodes for this pool
		//  which are Pulse Secure vTMs, whose virtual servers have the "ssl_trust_magic"
		//  setting enabled.
		Enhance *bool `json:"enhance,omitempty"`

		// Whether or not to send an SSL/TLS "close alert" when initiating
		//  a socket disconnection.
		SendCloseAlerts *bool `json:"send_close_alerts,omitempty"`

		// Whether or not the software should use the TLS 1.0 server_name
		//  extension, which may help the back-end node provide the correct
		//  certificate. Enabling this setting will force the use of at least
		//  TLS 1.0.
		ServerName *bool `json:"server_name,omitempty"`

		// Whether or not the SSL client cache will be used for this pool.
		//  Choosing the global setting means the value of the configuration
		//  key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!client_cache!enabled">
		//  "ssl!client_cache!enabled"</a> from the Global Settings section
		//  of the System tab will be enforced.
		SessionCacheEnabled *string `json:"session_cache_enabled,omitempty"`

		// Whether or not SSL session tickets will be used for this pool
		//  if the session cache is also enabled. Choosing the global setting
		//  means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!client_cache!tickets_enabled">
		//  "ssl!client_cache!enabled"</a> from the Global Settings section
		//  of the System tab will be enforced.
		SessionTicketsEnabled *string `json:"session_tickets_enabled,omitempty"`

		// The SSL signature algorithms preference list for SSL connections
		//  from this pool using TLS version 1.2 or higher. Leaving this
		//  empty will make the pool use the globally configured preference
		//  list, "signature_algorithms" in the "ssl" section of the "global_settings"
		//  resource.  See there and in the online help for how to specify
		//  SSL signature algorithms.
		SignatureAlgorithms *string `json:"signature_algorithms,omitempty"`

		// Whether or not strict certificate verification should be performed.
		//  This will turn on checks to disallow server certificates that
		//  don't match the server name or a name in the ssl_common_name_match
		//  list, are self-signed, expired, revoked, or have an unknown CA.
		StrictVerify *bool `json:"strict_verify,omitempty"`

		// Whether or not SSLv3 is enabled for this pool. Choosing the global
		//  setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_ssl3">
		//  "ssl!support_ssl3"</a> from the Global Settings section of the
		//  System tab will be enforced.
		SupportSsl3 *string `json:"support_ssl3,omitempty"`

		// Whether or not TLSv1.0 is enabled for this pool. Choosing the
		//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1">
		//  "ssl!support_tls1"</a> from the Global Settings section of the
		//  System tab will be enforced.
		SupportTls1 *string `json:"support_tls1,omitempty"`

		// Whether or not TLSv1.1 is enabled for this pool. Choosing the
		//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_1">
		//  "ssl!support_tls1_1"</a> from the Global Settings section of
		//  the System tab will be enforced.
		SupportTls11 *string `json:"support_tls1_1,omitempty"`

		// Whether or not TLSv1.2 is enabled for this pool. Choosing the
		//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_2">
		//  "ssl!support_tls1_2"</a> from the Global Settings section of
		//  the System tab will be enforced.
		SupportTls12 *string `json:"support_tls1_2,omitempty"`
	} `json:"ssl"`

	Tcp struct {
		// Whether or not Nagle's algorithm should be used for TCP connections
		//  to the back-end nodes.
		Nagle *bool `json:"nagle,omitempty"`
	} `json:"tcp"`

	Udp struct {
		// The IP addresses and ports from which responses to UDP requests
		//  should be accepted.   If set to accept responses from a specific
		//  set of IP addresses, you will need to enter a CIDR Mask (such
		//  as 10.100.0.0/16).
		AcceptFrom *string `json:"accept_from,omitempty"`

		// The CIDR mask that matches IPs we want to receive responses from.
		AcceptFromMask *string `json:"accept_from_mask,omitempty"`

		// The maximum length of time that a node is permitted to take after
		//  receiving a UDP request packet before sending a reply packet.
		//  Zero indicates that there is no maximum, preventing a node that
		//  does not send replies from being presumed to have failed.
		ResponseTimeout *int `json:"response_timeout,omitempty"`
	} `json:"udp"`
}

type PoolNodesTable struct {
	// A node is a combination of an ip address and port
	Node *string `json:"node,omitempty"`

	// The priority of the node, higher values signify higher priority.
	//  If a priority is not specified for a node it is assumed to be
	//  "1".
	Priority *int `json:"priority,omitempty"`

	// The source address the Traffic Manager uses to connect to this
	//  node.
	SourceIp *string `json:"source_ip,omitempty"`

	// The state of the pool, which can either be Active, Draining or
	//  Disabled
	State *string `json:"state,omitempty"`

	// Weight for the node. The actual value in isolation does not matter:
	//  As long as it is a valid integer 1-100, the per-node weightings
	//  are calculated on the relative values between the nodes.
	Weight *int `json:"weight,omitempty"`
}

type PoolNodesTableTable []PoolNodesTable
