// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func suppressNodesTableDiffs(k, old, new string, d *schema.ResourceData) bool {
	if d.Get("auto_scaling_enabled") == true {
		return true
	}
	if _, ok := d.GetOk("nodes_table_json"); ok {
		return true
	}
	return false
}

func resourcePool() *schema.Resource {
	return &schema.Resource{
		Read:   resourcePoolRead,
		Exists: resourcePoolExists,
		Create: resourcePoolCreate,
		Update: resourcePoolUpdate,
		Delete: resourcePoolDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourcePoolSchema(),
	}
}

func getResourcePoolSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

		"name": &schema.Schema{
			Type:         schema.TypeString,
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.NoZeroValues,
		},

		// The Bandwidth Management Class this pool uses, if any.
		"bandwidth_class": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// If all of the nodes in this pool have failed, then requests can
		//  be diverted to another pool.
		"failure_pool": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The maximum number of nodes to which the traffic manager will
		//  attempt to send a request before returning an error to the client.
		//  Requests that are non-retryable will be attempted against only
		//  one node. Zero signifies no limit.
		"max_connection_attempts": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 99999),
			Default:      0,
		},

		// The maximum number of unused HTTP keepalive connections that
		//  should be maintained to an individual node.  Zero signifies no
		//  limit.
		"max_idle_connections_pernode": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 999999),
			Default:      50,
		},

		// The maximum number of connection attempts the traffic manager
		//  will make where the server fails to respond within the time limit
		//  defined by the "max_reply_time" setting. Zero signifies no limit.
		"max_timed_out_connection_attempts": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 99999),
			Default:      2,
		},

		// The monitors assigned to this pool, used to detect failures in
		//  the back end nodes.
		"monitors": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Whether or not connections to the back-end nodes should be closed
		//  with a RST packet, rather than a FIN packet. This avoids the
		//  TIME_WAIT state, which on rare occasions allows wandering duplicate
		//  packets to be safely ignored.
		"node_close_with_rst": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The number of times the software will attempt to connect to the
		//  same back-end node before marking it as failed.  This is only
		//  used when "passive_monitoring" is enabled.
		"node_connection_attempts": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 100),
			Default:      3,
		},

		// Specify the deletion behavior for nodes in this pool.
		"node_delete_behavior": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"drain", "immediate"}, false),
			Default:      "immediate",
		},

		// The maximum time that a node will be allowed to remain in a draining
		//  state after it has been deleted. A value of 0 means no maximum
		//  time.
		"node_drain_to_delete_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 99999),
			Default:      0,
		},

		// A table of all nodes in this pool. A node should be specified
		//  as a "<ip>:<port>" pair, and has a state, weight and priority.
		"nodes_table": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			DiffSuppressFunc: suppressNodesTableDiffs,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{

					// node
					"node": &schema.Schema{
						Type:     schema.TypeString,
						Required: true,
					},

					// priority
					"priority": &schema.Schema{
						Type:         schema.TypeInt,
						Optional:     true,
						ValidateFunc: validation.IntAtLeast(0),
						Default:      1,
					},

					// source_ip
					"source_ip": &schema.Schema{
						Type:     schema.TypeString,
						Optional: true,
					},

					// state
					"state": &schema.Schema{
						Type:         schema.TypeString,
						Optional:     true,
						ValidateFunc: validation.StringInSlice([]string{"active", "disabled", "draining"}, false),
						Default:      "active",
					},

					// weight
					"weight": &schema.Schema{
						Type:         schema.TypeInt,
						Optional:     true,
						ValidateFunc: validation.IntBetween(1, 100),
						Default:      1,
					},
				},
			},
		},

		// JSON representation of nodes_table
		"nodes_table_json": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.ValidateJsonString,
		},

		// A description of the pool.
		"note": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not the software should check that 'real' requests
		//  (i.e. not those from monitors) to this pool appear to be working.
		//   This should normally be enabled, so that when a node is refusing
		//  connections, responding too slowly, or sending back invalid data,
		//  it can mark that node as failed, and stop sending requests to
		//  it. <br>If this is disabled, you should ensure that suitable
		//  health monitors are configured to check your servers instead,
		//  otherwise failed requests will not be detected and subsequently
		//  retried.
		"passive_monitoring": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The default Session Persistence class this pool uses, if any.
		"persistence_class": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not connections to the back-ends appear to originate
		//  from the source client IP address.
		"transparent": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The time in seconds from the creation of the node which the traffic
		//  manager should wait before adding the node to the autoscaled
		//  pool. Set this to allow applications on the newly created node
		//  time to intialize before being sent traffic.
		"auto_scaling_addnode_delaytime": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// The Cloud Credentials object containing authentication credentials
		//  to use in cloud API calls.
		"auto_scaling_cloud_credentials": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The ESX host or ESX cluster name to put the new virtual machine
		//  instances on.
		"auto_scaling_cluster": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The name of the logical datacenter on the vCenter server. Virtual
		//  machines will be scaled up and down under the datacenter root
		//  folder.
		"auto_scaling_data_center": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The name of the datastore to be used by the newly created virtual
		//  machine.
		"auto_scaling_data_store": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Are the nodes of this pool subject to autoscaling?  If yes, nodes
		//  will be automatically added and removed from the pool by the
		//  chosen autoscaling mechanism.
		"auto_scaling_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not autoscaling is being handled by an external system.
		//  Set this value to Yes if all aspects of autoscaling are handled
		//  by an external system, such as RightScale. If set to No, the
		//  traffic manager will determine when to scale the pool and will
		//  communicate with the cloud provider to create and destroy nodes
		//  as necessary.
		"auto_scaling_external": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Any extra arguments to the autoscaling API. Each argument can be
		//  separated by comma. E.g in case of EC2, it can take extra parameters
		//  to the Amazon's RunInstance API say
		//  DisableApiTermination=false,Placement.Tenancy=default.
		"auto_scaling_extraargs": &schema.Schema{
			Type:       schema.TypeString,
			Optional:   true,
		},

		// The time period in seconds for which a change condition must
		//  persist before the change is actually instigated.
		"auto_scaling_hysteresis": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      20,
		},

		// The identifier for the image of the instances to create.
		"auto_scaling_imageid": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Which type of IP addresses on the node to use.  Choose private
		//  IPs if the traffic manager is in the same cloud as the nodes,
		//  otherwise choose public IPs.
		"auto_scaling_ips_to_use": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"private_ips", "publicips"}, false),
			Default:      "publicips",
		},

		// The time in seconds for which the last node in an autoscaled
		//  pool must have been idle before it is destroyed.  This is only
		//  relevant if min_nodes is 0.
		"auto_scaling_last_node_idle_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      3600,
		},

		// The maximum number of nodes in this autoscaled pool.
		"auto_scaling_max_nodes": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      4,
		},

		// The minimum number of nodes in this autoscaled pool.
		"auto_scaling_min_nodes": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      1,
		},

		// The beginning of the name of nodes in the cloud that are part
		//  of this autoscaled pool.
		"auto_scaling_name": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The port number to use for each node in this autoscaled pool.
		"auto_scaling_port": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 65535),
			Default:      80,
		},

		// The time period in seconds after the instigation of a re-size
		//  during which no further changes will be made to the pool size.
		"auto_scaling_refractory": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      180,
		},

		// The expected response time of the nodes in ms.  This time is
		//  used as a reference when deciding whether a node's response time
		//  is conforming.  All responses from all the nodes will be compared
		//  to this reference and the percentage of conforming responses
		//  is the base for decisions about scaling the pool up or down.
		"auto_scaling_response_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      1000,
		},

		// The fraction, in percent, of conforming requests above which
		//  the pool size is decreased.  If the percentage of conforming
		//  requests exceeds this value, the pool is scaled down.
		"auto_scaling_scale_down_level": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      95,
		},

		// The fraction, in percent, of conforming requests below which
		//  the pool size is increased.  If the percentage of conforming
		//  requests drops below this value, the pool is scaled up.
		"auto_scaling_scale_up_level": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      40,
		},

		// List of security group IDs to associate to the new EC2 instance.
		"auto_scaling_securitygroupids": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The identifier for the size of the instances to create.
		"auto_scaling_size_id": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// List of subnet IDs where the new EC2-VPC instance(s) will be
		//  launched. Instances will be evenly distributed among the subnets.
		//  If the list is empty, instances will be launched inside EC2-Classic.
		"auto_scaling_subnetids": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// How long the pool should wait for a connection to a node to be
		//  established before giving up and trying another node.
		"connection_max_connect_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 99999),
			Default:      4,
		},

		// The maximum number of concurrent connections allowed to each
		//  back-end node in this pool per machine. A value of 0 means unlimited
		//  connections.
		"connection_max_connections_per_node": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 999999),
			Default:      0,
		},

		// The maximum number of connections that can be queued due to connections
		//  limits. A value of 0 means unlimited queue size.
		"connection_max_queue_size": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 999999),
			Default:      0,
		},

		// How long the pool should wait for a response from the node before
		//  either discarding the request or trying another node (retryable
		//  requests only).
		"connection_max_reply_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 99999),
			Default:      30,
		},

		// The maximum time to keep a connection queued in seconds.
		"connection_queue_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 31536000),
			Default:      10,
		},

		// When enabled, the Traffic Manager will periodically resolve the
		//  hostnames in the "hostnames" list using a DNS query, and use
		//  the results to automatically add, remove or update the IP addresses
		//  of the nodes in the pool.
		"dns_autoscale_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// A list of hostnames which will be used for DNS-derived autoscaling
		"dns_autoscale_hostnames": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The port number to use for each node when using DNS-derived autoscaling
		"dns_autoscale_port": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 65535),
			Default:      80,
		},

		// Whether or not the backend IPv4 nodes understand the EPRT and
		//  EPSV command from RFC 2428.  It is always assumed that IPv6 nodes
		//  support these commands.
		"ftp_support_rfc_2428": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not the pool should maintain HTTP keepalive connections
		//  to the nodes.
		"http_keepalive": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Whether or not the pool should maintain HTTP keepalive connections
		//  to the nodes for non-idempotent requests.
		"http_keepalive_non_idempotent": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The Kerberos principal the traffic manager should use when performing
		//  Kerberos Protocol Transition.
		"kerberos_protocol_transition_principal": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The Kerberos principal name of the service this pool targets.
		"kerberos_protocol_transition_target": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The load balancing algorithm that this pool uses to distribute
		//  load across its nodes.
		"load_balancing_algorithm": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"fastest_response_time", "least_connections", "perceptive", "random", "round_robin", "weighted_least_connections", "weighted_round_robin"}, false),
			Default:      "round_robin",
		},

		// Enable priority lists.
		"load_balancing_priority_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Minimum number of highest-priority active nodes.
		"load_balancing_priority_nodes": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 65535),
			Default:      1,
		},

		// Close all connections to a node once we detect that it has failed.
		"node_close_on_death": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The amount of time, in seconds, that a traffic manager will wait
		//  before re-trying a node that has been marked as failed by passive
		//  monitoring.
		"node_retry_fail_time": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(1, 99999),
			Default:      60,
		},

		// Are the nodes of this pool determined by a Service Discovery
		//  plugin? If yes, nodes will be automatically added and removed
		//  from the pool by the traffic manager.
		"service_discovery_enabled": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// The minimum time before rerunning the Service Discovery plugin
		"service_discovery_interval": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      10,
		},

		// The plugin script a Service Discovery autoscaled pool should
		//  use to retrieve the list of nodes.
		"service_discovery_plugin": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The arguments for the script specified in "service_discovery!plugin",
		//  e.g. a common instance tag, or name of a managed group of cloud
		//  instances.
		"service_discovery_plugin_args": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The maximum time a plugin should be allowed to run before timing
		//  out. Set to 0 for no timeout.
		"service_discovery_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntAtLeast(0),
			Default:      0,
		},

		// If we are encrypting traffic for an SMTP connection, should we
		//  upgrade to SSL using STARTTLS.
		"smtp_send_starttls": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The SSL/TLS cipher suites to allow for connections to a back-end
		//  node. Leaving this empty will make the pool use the globally
		//  configured cipher suites, see configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!cipher_suites">
		//  "ssl!cipher_suites"</a> in the Global Settings section of the
		//  System tab.  See there for how to specify SSL/TLS cipher suites.
		"ssl_cipher_suites": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not a suitable certificate and private key from the
		//  SSL Client Certificates catalog be used if the back-end server
		//  requests client authentication.
		"ssl_client_auth": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// A list of names against which the 'common name' of the certificate
		//  is matched; these names are used in addition to the node's hostname
		//  or IP address as specified in the config file or added by the
		//  autoscaler process.
		"ssl_common_name_match": &schema.Schema{
			Type:     schema.TypeSet,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// The SSL elliptic curve preference list for SSL connections from
		//  this pool using TLS version 1.0 or higher. Leaving this empty
		//  will make the pool use the globally configured preference list.
		//  The named curves P256, P384 and P521 may be configured.
		"ssl_elliptic_curves": &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			Elem:     &schema.Schema{Type: schema.TypeString},
		},

		// Whether or not the pool should encrypt data before sending it
		//  to a back-end node.
		"ssl_enable": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// SSL protocol enhancements allow your traffic manager to prefix
		//  each new SSL connection with information about the client. This
		//  enables Pulse Secure Virtual Traffic Manager virtual servers
		//  referenced by this pool to discover the original client's IP
		//  address. Only enable this if you are using nodes for this pool
		//  which are Pulse Secure vTMs, whose virtual servers have the "ssl_trust_magic"
		//  setting enabled.
		"ssl_enhance": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not to send an SSL/TLS "close alert" when initiating
		//  a socket disconnection.
		"ssl_send_close_alerts": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// Whether or not the software should use the TLS 1.0 server_name
		//  extension, which may help the back-end node provide the correct
		//  certificate. Enabling this setting will force the use of at least
		//  TLS 1.0.
		"ssl_server_name": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not the SSL client cache will be used for this pool.
		//  Choosing the global setting means the value of the configuration
		//  key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!client_cache!enabled">
		//  "ssl!client_cache!enabled"</a> from the Global Settings section
		//  of the System tab will be enforced.
		"ssl_session_cache_enabled": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not SSL session tickets will be used for this pool
		//  if the session cache is also enabled. Choosing the global setting
		//  means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!client_cache!tickets_enabled">
		//  "ssl!client_cache!enabled"</a> from the Global Settings section
		//  of the System tab will be enforced.
		"ssl_session_tickets_enabled": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// The SSL signature algorithms preference list for SSL connections
		//  from this pool using TLS version 1.2 or higher. Leaving this
		//  empty will make the pool use the globally configured preference
		//  list, "signature_algorithms" in the "ssl" section of the "global_settings"
		//  resource.  See there and in the online help for how to specify
		//  SSL signature algorithms.
		"ssl_signature_algorithms": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// Whether or not strict certificate verification should be performed.
		//  This will turn on checks to disallow server certificates that
		//  don't match the server name or a name in the ssl_common_name_match
		//  list, are self-signed, expired, revoked, or have an unknown CA.
		"ssl_strict_verify": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
		},

		// Whether or not SSLv3 is enabled for this pool. Choosing the global
		//  setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_ssl3">
		//  "ssl!support_ssl3"</a> from the Global Settings section of the
		//  System tab will be enforced.
		"ssl_support_ssl3": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not TLSv1.0 is enabled for this pool. Choosing the
		//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1">
		//  "ssl!support_tls1"</a> from the Global Settings section of the
		//  System tab will be enforced.
		"ssl_support_tls1": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not TLSv1.1 is enabled for this pool. Choosing the
		//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_1">
		//  "ssl!support_tls1_1"</a> from the Global Settings section of
		//  the System tab will be enforced.
		"ssl_support_tls1_1": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not TLSv1.2 is enabled for this pool. Choosing the
		//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1_2">
		//  "ssl!support_tls1_2"</a> from the Global Settings section of
		//  the System tab will be enforced.
		"ssl_support_tls1_2": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
			Default:      "use_default",
		},

		// Whether or not Nagle's algorithm should be used for TCP connections
		//  to the back-end nodes.
		"tcp_nagle": &schema.Schema{
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},

		// The IP addresses and ports from which responses to UDP requests
		//  should be accepted.   If set to accept responses from a specific
		//  set of IP addresses, you will need to enter a CIDR Mask (such
		//  as 10.100.0.0/16).
		"udp_accept_from": &schema.Schema{
			Type:         schema.TypeString,
			Optional:     true,
			ValidateFunc: validation.StringInSlice([]string{"all", "dest_ip_only", "dest_only", "ip_mask"}, false),
			Default:      "dest_only",
		},

		// The CIDR mask that matches IPs we want to receive responses from.
		"udp_accept_from_mask": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},

		// The maximum length of time that a node is permitted to take after
		//  receiving a UDP request packet before sending a reply packet.
		//  Zero indicates that there is no maximum, preventing a node that
		//  does not send replies from being presumed to have failed.
		"udp_response_timeout": &schema.Schema{
			Type:         schema.TypeInt,
			Optional:     true,
			ValidateFunc: validation.IntBetween(0, 99999),
			Default:      0,
		},
	}
}

func resourcePoolRead(d *schema.ResourceData, tm interface{}) (readError error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetPool(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_pool '%v': %v", objectName, err.ErrorText)
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
	lastAssignedField = "failure_pool"
	d.Set("failure_pool", string(*object.Basic.FailurePool))
	lastAssignedField = "max_connection_attempts"
	d.Set("max_connection_attempts", int(*object.Basic.MaxConnectionAttempts))
	lastAssignedField = "max_idle_connections_pernode"
	d.Set("max_idle_connections_pernode", int(*object.Basic.MaxIdleConnectionsPernode))
	lastAssignedField = "max_timed_out_connection_attempts"
	d.Set("max_timed_out_connection_attempts", int(*object.Basic.MaxTimedOutConnectionAttempts))
	lastAssignedField = "monitors"
	d.Set("monitors", []string(*object.Basic.Monitors))
	lastAssignedField = "node_close_with_rst"
	d.Set("node_close_with_rst", bool(*object.Basic.NodeCloseWithRst))
	lastAssignedField = "node_connection_attempts"
	d.Set("node_connection_attempts", int(*object.Basic.NodeConnectionAttempts))
	lastAssignedField = "node_delete_behavior"
	d.Set("node_delete_behavior", string(*object.Basic.NodeDeleteBehavior))
	lastAssignedField = "node_drain_to_delete_timeout"
	d.Set("node_drain_to_delete_timeout", int(*object.Basic.NodeDrainToDeleteTimeout))
	lastAssignedField = "nodes_table"
	nodesTable := make([]map[string]interface{}, 0, len(*object.Basic.NodesTable))
	for _, item := range *object.Basic.NodesTable {
		itemTerraform := make(map[string]interface{})
		if item.Node != nil {
			itemTerraform["node"] = string(*item.Node)
		}
		if item.Priority != nil {
			itemTerraform["priority"] = int(*item.Priority)
		} else {
			itemTerraform["priority"] = 1
		}
		if item.SourceIp != nil {
			itemTerraform["source_ip"] = string(*item.SourceIp)
		}
		if item.State != nil {
			itemTerraform["state"] = string(*item.State)
		}
		if item.Weight != nil {
			itemTerraform["weight"] = int(*item.Weight)
		} else {
			itemTerraform["weight"] = 1
		}
		nodesTable = append(nodesTable, itemTerraform)
	}
	d.Set("nodes_table", nodesTable)
	nodesTableJson, _ := json.Marshal(nodesTable)
	d.Set("nodes_table_json", nodesTableJson)
	lastAssignedField = "note"
	d.Set("note", string(*object.Basic.Note))
	lastAssignedField = "passive_monitoring"
	d.Set("passive_monitoring", bool(*object.Basic.PassiveMonitoring))
	lastAssignedField = "persistence_class"
	d.Set("persistence_class", string(*object.Basic.PersistenceClass))
	lastAssignedField = "transparent"
	d.Set("transparent", bool(*object.Basic.Transparent))
	lastAssignedField = "auto_scaling_addnode_delaytime"
	d.Set("auto_scaling_addnode_delaytime", int(*object.AutoScaling.AddnodeDelaytime))
	lastAssignedField = "auto_scaling_cloud_credentials"
	d.Set("auto_scaling_cloud_credentials", string(*object.AutoScaling.CloudCredentials))
	lastAssignedField = "auto_scaling_cluster"
	d.Set("auto_scaling_cluster", string(*object.AutoScaling.Cluster))
	lastAssignedField = "auto_scaling_data_center"
	d.Set("auto_scaling_data_center", string(*object.AutoScaling.DataCenter))
	lastAssignedField = "auto_scaling_data_store"
	d.Set("auto_scaling_data_store", string(*object.AutoScaling.DataStore))
	lastAssignedField = "auto_scaling_enabled"
	d.Set("auto_scaling_enabled", bool(*object.AutoScaling.Enabled))
	lastAssignedField = "auto_scaling_external"
	d.Set("auto_scaling_external", bool(*object.AutoScaling.External))
	lastAssignedField = "auto_scaling_extraargs"
	d.Set("auto_scaling_extraargs", string(*object.AutoScaling.Extraargs))
	lastAssignedField = "auto_scaling_hysteresis"
	d.Set("auto_scaling_hysteresis", int(*object.AutoScaling.Hysteresis))
	lastAssignedField = "auto_scaling_imageid"
	d.Set("auto_scaling_imageid", string(*object.AutoScaling.Imageid))
	lastAssignedField = "auto_scaling_ips_to_use"
	d.Set("auto_scaling_ips_to_use", string(*object.AutoScaling.IpsToUse))
	lastAssignedField = "auto_scaling_last_node_idle_time"
	d.Set("auto_scaling_last_node_idle_time", int(*object.AutoScaling.LastNodeIdleTime))
	lastAssignedField = "auto_scaling_max_nodes"
	d.Set("auto_scaling_max_nodes", int(*object.AutoScaling.MaxNodes))
	lastAssignedField = "auto_scaling_min_nodes"
	d.Set("auto_scaling_min_nodes", int(*object.AutoScaling.MinNodes))
	lastAssignedField = "auto_scaling_name"
	d.Set("auto_scaling_name", string(*object.AutoScaling.Name))
	lastAssignedField = "auto_scaling_port"
	d.Set("auto_scaling_port", int(*object.AutoScaling.Port))
	lastAssignedField = "auto_scaling_refractory"
	d.Set("auto_scaling_refractory", int(*object.AutoScaling.Refractory))
	lastAssignedField = "auto_scaling_response_time"
	d.Set("auto_scaling_response_time", int(*object.AutoScaling.ResponseTime))
	lastAssignedField = "auto_scaling_scale_down_level"
	d.Set("auto_scaling_scale_down_level", int(*object.AutoScaling.ScaleDownLevel))
	lastAssignedField = "auto_scaling_scale_up_level"
	d.Set("auto_scaling_scale_up_level", int(*object.AutoScaling.ScaleUpLevel))
	lastAssignedField = "auto_scaling_securitygroupids"
	d.Set("auto_scaling_securitygroupids", []string(*object.AutoScaling.Securitygroupids))
	lastAssignedField = "auto_scaling_size_id"
	d.Set("auto_scaling_size_id", string(*object.AutoScaling.SizeId))
	lastAssignedField = "auto_scaling_subnetids"
	d.Set("auto_scaling_subnetids", []string(*object.AutoScaling.Subnetids))
	lastAssignedField = "connection_max_connect_time"
	d.Set("connection_max_connect_time", int(*object.Connection.MaxConnectTime))
	lastAssignedField = "connection_max_connections_per_node"
	d.Set("connection_max_connections_per_node", int(*object.Connection.MaxConnectionsPerNode))
	lastAssignedField = "connection_max_queue_size"
	d.Set("connection_max_queue_size", int(*object.Connection.MaxQueueSize))
	lastAssignedField = "connection_max_reply_time"
	d.Set("connection_max_reply_time", int(*object.Connection.MaxReplyTime))
	lastAssignedField = "connection_queue_timeout"
	d.Set("connection_queue_timeout", int(*object.Connection.QueueTimeout))
	lastAssignedField = "dns_autoscale_enabled"
	d.Set("dns_autoscale_enabled", bool(*object.DnsAutoscale.Enabled))
	lastAssignedField = "dns_autoscale_hostnames"
	d.Set("dns_autoscale_hostnames", []string(*object.DnsAutoscale.Hostnames))
	lastAssignedField = "dns_autoscale_port"
	d.Set("dns_autoscale_port", int(*object.DnsAutoscale.Port))
	lastAssignedField = "ftp_support_rfc_2428"
	d.Set("ftp_support_rfc_2428", bool(*object.Ftp.SupportRfc2428))
	lastAssignedField = "http_keepalive"
	d.Set("http_keepalive", bool(*object.Http.Keepalive))
	lastAssignedField = "http_keepalive_non_idempotent"
	d.Set("http_keepalive_non_idempotent", bool(*object.Http.KeepaliveNonIdempotent))
	lastAssignedField = "kerberos_protocol_transition_principal"
	d.Set("kerberos_protocol_transition_principal", string(*object.KerberosProtocolTransition.Principal))
	lastAssignedField = "kerberos_protocol_transition_target"
	d.Set("kerberos_protocol_transition_target", string(*object.KerberosProtocolTransition.Target))
	lastAssignedField = "load_balancing_algorithm"
	d.Set("load_balancing_algorithm", string(*object.LoadBalancing.Algorithm))
	lastAssignedField = "load_balancing_priority_enabled"
	d.Set("load_balancing_priority_enabled", bool(*object.LoadBalancing.PriorityEnabled))
	lastAssignedField = "load_balancing_priority_nodes"
	d.Set("load_balancing_priority_nodes", int(*object.LoadBalancing.PriorityNodes))
	lastAssignedField = "node_close_on_death"
	d.Set("node_close_on_death", bool(*object.Node.CloseOnDeath))
	lastAssignedField = "node_retry_fail_time"
	d.Set("node_retry_fail_time", int(*object.Node.RetryFailTime))
	lastAssignedField = "service_discovery_enabled"
	d.Set("service_discovery_enabled", bool(*object.ServiceDiscovery.Enabled))
	lastAssignedField = "service_discovery_interval"
	d.Set("service_discovery_interval", int(*object.ServiceDiscovery.Interval))
	lastAssignedField = "service_discovery_plugin"
	d.Set("service_discovery_plugin", string(*object.ServiceDiscovery.Plugin))
	lastAssignedField = "service_discovery_plugin_args"
	d.Set("service_discovery_plugin_args", string(*object.ServiceDiscovery.PluginArgs))
	lastAssignedField = "service_discovery_timeout"
	d.Set("service_discovery_timeout", int(*object.ServiceDiscovery.Timeout))
	lastAssignedField = "smtp_send_starttls"
	d.Set("smtp_send_starttls", bool(*object.Smtp.SendStarttls))
	lastAssignedField = "ssl_cipher_suites"
	d.Set("ssl_cipher_suites", string(*object.Ssl.CipherSuites))
	lastAssignedField = "ssl_client_auth"
	d.Set("ssl_client_auth", bool(*object.Ssl.ClientAuth))
	lastAssignedField = "ssl_common_name_match"
	d.Set("ssl_common_name_match", []string(*object.Ssl.CommonNameMatch))
	lastAssignedField = "ssl_elliptic_curves"
	d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	lastAssignedField = "ssl_enable"
	d.Set("ssl_enable", bool(*object.Ssl.Enable))
	lastAssignedField = "ssl_enhance"
	d.Set("ssl_enhance", bool(*object.Ssl.Enhance))
	lastAssignedField = "ssl_send_close_alerts"
	d.Set("ssl_send_close_alerts", bool(*object.Ssl.SendCloseAlerts))
	lastAssignedField = "ssl_server_name"
	d.Set("ssl_server_name", bool(*object.Ssl.ServerName))
	lastAssignedField = "ssl_session_cache_enabled"
	d.Set("ssl_session_cache_enabled", string(*object.Ssl.SessionCacheEnabled))
	lastAssignedField = "ssl_session_tickets_enabled"
	d.Set("ssl_session_tickets_enabled", string(*object.Ssl.SessionTicketsEnabled))
	lastAssignedField = "ssl_signature_algorithms"
	d.Set("ssl_signature_algorithms", string(*object.Ssl.SignatureAlgorithms))
	lastAssignedField = "ssl_strict_verify"
	d.Set("ssl_strict_verify", bool(*object.Ssl.StrictVerify))
	lastAssignedField = "ssl_support_ssl3"
	d.Set("ssl_support_ssl3", string(*object.Ssl.SupportSsl3))
	lastAssignedField = "ssl_support_tls1"
	d.Set("ssl_support_tls1", string(*object.Ssl.SupportTls1))
	lastAssignedField = "ssl_support_tls1_1"
	d.Set("ssl_support_tls1_1", string(*object.Ssl.SupportTls11))
	lastAssignedField = "ssl_support_tls1_2"
	d.Set("ssl_support_tls1_2", string(*object.Ssl.SupportTls12))
	lastAssignedField = "tcp_nagle"
	d.Set("tcp_nagle", bool(*object.Tcp.Nagle))
	lastAssignedField = "udp_accept_from"
	d.Set("udp_accept_from", string(*object.Udp.AcceptFrom))
	lastAssignedField = "udp_accept_from_mask"
	d.Set("udp_accept_from_mask", string(*object.Udp.AcceptFromMask))
	lastAssignedField = "udp_response_timeout"
	d.Set("udp_response_timeout", int(*object.Udp.ResponseTimeout))
	d.SetId(objectName)
	return nil
}

func resourcePoolExists(d *schema.ResourceData, tm interface{}) (bool, error) {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
	}
	_, err := tm.(*vtm.VirtualTrafficManager).GetPool(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			return false, nil
		}
		return false, fmt.Errorf("%v", err.ErrorText)
	}
	return true, nil
}

func resourcePoolCreate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object := tm.(*vtm.VirtualTrafficManager).NewPool(objectName)
	resourcePoolObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error creating vtm_pool '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourcePoolUpdate(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	object, err := tm.(*vtm.VirtualTrafficManager).GetPool(objectName)
	if err != nil {
		return fmt.Errorf("Failed to update vtm_pool '%v': %v", objectName, err)
	}
	resourcePoolObjectFieldAssignments(d, object)
	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_pool '%s': %s %s", objectName, applyErr.ErrorText, info)
	}
	d.SetId(objectName)
	return nil
}

func resourcePoolObjectFieldAssignments(d *schema.ResourceData, object *vtm.Pool) {
	setString(&object.Basic.BandwidthClass, d, "bandwidth_class")
	setString(&object.Basic.FailurePool, d, "failure_pool")
	setInt(&object.Basic.MaxConnectionAttempts, d, "max_connection_attempts")
	setInt(&object.Basic.MaxIdleConnectionsPernode, d, "max_idle_connections_pernode")
	setInt(&object.Basic.MaxTimedOutConnectionAttempts, d, "max_timed_out_connection_attempts")

	if _, ok := d.GetOk("monitors"); ok {
		setStringSet(&object.Basic.Monitors, d, "monitors")
	} else {
		object.Basic.Monitors = &[]string{}
		d.Set("monitors", []string(*object.Basic.Monitors))
	}
	setBool(&object.Basic.NodeCloseWithRst, d, "node_close_with_rst")
	setInt(&object.Basic.NodeConnectionAttempts, d, "node_connection_attempts")
	setString(&object.Basic.NodeDeleteBehavior, d, "node_delete_behavior")
	setInt(&object.Basic.NodeDrainToDeleteTimeout, d, "node_drain_to_delete_timeout")
	setString(&object.Basic.Note, d, "note")
	setBool(&object.Basic.PassiveMonitoring, d, "passive_monitoring")
	setString(&object.Basic.PersistenceClass, d, "persistence_class")
	setBool(&object.Basic.Transparent, d, "transparent")
	setInt(&object.AutoScaling.AddnodeDelaytime, d, "auto_scaling_addnode_delaytime")
	setString(&object.AutoScaling.CloudCredentials, d, "auto_scaling_cloud_credentials")
	setString(&object.AutoScaling.Cluster, d, "auto_scaling_cluster")
	setString(&object.AutoScaling.DataCenter, d, "auto_scaling_data_center")
	setString(&object.AutoScaling.DataStore, d, "auto_scaling_data_store")
	setBool(&object.AutoScaling.Enabled, d, "auto_scaling_enabled")
	setBool(&object.AutoScaling.External, d, "auto_scaling_external")
	setString(&object.AutoScaling.Extraargs, d, "auto_scaling_extraargs")
	setInt(&object.AutoScaling.Hysteresis, d, "auto_scaling_hysteresis")
	setString(&object.AutoScaling.Imageid, d, "auto_scaling_imageid")
	setString(&object.AutoScaling.IpsToUse, d, "auto_scaling_ips_to_use")
	setInt(&object.AutoScaling.LastNodeIdleTime, d, "auto_scaling_last_node_idle_time")
	setInt(&object.AutoScaling.MaxNodes, d, "auto_scaling_max_nodes")
	setInt(&object.AutoScaling.MinNodes, d, "auto_scaling_min_nodes")
	setString(&object.AutoScaling.Name, d, "auto_scaling_name")
	setInt(&object.AutoScaling.Port, d, "auto_scaling_port")
	setInt(&object.AutoScaling.Refractory, d, "auto_scaling_refractory")
	setInt(&object.AutoScaling.ResponseTime, d, "auto_scaling_response_time")
	setInt(&object.AutoScaling.ScaleDownLevel, d, "auto_scaling_scale_down_level")
	setInt(&object.AutoScaling.ScaleUpLevel, d, "auto_scaling_scale_up_level")

	if _, ok := d.GetOk("auto_scaling_securitygroupids"); ok {
		setStringSet(&object.AutoScaling.Securitygroupids, d, "auto_scaling_securitygroupids")
	} else {
		object.AutoScaling.Securitygroupids = &[]string{}
		d.Set("auto_scaling_securitygroupids", []string(*object.AutoScaling.Securitygroupids))
	}
	setString(&object.AutoScaling.SizeId, d, "auto_scaling_size_id")

	if _, ok := d.GetOk("auto_scaling_subnetids"); ok {
		setStringSet(&object.AutoScaling.Subnetids, d, "auto_scaling_subnetids")
	} else {
		object.AutoScaling.Subnetids = &[]string{}
		d.Set("auto_scaling_subnetids", []string(*object.AutoScaling.Subnetids))
	}

	object.Basic.NodesTable = &vtm.PoolNodesTableTable{}
	if nodesTableJson, ok := d.GetOk("nodes_table_json"); ok {
		_ = json.Unmarshal([]byte(nodesTableJson.(string)), object.Basic.NodesTable)
	} else if nodesTable, ok := d.GetOk("nodes_table"); ok {
		for _, row := range nodesTable.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.PoolNodesTable{}
			VtmObject.Node = getStringAddr(itemTerraform["node"].(string))
			VtmObject.Priority = getIntAddr(itemTerraform["priority"].(int))
			VtmObject.SourceIp = getStringAddr(itemTerraform["source_ip"].(string))
			VtmObject.State = getStringAddr(itemTerraform["state"].(string))
			VtmObject.Weight = getIntAddr(itemTerraform["weight"].(int))
			*object.Basic.NodesTable = append(*object.Basic.NodesTable, VtmObject)
		}
		d.Set("nodes_table", nodesTable)
	} else {
		d.Set("nodes_table", make([]map[string]interface{}, 0, len(*object.Basic.NodesTable)))
	}
	setInt(&object.Connection.MaxConnectTime, d, "connection_max_connect_time")
	setInt(&object.Connection.MaxConnectionsPerNode, d, "connection_max_connections_per_node")
	setInt(&object.Connection.MaxQueueSize, d, "connection_max_queue_size")
	setInt(&object.Connection.MaxReplyTime, d, "connection_max_reply_time")
	setInt(&object.Connection.QueueTimeout, d, "connection_queue_timeout")
	setBool(&object.DnsAutoscale.Enabled, d, "dns_autoscale_enabled")

	if _, ok := d.GetOk("dns_autoscale_hostnames"); ok {
		setStringSet(&object.DnsAutoscale.Hostnames, d, "dns_autoscale_hostnames")
	} else {
		object.DnsAutoscale.Hostnames = &[]string{}
		d.Set("dns_autoscale_hostnames", []string(*object.DnsAutoscale.Hostnames))
	}
	setInt(&object.DnsAutoscale.Port, d, "dns_autoscale_port")
	setBool(&object.Ftp.SupportRfc2428, d, "ftp_support_rfc_2428")
	setBool(&object.Http.Keepalive, d, "http_keepalive")
	setBool(&object.Http.KeepaliveNonIdempotent, d, "http_keepalive_non_idempotent")
	setString(&object.KerberosProtocolTransition.Principal, d, "kerberos_protocol_transition_principal")
	setString(&object.KerberosProtocolTransition.Target, d, "kerberos_protocol_transition_target")
	setString(&object.LoadBalancing.Algorithm, d, "load_balancing_algorithm")
	setBool(&object.LoadBalancing.PriorityEnabled, d, "load_balancing_priority_enabled")
	setInt(&object.LoadBalancing.PriorityNodes, d, "load_balancing_priority_nodes")
	setBool(&object.Node.CloseOnDeath, d, "node_close_on_death")
	setInt(&object.Node.RetryFailTime, d, "node_retry_fail_time")
	setBool(&object.ServiceDiscovery.Enabled, d, "service_discovery_enabled")
	setInt(&object.ServiceDiscovery.Interval, d, "service_discovery_interval")
	setString(&object.ServiceDiscovery.Plugin, d, "service_discovery_plugin")
	setString(&object.ServiceDiscovery.PluginArgs, d, "service_discovery_plugin_args")
	setInt(&object.ServiceDiscovery.Timeout, d, "service_discovery_timeout")
	setBool(&object.Smtp.SendStarttls, d, "smtp_send_starttls")
	setString(&object.Ssl.CipherSuites, d, "ssl_cipher_suites")
	setBool(&object.Ssl.ClientAuth, d, "ssl_client_auth")

	if _, ok := d.GetOk("ssl_common_name_match"); ok {
		setStringSet(&object.Ssl.CommonNameMatch, d, "ssl_common_name_match")
	} else {
		object.Ssl.CommonNameMatch = &[]string{}
		d.Set("ssl_common_name_match", []string(*object.Ssl.CommonNameMatch))
	}

	if _, ok := d.GetOk("ssl_elliptic_curves"); ok {
		setStringList(&object.Ssl.EllipticCurves, d, "ssl_elliptic_curves")
	} else {
		object.Ssl.EllipticCurves = &[]string{}
		d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	}
	setBool(&object.Ssl.Enable, d, "ssl_enable")
	setBool(&object.Ssl.Enhance, d, "ssl_enhance")
	setBool(&object.Ssl.SendCloseAlerts, d, "ssl_send_close_alerts")
	setBool(&object.Ssl.ServerName, d, "ssl_server_name")
	setString(&object.Ssl.SessionCacheEnabled, d, "ssl_session_cache_enabled")
	setString(&object.Ssl.SessionTicketsEnabled, d, "ssl_session_tickets_enabled")
	setString(&object.Ssl.SignatureAlgorithms, d, "ssl_signature_algorithms")
	setBool(&object.Ssl.StrictVerify, d, "ssl_strict_verify")
	setString(&object.Ssl.SupportSsl3, d, "ssl_support_ssl3")
	setString(&object.Ssl.SupportTls1, d, "ssl_support_tls1")
	setString(&object.Ssl.SupportTls11, d, "ssl_support_tls1_1")
	setString(&object.Ssl.SupportTls12, d, "ssl_support_tls1_2")
	setBool(&object.Tcp.Nagle, d, "tcp_nagle")
	setString(&object.Udp.AcceptFrom, d, "udp_accept_from")
	setString(&object.Udp.AcceptFromMask, d, "udp_accept_from_mask")
	setInt(&object.Udp.ResponseTimeout, d, "udp_response_timeout")
}

func resourcePoolDelete(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	err := tm.(*vtm.VirtualTrafficManager).DeletePool(objectName)
	if err != nil {
		return fmt.Errorf("Failed to delete vtm_pool '%v': %v", objectName, err.ErrorText)
	}
	d.SetId("")
	return nil
}
