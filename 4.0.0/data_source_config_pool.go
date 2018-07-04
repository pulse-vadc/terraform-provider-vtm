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

func dataSourcePool() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePoolRead,

		Schema: map[string]*schema.Schema{

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
				Type:     schema.TypeList,
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
				Type:     schema.TypeList,
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
				Type:     schema.TypeList,
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
				Type:     schema.TypeList,
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

			// Whether connections to the back-end nodes should appear to originate
			//  from an IP address raised on the traffic manager, rather than
			//  the IP address from which they were received by the traffic manager.
			"l4accel_snat": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
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

			// If we are encrypting traffic for an SMTP connection, should we
			//  upgrade to SSL using STARTTLS.
			"smtp_send_starttls": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
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
				Type:     schema.TypeList,
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
			//  enables Brocade vTM virtual servers referenced by this pool to
			//  discover the original client's IP address. Only enable this if
			//  you are using nodes for this pool which are Brocade Virtual Traffic
			//  Managers, whose virtual servers have the "ssl_trust_magic" setting
			//  enabled.
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

			// The SSL/TLS ciphers to allow for connections to a back-end node.
			//  Leaving this empty will make the pool use the globally configured
			//  ciphers, see configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!ssl3_ciphers">
			//  "ssl!ssl3_ciphers"</a> in the Global Settings section of the
			//  System tab.  See there for how to specify SSL/TLS ciphers.
			"ssl_ssl_ciphers": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// No longer supported. Formerly controlled whether SSLv2 could
			//  be used for SSL connections to pool nodes.
			"ssl_ssl_support_ssl2": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not SSLv3 is enabled for this pool. Choosing the global
			//  setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_ssl3">
			//  "ssl!support_ssl3"</a> from the Global Settings section of the
			//  System tab will be enforced.
			"ssl_ssl_support_ssl3": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not TLSv1.0 is enabled for this pool. Choosing the
			//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1">
			//  "ssl!support_tls1"</a> from the Global Settings section of the
			//  System tab will be enforced.
			"ssl_ssl_support_tls1": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not TLSv1.1 is enabled for this pool. Choosing the
			//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1.1">
			//  "ssl!support_tls1.1"</a> from the Global Settings section of
			//  the System tab will be enforced.
			"ssl_ssl_support_tls1_1": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
			},

			// Whether or not TLSv1.2 is enabled for this pool. Choosing the
			//  global setting means the value of the configuration key <a href="?fold_open=SSL%20Configuration&section=Global%20Settings#a_ssl!support_tls1.2">
			//  "ssl!support_tls1.2"</a> from the Global Settings section of
			//  the System tab will be enforced.
			"ssl_ssl_support_tls1_2": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled", "use_default"}, false),
				Default:      "use_default",
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
		},
	}
}

func dataSourcePoolRead(d *schema.ResourceData, tm interface{}) error {
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
	d.Set("bandwidth_class", string(*object.Basic.BandwidthClass))
	d.Set("failure_pool", string(*object.Basic.FailurePool))
	d.Set("max_connection_attempts", int(*object.Basic.MaxConnectionAttempts))
	d.Set("max_idle_connections_pernode", int(*object.Basic.MaxIdleConnectionsPernode))
	d.Set("max_timed_out_connection_attempts", int(*object.Basic.MaxTimedOutConnectionAttempts))
	d.Set("monitors", []string(*object.Basic.Monitors))
	d.Set("node_close_with_rst", bool(*object.Basic.NodeCloseWithRst))
	d.Set("node_connection_attempts", int(*object.Basic.NodeConnectionAttempts))
	d.Set("node_delete_behavior", string(*object.Basic.NodeDeleteBehavior))
	d.Set("node_drain_to_delete_timeout", int(*object.Basic.NodeDrainToDeleteTimeout))

	nodesTable := make([]map[string]interface{}, 0, len(*object.Basic.NodesTable))
	for _, item := range *object.Basic.NodesTable {
		itemTerraform := make(map[string]interface{})
		if item.Node != nil {
			itemTerraform["node"] = string(*item.Node)
		}
		if item.Priority != nil {
			itemTerraform["priority"] = int(*item.Priority)
		}
		if item.SourceIp != nil {
			itemTerraform["source_ip"] = string(*item.SourceIp)
		}
		if item.State != nil {
			itemTerraform["state"] = string(*item.State)
		}
		if item.Weight != nil {
			itemTerraform["weight"] = int(*item.Weight)
		}
		nodesTable = append(nodesTable, itemTerraform)
	}
	d.Set("nodes_table", nodesTable)
	nodesTableJson, _ := json.Marshal(nodesTable)
	d.Set("nodes_table_json", nodesTableJson)
	d.Set("note", string(*object.Basic.Note))
	d.Set("passive_monitoring", bool(*object.Basic.PassiveMonitoring))
	d.Set("persistence_class", string(*object.Basic.PersistenceClass))
	d.Set("transparent", bool(*object.Basic.Transparent))
	d.Set("auto_scaling_addnode_delaytime", int(*object.AutoScaling.AddnodeDelaytime))
	d.Set("auto_scaling_cloud_credentials", string(*object.AutoScaling.CloudCredentials))
	d.Set("auto_scaling_cluster", string(*object.AutoScaling.Cluster))
	d.Set("auto_scaling_data_center", string(*object.AutoScaling.DataCenter))
	d.Set("auto_scaling_data_store", string(*object.AutoScaling.DataStore))
	d.Set("auto_scaling_enabled", bool(*object.AutoScaling.Enabled))
	d.Set("auto_scaling_external", bool(*object.AutoScaling.External))
	d.Set("auto_scaling_hysteresis", int(*object.AutoScaling.Hysteresis))
	d.Set("auto_scaling_imageid", string(*object.AutoScaling.Imageid))
	d.Set("auto_scaling_ips_to_use", string(*object.AutoScaling.IpsToUse))
	d.Set("auto_scaling_last_node_idle_time", int(*object.AutoScaling.LastNodeIdleTime))
	d.Set("auto_scaling_max_nodes", int(*object.AutoScaling.MaxNodes))
	d.Set("auto_scaling_min_nodes", int(*object.AutoScaling.MinNodes))
	d.Set("auto_scaling_name", string(*object.AutoScaling.Name))
	d.Set("auto_scaling_port", int(*object.AutoScaling.Port))
	d.Set("auto_scaling_refractory", int(*object.AutoScaling.Refractory))
	d.Set("auto_scaling_response_time", int(*object.AutoScaling.ResponseTime))
	d.Set("auto_scaling_scale_down_level", int(*object.AutoScaling.ScaleDownLevel))
	d.Set("auto_scaling_scale_up_level", int(*object.AutoScaling.ScaleUpLevel))
	d.Set("auto_scaling_securitygroupids", []string(*object.AutoScaling.Securitygroupids))
	d.Set("auto_scaling_size_id", string(*object.AutoScaling.SizeId))
	d.Set("auto_scaling_subnetids", []string(*object.AutoScaling.Subnetids))
	d.Set("connection_max_connect_time", int(*object.Connection.MaxConnectTime))
	d.Set("connection_max_connections_per_node", int(*object.Connection.MaxConnectionsPerNode))
	d.Set("connection_max_queue_size", int(*object.Connection.MaxQueueSize))
	d.Set("connection_max_reply_time", int(*object.Connection.MaxReplyTime))
	d.Set("connection_queue_timeout", int(*object.Connection.QueueTimeout))
	d.Set("dns_autoscale_enabled", bool(*object.DnsAutoscale.Enabled))
	d.Set("dns_autoscale_hostnames", []string(*object.DnsAutoscale.Hostnames))
	d.Set("dns_autoscale_port", int(*object.DnsAutoscale.Port))
	d.Set("ftp_support_rfc_2428", bool(*object.Ftp.SupportRfc2428))
	d.Set("http_keepalive", bool(*object.Http.Keepalive))
	d.Set("http_keepalive_non_idempotent", bool(*object.Http.KeepaliveNonIdempotent))
	d.Set("kerberos_protocol_transition_principal", string(*object.KerberosProtocolTransition.Principal))
	d.Set("kerberos_protocol_transition_target", string(*object.KerberosProtocolTransition.Target))
	d.Set("l4accel_snat", bool(*object.L4Accel.Snat))
	d.Set("load_balancing_algorithm", string(*object.LoadBalancing.Algorithm))
	d.Set("load_balancing_priority_enabled", bool(*object.LoadBalancing.PriorityEnabled))
	d.Set("load_balancing_priority_nodes", int(*object.LoadBalancing.PriorityNodes))
	d.Set("node_close_on_death", bool(*object.Node.CloseOnDeath))
	d.Set("node_retry_fail_time", int(*object.Node.RetryFailTime))
	d.Set("smtp_send_starttls", bool(*object.Smtp.SendStarttls))
	d.Set("ssl_client_auth", bool(*object.Ssl.ClientAuth))
	d.Set("ssl_common_name_match", []string(*object.Ssl.CommonNameMatch))
	d.Set("ssl_elliptic_curves", []string(*object.Ssl.EllipticCurves))
	d.Set("ssl_enable", bool(*object.Ssl.Enable))
	d.Set("ssl_enhance", bool(*object.Ssl.Enhance))
	d.Set("ssl_send_close_alerts", bool(*object.Ssl.SendCloseAlerts))
	d.Set("ssl_server_name", bool(*object.Ssl.ServerName))
	d.Set("ssl_signature_algorithms", string(*object.Ssl.SignatureAlgorithms))
	d.Set("ssl_ssl_ciphers", string(*object.Ssl.SslCiphers))
	d.Set("ssl_ssl_support_ssl2", string(*object.Ssl.SslSupportSsl2))
	d.Set("ssl_ssl_support_ssl3", string(*object.Ssl.SslSupportSsl3))
	d.Set("ssl_ssl_support_tls1", string(*object.Ssl.SslSupportTls1))
	d.Set("ssl_ssl_support_tls1_1", string(*object.Ssl.SslSupportTls11))
	d.Set("ssl_ssl_support_tls1_2", string(*object.Ssl.SslSupportTls12))
	d.Set("ssl_strict_verify", bool(*object.Ssl.StrictVerify))
	d.Set("tcp_nagle", bool(*object.Tcp.Nagle))
	d.Set("udp_accept_from", string(*object.Udp.AcceptFrom))
	d.Set("udp_accept_from_mask", string(*object.Udp.AcceptFromMask))
	d.Set("udp_response_timeout", int(*object.Udp.ResponseTimeout))

	d.SetId(objectName)
	return nil
}
