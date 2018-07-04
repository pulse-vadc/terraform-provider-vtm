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

func dataSourceTrafficManager() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficManagerRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// The Application Firewall master XML IP.
			"adminmasterxmlip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0.0.0.0",
			},

			// The Application Firewall slave XML IP.
			"adminslavexmlip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0.0.0.0",
			},

			// The table of network cards of a hardware appliance
			"appliance_card": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// interfaces
						"interfaces": &schema.Schema{
							Type:     schema.TypeList,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},

						// label
						"label": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
							Default:  "-",
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of appliance_card
			"appliance_card_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// Custom kernel parameters applied by the user with sysctl interface
			"appliance_sysctl": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// description
						"description": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// sysctl
						"sysctl": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// value
						"value": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of appliance_sysctl
			"appliance_sysctl_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// The Application Firewall Authentication Server IP.
			"authenticationserverip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0.0.0.0",
			},

			// Cloud platform where the traffic manager is running.
			"cloud_platform": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// This is the location of the local traffic manager is in.
			"location": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Replace Traffic Manager name with an IP address.
			"nameip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// How many worker threads the Web Accelerator process should create
			//  to optimise content. By default, one thread will be created for
			//  each CPU on the system.
			"num_aptimizer_threads": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// The number of worker processes the software will run.  By default,
			//  one child process will be created for each CPU on the system.
			//   You may wish to reduce this to effectively "reserve" CPU(s)
			//  for other processes running on the host system.
			"num_children": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// The number of Application Firewall decider process to run.
			"numberofcpus": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 64),
				Default:      0,
			},

			// The Application Firewall REST Internal API port, this port should
			//  not be accessed directly
			"restserverport": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      0,
			},

			// A table mapping interfaces to networks, used by the traffic manager
			//  to select which interface to raise a Traffic IP on.
			"trafficip": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// networks
						"networks": &schema.Schema{
							Type:     schema.TypeList,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},

			// JSON representation of trafficip
			"trafficip_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// The Application Firewall Updater IP.
			"updaterip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0.0.0.0",
			},

			// Whether this machine should be recognised as a Bare-Metal Appliance.
			"appliance_force_hardware": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The default gateway.
			"appliance_gateway_ipv4": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The default IPv6 gateway.
			"appliance_gateway_ipv6": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Name (hostname.domainname) of the appliance.
			"appliance_hostname": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A table of hostname to static ip address mappings, to be placed
			//  in the /etc/hosts file.
			"appliance_hosts": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// ip_address
						"ip_address": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// A table of network interface specific settings.
			"appliance_if": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// autoneg
						"autoneg": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},

						// bmode
						"bmode": &schema.Schema{
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice([]string{"802_3ad", "balance_alb"}, false),
							Default:      "802_3ad",
						},

						// bond
						"bond": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},

						// duplex
						"duplex": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  true,
						},

						// mode
						"mode": &schema.Schema{
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice([]string{"dhcp", "static"}, false),
							Default:      "static",
						},

						// mtu
						"mtu": &schema.Schema{
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(68, 9216),
							Default:      1500,
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// speed
						"speed": &schema.Schema{
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice([]string{"10", "100", "1000"}, false),
							Default:      "1000",
						},
					},
				},
			},

			// A table of network interfaces and their network settings.
			"appliance_ip": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// addr
						"addr": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// isexternal
						"isexternal": &schema.Schema{
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},

						// mask
						"mask": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// Whether IPMI LAN access should be enabled or not.
			"appliance_ipmi_lan_access": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The IP address of the appliance IPMI LAN channel.
			"appliance_ipmi_lan_addr": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The default gateway of the IPMI LAN channel.
			"appliance_ipmi_lan_gateway": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The addressing mode the IPMI LAN channel operates.
			"appliance_ipmi_lan_ipsrc": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"dhcp", "static"}, false),
				Default:      "static",
			},

			// Set the IP netmask for the IPMI LAN channel.
			"appliance_ipmi_lan_mask": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not IPv4 forwarding is enabled.
			"appliance_ipv4_forwarding": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not IPv6 forwarding is enabled.
			"appliance_ipv6_forwarding": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the license agreement has been accepted.  This
			//  determines whether or not the Initial Configuration wizard is
			//  displayed.
			"appliance_licence_agreed": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Whether or not the software manages the Azure policy routing.
			"appliance_manageazureroutes": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the software manages system configuration based
			//  on Data Plane Acceleration mode
			"appliance_managedpa": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the software manages the EC2 config.
			"appliance_manageec2conf": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the software manages the IP transparency
			"appliance_manageiptrans": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the software manages return path routing. If disabled,
			//  the appliance won't modify iptables / rules / routes for this
			//  feature.
			"appliance_managereturnpath": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the software manages the EC2-VPC secondary IPs.
			"appliance_managevpcconf": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The IP addresses of the nameservers the appliance should use
			//  and place in "/etc/resolv.conf".
			"appliance_name_servers": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The NTP servers the appliance should use to synchronize its clock.
			"appliance_ntpservers": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// A table of destination IP addresses and routing details to reach
			//  them.
			"appliance_routes": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// gw
						"gw": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// if
						"if": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// mask
						"mask": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// name
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// The search domains the appliance should use and place in "/etc/resolv.conf".
			"appliance_search_domains": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The client ID provided by the portal for this server.
			"appliance_shim_client_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The client key provided by the portal for this server.
			"appliance_shim_client_key": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Enable the Riverbed Cloud SteelHead discovery agent on this appliance.
			"appliance_shim_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The IP addresses of the Riverbed Cloud SteelHeads to use, as
			//  a space or comma separated list. If using priority load balancing
			//  this should be in ascending order of priority (highest priority
			//  last).
			"appliance_shim_ips": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The load balancing method for selecting a Riverbed Cloud SteelHead
			//  appliance.
			"appliance_shim_load_balance": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"priority", "round_robin"}, false),
				Default:      "round_robin",
			},

			// The minimum severity that the discovery agent will record to
			//  its log.
			"appliance_shim_log_level": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"critical", "debug", "info", "notice", "serious", "warning"}, false),
				Default:      "notice",
			},

			// The mode used to discover Riverbed Cloud SteelHeads in the local
			//  cloud or data center.
			"appliance_shim_mode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"local", "manual", "portal"}, false),
				Default:      "portal",
			},

			// The hostname or IP address of the local portal to use.
			"appliance_shim_portal_url": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The IP or hostname of the proxy server to use to connect to the
			//  portal. Leave blank to not use a proxy server.
			"appliance_shim_proxy_host": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The port of the proxy server, must be set if a proxy server has
			//  been configured.
			"appliance_shim_proxy_port": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// Whether or not the SSH server is enabled on the appliance.
			"appliance_ssh_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the SSH server allows password based login.
			"appliance_ssh_password_allowed": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The port that the SSH server should listen on.
			"appliance_ssh_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      22,
			},

			// The timezone the appliance should use.  This must be a path to
			//  a timezone file that exists under "/usr/share/zoneinfo/".
			"appliance_timezone": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "US/Pacific",
			},

			// The VLANs the software should raise.  A VLAN should be configured
			//  using the format "<dev>.<vlanid>", where "<dev>" is the name
			//  of a network device that exists in the host system, "eth0.100"
			//  for example.
			"appliance_vlans": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// Whether or not this instance of the software can send configuration
			//  updates to other members of the cluster.  When not clustered
			//  this key is ignored. When clustered the value can only be changed
			//  by another machine in the cluster that has "allow_update" set
			//  to "true".  If set to "false" then it will not be possible to
			//  log into the admin server for this instance.
			"cluster_comms_allow_update": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The IP address that the software should bind to for internal
			//  administration communications.  See also "port".  If the software
			//  is not part of a cluster the default is to use "127.0.0.1" and
			//  there should be no reason to touch this setting.  If the software
			//  is part of a cluster then the default is to listen on all raised
			//  IPs, in this case an alternative configuration is to listen on
			//  a single IP address.  This may be useful if you have a separate
			//  management network and wish to restrict control messages to it.
			//   It is important to ensure that the "allowed_update_hosts" (in
			//  the "Global Settings" resource) is compatible with the IP configured
			//  here.
			"cluster_comms_bind_ip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "*",
			},

			// This is the optional external ip of the traffic manager, which
			//  is used to circumvent natting when traffic managers in a cluster
			//  span different networks.
			"cluster_comms_external_ip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The port that the software should listen on for internal administration
			//  communications.  See also "bind_ip".
			"cluster_comms_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      9080,
			},

			// List of MAC addresses of interfaces which the traffic manager
			//  can use to associate the EC2 elastic IPs (Traffic IPs) to the
			//  instance.
			"ec2_trafficips_public_enis": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The BGP router id  If set to empty, then the IPv4 address used
			//  to communicate with the default IPv4 gateway is used instead.
			//   Specifying 0.0.0.0 will stop the traffic manager routing software
			//  from running the BGP protocol.
			"fault_tolerance_bgp_router_id": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// IP addresses associated with the links dedicated by the user
			//  for receiving L4 state sync messages from other peers in a cluster.
			"fault_tolerance_lss_dedicated_ips": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The traffic manager's permanent IPv4 address which the routing
			//  software will use for peering and transit traffic, and as its
			//  OSPF router ID.  If set to empty, then the address used to communicate
			//  with the default IPv4 gateway is used instead.  Specifying 0.0.0.0
			//  will stop the traffic manager routing software from running the
			//  OSPF protocol.
			"fault_tolerance_ospfv2_ip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The IP addresses of routers which are expected to be found as
			//  OSPFv2 neighbors of the traffic manager. A warning will be reported
			//  if some of the expected routers are not peered, and an error
			//  will be reported if none of the expected routers are peered.
			//  An empty list disables monitoring. The special value %gateway%
			//  is a placeholder for the default gateway.
			"fault_tolerance_ospfv2_neighbor_addrs": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// Whether the Traffic Manager should configure the iptables built-in
			//  chains to call Traffic Manager defined rules (e.g. the IP transparency
			//  chain). This should only be disabled in case of conflict with
			//  other software that manages iptables, e.g. firewalls. When disabled,
			//  you will need to add rules manually to use these features - see
			//  the user manual for details.
			"iptables_config_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The netfilter forwarding mark to use for IP transparency rules
			"iptrans_fwmark": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Default:      320,
			},

			// Whether IP transparency may be used via netfilter/iptables. This
			//  requires Linux 2.6.24 and the iptables socket extension. For
			//  older Linux versions, the "ztrans" kernel module may be used
			//  instead.
			"iptrans_iptables_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// The special routing table ID to use for IP transparency rules
			"iptrans_routing_table": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(256, 2147483647),
				Default:      320,
			},

			// The port the Java Extension handler process should listen on.
			//   This port will be bound for localhost communications only.
			"java_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1024, 65535),
				Default:      9060,
			},

			// The e-mail address sent as part of a remote licensing request.
			"remote_licensing_email_address": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A free-text field sent as part of a remote licensing request.
			"remote_licensing_message": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A list of IP Addresses which the REST API will listen on for
			//  connections. The list should contain IP addresses (IPv4 or IPv6)
			//  or a single entry containing an asterisk (*). This indicates
			//  that the REST API should listen on all IP Addresses.
			"rest_api_bind_ips": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// The port on which the REST API should listen for requests.
			"rest_api_port": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      9070,
			},

			// Restrict which IP addresses can access the SNMP command responder
			//  service.  The value can be "all", "localhost", or a list of IP
			//  CIDR subnet masks.  For example "10.100.0.0/16" would allow connections
			//  from any IP address beginning with "10.100".
			"snmp_allow": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},

			// The authentication password. Required (minimum length 8 characters)
			//  if "security_level" includes authentication.
			"snmp_auth_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The IP address the SNMP service should bind its listen port to.
			//   The value "*" (asterisk) means SNMP will listen on all IP addresses.
			"snmp_bind_ip": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "*",
			},

			// The community string required for SNMPv1 and SNMPv2c commands.
			//   (If empty, all SNMPv1 and SNMPv2c commands will be rejected).
			"snmp_community": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "public",
			},

			// Whether or not the SNMP command responder service should be enabled
			//  on this traffic manager.
			"snmp_enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The hash algorithm for authenticated SNMPv3 communications.
			"snmp_hash_algorithm": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"md5", "sha1"}, false),
				Default:      "md5",
			},

			// The port the SNMP command responder service should listen on.
			//  The value "default" denotes port 161 if the software is running
			//  with root privileges, and 1161 otherwise.
			"snmp_port": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
			},

			// The privacy password. Required (minimum length 8 characters)
			//  if "security_level" includes privacy (message encryption).
			"snmp_priv_password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The security level for SNMPv3 communications.
			"snmp_security_level": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"authnopriv", "authpriv", "noauthnopriv"}, false),
				Default:      "noauthnopriv",
			},

			// The username required for SNMPv3 commands.  (If empty, all SNMPv3
			//  commands will be rejected).
			"snmp_username": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceTrafficManagerRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetTrafficManager(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_traffic_manager '%v': %v", objectName, err.ErrorText)
	}
	d.Set("adminmasterxmlip", string(*object.Basic.Adminmasterxmlip))
	d.Set("adminslavexmlip", string(*object.Basic.Adminslavexmlip))

	applianceCard := make([]map[string]interface{}, 0, len(*object.Basic.ApplianceCard))
	for _, item := range *object.Basic.ApplianceCard {
		itemTerraform := make(map[string]interface{})
		if item.Interfaces != nil {
			itemTerraform["interfaces"] = []string(*item.Interfaces)
		}
		if item.Label != nil {
			itemTerraform["label"] = string(*item.Label)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		applianceCard = append(applianceCard, itemTerraform)
	}
	d.Set("appliance_card", applianceCard)
	applianceCardJson, _ := json.Marshal(applianceCard)
	d.Set("appliance_card_json", applianceCardJson)

	applianceSysctl := make([]map[string]interface{}, 0, len(*object.Basic.ApplianceSysctl))
	for _, item := range *object.Basic.ApplianceSysctl {
		itemTerraform := make(map[string]interface{})
		if item.Description != nil {
			itemTerraform["description"] = string(*item.Description)
		}
		if item.Sysctl != nil {
			itemTerraform["sysctl"] = string(*item.Sysctl)
		}
		if item.Value != nil {
			itemTerraform["value"] = string(*item.Value)
		}
		applianceSysctl = append(applianceSysctl, itemTerraform)
	}
	d.Set("appliance_sysctl", applianceSysctl)
	applianceSysctlJson, _ := json.Marshal(applianceSysctl)
	d.Set("appliance_sysctl_json", applianceSysctlJson)
	d.Set("authenticationserverip", string(*object.Basic.Authenticationserverip))
	d.Set("cloud_platform", string(*object.Basic.CloudPlatform))
	d.Set("location", string(*object.Basic.Location))
	d.Set("nameip", string(*object.Basic.Nameip))
	d.Set("num_aptimizer_threads", int(*object.Basic.NumAptimizerThreads))
	d.Set("num_children", int(*object.Basic.NumChildren))
	d.Set("numberofcpus", int(*object.Basic.Numberofcpus))
	d.Set("restserverport", int(*object.Basic.Restserverport))

	trafficip := make([]map[string]interface{}, 0, len(*object.Basic.Trafficip))
	for _, item := range *object.Basic.Trafficip {
		itemTerraform := make(map[string]interface{})
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Networks != nil {
			itemTerraform["networks"] = []string(*item.Networks)
		}
		trafficip = append(trafficip, itemTerraform)
	}
	d.Set("trafficip", trafficip)
	trafficipJson, _ := json.Marshal(trafficip)
	d.Set("trafficip_json", trafficipJson)
	d.Set("updaterip", string(*object.Basic.Updaterip))
	d.Set("appliance_force_hardware", bool(*object.Appliance.ForceHardware))
	d.Set("appliance_gateway_ipv4", string(*object.Appliance.GatewayIpv4))
	d.Set("appliance_gateway_ipv6", string(*object.Appliance.GatewayIpv6))
	d.Set("appliance_hostname", string(*object.Appliance.Hostname))

	applianceHosts := make([]map[string]interface{}, 0, len(*object.Appliance.Hosts))
	for _, item := range *object.Appliance.Hosts {
		itemTerraform := make(map[string]interface{})
		if item.IpAddress != nil {
			itemTerraform["ip_address"] = string(*item.IpAddress)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		applianceHosts = append(applianceHosts, itemTerraform)
	}
	d.Set("appliance_hosts", applianceHosts)
	applianceHostsJson, _ := json.Marshal(applianceHosts)
	d.Set("appliance_hosts_json", applianceHostsJson)

	applianceIf := make([]map[string]interface{}, 0, len(*object.Appliance.If))
	for _, item := range *object.Appliance.If {
		itemTerraform := make(map[string]interface{})
		if item.Autoneg != nil {
			itemTerraform["autoneg"] = bool(*item.Autoneg)
		}
		if item.Bmode != nil {
			itemTerraform["bmode"] = string(*item.Bmode)
		}
		if item.Bond != nil {
			itemTerraform["bond"] = string(*item.Bond)
		}
		if item.Duplex != nil {
			itemTerraform["duplex"] = bool(*item.Duplex)
		}
		if item.Mode != nil {
			itemTerraform["mode"] = string(*item.Mode)
		}
		if item.Mtu != nil {
			itemTerraform["mtu"] = int(*item.Mtu)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		if item.Speed != nil {
			itemTerraform["speed"] = string(*item.Speed)
		}
		applianceIf = append(applianceIf, itemTerraform)
	}
	d.Set("appliance_if", applianceIf)
	applianceIfJson, _ := json.Marshal(applianceIf)
	d.Set("appliance_if_json", applianceIfJson)

	applianceIp := make([]map[string]interface{}, 0, len(*object.Appliance.Ip))
	for _, item := range *object.Appliance.Ip {
		itemTerraform := make(map[string]interface{})
		if item.Addr != nil {
			itemTerraform["addr"] = string(*item.Addr)
		}
		if item.Isexternal != nil {
			itemTerraform["isexternal"] = bool(*item.Isexternal)
		}
		if item.Mask != nil {
			itemTerraform["mask"] = string(*item.Mask)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		applianceIp = append(applianceIp, itemTerraform)
	}
	d.Set("appliance_ip", applianceIp)
	applianceIpJson, _ := json.Marshal(applianceIp)
	d.Set("appliance_ip_json", applianceIpJson)
	d.Set("appliance_ipmi_lan_access", bool(*object.Appliance.IpmiLanAccess))
	d.Set("appliance_ipmi_lan_addr", string(*object.Appliance.IpmiLanAddr))
	d.Set("appliance_ipmi_lan_gateway", string(*object.Appliance.IpmiLanGateway))
	d.Set("appliance_ipmi_lan_ipsrc", string(*object.Appliance.IpmiLanIpsrc))
	d.Set("appliance_ipmi_lan_mask", string(*object.Appliance.IpmiLanMask))
	d.Set("appliance_ipv4_forwarding", bool(*object.Appliance.Ipv4Forwarding))
	d.Set("appliance_ipv6_forwarding", bool(*object.Appliance.Ipv6Forwarding))
	d.Set("appliance_licence_agreed", bool(*object.Appliance.LicenceAgreed))
	d.Set("appliance_manageazureroutes", bool(*object.Appliance.Manageazureroutes))
	d.Set("appliance_managedpa", bool(*object.Appliance.Managedpa))
	d.Set("appliance_manageec2conf", bool(*object.Appliance.Manageec2Conf))
	d.Set("appliance_manageiptrans", bool(*object.Appliance.Manageiptrans))
	d.Set("appliance_managereturnpath", bool(*object.Appliance.Managereturnpath))
	d.Set("appliance_managevpcconf", bool(*object.Appliance.Managevpcconf))
	d.Set("appliance_name_servers", []string(*object.Appliance.NameServers))
	d.Set("appliance_ntpservers", []string(*object.Appliance.Ntpservers))

	applianceRoutes := make([]map[string]interface{}, 0, len(*object.Appliance.Routes))
	for _, item := range *object.Appliance.Routes {
		itemTerraform := make(map[string]interface{})
		if item.Gw != nil {
			itemTerraform["gw"] = string(*item.Gw)
		}
		if item.If != nil {
			itemTerraform["if"] = string(*item.If)
		}
		if item.Mask != nil {
			itemTerraform["mask"] = string(*item.Mask)
		}
		if item.Name != nil {
			itemTerraform["name"] = string(*item.Name)
		}
		applianceRoutes = append(applianceRoutes, itemTerraform)
	}
	d.Set("appliance_routes", applianceRoutes)
	applianceRoutesJson, _ := json.Marshal(applianceRoutes)
	d.Set("appliance_routes_json", applianceRoutesJson)
	d.Set("appliance_search_domains", []string(*object.Appliance.SearchDomains))
	d.Set("appliance_shim_client_id", string(*object.Appliance.ShimClientId))
	d.Set("appliance_shim_client_key", string(*object.Appliance.ShimClientKey))
	d.Set("appliance_shim_enabled", bool(*object.Appliance.ShimEnabled))
	d.Set("appliance_shim_ips", string(*object.Appliance.ShimIps))
	d.Set("appliance_shim_load_balance", string(*object.Appliance.ShimLoadBalance))
	d.Set("appliance_shim_log_level", string(*object.Appliance.ShimLogLevel))
	d.Set("appliance_shim_mode", string(*object.Appliance.ShimMode))
	d.Set("appliance_shim_portal_url", string(*object.Appliance.ShimPortalUrl))
	d.Set("appliance_shim_proxy_host", string(*object.Appliance.ShimProxyHost))
	d.Set("appliance_shim_proxy_port", string(*object.Appliance.ShimProxyPort))
	d.Set("appliance_ssh_enabled", bool(*object.Appliance.SshEnabled))
	d.Set("appliance_ssh_password_allowed", bool(*object.Appliance.SshPasswordAllowed))
	d.Set("appliance_ssh_port", int(*object.Appliance.SshPort))
	d.Set("appliance_timezone", string(*object.Appliance.Timezone))
	d.Set("appliance_vlans", []string(*object.Appliance.Vlans))
	d.Set("cluster_comms_allow_update", bool(*object.ClusterComms.AllowUpdate))
	d.Set("cluster_comms_bind_ip", string(*object.ClusterComms.BindIp))
	d.Set("cluster_comms_external_ip", string(*object.ClusterComms.ExternalIp))
	d.Set("cluster_comms_port", int(*object.ClusterComms.Port))
	d.Set("ec2_trafficips_public_enis", []string(*object.Ec2.TrafficipsPublicEnis))
	d.Set("fault_tolerance_bgp_router_id", string(*object.FaultTolerance.BgpRouterId))
	d.Set("fault_tolerance_lss_dedicated_ips", []string(*object.FaultTolerance.LssDedicatedIps))
	d.Set("fault_tolerance_ospfv2_ip", string(*object.FaultTolerance.Ospfv2Ip))
	d.Set("fault_tolerance_ospfv2_neighbor_addrs", []string(*object.FaultTolerance.Ospfv2NeighborAddrs))
	d.Set("iptables_config_enabled", bool(*object.Iptables.ConfigEnabled))
	d.Set("iptrans_fwmark", int(*object.Iptrans.Fwmark))
	d.Set("iptrans_iptables_enabled", bool(*object.Iptrans.IptablesEnabled))
	d.Set("iptrans_routing_table", int(*object.Iptrans.RoutingTable))
	d.Set("java_port", int(*object.Java.Port))
	d.Set("remote_licensing_email_address", string(*object.RemoteLicensing.EmailAddress))
	d.Set("remote_licensing_message", string(*object.RemoteLicensing.Message))
	d.Set("rest_api_bind_ips", []string(*object.RestApi.BindIps))
	d.Set("rest_api_port", int(*object.RestApi.Port))
	d.Set("snmp_allow", []string(*object.Snmp.Allow))
	d.Set("snmp_auth_password", string(*object.Snmp.AuthPassword))
	d.Set("snmp_bind_ip", string(*object.Snmp.BindIp))
	d.Set("snmp_community", string(*object.Snmp.Community))
	d.Set("snmp_enabled", bool(*object.Snmp.Enabled))
	d.Set("snmp_hash_algorithm", string(*object.Snmp.HashAlgorithm))
	d.Set("snmp_port", string(*object.Snmp.Port))
	d.Set("snmp_priv_password", string(*object.Snmp.PrivPassword))
	d.Set("snmp_security_level", string(*object.Snmp.SecurityLevel))
	d.Set("snmp_username", string(*object.Snmp.Username))

	d.SetId(objectName)
	return nil
}
