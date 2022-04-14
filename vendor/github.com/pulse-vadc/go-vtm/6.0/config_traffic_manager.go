// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.0.
package vtm

import (
	"encoding/json"
)

type TrafficManager struct {
	connector                *vtmConnector
	TrafficManagerProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetTrafficManager(name string) (*TrafficManager, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetTrafficManager(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/traffic_managers/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(TrafficManager)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object TrafficManager) Apply() (*TrafficManager, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewTrafficManager(name string) *TrafficManager {
	object := new(TrafficManager)

	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/traffic_managers/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteTrafficManager(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/traffic_managers/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListTrafficManagers() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.0/config/active/traffic_managers")
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

type TrafficManagerProperties struct {
	Appliance struct {
		// Whether to disable the cloud-init service
		DisableCloudInit *bool `json:"disable_cloud_init,omitempty"`

		// Whether the traffic manager appliance should run without kernel
		//  page table isolation (KPTI). KPTI provides protection to prevent
		//  unprivileged software from being potentially able to read arbitrary
		//  memory from the kernel (i.e. the Meltdown attack, CVE-2017-5754);
		//  however this protection incurs a general system performance penalty.
		//  If you are running trusted software on the appliance, and the
		//  trade-off between performance at the cost of 'defense in depth'
		//  favors the former in your deployment, you may wish to enable
		//  this configuration key. If you are unsure, it is recommended
		//  that you leave this key disabled, which is also the default.
		DisableKpti *bool `json:"disable_kpti,omitempty"`

		// The DNS cache setting the appliance should use and place in "/etc/systemd/resolved.conf".
		Dnscache *bool `json:"dnscache,omitempty"`

		// The DNSSEC setting the appliance should use and place in "/etc/systemd/resolved.conf".
		Dnssec *string `json:"dnssec,omitempty"`

		// The default gateway.
		GatewayIpv4 *string `json:"gateway_ipv4,omitempty"`

		// The default IPv6 gateway.
		GatewayIpv6 *string `json:"gateway_ipv6,omitempty"`

		// Name (hostname.domainname) of the appliance.
		Hostname *string `json:"hostname,omitempty"`

		// A table of hostname to static ip address mappings, to be placed
		//  in the /etc/hosts file.
		Hosts *TrafficManagerHostsTable `json:"hosts,omitempty"`

		// A table of network interface specific settings.
		If *TrafficManagerIfTable `json:"if,omitempty"`

		// A table of network interfaces and their network settings.
		Ip *TrafficManagerIpTable `json:"ip,omitempty"`

		// Whether IPMI LAN access should be enabled or not.
		IpmiLanAccess *bool `json:"ipmi_lan_access,omitempty"`

		// The IP address of the appliance IPMI LAN channel.
		IpmiLanAddr *string `json:"ipmi_lan_addr,omitempty"`

		// The default gateway of the IPMI LAN channel.
		IpmiLanGateway *string `json:"ipmi_lan_gateway,omitempty"`

		// The addressing mode the IPMI LAN channel operates.
		IpmiLanIpsrc *string `json:"ipmi_lan_ipsrc,omitempty"`

		// Set the IP netmask for the IPMI LAN channel.
		IpmiLanMask *string `json:"ipmi_lan_mask,omitempty"`

		// Whether or not IPv4 forwarding is enabled.
		Ipv4Forwarding *bool `json:"ipv4_forwarding,omitempty"`

		// Whether or not IPv6 forwarding is enabled.
		Ipv6Forwarding *bool `json:"ipv6_forwarding,omitempty"`

		// Whether or not the license agreement has been accepted.  This
		//  determines whether or not the Initial Configuration wizard is
		//  displayed.
		LicenceAgreed *bool `json:"licence_agreed,omitempty"`

		// Whether or not the software manages the Azure policy routing.
		Manageazureroutes *bool `json:"manageazureroutes,omitempty"`

		// Whether or not the software manages the EC2 config.
		Manageec2Conf *bool `json:"manageec2conf,omitempty"`

		// Whether or not the software manages the IP transparency
		Manageiptrans *bool `json:"manageiptrans,omitempty"`

		// Whether or not the software manages the system configuration
		//  for reserved ports
		Managereservedports *bool `json:"managereservedports,omitempty"`

		// Whether or not the software manages return path routing. If disabled,
		//  the appliance won't modify iptables / rules / routes for this
		//  feature.
		Managereturnpath *bool `json:"managereturnpath,omitempty"`

		// Whether or not the software manages the system services
		Manageservices *bool `json:"manageservices,omitempty"`

		// Whether or not the software manages user specified sysctl keys.
		Managesysctl *bool `json:"managesysctl,omitempty"`

		// Whether or not the software manages the EC2-VPC secondary IPs.
		Managevpcconf *bool `json:"managevpcconf,omitempty"`

		// The IP addresses of the nameservers the appliance should use
		//  and place in "/etc/systemd/resolved.conf".
		NameServers *[]string `json:"name_servers,omitempty"`

		// The NTP servers the appliance should use to synchronize its clock.
		Ntpservers *[]string `json:"ntpservers,omitempty"`

		// A table of destination IP addresses and routing details to reach
		//  them.
		Routes *TrafficManagerRoutesTable `json:"routes,omitempty"`

		// The search domains the appliance should use and place in "/etc/systemd/resolved.conf".
		SearchDomains *[]string `json:"search_domains,omitempty"`

		// Whether or not the SSH server is enabled on the appliance.
		SshEnabled *bool `json:"ssh_enabled,omitempty"`

		// Whether or not the SSH server allows password based login.
		SshPasswordAllowed *bool `json:"ssh_password_allowed,omitempty"`

		// The port that the SSH server should listen on.
		SshPort *int `json:"ssh_port,omitempty"`

		// The timezone the appliance should use.  This must be a path to
		//  a timezone file that exists under "/usr/share/zoneinfo/".
		Timezone *string `json:"timezone,omitempty"`

		// The VLANs the software should raise.  A VLAN should be configured
		//  using the format "<dev>.<vlanid>", where "<dev>" is the name
		//  of a network device that exists in the host system, "eth0.100"
		//  for example.
		Vlans *[]string `json:"vlans,omitempty"`
	} `json:"appliance"`

	Autodiscover struct {
		// This key overrides the product ID used by traffic manager instances
		//  to discover each other when clustering. Traffic managers will
		//  only discover each other if their product IDs are the same and
		//  their versions are compatible.
		ProductId *string `json:"product_id,omitempty"`
	} `json:"autodiscover"`

	Basic struct {
		// The Application Firewall master XML IP.
		Adminmasterxmlip *string `json:"adminMasterXMLIP,omitempty"`

		// The Application Firewall slave XML IP.
		Adminslavexmlip *string `json:"adminSlaveXMLIP,omitempty"`

		// The table of network cards of a hardware appliance
		ApplianceCard *TrafficManagerApplianceCardTable `json:"appliance_card,omitempty"`

		// Custom kernel parameters applied by the user with sysctl interface
		ApplianceSysctl *TrafficManagerApplianceSysctlTable `json:"appliance_sysctl,omitempty"`

		// The Application Firewall Authentication Server IP.
		Authenticationserverip *string `json:"authenticationServerIP,omitempty"`

		// Cloud platform where the traffic manager is running.
		CloudPlatform *string `json:"cloud_platform,omitempty"`

		// Whether user has accepted the Developer mode and will not be
		//  prompted for uploading license key
		DeveloperModeAccepted *bool `json:"developer_mode_accepted,omitempty"`

		// The percentage level of disk usage that triggers a SERIOUS event
		//  log entry
		DiskSerious *int `json:"disk_serious,omitempty"`

		// The percentage level of disk usage that triggers a WARN event
		//  log entry
		DiskWarn *int `json:"disk_warn,omitempty"`

		// The policy for loading and unloading kernel modules
		KmodPolicy *string `json:"kmod_policy,omitempty"`

		// This is the location of the local traffic manager is in.
		Location *string `json:"location,omitempty"`

		// Replace Traffic Manager name with an IP address.
		Nameip *string `json:"nameip,omitempty"`

		// How many worker threads the Web Accelerator process should create
		//  to optimise content. By default, one thread will be created for
		//  each CPU on the system.
		NumAptimizerThreads *int `json:"num_aptimizer_threads,omitempty"`

		// The number of worker processes the software will run.  By default,
		//  one child process will be created for each CPU on the system.
		//   You may wish to reduce this to effectively "reserve" CPU(s)
		//  for other processes running on the host system.
		NumChildren *int `json:"num_children,omitempty"`

		// The number of Application Firewall decider process to run.
		Numberofcpus *int `json:"numberOfCPUs,omitempty"`

		// The Application Firewall REST Internal API port, this port should
		//  not be accessed directly
		Restserverport *int `json:"restServerPort,omitempty"`

		// Whether or not to start the sysd process on software installations.
		//  Appliance and EC2 will always run sysd regardless of this config
		//  key.
		StartSysd *bool `json:"start_sysd,omitempty"`

		// A table mapping interfaces to networks, used by the traffic manager
		//  to select which interface to raise a Traffic IP on.
		Trafficip *TrafficManagerTrafficipTable `json:"trafficip,omitempty"`

		// The Application Firewall Updater IP.
		Updaterip *string `json:"updaterIP,omitempty"`

		// Which polling method to use.  The default for your platform is
		//  almost always the optimal choice.
		UseMx *string `json:"use_mx,omitempty"`
	} `json:"basic"`

	ClusterComms struct {
		// Whether or not this instance of the software can send configuration
		//  updates to other members of the cluster.  When not clustered
		//  this key is ignored. When clustered the value can only be changed
		//  by another machine in the cluster that has "allow_update" set
		//  to "true".  If set to "false" then it will not be possible to
		//  log into the admin server for this instance.
		AllowUpdate *bool `json:"allow_update,omitempty"`

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
		BindIp *string `json:"bind_ip,omitempty"`

		// This is the optional external ip of the traffic manager, which
		//  is used to circumvent natting when traffic managers in a cluster
		//  span different networks.
		ExternalIp *string `json:"external_ip,omitempty"`

		// The port that the software should listen on for internal administration
		//  communications.  See also "bind_ip".
		Port *int `json:"port,omitempty"`
	} `json:"cluster_comms"`

	Ec2 struct {
		// The availability zone of this EC2 instance, should be set when
		//  the appliance is first booted. Not required for non-EC2 systems.
		AvailabilityZone *string `json:"availability_zone,omitempty"`

		// The EC2 instance ID of this EC2 virtual appliance, should be
		//  set when the appliance is first booted. Not required for non-EC2
		//  systems.
		Instanceid *string `json:"instanceid,omitempty"`

		// List of MAC addresses of interfaces which the traffic manager
		//  can use to associate the EC2 elastic IPs (Traffic IPs) to the
		//  instance.
		TrafficipsPublicEnis *[]string `json:"trafficips_public_enis,omitempty"`

		// The ID of the VPC the instance is in, should be set when the
		//  appliance is first booted. Not required for non-VPC EC2 or non-EC2
		//  systems.
		Vpcid *string `json:"vpcid,omitempty"`
	} `json:"ec2"`

	FaultTolerance struct {
		// The BGP router id  If set to empty, then the IPv4 address used
		//  to communicate with the default IPv4 gateway is used instead.
		//   Specifying 0.0.0.0 will stop the traffic manager routing software
		//  from running the BGP protocol.
		BgpRouterId *string `json:"bgp_router_id,omitempty"`

		// The traffic manager's permanent IPv4 address which the routing
		//  software will use for peering and transit traffic, and as its
		//  OSPF router ID.  If set to empty, then the address used to communicate
		//  with the default IPv4 gateway is used instead.  Specifying 0.0.0.0
		//  will stop the traffic manager routing software from running the
		//  OSPF protocol.
		Ospfv2Ip *string `json:"ospfv2_ip,omitempty"`

		// The IP addresses of routers which are expected to be found as
		//  OSPFv2 neighbors of the traffic manager. A warning will be reported
		//  if some of the expected routers are not peered, and an error
		//  will be reported if none of the expected routers are peered.
		//  An empty list disables monitoring. The special value %gateway%
		//  is a placeholder for the default gateway.
		Ospfv2NeighborAddrs *[]string `json:"ospfv2_neighbor_addrs,omitempty"`

		// This key does nothing.
		RhiSupport *bool `json:"rhi_support,omitempty"`

		// The routing software log level. Values are: 0 - emergency 1 -
		//  alert 2 - critical 3 - error 4 - warning 5 - notification 6 -
		//  informational 7 - debug Messages with priority less or equal
		//  to the set level will be logged.
		RoutingSwLogLevel *int `json:"routing_sw_log_level,omitempty"`
	} `json:"fault_tolerance"`

	Iptables struct {
		// Whether the Traffic Manager should configure the iptables built-in
		//  chains to call Traffic Manager defined rules (e.g. the IP transparency
		//  chain). This should only be disabled in case of conflict with
		//  other software that manages iptables, e.g. firewalls. When disabled,
		//  you will need to add rules manually to use these features - see
		//  the user manual for details.
		ConfigEnabled *bool `json:"config_enabled,omitempty"`
	} `json:"iptables"`

	Iptrans struct {
		// The iptables named chain to use for IP transparency rules.
		Chain *string `json:"chain,omitempty"`

		// The netfilter forwarding mark to use for IP transparency rules
		Fwmark *int `json:"fwmark,omitempty"`

		// Whether IP transparency may be used via netfilter/iptables. This
		//  requires Linux 2.6.24 and the iptables socket extension. For
		//  older Linux versions, the "ztrans" kernel module may be used
		//  instead.
		IptablesEnabled *bool `json:"iptables_enabled,omitempty"`

		// The special routing table ID to use for IP transparency rules
		RoutingTable *int `json:"routing_table,omitempty"`
	} `json:"iptrans"`

	Java struct {
		// The port the Java Extension handler process should listen on.
		//   This port will be bound for localhost communications only.
		Port *int `json:"port,omitempty"`
	} `json:"java"`

	Kerberos struct {
		// The hostname to use in Kerberos principal names.
		Hostname *string `json:"hostname,omitempty"`

		// How many worker threads the Kerberos Protocol Transition helper
		//  process will use.
		NumKptThreads *int `json:"num_kpt_threads,omitempty"`
	} `json:"kerberos"`

	RemoteLicensing struct {
		// The e-mail address sent as part of a remote licensing request.
		EmailAddress *string `json:"email_address,omitempty"`

		// A free-text field sent as part of a remote licensing request.
		Message *string `json:"message,omitempty"`
	} `json:"remote_licensing"`

	RestApi struct {
		// A list of IP Addresses which the REST API will listen on for
		//  connections. The list should contain IP addresses (IPv4 or IPv6)
		//  or a single entry containing an asterisk (*). This indicates
		//  that the REST API should listen on all IP Addresses.
		BindIps *[]string `json:"bind_ips,omitempty"`

		// The port on which the REST API should listen for requests.
		Port *int `json:"port,omitempty"`
	} `json:"rest_api"`

	Snmp struct {
		// Restrict which IP addresses can access the SNMP command responder
		//  service.  The value can be "all", "localhost", or a list of IP
		//  CIDR subnet masks.  For example "10.100.0.0/16" would allow connections
		//  from any IP address beginning with "10.100".
		Allow *[]string `json:"allow,omitempty"`

		// The authentication password. Required (minimum length 8 characters)
		//  if "security_level" includes authentication.
		AuthPassword *string `json:"auth_password,omitempty"`

		// The IP address the SNMP service should bind its listen port to.
		//   The value "*" (asterisk) means SNMP will listen on all IP addresses.
		BindIp *string `json:"bind_ip,omitempty"`

		// The community string required for SNMPv1 and SNMPv2c commands.
		//   (If empty, all SNMPv1 and SNMPv2c commands will be rejected).
		Community *string `json:"community,omitempty"`

		// Whether or not the SNMP command responder service should be enabled
		//  on this traffic manager.
		Enabled *bool `json:"enabled,omitempty"`

		// The hash algorithm for authenticated SNMPv3 communications.
		HashAlgorithm *string `json:"hash_algorithm,omitempty"`

		// The port the SNMP command responder service should listen on.
		//  The value "default" denotes port 161 if the software is running
		//  with root privileges, and 1161 otherwise.
		Port *string `json:"port,omitempty"`

		// The privacy password. Required (minimum length 8 characters)
		//  if "security_level" includes privacy (message encryption).
		PrivPassword *string `json:"priv_password,omitempty"`

		// The security level for SNMPv3 communications.
		SecurityLevel *string `json:"security_level,omitempty"`

		// The username required for SNMPv3 commands.  (If empty, all SNMPv3
		//  commands will be rejected).
		Username *string `json:"username,omitempty"`
	} `json:"snmp"`
}

type TrafficManagerHosts struct {
	// The static IP address of the host.
	IpAddress *string `json:"ip_address,omitempty"`

	// The name of a host.
	Name *string `json:"name,omitempty"`
}

type TrafficManagerHostsTable []TrafficManagerHosts

type TrafficManagerIf struct {
	// Whether auto-negotiation should be enabled for the interface.
	Autoneg *bool `json:"autoneg,omitempty"`

	// The trunking mode used for the interface (only 802.3ad is currently
	//  supported).
	Bmode *string `json:"bmode,omitempty"`

	// The trunk of which the interface should be a member.
	Bond *string `json:"bond,omitempty"`

	// Whether full-duplex should be enabled for the interface.
	Duplex *bool `json:"duplex,omitempty"`

	// Set the configuriation mode of an interface, the interface name
	//  is used in place of the "*" (asterisk).
	Mode *string `json:"mode,omitempty"`

	// The maximum transmission unit (MTU) of the interface.
	Mtu *int `json:"mtu,omitempty"`

	// A network interface name.
	Name *string `json:"name,omitempty"`

	// The speed of the interface.
	Speed *string `json:"speed,omitempty"`
}

type TrafficManagerIfTable []TrafficManagerIf

type TrafficManagerIp struct {
	// The IP address for the interface.
	Addr *string `json:"addr,omitempty"`

	// Whether the interface is externally facing.
	Isexternal *bool `json:"isexternal,omitempty"`

	// The IP mask (netmask) for the interface.
	Mask *string `json:"mask,omitempty"`

	// A network interface name.
	Name *string `json:"name,omitempty"`
}

type TrafficManagerIpTable []TrafficManagerIp

type TrafficManagerRoutes struct {
	// The gateway IP to configure for the route.
	Gw *string `json:"gw,omitempty"`

	// The network interface to configure for the route.
	If *string `json:"if,omitempty"`

	// The netmask to apply to the IP address.
	Mask *string `json:"mask,omitempty"`

	// A destination IP address.
	Name *string `json:"name,omitempty"`
}

type TrafficManagerRoutesTable []TrafficManagerRoutes

type TrafficManagerApplianceCard struct {
	// The order of the interfaces of a network card
	Interfaces *[]string `json:"interfaces,omitempty"`

	// The labels of the installed network cards
	Label *string `json:"label,omitempty"`

	// Network card PCI ID
	Name *string `json:"name,omitempty"`
}

type TrafficManagerApplianceCardTable []TrafficManagerApplianceCard

type TrafficManagerApplianceSysctl struct {
	// Associated optional description for the sysctl
	Description *string `json:"description,omitempty"`

	// The name of the kernel parameter, e.g. net.ipv4.forward
	Sysctl *string `json:"sysctl,omitempty"`

	// The value of the kernel parameter
	Value *string `json:"value,omitempty"`
}

type TrafficManagerApplianceSysctlTable []TrafficManagerApplianceSysctl

type TrafficManagerTrafficip struct {
	// A network interface.
	Name *string `json:"name,omitempty"`

	// A set of IP/masks to which the network interface maps.
	Networks *[]string `json:"networks,omitempty"`
}

type TrafficManagerTrafficipTable []TrafficManagerTrafficip
