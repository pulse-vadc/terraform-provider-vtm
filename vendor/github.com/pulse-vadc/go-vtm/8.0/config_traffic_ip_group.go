// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.0.
package vtm

import (
	"encoding/json"
)

type TrafficIpGroup struct {
	connector                *vtmConnector
	TrafficIpGroupProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetTrafficIpGroup(name string) (*TrafficIpGroup, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetTrafficIpGroup(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/traffic_ip_groups/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(TrafficIpGroup)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object TrafficIpGroup) Apply() (*TrafficIpGroup, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewTrafficIpGroup(name string) *TrafficIpGroup {
	object := new(TrafficIpGroup)

	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/traffic_ip_groups/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteTrafficIpGroup(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/traffic_ip_groups/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListTrafficIpGroups() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/traffic_ip_groups")
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

type TrafficIpGroupProperties struct {
	Basic struct {
		// If set to "No", the traffic IP group will be disabled and none
		//  of the traffic IP addresses will be raised.
		Enabled *bool `json:"enabled,omitempty"`

		// Whether or not the source port should be taken into account when
		//  deciding which traffic manager should handle a request.
		HashSourcePort *bool `json:"hash_source_port,omitempty"`

		// Configure how traffic IPs are assigned to traffic managers in
		//  Single-Hosted mode
		IpAssignmentMode *string `json:"ip_assignment_mode,omitempty"`

		// A table assigning traffic IP addresses to machines that should
		//  host them. Traffic IP addresses not specified in this table will
		//  automatically be assigned to a machine.
		IpMapping *TrafficIpGroupIpMappingTable `json:"ip_mapping,omitempty"`

		// The IP addresses that belong to the Traffic IP group.
		Ipaddresses *[]string `json:"ipaddresses,omitempty"`

		// If set to "Yes" then all the traffic IPs will be raised on a
		//  single traffic manager.  By default they're distributed across
		//  all active traffic managers in the traffic IP group.
		Keeptogether *bool `json:"keeptogether,omitempty"`

		// The location in which the Traffic IP group is based.
		Location *int `json:"location,omitempty"`

		// The traffic managers that can host the traffic IP group's IP
		//  addresses.
		Machines *[]string `json:"machines,omitempty"`

		// The method used to distribute traffic IPs across machines in
		//  the cluster. If "multihosted" is used then "multicast" must be
		//  set to an appropriate multicast IP address.
		Mode *string `json:"mode,omitempty"`

		// The multicast IP address used to duplicate traffic to all traffic
		//  managers in the group.
		Multicast *string `json:"multicast,omitempty"`

		// A note, used to describe this Traffic IP Group
		Note *string `json:"note,omitempty"`

		// The base BGP routing metric for this Traffic IP group. This is
		//  the advertised routing cost for the active traffic manager in
		//  the cluster. It can be used to set up inter-cluster failover.
		RhiBgpMetricBase *int `json:"rhi_bgp_metric_base,omitempty"`

		// The BGP routing metric offset for this Traffic IP group. This
		//  is the difference between the advertised routing cost for the
		//  active and passive traffic manager in the cluster.
		RhiBgpPassiveMetricOffset *int `json:"rhi_bgp_passive_metric_offset,omitempty"`

		// The base OSPFv2 routing metric for this Traffic IP group. This
		//  is the advertised routing cost for the active traffic manager
		//  in the cluster. It can be used to set up inter-cluster failover.
		RhiOspfv2MetricBase *int `json:"rhi_ospfv2_metric_base,omitempty"`

		// The OSPFv2 routing metric offset for this Traffic IP group. This
		//  is the difference between the advertised routing cost for the
		//  active and passive traffic manager in the cluster.
		RhiOspfv2PassiveMetricOffset *int `json:"rhi_ospfv2_passive_metric_offset,omitempty"`

		// A list of protocols to be used for RHI. Currently must be 'ospf'
		//  or 'bgp' or both. The default, if empty, is 'ospf', which means
		//  that it is not possible to specify no protocol.
		RhiProtocols *string `json:"rhi_protocols,omitempty"`

		// A list of traffic managers that are in 'passive' mode. This means
		//  that in a fully working environment, they will not have any traffic
		//  IP addresses assigned to them.
		Slaves *[]string `json:"slaves,omitempty"`
	} `json:"basic"`
}

type TrafficIpGroupIpMapping struct {
	// A traffic IP address (from the ipaddresses property).
	Ip *string `json:"ip,omitempty"`

	// The name of the traffic manager that should host the IP address.
	TrafficManager *string `json:"traffic_manager,omitempty"`
}

type TrafficIpGroupIpMappingTable []TrafficIpGroupIpMapping
