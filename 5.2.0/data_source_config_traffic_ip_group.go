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

func dataSourceTrafficIpGroup() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTrafficIpGroupRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},

			// IP addresses associated with the Traffic IP group that can be
			//  used for communication with back-end servers.
			"backend_traffic_ips": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// If set to "No", the traffic IP group will be disabled and none
			//  of the traffic IP addresses will be raised.
			"enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Whether or not the source port should be taken into account when
			//  deciding which traffic manager should handle a request.
			"hash_source_port": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// Configure how traffic IPs are assigned to traffic managers in
			//  Single-Hosted mode
			"ip_assignment_mode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"alphabetic", "balanced"}, false),
				Default:      "balanced",
			},

			// A table assigning traffic IP addresses to machines that should
			//  host them. Traffic IP addresses not specified in this table will
			//  automatically be assigned to a machine.
			"ip_mapping": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// ip
						"ip": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// traffic_manager
						"traffic_manager": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of ip_mapping
			"ip_mapping_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// The IP addresses that belong to the Traffic IP group.
			"ipaddresses": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// If set to "Yes" then all the traffic IPs will be raised on a
			//  single traffic manager.  By default they're distributed across
			//  all active traffic managers in the traffic IP group.
			"keeptogether": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},

			// The location in which the Traffic IP group is based.
			"location": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				Default:  0,
			},

			// The traffic managers that can host the traffic IP group's IP
			//  addresses.
			"machines": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},

			// The method used to distribute traffic IPs across machines in
			//  the cluster. If "multihosted" is used then "multicast" must be
			//  set to an appropriate multicast IP address.
			"mode": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice([]string{"ec2elastic", "ec2vpcelastic", "ec2vpcprivate", "multihosted", "rhi", "singlehosted"}, false),
				Default:      "singlehosted",
			},

			// The multicast IP address used to duplicate traffic to all traffic
			//  managers in the group.
			"multicast": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// A note, used to describe this Traffic IP Group
			"note": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},

			// The base BGP routing metric for this Traffic IP group. This is
			//  the advertised routing cost for the active traffic manager in
			//  the cluster. It can be used to set up inter-cluster failover.
			"rhi_bgp_metric_base": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 4294967295),
				Default:      10,
			},

			// The BGP routing metric offset for this Traffic IP group. This
			//  is the difference between the advertised routing cost for the
			//  active and passive traffic manager in the cluster.
			"rhi_bgp_passive_metric_offset": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 4294967295),
				Default:      10,
			},

			// The base OSPFv2 routing metric for this Traffic IP group. This
			//  is the advertised routing cost for the active traffic manager
			//  in the cluster. It can be used to set up inter-cluster failover.
			"rhi_ospfv2_metric_base": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      10,
			},

			// The OSPFv2 routing metric offset for this Traffic IP group. This
			//  is the difference between the advertised routing cost for the
			//  active and passive traffic manager in the cluster.
			"rhi_ospfv2_passive_metric_offset": &schema.Schema{
				Type:         schema.TypeInt,
				Optional:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
				Default:      10,
			},

			// A list of protocols to be used for RHI. Currently must be 'ospf'
			//  or 'bgp' or both. The default, if empty, is 'ospf', which means
			//  that it is not possible to specify no protocol.
			"rhi_protocols": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "ospf",
			},

			// A list of traffic managers that are in 'passive' mode. This means
			//  that in a fully working environment, they will not have any traffic
			//  IP addresses assigned to them.
			"slaves": &schema.Schema{
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceTrafficIpGroupRead(d *schema.ResourceData, tm interface{}) error {
	objectName := d.Get("name").(string)
	if objectName == "" {
		objectName = d.Id()
		d.Set("name", objectName)
	}
	object, err := tm.(*vtm.VirtualTrafficManager).GetTrafficIpGroup(objectName)
	if err != nil {
		if err.ErrorId == "resource.not_found" {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Failed to read vtm_traffic_ip_group '%v': %v", objectName, err.ErrorText)
	}
	d.Set("backend_traffic_ips", []string(*object.Basic.BackendTrafficIps))
	d.Set("enabled", bool(*object.Basic.Enabled))
	d.Set("hash_source_port", bool(*object.Basic.HashSourcePort))
	d.Set("ip_assignment_mode", string(*object.Basic.IpAssignmentMode))

	ipMapping := make([]map[string]interface{}, 0, len(*object.Basic.IpMapping))
	for _, item := range *object.Basic.IpMapping {
		itemTerraform := make(map[string]interface{})
		if item.Ip != nil {
			itemTerraform["ip"] = string(*item.Ip)
		}
		if item.TrafficManager != nil {
			itemTerraform["traffic_manager"] = string(*item.TrafficManager)
		}
		ipMapping = append(ipMapping, itemTerraform)
	}
	d.Set("ip_mapping", ipMapping)
	ipMappingJson, _ := json.Marshal(ipMapping)
	d.Set("ip_mapping_json", ipMappingJson)
	d.Set("ipaddresses", []string(*object.Basic.Ipaddresses))
	d.Set("keeptogether", bool(*object.Basic.Keeptogether))
	d.Set("location", int(*object.Basic.Location))
	d.Set("machines", []string(*object.Basic.Machines))
	d.Set("mode", string(*object.Basic.Mode))
	d.Set("multicast", string(*object.Basic.Multicast))
	d.Set("note", string(*object.Basic.Note))
	d.Set("rhi_bgp_metric_base", int(*object.Basic.RhiBgpMetricBase))
	d.Set("rhi_bgp_passive_metric_offset", int(*object.Basic.RhiBgpPassiveMetricOffset))
	d.Set("rhi_ospfv2_metric_base", int(*object.Basic.RhiOspfv2MetricBase))
	d.Set("rhi_ospfv2_passive_metric_offset", int(*object.Basic.RhiOspfv2PassiveMetricOffset))
	d.Set("rhi_protocols", string(*object.Basic.RhiProtocols))
	d.Set("slaves", []string(*object.Basic.Slaves))

	d.SetId(objectName)
	return nil
}
