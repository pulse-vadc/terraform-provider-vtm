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

func dataSourceApplianceNat() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceApplianceNatRead,

		Schema: map[string]*schema.Schema{

			// This is table 'many_to_one_all_ports'
			"many_to_one_all_ports": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// pool
						"pool": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// rule_number
						"rule_number": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// tip
						"tip": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of many_to_one_all_ports
			"many_to_one_all_ports_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// This is table 'many_to_one_port_locked'
			"many_to_one_port_locked": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// pool
						"pool": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// port
						"port": &schema.Schema{
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(1, 65535),
						},

						// protocol
						"protocol": &schema.Schema{
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice([]string{"icmp", "sctp", "tcp", "udp", "udplite"}, false),
						},

						// rule_number
						"rule_number": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// tip
						"tip": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of many_to_one_port_locked
			"many_to_one_port_locked_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// This is table 'one_to_one'
			"one_to_one": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// enable_inbound
						"enable_inbound": &schema.Schema{
							Type:     schema.TypeBool,
							Required: true,
						},

						// ip
						"ip": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// rule_number
						"rule_number": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// tip
						"tip": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of one_to_one
			"one_to_one_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},

			// This is table 'port_mapping'
			"port_mapping": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						// dport_first
						"dport_first": &schema.Schema{
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(1, 65535),
						},

						// dport_last
						"dport_last": &schema.Schema{
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validation.IntBetween(1, 65535),
						},

						// rule_number
						"rule_number": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},

						// virtual_server
						"virtual_server": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			// JSON representation of port_mapping
			"port_mapping_json": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.ValidateJsonString,
			},
		},
	}
}

func dataSourceApplianceNatRead(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetApplianceNat()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_appliance_nat: %v", err.ErrorText)
	}

	manyToOneAllPorts := make([]map[string]interface{}, 0, len(*object.Basic.ManyToOneAllPorts))
	for _, item := range *object.Basic.ManyToOneAllPorts {
		itemTerraform := make(map[string]interface{})
		if item.Pool != nil {
			itemTerraform["pool"] = string(*item.Pool)
		}
		if item.RuleNumber != nil {
			itemTerraform["rule_number"] = string(*item.RuleNumber)
		}
		if item.Tip != nil {
			itemTerraform["tip"] = string(*item.Tip)
		}
		manyToOneAllPorts = append(manyToOneAllPorts, itemTerraform)
	}
	d.Set("many_to_one_all_ports", manyToOneAllPorts)
	manyToOneAllPortsJson, _ := json.Marshal(manyToOneAllPorts)
	d.Set("many_to_one_all_ports_json", manyToOneAllPortsJson)

	manyToOnePortLocked := make([]map[string]interface{}, 0, len(*object.Basic.ManyToOnePortLocked))
	for _, item := range *object.Basic.ManyToOnePortLocked {
		itemTerraform := make(map[string]interface{})
		if item.Pool != nil {
			itemTerraform["pool"] = string(*item.Pool)
		}
		if item.Port != nil {
			itemTerraform["port"] = int(*item.Port)
		}
		if item.Protocol != nil {
			itemTerraform["protocol"] = string(*item.Protocol)
		}
		if item.RuleNumber != nil {
			itemTerraform["rule_number"] = string(*item.RuleNumber)
		}
		if item.Tip != nil {
			itemTerraform["tip"] = string(*item.Tip)
		}
		manyToOnePortLocked = append(manyToOnePortLocked, itemTerraform)
	}
	d.Set("many_to_one_port_locked", manyToOnePortLocked)
	manyToOnePortLockedJson, _ := json.Marshal(manyToOnePortLocked)
	d.Set("many_to_one_port_locked_json", manyToOnePortLockedJson)

	oneToOne := make([]map[string]interface{}, 0, len(*object.Basic.OneToOne))
	for _, item := range *object.Basic.OneToOne {
		itemTerraform := make(map[string]interface{})
		if item.EnableInbound != nil {
			itemTerraform["enable_inbound"] = bool(*item.EnableInbound)
		}
		if item.Ip != nil {
			itemTerraform["ip"] = string(*item.Ip)
		}
		if item.RuleNumber != nil {
			itemTerraform["rule_number"] = string(*item.RuleNumber)
		}
		if item.Tip != nil {
			itemTerraform["tip"] = string(*item.Tip)
		}
		oneToOne = append(oneToOne, itemTerraform)
	}
	d.Set("one_to_one", oneToOne)
	oneToOneJson, _ := json.Marshal(oneToOne)
	d.Set("one_to_one_json", oneToOneJson)

	portMapping := make([]map[string]interface{}, 0, len(*object.Basic.PortMapping))
	for _, item := range *object.Basic.PortMapping {
		itemTerraform := make(map[string]interface{})
		if item.DportFirst != nil {
			itemTerraform["dport_first"] = int(*item.DportFirst)
		}
		if item.DportLast != nil {
			itemTerraform["dport_last"] = int(*item.DportLast)
		}
		if item.RuleNumber != nil {
			itemTerraform["rule_number"] = string(*item.RuleNumber)
		}
		if item.VirtualServer != nil {
			itemTerraform["virtual_server"] = string(*item.VirtualServer)
		}
		portMapping = append(portMapping, itemTerraform)
	}
	d.Set("port_mapping", portMapping)
	portMappingJson, _ := json.Marshal(portMapping)
	d.Set("port_mapping_json", portMappingJson)

	d.SetId("appliance_nat")
	return nil
}
