// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	vtm "github.com/pulse-vadc/go-vtm/7.1"
)

func resourceApplianceNat() *schema.Resource {
	return &schema.Resource{
		Read:   resourceApplianceNatRead,
		Create: resourceApplianceNatUpdate,
		Update: resourceApplianceNatUpdate,
		Delete: resourceApplianceNatDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: getResourceApplianceNatSchema(),
	}
}

func getResourceApplianceNatSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{

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
	}
}

func resourceApplianceNatRead(d *schema.ResourceData, tm interface{}) (readError error) {
	object, err := tm.(*vtm.VirtualTrafficManager).GetApplianceNat()
	if err != nil {
		return fmt.Errorf("Failed to read vtm_nat: %v", err.ErrorText)
	}

	var lastAssignedField string

	defer func() {
		r := recover()
		if r != nil {
			readError = fmt.Errorf("Field '%s' missing from vTM configuration", lastAssignedField)
		}
	}()

	lastAssignedField = "many_to_one_all_ports"
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
	lastAssignedField = "many_to_one_port_locked"
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
	lastAssignedField = "one_to_one"
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
	lastAssignedField = "port_mapping"
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
	d.SetId("nat")
	return nil
}

func resourceApplianceNatUpdate(d *schema.ResourceData, tm interface{}) error {
	object, err := tm.(*vtm.VirtualTrafficManager).GetApplianceNat()
	if err != nil {
		return fmt.Errorf("Failed to update vtm_nat: %v", err)
	}

	object.Basic.ManyToOneAllPorts = &vtm.ApplianceNatManyToOneAllPortsTable{}
	if manyToOneAllPortsJson, ok := d.GetOk("many_to_one_all_ports_json"); ok {
		_ = json.Unmarshal([]byte(manyToOneAllPortsJson.(string)), object.Basic.ManyToOneAllPorts)
	} else if manyToOneAllPorts, ok := d.GetOk("many_to_one_all_ports"); ok {
		for _, row := range manyToOneAllPorts.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.ApplianceNatManyToOneAllPorts{}
			VtmObject.Pool = getStringAddr(itemTerraform["pool"].(string))
			VtmObject.RuleNumber = getStringAddr(itemTerraform["rule_number"].(string))
			VtmObject.Tip = getStringAddr(itemTerraform["tip"].(string))
			*object.Basic.ManyToOneAllPorts = append(*object.Basic.ManyToOneAllPorts, VtmObject)
		}
		d.Set("many_to_one_all_ports", manyToOneAllPorts)
	} else {
		d.Set("many_to_one_all_ports", make([]map[string]interface{}, 0, len(*object.Basic.ManyToOneAllPorts)))
	}

	object.Basic.ManyToOnePortLocked = &vtm.ApplianceNatManyToOnePortLockedTable{}
	if manyToOnePortLockedJson, ok := d.GetOk("many_to_one_port_locked_json"); ok {
		_ = json.Unmarshal([]byte(manyToOnePortLockedJson.(string)), object.Basic.ManyToOnePortLocked)
	} else if manyToOnePortLocked, ok := d.GetOk("many_to_one_port_locked"); ok {
		for _, row := range manyToOnePortLocked.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.ApplianceNatManyToOnePortLocked{}
			VtmObject.Pool = getStringAddr(itemTerraform["pool"].(string))
			VtmObject.Port = getIntAddr(itemTerraform["port"].(int))
			VtmObject.Protocol = getStringAddr(itemTerraform["protocol"].(string))
			VtmObject.RuleNumber = getStringAddr(itemTerraform["rule_number"].(string))
			VtmObject.Tip = getStringAddr(itemTerraform["tip"].(string))
			*object.Basic.ManyToOnePortLocked = append(*object.Basic.ManyToOnePortLocked, VtmObject)
		}
		d.Set("many_to_one_port_locked", manyToOnePortLocked)
	} else {
		d.Set("many_to_one_port_locked", make([]map[string]interface{}, 0, len(*object.Basic.ManyToOnePortLocked)))
	}

	object.Basic.OneToOne = &vtm.ApplianceNatOneToOneTable{}
	if oneToOneJson, ok := d.GetOk("one_to_one_json"); ok {
		_ = json.Unmarshal([]byte(oneToOneJson.(string)), object.Basic.OneToOne)
	} else if oneToOne, ok := d.GetOk("one_to_one"); ok {
		for _, row := range oneToOne.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.ApplianceNatOneToOne{}
			VtmObject.EnableInbound = getBoolAddr(itemTerraform["enable_inbound"].(bool))
			VtmObject.Ip = getStringAddr(itemTerraform["ip"].(string))
			VtmObject.RuleNumber = getStringAddr(itemTerraform["rule_number"].(string))
			VtmObject.Tip = getStringAddr(itemTerraform["tip"].(string))
			*object.Basic.OneToOne = append(*object.Basic.OneToOne, VtmObject)
		}
		d.Set("one_to_one", oneToOne)
	} else {
		d.Set("one_to_one", make([]map[string]interface{}, 0, len(*object.Basic.OneToOne)))
	}

	object.Basic.PortMapping = &vtm.ApplianceNatPortMappingTable{}
	if portMappingJson, ok := d.GetOk("port_mapping_json"); ok {
		_ = json.Unmarshal([]byte(portMappingJson.(string)), object.Basic.PortMapping)
	} else if portMapping, ok := d.GetOk("port_mapping"); ok {
		for _, row := range portMapping.(*schema.Set).List() {
			itemTerraform := row.(map[string]interface{})
			VtmObject := vtm.ApplianceNatPortMapping{}
			VtmObject.DportFirst = getIntAddr(itemTerraform["dport_first"].(int))
			VtmObject.DportLast = getIntAddr(itemTerraform["dport_last"].(int))
			VtmObject.RuleNumber = getStringAddr(itemTerraform["rule_number"].(string))
			VtmObject.VirtualServer = getStringAddr(itemTerraform["virtual_server"].(string))
			*object.Basic.PortMapping = append(*object.Basic.PortMapping, VtmObject)
		}
		d.Set("port_mapping", portMapping)
	} else {
		d.Set("port_mapping", make([]map[string]interface{}, 0, len(*object.Basic.PortMapping)))
	}

	_, applyErr := object.Apply()
	if applyErr != nil {
		info := formatErrorInfo(applyErr.ErrorInfo.(map[string]interface{}))
		return fmt.Errorf("Error updating vtm_nat: %s %s", applyErr.ErrorText, info)
	}
	d.SetId("nat")
	return nil
}

func resourceApplianceNatDelete(d *schema.ResourceData, tm interface{}) error {
	d.SetId("")
	return nil
}
