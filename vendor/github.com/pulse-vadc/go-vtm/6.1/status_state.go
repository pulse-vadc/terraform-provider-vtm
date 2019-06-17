// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.1.
package vtm

import (
	"encoding/json"
)

type SystemState struct {
	State struct {
		ErrorLevel  *string   `json:"error_level"`
		Errors      *[]string `json:"errors"`
		FailedNodes *[]struct {
			Node  *string   `json:"node"`
			Pools *[]string `json:"pools"`
		} `json:"failed_nodes"`
		License *string `json:"license"`
		Pools   *[]struct {
			ActiveNodes   *[]string `json:"active_nodes"`
			DisabledNodes *[]string `json:"disabled_nodes"`
			DrainingNodes *[]string `json:"draining_nodes"`
			FailurePool   *string   `json:"failure_pool"`
			Name          *string   `json:"name"`
		} `json:"pools"`
		TipErrors      *[]string `json:"tip_errors"`
		VirtualServers *[]struct {
			Name            *string   `json:"name"`
			Pool            *string   `json:"pool"`
			Port            *int      `json:"port"`
			Throughput      *int      `json:"throughput"`
			TsRedirectPools *[]string `json:"ts_redirect_pools"`
		} `json:"virtual_servers"`
	} `json:"state"`
}

func (vtm VirtualTrafficManager) GetSystemState() (*SystemState, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.1/status/local_tm/state")
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SystemState)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
