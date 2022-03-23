// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 7.0.
package vtm

import (
	"encoding/json"
)

type RuleStatistics struct {
	Statistics struct {
		Aborts                *int `json:"aborts"`
		Discards              *int `json:"discards"`
		ExecutionTimeWarnings *int `json:"execution_time_warnings"`
		Executions            *int `json:"executions"`
		PoolSelect            *int `json:"pool_select"`
		Responds              *int `json:"responds"`
		Retries               *int `json:"retries"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetRuleStatistics(name string) (*RuleStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.0/status/local_tm/statistics/rules/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(RuleStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
