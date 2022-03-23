// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.0.
package vtm

import (
	"encoding/json"
)

type RuleAuthenticatorStatistics struct {
	Statistics struct {
		Errors   *int `json:"errors"`
		Fails    *int `json:"fails"`
		Passes   *int `json:"passes"`
		Requests *int `json:"requests"`
	} `json:"statistics"`
}

func (vtm VirtualTrafficManager) GetRuleAuthenticatorStatistics(name string) (*RuleAuthenticatorStatistics, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.0/status/local_tm/statistics/rule_authenticators/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(RuleAuthenticatorStatistics)
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}
