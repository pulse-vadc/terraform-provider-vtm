// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type ServiceLevelMonitor struct {
	connector                     *vtmConnector
	ServiceLevelMonitorProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetServiceLevelMonitor(name string) (*ServiceLevelMonitor, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetServiceLevelMonitor(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/service_level_monitors/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(ServiceLevelMonitor)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object ServiceLevelMonitor) Apply() (*ServiceLevelMonitor, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewServiceLevelMonitor(name string) *ServiceLevelMonitor {
	object := new(ServiceLevelMonitor)

	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/service_level_monitors/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteServiceLevelMonitor(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/service_level_monitors/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListServiceLevelMonitors() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/service_level_monitors")
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

type ServiceLevelMonitorProperties struct {
	Basic struct {
		// A description for the SLM class.
		Note *string `json:"note,omitempty"`

		// Responses that arrive within this time limit, expressed in milliseconds,
		//  are treated as conforming.
		ResponseTime *int `json:"response_time,omitempty"`

		// When the percentage of conforming responses drops below this
		//  level, a serious error level message will be emitted.
		SeriousThreshold *int `json:"serious_threshold,omitempty"`

		// When the percentage of conforming responses drops below this
		//  level, a warning message will be emitted.
		WarningThreshold *int `json:"warning_threshold,omitempty"`
	} `json:"basic"`
}
