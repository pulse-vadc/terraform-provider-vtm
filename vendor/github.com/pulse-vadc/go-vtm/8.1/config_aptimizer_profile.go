// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.1.
package vtm

import (
	"encoding/json"
)

type AptimizerProfile struct {
	connector                  *vtmConnector
	AptimizerProfileProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetAptimizerProfile(name string) (*AptimizerProfile, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetAptimizerProfile(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.1/config/active/aptimizer/profiles/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(AptimizerProfile)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object AptimizerProfile) Apply() (*AptimizerProfile, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewAptimizerProfile(name string) *AptimizerProfile {
	object := new(AptimizerProfile)

	conn := vtm.connector.getChildConnector("/tm/8.1/config/active/aptimizer/profiles/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteAptimizerProfile(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.1/config/active/aptimizer/profiles/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListAptimizerProfiles() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.1/config/active/aptimizer/profiles")
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

type AptimizerProfileProperties struct {
	Basic struct {
		// If Web Accelerator can finish optimizing the resource within
		//  this time limit then serve the optimized content to the client,
		//  otherwise complete the optimization in the background and return
		//  the original content to the client. If set to 0, Web Accelerator
		//  will always wait for the optimization to complete before sending
		//  a response to the client.
		BackgroundAfter *int `json:"background_after,omitempty"`

		// If a web page contains resources that have not yet been optimized,
		//  fetch and optimize those resources in the background and send
		//  a partially optimized web page to clients until all resources
		//  on that page are ready.
		BackgroundOnAdditionalResources *bool `json:"background_on_additional_resources,omitempty"`

		// Placeholder to be overwritten when we have Web Accelerator support
		//  in RESTD
		Config *string `json:"config,omitempty"`

		// Set the Web Accelerator mode to turn acceleration on or off.
		Mode *string `json:"mode,omitempty"`

		// Show the Web Accelerator information bar on optimized web pages.
		//  This requires HTML optimization to be enabled in the acceleration
		//  settings.
		ShowInfoBar *bool `json:"show_info_bar,omitempty"`
	} `json:"basic"`
}
