// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.2.
package vtm

import (
	"encoding/json"
	"io/ioutil"
)

func (vtm VirtualTrafficManager) ListServicediscoverys() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/servicediscovery")
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

func (vtm VirtualTrafficManager) GetServicediscovery(name string) (string, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetServicediscovery(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/servicediscovery/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return "", object
	}
	bodyText, err := ioutil.ReadAll(data)
	if err != nil {
		panic(err)
	}
	return string(bodyText), nil
}

func (vtm VirtualTrafficManager) SetServicediscovery(name, content string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/servicediscovery/" + name)
	data, ok := conn.put(content, TEXT_ONLY_OBJ)
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) DeleteServicediscovery(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/servicediscovery/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}
