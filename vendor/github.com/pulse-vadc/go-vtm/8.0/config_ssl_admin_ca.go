// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.0.
package vtm

import (
	"encoding/json"
	"io/ioutil"
)

func (vtm VirtualTrafficManager) ListSslAdminCas() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/admin_cas")
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

func (vtm VirtualTrafficManager) GetSslAdminCa(name string) (string, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetSslAdminCa(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/admin_cas/" + name)
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

func (vtm VirtualTrafficManager) SetSslAdminCa(name, content string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/admin_cas/" + name)
	data, ok := conn.put(content, TEXT_ONLY_OBJ)
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) DeleteSslAdminCa(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/admin_cas/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}
