// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.2.
package vtm

import (
	"encoding/json"
)

type SslClientKey struct {
	connector              *vtmConnector
	SslClientKeyProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetSslClientKey(name string) (*SslClientKey, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetSslClientKey(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/client_keys/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SslClientKey)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object SslClientKey) Apply() (*SslClientKey, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewSslClientKey(name string, note string, private string, public string, request string) *SslClientKey {
	object := new(SslClientKey)
	object.Basic.Note = &note
	object.Basic.Private = &private
	object.Basic.Public = &public
	object.Basic.Request = &request
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/client_keys/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteSslClientKey(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/client_keys/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListSslClientKeys() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/client_keys")
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

type SslClientKeyProperties struct {
	Basic struct {
		// Notes for this certificate
		Note *string `json:"note,omitempty"`

		// Private key for certificate
		Private *string `json:"private,omitempty"`

		// Public certificate
		Public *string `json:"public,omitempty"`

		// Certificate Signing Request for certificate
		Request *string `json:"request,omitempty"`
	} `json:"basic"`
}
