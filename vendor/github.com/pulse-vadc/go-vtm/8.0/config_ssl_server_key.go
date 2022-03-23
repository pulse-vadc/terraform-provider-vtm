// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.0.
package vtm

import (
	"encoding/json"
)

type SslServerKey struct {
	connector              *vtmConnector
	SslServerKeyProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetSslServerKey(name string) (*SslServerKey, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetSslServerKey(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/server_keys/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SslServerKey)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object SslServerKey) Apply() (*SslServerKey, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewSslServerKey(name string, note string, private string, public string, request string) *SslServerKey {
	object := new(SslServerKey)
	object.Basic.Note = &note
	object.Basic.Private = &private
	object.Basic.Public = &public
	object.Basic.Request = &request
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/server_keys/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteSslServerKey(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/server_keys/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListSslServerKeys() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.0/config/active/ssl/server_keys")
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

type SslServerKeyProperties struct {
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
