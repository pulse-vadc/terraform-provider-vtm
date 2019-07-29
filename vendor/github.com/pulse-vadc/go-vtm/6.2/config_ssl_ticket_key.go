// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 6.2.
package vtm

import (
	"encoding/json"
)

type SslTicketKey struct {
	connector              *vtmConnector
	SslTicketKeyProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetSslTicketKey(name string) (*SslTicketKey, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetSslTicketKey(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/ticket_keys/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SslTicketKey)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object SslTicketKey) Apply() (*SslTicketKey, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewSslTicketKey(name string, id string, key string, validity_end int, validity_start int) *SslTicketKey {
	object := new(SslTicketKey)
	object.Basic.Id = &id
	object.Basic.Key = &key
	object.Basic.ValidityEnd = &validity_end
	object.Basic.ValidityStart = &validity_start
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/ticket_keys/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteSslTicketKey(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/ticket_keys/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListSslTicketKeys() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/6.2/config/active/ssl/ticket_keys")
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

type SslTicketKeyProperties struct {
	Basic struct {
		// The algorithm used to encrypt session tickets.  The algorithm
		//  determines the length of the key that must be provided.
		Algorithm *string `json:"algorithm,omitempty"`

		// A 16-byte key identifier, with each byte encoded as two hexadecimal
		//  digits. Key identifiers are transmitted in plaintext at the beginning
		//  of a TLS session ticket, and are used to identify the ticket
		//  encryption key that was used to encrypt a ticket. (They correspond
		//  to the 'key_name' field in RFC 5077.) They are required to be
		//  unique across the set of SSL ticket encryption keys.
		Id *string `json:"id,omitempty"`

		// The session ticket encryption key, with each byte encoded as
		//  two hexadecimal digits. The required key length is determined
		//  by the chosen key algorithm. See the documentation for the 'algorithm'
		//  field for more details.
		Key *string `json:"key,omitempty"`

		// The latest time at which this key may be used to encrypt new
		//  session tickets. Given as number of seconds since the epoch (1970-01-01T00:00:00Z).
		ValidityEnd *int `json:"validity_end,omitempty"`

		// The earliest time at which this key may be used to encrypt new
		//  session tickets. Given as number of seconds since the epoch (1970-01-01T00:00:00Z).
		ValidityStart *int `json:"validity_start,omitempty"`
	} `json:"basic"`
}
