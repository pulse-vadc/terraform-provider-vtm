// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.2.
package vtm

import (
	"encoding/json"
)

type SamlTrustedidp struct {
	connector                *vtmConnector
	SamlTrustedidpProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetSamlTrustedidp(name string) (*SamlTrustedidp, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetSamlTrustedidp(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/saml/trustedidps/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SamlTrustedidp)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object SamlTrustedidp) Apply() (*SamlTrustedidp, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewSamlTrustedidp(name string, certificate string, entity_id string, url string) *SamlTrustedidp {
	object := new(SamlTrustedidp)
	object.Basic.Certificate = &certificate
	object.Basic.EntityId = &entity_id
	object.Basic.Url = &url
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/saml/trustedidps/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteSamlTrustedidp(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/saml/trustedidps/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListSamlTrustedidps() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.2/config/active/saml/trustedidps")
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

type SamlTrustedidpProperties struct {
	Basic struct {
		// Whether or not to add the zlib header when compressing the AuthnRequest
		AddZlibHeader *bool `json:"add_zlib_header,omitempty"`

		// The certificate used to verify Assertions signed by the identity
		//  provider
		Certificate *string `json:"certificate,omitempty"`

		// The entity id of the IDP
		EntityId *string `json:"entity_id,omitempty"`

		// Whether or not SAML responses will be verified strictly
		StrictVerify *bool `json:"strict_verify,omitempty"`

		// The IDP URL to which Authentication Requests should be sent
		Url *string `json:"url,omitempty"`
	} `json:"basic"`
}
