// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type KerberosPrincipal struct {
	connector                   *vtmConnector
	KerberosPrincipalProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetKerberosPrincipal(name string) (*KerberosPrincipal, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetKerberosPrincipal(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/kerberos/principals/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(KerberosPrincipal)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object KerberosPrincipal) Apply() (*KerberosPrincipal, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewKerberosPrincipal(name string, keytab string, service string) *KerberosPrincipal {
	object := new(KerberosPrincipal)
	object.Basic.Keytab = &keytab
	object.Basic.Service = &service
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/kerberos/principals/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteKerberosPrincipal(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/kerberos/principals/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListKerberosPrincipals() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/kerberos/principals")
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

type KerberosPrincipalProperties struct {
	Basic struct {
		// A list of "<hostname/ip>:<port>" pairs for Kerberos key distribution
		//  center (KDC) services to be explicitly used for the realm of
		//  the principal.  If no KDCs are explicitly configured, DNS will
		//  be used to discover the KDC(s) to use.
		Kdcs *[]string `json:"kdcs,omitempty"`

		// The name of the Kerberos keytab file containing suitable credentials
		//  to authenticate as the specified Kerberos principal.
		Keytab *string `json:"keytab,omitempty"`

		// The name of an optional Kerberos configuration file (krb5.conf).
		Krb5Conf *string `json:"krb5conf,omitempty"`

		// The Kerberos realm where the principal belongs.
		Realm *string `json:"realm,omitempty"`

		// The service name part of the Kerberos principal name the traffic
		//  manager should use to authenticate itself.
		Service *string `json:"service,omitempty"`
	} `json:"basic"`
}
