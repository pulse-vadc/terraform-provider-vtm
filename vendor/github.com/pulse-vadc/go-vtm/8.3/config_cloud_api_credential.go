// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.3.
package vtm

import (
	"encoding/json"
)

type CloudApiCredential struct {
	connector                    *vtmConnector
	CloudApiCredentialProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetCloudApiCredential(name string) (*CloudApiCredential, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetCloudApiCredential(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/cloud_api_credentials/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(CloudApiCredential)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object CloudApiCredential) Apply() (*CloudApiCredential, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewCloudApiCredential(name string) *CloudApiCredential {
	object := new(CloudApiCredential)

	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/cloud_api_credentials/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteCloudApiCredential(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/cloud_api_credentials/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListCloudApiCredentials() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/cloud_api_credentials")
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

type CloudApiCredentialProperties struct {
	Basic struct {
		// The vCenter server hostname or IP address.
		ApiServer *string `json:"api_server,omitempty"`

		// The traffic manager creates and destroys nodes via API calls.
		//  This setting specifies (in seconds) how long to wait for such
		//  calls to complete.
		CloudApiTimeout *int `json:"cloud_api_timeout,omitempty"`

		// The first part of the credentials for the cloud user.  Typically
		//  this is some variation on the username concept.
		Cred1 *string `json:"cred1,omitempty"`

		// The second part of the credentials for the cloud user.  Typically
		//  this is some variation on the password concept.
		Cred2 *string `json:"cred2,omitempty"`

		// The third part of the credentials for the cloud user.  Typically
		//  this is some variation on the authentication token concept.
		Cred3 *string `json:"cred3,omitempty"`

		// The script to call for communication with the cloud API.
		Script *string `json:"script,omitempty"`

		// The traffic manager will periodically check the status of the
		//  cloud through an API call. This setting specifies the interval
		//  between such updates.
		UpdateInterval *int `json:"update_interval,omitempty"`
	} `json:"basic"`
}
