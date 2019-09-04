// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 4.0.
package vtm

import (
	"encoding/json"
)

type SystemBackupsFull struct {
	connector                   *vtmConnector
	SystemBackupsFullProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetSystemBackupsFull(name string) (*SystemBackupsFull, *vtmErrorResponse) {
	// 'name' automatically gets escaped
	conn := vtm.connector.getChildConnector("/tm/7.0/status/local_tm/backups/full/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(SystemBackupsFull)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object SystemBackupsFull) Apply() (*SystemBackupsFull, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewSystemBackupsFull(name string) *SystemBackupsFull {
	object := new(SystemBackupsFull)
	conn := vtm.connector.getChildConnector("/tm/7.0/status/local_tm/backups/full/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteSystemBackupsFull(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/7.0/status/local_tm/backups/full/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListSystemBackupsFull() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.0/status/local_tm/backups/full")
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

type SystemBackupsFullProperties struct {
	Backup struct {
		Description *string `json:"description,omitempty"`
		TimeStamp   *int    `json:"time_stamp,omitempty"`
		Version     *string `json:"version,omitempty"`
	} `json:"backup"`
}
