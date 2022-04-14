// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 7.1.
package vtm

import (
	"encoding/json"
)

type LogExport struct {
	connector           *vtmConnector
	LogExportProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetLogExport(name string) (*LogExport, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetLogExport(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/log_export/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(LogExport)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object LogExport) Apply() (*LogExport, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewLogExport(name string) *LogExport {
	object := new(LogExport)

	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/log_export/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteLogExport(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/log_export/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListLogExports() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/7.1/config/active/log_export")
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

type LogExportProperties struct {
	Basic struct {
		// Whether entries from the specified log files should be exported
		//  only from appliances.
		ApplianceOnly *bool `json:"appliance_only,omitempty"`

		// Export entries from the log files included in this category.
		Enabled *bool `json:"enabled,omitempty"`

		// The set of files to export as part of this category, specified
		//  as a list of glob patterns.
		Files *[]string `json:"files,omitempty"`

		// How much historic log activity should be exported.
		History *string `json:"history,omitempty"`

		// The number of days of historic log entries that should be exported.
		HistoryPeriod *int `json:"history_period,omitempty"`

		// The set of traffic managers on which this log should be exported.
		//  '*' will select all traffic managers in the cluster.
		Machines *[]string `json:"machines,omitempty"`

		// This is table 'metadata'
		Metadata *LogExportMetadataTable `json:"metadata,omitempty"`

		// A description of this category of log files.
		Note *string `json:"note,omitempty"`

		// The type of pre-processing that should be applied to log entries
		//  before they are exported.
		Preprocess *string `json:"preprocess,omitempty"`
	} `json:"basic"`
}

type LogExportMetadata struct {
	// The name of a metadata item which should be sent to the analytics
	//  engine along with entries from these log files.
	Name *string `json:"name,omitempty"`

	// Additional metadata to include with the log entries when exporting
	//  them to the configured endpoint. Metadata can be used by the
	//  system that is receiving the exported data to categorise and
	//  parse the log entries.
	Value *string `json:"value,omitempty"`
}

type LogExportMetadataTable []LogExportMetadata
