// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type Monitor struct {
	connector         *vtmConnector
	MonitorProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetMonitor(name string) (*Monitor, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetMonitor(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/monitors/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Monitor)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Monitor) Apply() (*Monitor, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewMonitor(name string) *Monitor {
	object := new(Monitor)

	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/monitors/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteMonitor(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/monitors/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListMonitors() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/monitors")
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

type MonitorProperties struct {
	Basic struct {
		// Should the monitor slowly increase the delay after it has failed?
		BackOff *bool `json:"back_off,omitempty"`

		// Whether or not SSL configuration is available via the Admin Server
		//  UI for this monitor.  This is for use by monitors pre-packaged
		//  with the software.
		CanEditSsl *bool `json:"can_edit_ssl,omitempty"`

		// Whether or not monitors of this type are capable of using SSL.
		CanUseSsl *bool `json:"can_use_ssl,omitempty"`

		// The minimum time between calls to a monitor.
		Delay *int `json:"delay,omitempty"`

		// Which of the monitor's configuration keys may be edited via the
		//  Admin Server UI.
		EditableKeys *[]string `json:"editable_keys,omitempty"`

		// Whether or not this monitor is provided as part of the software
		//  release.
		Factory *bool `json:"factory,omitempty"`

		// The number of times in a row that a node must fail execution
		//  of the monitor before it is classed as unavailable.
		Failures *int `json:"failures,omitempty"`

		// Should this monitor only report health (ignore load)?
		HealthOnly *bool `json:"health_only,omitempty"`

		// The machine to monitor, where relevant this should be in the
		//  form "<hostname>:<port>", for "ping" monitors the ":<port>" part
		//  must not be specified.
		Machine *string `json:"machine,omitempty"`

		// A description of the monitor.
		Note *string `json:"note,omitempty"`

		// A monitor can either monitor each node in the pool separately
		//  and disable an individual node if it fails, or it can monitor
		//  a specific machine and disable the entire pool if that machine
		//  fails. GLB location monitors must monitor a specific machine.
		Scope *string `json:"scope,omitempty"`

		// The maximum runtime for an individual instance of the monitor.
		Timeout *int `json:"timeout,omitempty"`

		// The internal monitor implementation of this monitor.
		Type *string `json:"type,omitempty"`

		// Whether or not the monitor should connect using SSL.
		UseSsl *bool `json:"use_ssl,omitempty"`

		// Whether or not the monitor should emit verbose logging. This
		//  is useful for diagnosing problems.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"basic"`

	Http struct {
		// The HTTP basic-auth "<user>:<password>" to use for the test HTTP
		//  request.
		Authentication *string `json:"authentication,omitempty"`

		// A regular expression that the HTTP response body must match.
		//   If the response body content doesn't matter then set this to
		//  ".*" (match anything).
		BodyRegex *string `json:"body_regex,omitempty"`

		// The host header to use in the test HTTP request.
		HostHeader *string `json:"host_header,omitempty"`

		// The path to use in the test HTTP request.  This must be a string
		//  beginning with a "/" (forward slash).
		Path *string `json:"path,omitempty"`

		// A regular expression that the HTTP status code must match.  If
		//  the status code doesn't matter then set this to ".*" (match anything).
		StatusRegex *string `json:"status_regex,omitempty"`
	} `json:"http"`

	Rtsp struct {
		// The regular expression that the RTSP response body must match.
		BodyRegex *string `json:"body_regex,omitempty"`

		// The path to use in the RTSP request (some servers will return
		//  500 Internal Server Error unless this is a valid media file).
		Path *string `json:"path,omitempty"`

		// The regular expression that the RTSP response status code must
		//  match.
		StatusRegex *string `json:"status_regex,omitempty"`
	} `json:"rtsp"`

	Script struct {
		// A table containing arguments and argument values to be passed
		//  to the monitor program.
		Arguments *MonitorArgumentsTable `json:"arguments,omitempty"`

		// The program to run.  This must be an executable file, either
		//  within the monitor scripts directory or specified as an absolute
		//  path to some other location on the filesystem.
		Program *string `json:"program,omitempty"`
	} `json:"script"`

	Sip struct {
		// The regular expression that the SIP response body must match.
		BodyRegex *string `json:"body_regex,omitempty"`

		// The regular expression that the SIP response status code must
		//  match.
		StatusRegex *string `json:"status_regex,omitempty"`

		// Which transport protocol the SIP monitor will use to query the
		//  server.
		Transport *string `json:"transport,omitempty"`
	} `json:"sip"`

	Tcp struct {
		// An optional string to write to the server before closing the
		//  connection.
		CloseString *string `json:"close_string,omitempty"`

		// The maximum amount of data to read back from a server, use 0
		//  for unlimited. Applies to TCP and HTTP monitors.
		MaxResponseLen *int `json:"max_response_len,omitempty"`

		// A regular expression to match against the response from the server.
		//  Applies to TCP monitors only.
		ResponseRegex *string `json:"response_regex,omitempty"`

		// The string to write down the TCP connection.
		WriteString *string `json:"write_string,omitempty"`
	} `json:"tcp"`

	Udp struct {
		// If this monitor uses UDP, should it accept responses from any
		//  IP and port?
		AcceptAll *bool `json:"accept_all,omitempty"`
	} `json:"udp"`
}

type MonitorArguments struct {
	// A description for the argument provided to the program.
	Description *string `json:"description,omitempty"`

	// The name of the argument to be passed to the monitor program.
	Name *string `json:"name,omitempty"`

	// The value of the argument to be passed to the monitor program.
	Value *string `json:"value,omitempty"`
}

type MonitorArgumentsTable []MonitorArguments
