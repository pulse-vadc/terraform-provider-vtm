// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type Protection struct {
	connector            *vtmConnector
	ProtectionProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetProtection(name string) (*Protection, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetProtection(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/protection/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Protection)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Protection) Apply() (*Protection, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewProtection(name string) *Protection {
	object := new(Protection)

	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/protection/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteProtection(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/protection/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListProtections() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/protection")
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

type ProtectionProperties struct {
	AccessRestriction struct {
		// Always allow access to these IP addresses. This overrides the
		//  connection limits for these machines, but does not stop other
		//  restrictions such as HTTP validity checks.
		Allowed *[]string `json:"allowed,omitempty"`

		// Disallow access to these IP addresses.
		Banned *[]string `json:"banned,omitempty"`
	} `json:"access_restriction"`

	Basic struct {
		// Whether or not to output verbose logging.
		Debug *bool `json:"debug,omitempty"`

		// Enable or disable this service protection class.
		Enabled *bool `json:"enabled,omitempty"`

		// After sending a HTTP error message to a client, wait up to this
		//  time before closing the connection.
		LingerTime *int `json:"linger_time,omitempty"`

		// Log service protection messages at these intervals. If set to
		//  "0" no messages will be logged and no alerts will be sent.
		LogTime *int `json:"log_time,omitempty"`

		// A description of the service protection class.
		Note *string `json:"note,omitempty"`

		// A TrafficScript rule that will be run on the connection after
		//  the service protection criteria have been evaluated.  This rule
		//  will be executed prior to normal rules configured for the virtual
		//  server.
		Rule *string `json:"rule,omitempty"`

		// Place the service protection class into testing mode. (Log when
		//  this class would have dropped a connection, but allow all connections
		//  through).
		Testing *bool `json:"testing,omitempty"`
	} `json:"basic"`

	ConcurrentConnections struct {
		// Additional limit on maximum concurrent connections from the top
		//  10 busiest connecting IP addresses combined.  The value should
		//  be between 1 and 10 times the "max_1_connections" limit.   (This
		//  limit is disabled if "per_process_connection_count" is "No",
		//  or "max_1_connections" is "0", or "min_connections" is "0".)
		Max10Connections *int `json:"max_10_connections,omitempty"`

		// Maximum concurrent connections each connecting IP address is
		//  allowed. Set to "0" to disable this limit.
		Max1Connections *int `json:"max_1_connections,omitempty"`

		// Entry threshold for the "max_10_connections" limit: the "max_10_connections"
		//  limit is not applied to connecting IP addresses with this many
		//  or fewer concurrent connections.   Setting to "0" disables both
		//  the "max_1_connections" and "max_10_connections" limits, if "per_process_connection_count"
		//  is "Yes". (If "per_process_connection_count" is "No", this setting
		//  is ignored.)
		MinConnections *int `json:"min_connections,omitempty"`

		// Whether concurrent connection counting and limits are per-process.
		//  (Each Traffic Manager typically has several processes: one process
		//  per available CPU core.)   If "Yes", a connecting IP address
		//  may make that many connections to each process within a Traffic
		//  Manager. If "No", a connecting IP address may make that many
		//  connections to each Traffic Manager as a whole.
		PerProcessConnectionCount *bool `json:"per_process_connection_count,omitempty"`
	} `json:"concurrent_connections"`

	ConnectionRate struct {
		// Maximum number of new connections each connecting IP address
		//  is allowed to make in the "rate_timer" interval.  Set to "0"
		//  to disable this limit. If applied to an HTTP Virtual Server each
		//  request sent on a connection that is kept alive counts as a new
		//  connection.  The rate limit is per process: each process within
		//  a Traffic Manager accepts new connections from the connecting
		//  IP address at this rate. (Each Traffic Manager typically has
		//  several processes: one process per available CPU core).
		MaxConnectionRate *int `json:"max_connection_rate,omitempty"`

		// How frequently the "max_connection_rate" is assessed. For example,
		//  a value of "1" (second) will impose a limit of "max_connection_rate"
		//  connections per second; a value of "60" will impose a limit of
		//  "max_connection_rate" connections per minute. The valid range
		//  is 1-99999 seconds.
		RateTimer *int `json:"rate_timer,omitempty"`
	} `json:"connection_rate"`

	Http struct {
		// Whether or not requests with poorly-formed URLs be should be
		//  rejected. This tests URL compliance as defined in RFC2396.  Note
		//  that enabling this may block some older, non-conforming web browsers.
		CheckRfc2396 *bool `json:"check_rfc2396,omitempty"`

		// Maximum permitted length of HTTP request body data, set to "0"
		//  to disable the limit.
		MaxBodyLength *int `json:"max_body_length,omitempty"`

		// Maximum permitted length of a single HTTP request header (key
		//  and value), set to "0" to disable the limit.
		MaxHeaderLength *int `json:"max_header_length,omitempty"`

		// Maximum permitted size of all the HTTP request headers, set to
		//  "0" to disable the limit.
		MaxRequestLength *int `json:"max_request_length,omitempty"`

		// Maximum permitted URL length, set to "0" to disable the limit.
		MaxUrlLength *int `json:"max_url_length,omitempty"`

		// Whether or not URLs and HTTP request headers that contain binary
		//  data (after decoding) should be rejected.
		RejectBinary *bool `json:"reject_binary,omitempty"`

		// This setting tells the traffic manager to send an HTTP error
		//  message if a connection fails the service protection tests, instead
		//  of just dropping it. Details of which HTTP response will be sent
		//  when particular tests fail can be found in the Help section for
		//  this page.
		SendErrorPage *bool `json:"send_error_page,omitempty"`
	} `json:"http"`
}
