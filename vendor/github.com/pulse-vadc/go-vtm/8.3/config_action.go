// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 8.3.
package vtm

import (
	"encoding/json"
)

type Action struct {
	connector        *vtmConnector
	ActionProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetAction(name string) (*Action, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetAction(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/actions/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(Action)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object Action) Apply() (*Action, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewAction(name string, typeParam string) *Action {
	object := new(Action)
	object.Basic.Type = &typeParam
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/actions/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteAction(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/actions/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListActions() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/8.3/config/active/actions")
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

type ActionProperties struct {
	Basic struct {
		// A description of the action.
		Note *string `json:"note,omitempty"`

		// Maximum length in bytes of a message sent to the remote syslog.
		//  Messages longer than this will be truncated before they are sent.
		SyslogMsgLenLimit *int `json:"syslog_msg_len_limit,omitempty"`

		// How long the action can run for before it is stopped automatically
		//  (set to 0 to disable timeouts).
		Timeout *int `json:"timeout,omitempty"`

		// The action type.
		Type *string `json:"type,omitempty"`

		// Enable or disable verbose logging for this action.
		Verbose *bool `json:"verbose,omitempty"`
	} `json:"basic"`

	Email struct {
		// The e-mail address from which messages will appear to originate.
		From *string `json:"from,omitempty"`

		// The SMTP server to which messages should be sent. This must be
		//  a valid IPv4 address or resolvable hostname (with optional port).
		Server *string `json:"server,omitempty"`

		// A set of e-mail addresses to which messages will be sent.
		To *[]string `json:"to,omitempty"`
	} `json:"email"`

	Log struct {
		// The full path of the file to log to. The text "%zeushome%" will
		//  be replaced with the location where the software is installed.
		File *string `json:"file,omitempty"`
	} `json:"log"`

	Program struct {
		// A table containing arguments and argument values to be passed
		//  to the event handling program.
		Arguments *ActionArgumentsTable `json:"arguments,omitempty"`

		// The program to run.
		Program *string `json:"program,omitempty"`
	} `json:"program"`

	Soap struct {
		// Additional information to send with the SOAP call.
		AdditionalData *string `json:"additional_data,omitempty"`

		// The password for HTTP basic authentication.
		Password *string `json:"password,omitempty"`

		// The address of the server implementing the SOAP interface (For
		//  example, https://example.com).
		Proxy *string `json:"proxy,omitempty"`

		// Username for HTTP basic authentication. Leave blank if you do
		//  not wish to use authentication.
		Username *string `json:"username,omitempty"`
	} `json:"soap"`

	Syslog struct {
		// The host and optional port to send syslog messages to (if empty,
		//  messages will be sent to localhost).
		Sysloghost *string `json:"sysloghost,omitempty"`
	} `json:"syslog"`

	Trap struct {
		// The authentication password for sending a Notify over SNMPv3.
		//  Blank to send unauthenticated traps.
		AuthPassword *string `json:"auth_password,omitempty"`

		// The community string to use when sending a Trap over SNMPv1 or
		//  a Notify over SNMPv2c.
		Community *string `json:"community,omitempty"`

		// The hash algorithm for SNMPv3 authentication.
		HashAlgorithm *string `json:"hash_algorithm,omitempty"`

		// The encryption password to encrypt a Notify message for SNMPv3.
		//  Requires that authentication also be configured. Blank to send
		//  unencrypted traps.
		PrivPassword *string `json:"priv_password,omitempty"`

		// The hostname or IPv4 address and optional port number that should
		//  receive traps.
		Traphost *string `json:"traphost,omitempty"`

		// The SNMP username to use to send the Notify over SNMPv3.
		Username *string `json:"username,omitempty"`

		// The SNMP version to use to send the Trap/Notify.
		Version *string `json:"version,omitempty"`
	} `json:"trap"`
}

type ActionArguments struct {
	// A description for the argument provided to the program.
	Description *string `json:"description,omitempty"`

	// The name of the argument to be passed to the event handling program.
	Name *string `json:"name,omitempty"`

	// The value of the argument to be passed to the event handling
	//  program.
	Value *string `json:"value,omitempty"`
}

type ActionArgumentsTable []ActionArguments
