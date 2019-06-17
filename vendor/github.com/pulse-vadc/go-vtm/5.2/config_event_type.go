// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type EventType struct {
	connector           *vtmConnector
	EventTypeProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetEventType(name string) (*EventType, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetEventType(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/event_types/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(EventType)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object EventType) Apply() (*EventType, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewEventType(name string) *EventType {
	object := new(EventType)

	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/event_types/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteEventType(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/event_types/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListEventTypes() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/event_types")
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

type EventTypeProperties struct {
	Basic struct {
		// The actions triggered by events matching this event type, as
		//  a list of action references.
		Actions *[]string `json:"actions,omitempty"`

		// If set to "Yes" this indicates that this configuration is built-in
		//  (provided as part of the software) and must not be deleted or
		//  edited.
		BuiltIn *bool `json:"built_in,omitempty"`

		// Whether or not the triggering of this event type will be logged
		//  to the main event log.
		Log2Mainlog *bool `json:"log2mainlog,omitempty"`

		// A description of this event type.
		Note *string `json:"note,omitempty"`
	} `json:"basic"`

	Cloudcredentials struct {
		// Cloud credentials event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Cloud credentials object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"cloudcredentials"`

	Config struct {
		// Configuration file event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"config"`

	Faulttolerance struct {
		// Fault tolerance event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"faulttolerance"`

	General struct {
		// General event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"general"`

	Glb struct {
		// GLB service event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// GLB service object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"glb"`

	Java struct {
		// Java event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"java"`

	Licensekeys struct {
		// License key event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// License key object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"licensekeys"`

	Locations struct {
		// Location event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Location object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"locations"`

	Monitors struct {
		// Monitor event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Monitors object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"monitors"`

	Pools struct {
		// Pool key event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Pool object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"pools"`

	Protection struct {
		// Service protection class event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Service protection class object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"protection"`

	Rules struct {
		// Rule event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Rule object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"rules"`

	Slm struct {
		// SLM class event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// SLM class object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"slm"`

	Ssl struct {
		// SSL event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"ssl"`

	Sslhw struct {
		// SSL hardware event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"sslhw"`

	Trafficscript struct {
		// TrafficScript event tags
		EventTags *[]string `json:"event_tags,omitempty"`
	} `json:"trafficscript"`

	Vservers struct {
		// Virtual server event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Virtual server object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"vservers"`

	Zxtms struct {
		// Traffic manager event tags
		EventTags *[]string `json:"event_tags,omitempty"`

		// Traffic manager object names
		Objects *[]string `json:"objects,omitempty"`
	} `json:"zxtms"`
}
