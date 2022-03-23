// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Go library for Pulse Virtual Traffic Manager REST version 5.2.
package vtm

import (
	"encoding/json"
)

type GlbService struct {
	connector            *vtmConnector
	GlbServiceProperties `json:"properties"`
}

func (vtm VirtualTrafficManager) GetGlbService(name string) (*GlbService, *vtmErrorResponse) {
	if name == "" {
		panic("Provided an empty \"name\" parameter to VirtualTrafficManager.GetGlbService(name)")
	}
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/glb_services/" + name)
	data, ok := conn.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return nil, object
	}
	object := new(GlbService)
	object.connector = conn
	if err := json.NewDecoder(data).Decode(object); err != nil {
		panic(err)
	}
	return object, nil
}

func (object GlbService) Apply() (*GlbService, *vtmErrorResponse) {
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

func (vtm VirtualTrafficManager) NewGlbService(name string) *GlbService {
	object := new(GlbService)

	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/glb_services/" + name)
	object.connector = conn
	return object
}

func (vtm VirtualTrafficManager) DeleteGlbService(name string) *vtmErrorResponse {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/glb_services/" + name)
	data, ok := conn.delete()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return object
	}
	return nil
}

func (vtm VirtualTrafficManager) ListGlbServices() (*[]string, *vtmErrorResponse) {
	conn := vtm.connector.getChildConnector("/tm/5.2/config/active/glb_services")
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

type GlbServiceProperties struct {
	Basic struct {
		// Defines the global load balancing algorithm to be used.
		Algorithm *string `json:"algorithm,omitempty"`

		// Are all the monitors required to be working in a location to
		//  mark this service as alive?
		AllMonitorsNeeded *bool `json:"all_monitors_needed,omitempty"`

		// The last location to fail will be available as soon as it recovers.
		Autorecovery *bool `json:"autorecovery,omitempty"`

		// Enable/Disable automatic failback mode.
		ChainedAutoFailback *bool `json:"chained_auto_failback,omitempty"`

		// The locations this service operates for and defines the order
		//  in which locations fail.
		ChainedLocationOrder *[]string `json:"chained_location_order,omitempty"`

		// Locations recovering from a failure will become disabled.
		DisableOnFailure *bool `json:"disable_on_failure,omitempty"`

		// A table mapping domains to the private keys that authenticate
		//  them
		DnssecKeys *GlbServiceDnssecKeysTable `json:"dnssec_keys,omitempty"`

		// The domains shown here should be a list of Fully Qualified Domain
		//  Names that you would like to balance globally. Responses from
		//  the back end DNS servers for queries that do not match this list
		//  will be forwarded to the client unmodified. Note: "*" may be
		//  used as a wild card.
		Domains *[]string `json:"domains,omitempty"`

		// Enable/Disable our response manipulation of DNS.
		Enabled *bool `json:"enabled,omitempty"`

		// How much should the locality of visitors affect the choice of
		//  location used? This value is a percentage, 0% means that no locality
		//  information will be used, and 100% means that locality will always
		//  control which location is used. Values between the two extremes
		//  will act accordingly.
		GeoEffect *int `json:"geo_effect,omitempty"`

		// The response to be sent in case there are no locations available.
		LastResortResponse *[]string `json:"last_resort_response,omitempty"`

		// This is the list of locations for which this service is draining.
		//  A location that is draining will never serve any of its service
		//  IP addresses for this domain. This can be used to take a location
		//  off-line.
		LocationDraining *[]string `json:"location_draining,omitempty"`

		// Table containing location specific settings.
		LocationSettings *GlbServiceLocationSettingsTable `json:"location_settings,omitempty"`

		// Peer reported monitor state timeout in seconds.
		PeerHealthTimeout *int `json:"peer_health_timeout,omitempty"`

		// Return all or none of the IPs under complete failure.
		ReturnIpsOnFail *bool `json:"return_ips_on_fail,omitempty"`

		// Response rules to be applied in the context of the service, in
		//  order, comma separated.
		Rules *[]string `json:"rules,omitempty"`

		// The TTL for the DNS resource records handled by the GLB service.
		Ttl *int `json:"ttl,omitempty"`
	} `json:"basic"`

	Log struct {
		// Log connections to this GLB service?
		Enabled *bool `json:"enabled,omitempty"`

		// The filename the verbose query information should be logged to.
		//  Appliances will ignore this.
		Filename *string `json:"filename,omitempty"`

		// The format of the log lines.
		Format *string `json:"format,omitempty"`
	} `json:"log"`
}

type GlbServiceDnssecKeys struct {
	// A domain authenticated by the associated private keys.
	Domain *string `json:"domain,omitempty"`

	// Private keys that authenticate the associated domain.
	SslKey *[]string `json:"ssl_key,omitempty"`
}

type GlbServiceDnssecKeysTable []GlbServiceDnssecKeys

type GlbServiceLocationSettings struct {
	// The IP addresses that are present in a location. If the Global
	//  Load Balancer decides to direct a DNS query to this location,
	//  then it will filter out all IPs that are not in this list.
	Ips *[]string `json:"ips,omitempty"`

	// Location to which the associated settings apply.
	Location *string `json:"location,omitempty"`

	// The monitors that are present in a location.
	Monitors *[]string `json:"monitors,omitempty"`

	// Weight for this location, for use by the weighted random algorithm.
	Weight *int `json:"weight,omitempty"`
}

type GlbServiceLocationSettingsTable []GlbServiceLocationSettings
