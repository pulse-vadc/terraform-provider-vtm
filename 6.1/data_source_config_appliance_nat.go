// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceApplianceNat() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceApplianceNatRead,
		Schema: setAllNotRequired(getResourceApplianceNatSchema()),
	}
}

func dataSourceApplianceNatRead(d *schema.ResourceData, tm interface{}) error {
	return resourceApplianceNatRead(d, tm)
}
