// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceTrafficIpGroup() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceTrafficIpGroupRead,
		Schema: setAllNotRequired(getResourceTrafficIpGroupSchema()),
	}
}

func dataSourceTrafficIpGroupRead(d *schema.ResourceData, tm interface{}) error {
	return resourceTrafficIpGroupRead(d, tm)
}
