// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceSecurity() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceSecurityRead,
		Schema: setAllNotRequired(getResourceSecuritySchema()),
	}
}

func dataSourceSecurityRead(d *schema.ResourceData, tm interface{}) error {
	return resourceSecurityRead(d, tm)
}
