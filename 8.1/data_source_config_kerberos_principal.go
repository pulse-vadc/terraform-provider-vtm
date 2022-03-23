// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceKerberosPrincipal() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceKerberosPrincipalRead,
		Schema: setAllNotRequired(getResourceKerberosPrincipalSchema()),
	}
}

func dataSourceKerberosPrincipalRead(d *schema.ResourceData, tm interface{}) error {
	return resourceKerberosPrincipalRead(d, tm)
}
