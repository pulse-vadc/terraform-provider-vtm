// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceVirtualServer() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceVirtualServerRead,
		Schema: setAllNotRequired(getResourceVirtualServerSchema()),
	}
}

func dataSourceVirtualServerRead(d *schema.ResourceData, tm interface{}) error {
	return resourceVirtualServerRead(d, tm)
}
