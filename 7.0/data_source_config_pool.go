// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourcePool() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourcePoolRead,
		Schema: setAllNotRequired(getResourcePoolSchema()),
	}
}

func dataSourcePoolRead(d *schema.ResourceData, tm interface{}) error {
	return resourcePoolRead(d, tm)
}
