// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceGlbService() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceGlbServiceRead,
		Schema: setAllNotRequired(getResourceGlbServiceSchema()),
	}
}

func dataSourceGlbServiceRead(d *schema.ResourceData, tm interface{}) error {
	return resourceGlbServiceRead(d, tm)
}
