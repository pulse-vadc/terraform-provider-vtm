// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceLocation() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceLocationRead,
		Schema: setAllNotRequired(getResourceLocationSchema()),
	}
}

func dataSourceLocationRead(d *schema.ResourceData, tm interface{}) error {
	return resourceLocationRead(d, tm)
}
