// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceBgpneighbor() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceBgpneighborRead,
		Schema: setAllNotRequired(getResourceBgpneighborSchema()),
	}
}

func dataSourceBgpneighborRead(d *schema.ResourceData, tm interface{}) error {
	return resourceBgpneighborRead(d, tm)
}
