// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceTrafficManager() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceTrafficManagerRead,
		Schema: setAllNotRequired(getResourceTrafficManagerSchema()),
	}
}

func dataSourceTrafficManagerRead(d *schema.ResourceData, tm interface{}) error {
	return resourceTrafficManagerRead(d, tm)
}
