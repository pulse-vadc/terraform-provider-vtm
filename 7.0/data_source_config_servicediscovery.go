// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceServicediscovery() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceServicediscoveryRead,
		Schema: setAllNotRequired(getResourceServicediscoverySchema()),
	}
}

func dataSourceServicediscoveryRead(d *schema.ResourceData, tm interface{}) error {
	return resourceServicediscoveryRead(d, tm)
}
