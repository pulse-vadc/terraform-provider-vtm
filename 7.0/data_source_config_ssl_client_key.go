// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceSslClientKey() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceSslClientKeyRead,
		Schema: setAllNotRequired(getResourceSslClientKeySchema()),
	}
}

func dataSourceSslClientKeyRead(d *schema.ResourceData, tm interface{}) error {
	return resourceSslClientKeyRead(d, tm)
}
