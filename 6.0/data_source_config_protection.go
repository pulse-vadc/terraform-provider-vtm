// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceProtection() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceProtectionRead,
		Schema: setAllNotRequired(getResourceProtectionSchema()),
	}
}

func dataSourceProtectionRead(d *schema.ResourceData, tm interface{}) error {
	return resourceProtectionRead(d, tm)
}
