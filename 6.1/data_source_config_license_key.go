// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceLicenseKey() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceLicenseKeyRead,
		Schema: setAllNotRequired(getResourceLicenseKeySchema()),
	}
}

func dataSourceLicenseKeyRead(d *schema.ResourceData, tm interface{}) error {
	return resourceLicenseKeyRead(d, tm)
}
