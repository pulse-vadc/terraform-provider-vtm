// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceCloudApiCredential() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceCloudApiCredentialRead,
		Schema: setAllNotRequired(getResourceCloudApiCredentialSchema()),
	}
}

func dataSourceCloudApiCredentialRead(d *schema.ResourceData, tm interface{}) error {
	return resourceCloudApiCredentialRead(d, tm)
}
