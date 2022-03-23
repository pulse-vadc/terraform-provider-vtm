// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceSslAdminCa() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceSslAdminCaRead,
		Schema: setAllNotRequired(getResourceSslAdminCaSchema()),
	}
}

func dataSourceSslAdminCaRead(d *schema.ResourceData, tm interface{}) error {
	return resourceSslAdminCaRead(d, tm)
}
