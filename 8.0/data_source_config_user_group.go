// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceUserGroup() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceUserGroupRead,
		Schema: setAllNotRequired(getResourceUserGroupSchema()),
	}
}

func dataSourceUserGroupRead(d *schema.ResourceData, tm interface{}) error {
	return resourceUserGroupRead(d, tm)
}
