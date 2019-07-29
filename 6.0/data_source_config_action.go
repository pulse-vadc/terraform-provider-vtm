// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceAction() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceActionRead,
		Schema: setAllNotRequired(getResourceActionSchema()),
	}
}

func dataSourceActionRead(d *schema.ResourceData, tm interface{}) error {
	return resourceActionRead(d, tm)
}
