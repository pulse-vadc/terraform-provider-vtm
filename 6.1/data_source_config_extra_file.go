// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceExtraFile() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceExtraFileRead,
		Schema: setAllNotRequired(getResourceExtraFileSchema()),
	}
}

func dataSourceExtraFileRead(d *schema.ResourceData, tm interface{}) error {
	return resourceExtraFileRead(d, tm)
}
