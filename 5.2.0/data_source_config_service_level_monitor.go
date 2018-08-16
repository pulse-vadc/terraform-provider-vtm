// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceServiceLevelMonitor() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceServiceLevelMonitorRead,
		Schema: setAllNotRequired(getResourceServiceLevelMonitorSchema()),
	}
}

func dataSourceServiceLevelMonitorRead(d *schema.ResourceData, tm interface{}) error {
	return resourceServiceLevelMonitorRead(d, tm)
}
