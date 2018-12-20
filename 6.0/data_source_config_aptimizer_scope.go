// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceAptimizerScope() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceAptimizerScopeRead,
		Schema: setAllNotRequired(getResourceAptimizerScopeSchema()),
	}
}

func dataSourceAptimizerScopeRead(d *schema.ResourceData, tm interface{}) error {
	return resourceAptimizerScopeRead(d, tm)
}
