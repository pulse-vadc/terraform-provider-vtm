// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourcePersistence() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourcePersistenceRead,
		Schema: setAllNotRequired(getResourcePersistenceSchema()),
	}
}

func dataSourcePersistenceRead(d *schema.ResourceData, tm interface{}) error {
	return resourcePersistenceRead(d, tm)
}
