// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import "github.com/hashicorp/terraform/helper/schema"

func dataSourceKerberosKrb5Conf() *schema.Resource {
	return &schema.Resource{
		Read:   dataSourceKerberosKrb5ConfRead,
		Schema: setAllNotRequired(getResourceKerberosKrb5ConfSchema()),
	}
}

func dataSourceKerberosKrb5ConfRead(d *schema.ResourceData, tm interface{}) error {
	return resourceKerberosKrb5ConfRead(d, tm)
}
