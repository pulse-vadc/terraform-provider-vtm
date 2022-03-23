// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *    - Reading of system object fields
 */

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
)

func TestDataSourceSystemState(t *testing.T) {
   var validError = regexp.MustCompile("^(ok|warn|error)$")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getDataSourceSystemStateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("data.vtm_state.state", "state_error_level", validError),
				),
			},
		},
	})
}

func getDataSourceSystemStateConfig() string {
	return fmt.Sprintf(`
		data "vtm_state" "state" {
		}`,
	)
}
