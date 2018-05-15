// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *    - Reading of system object fields
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
)

func TestDataSourceSystemState(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getDataSourceSystemStateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_state.state", "data_plane_acceleration_running", "false"),
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
