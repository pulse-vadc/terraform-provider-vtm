// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - cRUd operations on the special-case vtm_traffic_manager config object
 */

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestResourceTrafficManagerEnhanced(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: dummyCheckTrafficManagerEnhancedDeleted,
		Steps: []resource.TestStep{
			{
				Config: getNonExistentTrafficManagerEnhancedConfig(),
				ExpectError: regexp.MustCompile("Failed"),
			},
			{
				Config: getEmptyTrafficManagerEnhancedConfig(),
				Check: resource.ComposeTestCheckFunc(
					// Check that a boolean default is set
					resource.TestCheckResourceAttr("vtm_traffic_manager.test_traffic_manager", "appliance_ipv4_forwarding", "false"),
				),
			},
			{
				Config: getBasicTrafficManagerEnhancedConfig(),
				Check: resource.ComposeTestCheckFunc(
					// Check that a boolean default is overridden
					resource.TestCheckResourceAttr("vtm_traffic_manager.test_traffic_manager", "appliance_ipv4_forwarding", "true"),
				),
			},
		},
	})
}

func dummyCheckTrafficManagerEnhancedDeleted(s *terraform.State) error {
	return nil
}

func getNonExistentTrafficManagerEnhancedConfig() string {
	return fmt.Sprintf(`
		resource "vtm_traffic_manager" "test_traffic_manager" {
			name = "non_existent_vtm"
		}`,
	)
}

func getEmptyTrafficManagerEnhancedConfig() string {
	return fmt.Sprintf(`
		data "vtm_traffic_manager_list" "tm_list" {}

		resource "vtm_traffic_manager" "test_traffic_manager" {
			name = "${data.vtm_traffic_manager_list.tm_list.object_list.0}"
		}`,
	)
}

func getBasicTrafficManagerEnhancedConfig() string {
	return fmt.Sprintf(`
		data "vtm_traffic_manager_list" "tm_list" {}

		resource "vtm_traffic_manager" "test_traffic_manager" {
			name = "${data.vtm_traffic_manager_list.tm_list.object_list.0}"
			appliance_ipv4_forwarding = true
		}`,
	)
}

