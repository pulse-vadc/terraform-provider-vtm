// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - cRUd operations on a singleton config object
 *   - //Setting non-zero defaults on string, integer, boolean and string list fields
 *   - //Setting specified values on fields with non-zero defaults
 *   - //Ensuring removed fields revert to defaults
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestResourceGlobalSettingsEnhanced(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: dummyCheckGlobalSettingsEnhancedDeleted,
		Steps: []resource.TestStep{
			{
				Config: getBasicGlobalSettingsEnhancedConfig(),
				Check: resource.ComposeTestCheckFunc(
					// Check that an integer default is set
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "chunk_size", "16384"),
					// Check that a string default is set
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "shared_pool_size", "10MB"),
					// Check that an integer default is overridden
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "accepting_delay", "100"),
					// Check that a string default is overridden
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "socket_optimizations", "yes"),
					// Check that a boolean default is overridden
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "appliance_return_path_routing_enabled", "true"),
				),
			},
			{
				Config: getResetGlobalSettingsEnhancedConfig(),
				Check: resource.ComposeTestCheckFunc(
					// Check that a removed integer integer field reverts to default value
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "accepting_delay", "50"),
					// Check that a removed string integer field reverts to default value
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "socket_optimizations", "auto"),
					// Check that a removed boolean integer field reverts to default value
					resource.TestCheckResourceAttr("vtm_global_settings.global_settings", "appliance_return_path_routing_enabled", "false"),
				),
			},
		},
	})
}

func dummyCheckGlobalSettingsEnhancedDeleted(s *terraform.State) error {
	return nil
}

func getBasicGlobalSettingsEnhancedConfig() string {
	return fmt.Sprintf(`
		resource "vtm_global_settings" "global_settings" {
			accepting_delay = 100
			socket_optimizations = "yes"
			appliance_return_path_routing_enabled = true
		}`,
	)
}

func getResetGlobalSettingsEnhancedConfig() string {
	return fmt.Sprintf(`
		resource "vtm_global_settings" "global_settings" {
		}`,
	)
}
