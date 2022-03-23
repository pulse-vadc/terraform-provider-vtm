// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_service_level_monitor object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/8.2"
)

func TestResourceServiceLevelMonitor(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestServiceLevelMonitor")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckServiceLevelMonitorDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicServiceLevelMonitorConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckServiceLevelMonitorExists,
				),
			},
		},
	})
}

func testAccCheckServiceLevelMonitorExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_service_level_monitor" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetServiceLevelMonitor(objectName); err != nil {
			return fmt.Errorf("ServiceLevelMonitor %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckServiceLevelMonitorDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_service_level_monitor" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetServiceLevelMonitor(objectName); err == nil {
			return fmt.Errorf("ServiceLevelMonitor %s still exists", objectName)
		}
	}

	return nil
}

func getBasicServiceLevelMonitorConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_service_level_monitor" "test_vtm_service_level_monitor" {
			name = "%s"

        }`,
		name,
	)
}
