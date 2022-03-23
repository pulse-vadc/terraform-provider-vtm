// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_monitor object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/8.0"
)

func TestResourceMonitor(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestMonitor")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckMonitorDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicMonitorConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckMonitorExists,
				),
			},
		},
	})
}

func testAccCheckMonitorExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_monitor" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetMonitor(objectName); err != nil {
			return fmt.Errorf("Monitor %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckMonitorDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_monitor" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetMonitor(objectName); err == nil {
			return fmt.Errorf("Monitor %s still exists", objectName)
		}
	}

	return nil
}

func getBasicMonitorConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_monitor" "test_vtm_monitor" {
			name = "%s"

        }`,
		name,
	)
}
