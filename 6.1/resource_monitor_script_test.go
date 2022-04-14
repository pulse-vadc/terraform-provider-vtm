// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_monitor_script object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceMonitorScript(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestMonitorScript")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckMonitorScriptDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicMonitorScriptConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckMonitorScriptExists,
				),
			},
		},
	})
}

func testAccCheckMonitorScriptExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_monitor_script" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetMonitorScript(objectName); err != nil {
			return fmt.Errorf("MonitorScript %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckMonitorScriptDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_monitor_script" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetMonitorScript(objectName); err == nil {
			return fmt.Errorf("MonitorScript %s still exists", objectName)
		}
	}

	return nil
}

func getBasicMonitorScriptConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_monitor_script" "test_vtm_monitor_script" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
