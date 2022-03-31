// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_log_export object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func TestResourceLogExport(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestLogExport")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckLogExportDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicLogExportConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckLogExportExists,
				),
			},
		},
	})
}

func testAccCheckLogExportExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_log_export" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetLogExport(objectName); err != nil {
			return fmt.Errorf("LogExport %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckLogExportDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_log_export" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetLogExport(objectName); err == nil {
			return fmt.Errorf("LogExport %s still exists", objectName)
		}
	}

	return nil
}

func getBasicLogExportConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_log_export" "test_vtm_log_export" {
			name = "%s"

        }`,
		name,
	)
}
