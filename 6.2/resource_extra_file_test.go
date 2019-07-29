// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_extra_file object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func TestResourceExtraFile(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestExtraFile")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckExtraFileDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicExtraFileConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExtraFileExists,
				),
			},
		},
	})
}

func testAccCheckExtraFileExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_extra_file" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetExtraFile(objectName); err != nil {
			return fmt.Errorf("ExtraFile %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckExtraFileDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_extra_file" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetExtraFile(objectName); err == nil {
			return fmt.Errorf("ExtraFile %s still exists", objectName)
		}
	}

	return nil
}

func getBasicExtraFileConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_extra_file" "test_vtm_extra_file" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
