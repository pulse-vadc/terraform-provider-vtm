// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_custom object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceCustom(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestCustom")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckCustomDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicCustomConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckCustomExists,
				),
			},
		},
	})
}

func testAccCheckCustomExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_custom" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetCustom(objectName); err != nil {
			return fmt.Errorf("Custom %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckCustomDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_custom" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetCustom(objectName); err == nil {
			return fmt.Errorf("Custom %s still exists", objectName)
		}
	}

	return nil
}

func getBasicCustomConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_custom" "test_vtm_custom" {
			name = "%s"

        }`,
		name,
	)
}
