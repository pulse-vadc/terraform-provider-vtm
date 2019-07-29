// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_protection object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceProtection(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestProtection")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckProtectionDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicProtectionConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckProtectionExists,
				),
			},
		},
	})
}

func testAccCheckProtectionExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_protection" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetProtection(objectName); err != nil {
			return fmt.Errorf("Protection %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckProtectionDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_protection" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetProtection(objectName); err == nil {
			return fmt.Errorf("Protection %s still exists", objectName)
		}
	}

	return nil
}

func getBasicProtectionConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_protection" "test_vtm_protection" {
			name = "%s"

        }`,
		name,
	)
}
