// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_pool object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourcePool(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestPool")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPoolDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicPoolConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPoolExists,
				),
			},
		},
	})
}

func testAccCheckPoolExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_pool" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetPool(objectName); err != nil {
			return fmt.Errorf("Pool %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckPoolDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_pool" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetPool(objectName); err == nil {
			return fmt.Errorf("Pool %s still exists", objectName)
		}
	}

	return nil
}

func getBasicPoolConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_pool" "test_vtm_pool" {
			name = "%s"

        }`,
		name,
	)
}
