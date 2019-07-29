// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_action object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceAction(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestAction")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckActionDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicActionConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckActionExists,
				),
			},
		},
	})
}

func testAccCheckActionExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_action" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetAction(objectName); err != nil {
			return fmt.Errorf("Action %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckActionDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_action" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetAction(objectName); err == nil {
			return fmt.Errorf("Action %s still exists", objectName)
		}
	}

	return nil
}

func getBasicActionConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_action" "test_vtm_action" {
			name = "%s"
			type = "email"

        }`,
		name,
	)
}
