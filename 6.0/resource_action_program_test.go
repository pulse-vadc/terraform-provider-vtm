// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_action_program object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func TestResourceActionProgram(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestActionProgram")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckActionProgramDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicActionProgramConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckActionProgramExists,
				),
			},
		},
	})
}

func testAccCheckActionProgramExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_action_program" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetActionProgram(objectName); err != nil {
			return fmt.Errorf("ActionProgram %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckActionProgramDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_action_program" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetActionProgram(objectName); err == nil {
			return fmt.Errorf("ActionProgram %s still exists", objectName)
		}
	}

	return nil
}

func getBasicActionProgramConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_action_program" "test_vtm_action_program" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
