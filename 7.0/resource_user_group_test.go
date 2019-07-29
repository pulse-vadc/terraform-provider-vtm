// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_user_group object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
)

func TestResourceUserGroup(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestUserGroup")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckUserGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicUserGroupConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckUserGroupExists,
				),
			},
		},
	})
}

func testAccCheckUserGroupExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_user_group" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetUserGroup(objectName); err != nil {
			return fmt.Errorf("UserGroup %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckUserGroupDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_user_group" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetUserGroup(objectName); err == nil {
			return fmt.Errorf("UserGroup %s still exists", objectName)
		}
	}

	return nil
}

func getBasicUserGroupConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_user_group" "test_vtm_user_group" {
			name = "%s"

        }`,
		name,
	)
}
