// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_user_authenticator object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func TestResourceUserAuthenticator(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestUserAuthenticator")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckUserAuthenticatorDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicUserAuthenticatorConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckUserAuthenticatorExists,
				),
			},
		},
	})
}

func testAccCheckUserAuthenticatorExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_user_authenticator" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetUserAuthenticator(objectName); err != nil {
			return fmt.Errorf("UserAuthenticator %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckUserAuthenticatorDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_user_authenticator" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetUserAuthenticator(objectName); err == nil {
			return fmt.Errorf("UserAuthenticator %s still exists", objectName)
		}
	}

	return nil
}

func getBasicUserAuthenticatorConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_user_authenticator" "test_vtm_user_authenticator" {
			name = "%s"
			type = "ldap"

        }`,
		name,
	)
}
