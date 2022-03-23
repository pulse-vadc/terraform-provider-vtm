// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_rule_authenticator object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceRuleAuthenticator(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestRuleAuthenticator")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRuleAuthenticatorDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicRuleAuthenticatorConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRuleAuthenticatorExists,
				),
			},
		},
	})
}

func testAccCheckRuleAuthenticatorExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_rule_authenticator" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetRuleAuthenticator(objectName); err != nil {
			return fmt.Errorf("RuleAuthenticator %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckRuleAuthenticatorDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_rule_authenticator" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetRuleAuthenticator(objectName); err == nil {
			return fmt.Errorf("RuleAuthenticator %s still exists", objectName)
		}
	}

	return nil
}

func getBasicRuleAuthenticatorConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_rule_authenticator" "test_vtm_rule_authenticator" {
			name = "%s"

        }`,
		name,
	)
}
