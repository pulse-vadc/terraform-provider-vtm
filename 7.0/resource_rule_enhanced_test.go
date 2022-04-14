// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - CRUD of a non-singleton, text-only resource
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/pulse-vadc/go-vtm/7.0"
)

func TestResourceRuleEnhanced(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestRule")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRuleEnhancedDestroy,
		Steps: []resource.TestStep{
			{
				Config: getRuleEnhancedConfig(objName, "one"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRuleEnhancedExists,
					resource.TestCheckResourceAttr("vtm_rule.my_rule", "content", "log.info('one');"),
				),
			},
			{
				Config: getRuleEnhancedConfig(objName, "two"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vtm_rule.my_rule", "content", "log.info('two');"),
				),
			},

		},
	})
}

func testAccCheckRuleEnhancedExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_rule" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetRule(objectName); err != nil {
			return fmt.Errorf("Rule %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckRuleEnhancedDestroy(s *terraform.State) error {

	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_rule" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetRule(objectName); err == nil {
			return fmt.Errorf("Rule %s still exists", objectName)
		}
	}

	return nil
}

func getRuleEnhancedConfig(name, ruleInsert string) string {
	return fmt.Sprintf(`
		resource "vtm_rule" "my_rule" {
			name = "%s"
			content = "log.info('%s');"
		}`,
		name, ruleInsert,
	)
}
