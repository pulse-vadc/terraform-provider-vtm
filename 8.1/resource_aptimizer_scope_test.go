// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_aptimizer_scope object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func TestResourceAptimizerScope(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestAptimizerScope")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAptimizerScopeDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicAptimizerScopeConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAptimizerScopeExists,
				),
			},
		},
	})
}

func testAccCheckAptimizerScopeExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_aptimizer_scope" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetAptimizerScope(objectName); err != nil {
			return fmt.Errorf("AptimizerScope %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckAptimizerScopeDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_aptimizer_scope" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetAptimizerScope(objectName); err == nil {
			return fmt.Errorf("AptimizerScope %s still exists", objectName)
		}
	}

	return nil
}

func getBasicAptimizerScopeConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_aptimizer_scope" "test_vtm_aptimizer_scope" {
			name = "%s"

        }`,
		name,
	)
}
