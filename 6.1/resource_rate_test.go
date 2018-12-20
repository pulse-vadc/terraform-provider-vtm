// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_rate object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceRate(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestRate")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRateDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicRateConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRateExists,
				),
			},
		},
	})
}

func testAccCheckRateExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_rate" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetRate(objectName); err != nil {
			return fmt.Errorf("Rate %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckRateDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_rate" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetRate(objectName); err == nil {
			return fmt.Errorf("Rate %s still exists", objectName)
		}
	}

	return nil
}

func getBasicRateConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_rate" "test_vtm_rate" {
			name = "%s"

        }`,
		name,
	)
}
