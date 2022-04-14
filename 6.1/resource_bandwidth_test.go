// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_bandwidth object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceBandwidth(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestBandwidth")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckBandwidthDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicBandwidthConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckBandwidthExists,
				),
			},
		},
	})
}

func testAccCheckBandwidthExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_bandwidth" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetBandwidth(objectName); err != nil {
			return fmt.Errorf("Bandwidth %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckBandwidthDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_bandwidth" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetBandwidth(objectName); err == nil {
			return fmt.Errorf("Bandwidth %s still exists", objectName)
		}
	}

	return nil
}

func getBasicBandwidthConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_bandwidth" "test_vtm_bandwidth" {
			name = "%s"

        }`,
		name,
	)
}
