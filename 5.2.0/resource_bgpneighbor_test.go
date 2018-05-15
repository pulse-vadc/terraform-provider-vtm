// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_bgpneighbor object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func TestResourceBgpneighbor(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestBgpneighbor")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckBgpneighborDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicBgpneighborConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckBgpneighborExists,
				),
			},
		},
	})
}

func testAccCheckBgpneighborExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_bgpneighbor" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetBgpneighbor(objectName); err != nil {
			return fmt.Errorf("Bgpneighbor %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckBgpneighborDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_bgpneighbor" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetBgpneighbor(objectName); err == nil {
			return fmt.Errorf("Bgpneighbor %s still exists", objectName)
		}
	}

	return nil
}

func getBasicBgpneighborConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_bgpneighbor" "test_vtm_bgpneighbor" {
			name = "%s"

        }`,
		name,
	)
}
