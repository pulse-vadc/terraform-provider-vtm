// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_glb_service object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func TestResourceGlbService(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestGlbService")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckGlbServiceDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicGlbServiceConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGlbServiceExists,
				),
			},
		},
	})
}

func testAccCheckGlbServiceExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_glb_service" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetGlbService(objectName); err != nil {
			return fmt.Errorf("GlbService %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckGlbServiceDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_glb_service" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetGlbService(objectName); err == nil {
			return fmt.Errorf("GlbService %s still exists", objectName)
		}
	}

	return nil
}

func getBasicGlbServiceConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_glb_service" "test_vtm_glb_service" {
			name = "%s"

        }`,
		name,
	)
}
