// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_license_key object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func TestResourceLicenseKey(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestLicenseKey")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckLicenseKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicLicenseKeyConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckLicenseKeyExists,
				),
			},
		},
	})
}

func testAccCheckLicenseKeyExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_license_key" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetLicenseKey(objectName); err != nil {
			return fmt.Errorf("LicenseKey %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckLicenseKeyDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_license_key" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetLicenseKey(objectName); err == nil {
			return fmt.Errorf("LicenseKey %s still exists", objectName)
		}
	}

	return nil
}

func getBasicLicenseKeyConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_license_key" "test_vtm_license_key" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
