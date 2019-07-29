// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_ssl_ca object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceSslCa(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestSslCa")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckSslCaDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicSslCaConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSslCaExists,
				),
			},
		},
	})
}

func testAccCheckSslCaExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_ssl_ca" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSslCa(objectName); err != nil {
			return fmt.Errorf("SslCa %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckSslCaDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_ssl_ca" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSslCa(objectName); err == nil {
			return fmt.Errorf("SslCa %s still exists", objectName)
		}
	}

	return nil
}

func getBasicSslCaConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_ssl_ca" "test_vtm_ssl_ca" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
