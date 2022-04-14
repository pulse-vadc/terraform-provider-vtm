// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_ssl_client_key object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func TestResourceSslClientKey(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestSslClientKey")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckSslClientKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicSslClientKeyConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSslClientKeyExists,
				),
			},
		},
	})
}

func testAccCheckSslClientKeyExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_ssl_client_key" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSslClientKey(objectName); err != nil {
			return fmt.Errorf("SslClientKey %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckSslClientKeyDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_ssl_client_key" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSslClientKey(objectName); err == nil {
			return fmt.Errorf("SslClientKey %s still exists", objectName)
		}
	}

	return nil
}

func getBasicSslClientKeyConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_ssl_client_key" "test_vtm_ssl_client_key" {
			name = "%s"
			note = "TEST_TEXT"
			private = "TEST_TEXT"
			public = "TEST_TEXT"
			request = "TEST_TEXT"

        }`,
		name,
	)
}
