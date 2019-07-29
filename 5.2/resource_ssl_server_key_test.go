// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_ssl_server_key object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/5.2"
)

func TestResourceSslServerKey(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestSslServerKey")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckSslServerKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicSslServerKeyConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSslServerKeyExists,
				),
			},
		},
	})
}

func testAccCheckSslServerKeyExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_ssl_server_key" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSslServerKey(objectName); err != nil {
			return fmt.Errorf("SslServerKey %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckSslServerKeyDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_ssl_server_key" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSslServerKey(objectName); err == nil {
			return fmt.Errorf("SslServerKey %s still exists", objectName)
		}
	}

	return nil
}

func getBasicSslServerKeyConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_ssl_server_key" "test_vtm_ssl_server_key" {
			name = "%s"
			note = "TEST_TEXT"
			private = "TEST_TEXT"
			public = "TEST_TEXT"
			request = "TEST_TEXT"

        }`,
		name,
	)
}
