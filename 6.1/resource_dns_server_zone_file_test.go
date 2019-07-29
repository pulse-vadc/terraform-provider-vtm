// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_dns_server_zone_file object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceDnsServerZoneFile(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestDnsServerZoneFile")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckDnsServerZoneFileDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicDnsServerZoneFileConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckDnsServerZoneFileExists,
				),
			},
		},
	})
}

func testAccCheckDnsServerZoneFileExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_dns_server_zone_file" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetDnsServerZoneFile(objectName); err != nil {
			return fmt.Errorf("DnsServerZoneFile %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckDnsServerZoneFileDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_dns_server_zone_file" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetDnsServerZoneFile(objectName); err == nil {
			return fmt.Errorf("DnsServerZoneFile %s still exists", objectName)
		}
	}

	return nil
}

func getBasicDnsServerZoneFileConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_dns_server_zone_file" "test_vtm_dns_server_zone_file" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
