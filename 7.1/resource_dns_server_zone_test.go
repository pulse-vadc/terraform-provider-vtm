// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_dns_server_zone object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/7.1"
)

func TestResourceDnsServerZone(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestDnsServerZone")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckDnsServerZoneDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicDnsServerZoneConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckDnsServerZoneExists,
				),
			},
		},
	})
}

func testAccCheckDnsServerZoneExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_dns_server_zone" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetDnsServerZone(objectName); err != nil {
			return fmt.Errorf("DnsServerZone %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckDnsServerZoneDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_dns_server_zone" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		tm.DeleteDnsServerZoneFile("TEST_TEXT")
		if _, err := tm.GetDnsServerZone(objectName); err == nil {
			return fmt.Errorf("DnsServerZone %s still exists", objectName)
		}
	}

	return nil
}

func getBasicDnsServerZoneConfig(name string) string {
	tm, _ := getTestVtm()
	tm.SetDnsServerZoneFile("TEST_TEXT", "CONTENT")
	return fmt.Sprintf(`
        resource "vtm_dns_server_zone" "test_vtm_dns_server_zone" {
			name = "%s"
			origin = "TEST_TEXT"
			zonefile = "TEST_TEXT"

        }`,
		name,
	)
}
