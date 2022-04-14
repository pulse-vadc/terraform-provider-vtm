// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_traffic_ip_group object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func TestResourceTrafficIpGroup(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestTrafficIpGroup")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckTrafficIpGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicTrafficIpGroupConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckTrafficIpGroupExists,
				),
			},
		},
	})
}

func testAccCheckTrafficIpGroupExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_traffic_ip_group" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetTrafficIpGroup(objectName); err != nil {
			return fmt.Errorf("TrafficIpGroup %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckTrafficIpGroupDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_traffic_ip_group" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetTrafficIpGroup(objectName); err == nil {
			return fmt.Errorf("TrafficIpGroup %s still exists", objectName)
		}
	}

	return nil
}

func getBasicTrafficIpGroupConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_traffic_ip_group" "test_vtm_traffic_ip_group" {
			name = "%s"

        }`,
		name,
	)
}
