// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_event_type object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/8.1"
)

func TestResourceEventType(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestEventType")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckEventTypeDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicEventTypeConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckEventTypeExists,
				),
			},
		},
	})
}

func testAccCheckEventTypeExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_event_type" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetEventType(objectName); err != nil {
			return fmt.Errorf("EventType %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckEventTypeDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_event_type" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetEventType(objectName); err == nil {
			return fmt.Errorf("EventType %s still exists", objectName)
		}
	}

	return nil
}

func getBasicEventTypeConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_event_type" "test_vtm_event_type" {
			name = "%s"

        }`,
		name,
	)
}
