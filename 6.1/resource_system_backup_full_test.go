// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_system_backup_full object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/pulse-vadc/go-vtm/6.1"
)

func TestResourceSystemBackupsFull(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestBackupFull")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckSystemBackupsFullDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicSystemBackupsFullConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSystemBackupsFullExists,
					resource.TestCheckResourceAttr("vtm_backups_full.test_vtm_backups_full", "description", "TEST_TEXT"),
				),
			},
		},
	})
}

func testAccCheckSystemBackupsFullExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_backups_full" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSystemBackupsFull(objectName); err != nil {
			return fmt.Errorf("BackupsFull %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckSystemBackupsFullDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_backups_full" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSystemBackupsFull(objectName); err == nil {
			return fmt.Errorf("BackupsFull %s still exists", objectName)
		}
	}

	return nil
}

func getBasicSystemBackupsFullConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_backups_full" "test_vtm_backups_full" {
			name = "%s"
			description = "TEST_TEXT"
        }`,
		name,
	)
}
