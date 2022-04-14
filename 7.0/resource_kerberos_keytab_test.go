// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_kerberos_keytab object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/7.0"
)

func TestResourceKerberosKeytab(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestKerberosKeytab")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckKerberosKeytabDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicKerberosKeytabConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKerberosKeytabExists,
				),
			},
		},
	})
}

func testAccCheckKerberosKeytabExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_kerberos_keytab" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetKerberosKeytab(objectName); err != nil {
			return fmt.Errorf("KerberosKeytab %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckKerberosKeytabDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_kerberos_keytab" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetKerberosKeytab(objectName); err == nil {
			return fmt.Errorf("KerberosKeytab %s still exists", objectName)
		}
	}

	return nil
}

func getBasicKerberosKeytabConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_kerberos_keytab" "test_vtm_kerberos_keytab" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
