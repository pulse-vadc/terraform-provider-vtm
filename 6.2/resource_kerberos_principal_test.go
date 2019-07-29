// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_kerberos_principal object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func TestResourceKerberosPrincipal(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestKerberosPrincipal")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckKerberosPrincipalDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicKerberosPrincipalConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKerberosPrincipalExists,
				),
			},
		},
	})
}

func testAccCheckKerberosPrincipalExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_kerberos_principal" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetKerberosPrincipal(objectName); err != nil {
			return fmt.Errorf("KerberosPrincipal %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckKerberosPrincipalDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_kerberos_principal" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		tm.DeleteKerberosKeytab("TEST_TEXT")
		if _, err := tm.GetKerberosPrincipal(objectName); err == nil {
			return fmt.Errorf("KerberosPrincipal %s still exists", objectName)
		}
	}

	return nil
}

func getBasicKerberosPrincipalConfig(name string) string {
	tm, _ := getTestVtm()
	tm.SetKerberosKeytab("TEST_TEXT", "CONTENT")
	return fmt.Sprintf(`
        resource "vtm_kerberos_principal" "test_vtm_kerberos_principal" {
			name = "%s"
			keytab = "TEST_TEXT"
			service = "TEST_TEXT"

        }`,
		name,
	)
}
