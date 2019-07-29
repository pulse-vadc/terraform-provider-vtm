// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_kerberos_krb5conf object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.2"
)

func TestResourceKerberosKrb5Conf(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestKerberosKrb5Conf")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckKerberosKrb5ConfDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicKerberosKrb5ConfConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKerberosKrb5ConfExists,
				),
			},
		},
	})
}

func testAccCheckKerberosKrb5ConfExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_kerberos_krb5conf" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetKerberosKrb5Conf(objectName); err != nil {
			return fmt.Errorf("KerberosKrb5Conf %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckKerberosKrb5ConfDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_kerberos_krb5conf" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetKerberosKrb5Conf(objectName); err == nil {
			return fmt.Errorf("KerberosKrb5Conf %s still exists", objectName)
		}
	}

	return nil
}

func getBasicKerberosKrb5ConfConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_kerberos_krb5conf" "test_vtm_kerberos_krb5conf" {
			name = "%s"
			content = "TEST_TEXT"

        }`,
		name,
	)
}
