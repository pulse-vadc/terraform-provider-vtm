// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_saml_trustedidp object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	vtm "github.com/pulse-vadc/go-vtm/6.0"
)

func TestResourceSamlTrustedidp(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestSamlTrustedidp")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckSamlTrustedidpDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicSamlTrustedidpConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSamlTrustedidpExists,
				),
			},
		},
	})
}

func testAccCheckSamlTrustedidpExists(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_saml_trustedidp" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSamlTrustedidp(objectName); err != nil {
			return fmt.Errorf("SamlTrustedidp %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckSamlTrustedidpDestroy(s *terraform.State) error {
	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_saml_trustedidp" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetSamlTrustedidp(objectName); err == nil {
			return fmt.Errorf("SamlTrustedidp %s still exists", objectName)
		}
	}

	return nil
}

func getBasicSamlTrustedidpConfig(name string) string {
	return fmt.Sprintf(`
        resource "vtm_saml_trustedidp" "test_vtm_saml_trustedidp" {
			name = "%s"
			certificate = "MIIDTzCCAjegAwIBAgIIECjOwJfReVYwDQYJKoZIhvcNAQELBQAwVjELMAkGA1UEBhMCR0IxEjAQBgNVBAcTCUNhbWJyaWRnZTEOMAwGA1UEChMFUHVsc2UxDDAKBgNVBAsTA0RldjEVMBMGA1UEAxMMd3d3LnRlc3QubmV0MB4XDTE4MDMxMzExMTAyOVoXDTI4MDMxMjExMTAyOVowVjELMAkGA1UEBhMCR0IxEjAQBgNVBAcTCUNhbWJyaWRnZTEOMAwGA1UEChMFUHVsc2UxDDAKBgNVBAsTA0RldjEVMBMGA1UEAxMMd3d3LnRlc3QubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArSZArz2/shOHqVojpSpdyxUo+vnkpg9wo3fskCXkE3jRPD5xJ4sJScT8TCAPuXKoyFppEBKI80u/rJf5mQBJq5XYKIZgkZ9032EWUcUknO+yL0YrPNKfesXgEjm7us7PNkVpVOp/x2ci2aQ8B+Gcnb6HkwwJ5dXHCK7JPlT39NPMx4JIg8HO0GaSGwLBH6AGiZffYvwe7KlGZRVodHgNLgky4Ej6Jp5HrncOdPcBuDHxb3Vrl3wsFHzcNHCQl/kGLKzWMrMagBg1Cn9G2jyKp0sDKv7podvwVjUVTl+fk7g5swcMe5IaiWZYh9LZGxK3N6BYeQZ0aFLy2njsRf3v4QIDAQABoyEwHzAdBgNVHQ4EFgQUtG4esyVxoT8oG2KQGWTbTgXsXOMwDQYJKoZIhvcNAQELBQADggEBAFNdJQarohgpot3JhOM2la+J6r/poOc/ZDGiNNEqbgGFcf6z4hAsuBtp9Ujr5BSN69jJpHItucC1j41iLrPsUkHscmXF4U8k+Zf7dvo/NOqZwMVSiLw1w33rfF4Rpge/HeMHIwNfqOCX9XtIqy9RB739vd6IXeHlRFRSH6E09J/SRgx0nI5wfN8b1e2FwmF556K+7JMsPf+T+7gu90of0nAbjQGhko1AqoGibXcMqA8JSKo7D6Sadnj42r6VRmA+QrkrnBYmZGCE9rXk9Fs+Qz0A3XdnXfxpN1ClNfxFV5BeiUCd+FsDvspq5kCIQKl2dBLCl4qF/hyycxnIZ8v8jFA="
			entity_id = "TEST_TEXT"
			url = "http://www.test.example.com/"

        }`,
		name,
	)
}
