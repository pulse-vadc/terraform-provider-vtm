// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - CRUD operations on a non-singleton, standard config object
 *   - Setting non-zero defaults on string, integer, boolean and string list fields
 *   - Setting specified values on fields with non-zero defaults
 *   - Ensuring removed fields revert to defaults
 *   - Providing no 'name' field causes invalid config error
 *   - Providing empty 'name' field causes invalid config error
 *   - Setting enum to invalid value causes invalid config error
 *   - Setting integer field to value below min causes invalid config error
 *   - Setting integer field to value above max causes invalid config error
 */

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/pulse-vadc/go-vtm/4.0"
)

func TestResourceVirtualServerEnhanced(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestVirtualServer")
	configInvalidRegex := regexp.MustCompile(`invalid`)

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckVirtualServerEnhancedDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicVirtualServerEnhancedConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVirtualServerEnhancedExists,
					// Check that a required string parameter is set
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "pool", "discard"),
					// Check that a required integer parameter is set
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "port", "1234"),
					// Check that an optional string parameter has the correct default
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "protocol", "http"),
					// Check that an optional integer parameter has the correct default
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "connect_timeout", "10"),
					// Check that an optional boolean parameter has the correct default
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "web_cache_enabled", "false"),
					// Test that a default-empty list is empty
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "request_rules.#", "0"),
					// Test that a default-populated list is correctly populated
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.#", "2"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.0", "text/html"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.1", "text/plain"),
					// Test that a default-empty table is empty
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "ssl_ocsp_issuers.#", "0"),
				),
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfig(objName, "client_first", 4321),
				Check: resource.ComposeTestCheckFunc(
					// Check that a required parameter has been changed
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "port", "4321"),
					// Check that a default string value has been replaced by a provided value
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "protocol", "client_first"),
					// Check that a integer parameter has the specified value
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "connect_timeout", "42"),
					// Check that a boolean parameter has the specified value
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "web_cache_enabled", "true"),
					// Check that a list field has been populated with provided values
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "request_rules.#", "2"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "request_rules.0", "rule1"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "request_rules.1", "rule2"),
					// Check that the default value of a list field has been replaced by a propvided value
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.#", "1"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.0", "application/test"),
					// Test that a table is correctly populated
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "ssl_ocsp_issuers.#", "2"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "ssl_ocsp_issuers.3824273407.issuer", "me"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "ssl_ocsp_issuers.2238529080.issuer", "DEFAULT"),
				),
			},
			{
				Config: getBasicVirtualServerEnhancedConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					// Check that a removed string parameter reverts to its non-zero default
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "protocol", "http"),
					// Check that a removed integer parameter reverts to its non-zero default
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "connect_timeout", "10"),
					// Check that a removed boolean parameter reverts to its default value
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "web_cache_enabled", "false"),
					// Check that a removed default-empty list field has been set to empty
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "request_rules.#", "0"),
					// Check that removed table rows are gone
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "ssl_ocsp_issuers.#", "0"),
					// Test that a default-populated list correctly reverts to default when parameter removed
					// TODO Add this back in when VTMTF-18 is fixed
					//resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.#", "2"),
					//resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.0", "text/html"),
					//resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.1", "text/plain"),
				),
			},
			{
				// Test that a missing 'name' field cause an error
				Config: getMissingVirtualServerEnhancedConfig(),
				ExpectError: configInvalidRegex,
			},
			{
				// Test that an empty 'name' field cause an error
				Config: getEmptyVirtualServerEnhancedConfig(),
				ExpectError: configInvalidRegex,
			},
			{
				// Test that an invalid value for an enum field causes an error
				Config: getAdvancedVirtualServerEnhancedConfig(objName, "ARGH!!!", 4321),
				ExpectError: configInvalidRegex,
			},
			{
				// Test that an invalid (too low) value for an integer field causes an error
				Config: getAdvancedVirtualServerEnhancedConfig(objName, "http", 0),
				ExpectError: configInvalidRegex,
			},
			{
				// Test that an invalid (too high) value for an integer field causes an error
				Config: getAdvancedVirtualServerEnhancedConfig(objName, "http", 100000),
				ExpectError: configInvalidRegex,
			},
			{
				// Reset to valid config after errors, else destroy operation fails
				Config: getAdvancedVirtualServerEnhancedConfig(objName, "http", 4321),
			},
		},
	})
}

func testAccCheckVirtualServerEnhancedExists(s *terraform.State) error {

	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_virtual_server" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetVirtualServer(objectName); err != nil {
			return fmt.Errorf("Virtual server %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckVirtualServerEnhancedDestroy(s *terraform.State) error {

	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_virtual_server" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetVirtualServer(objectName); err == nil {
			return fmt.Errorf("Virtual server %s still exists", objectName)
		}
	}

	return nil
}

func getBasicVirtualServerEnhancedConfig(name string) string {
	return fmt.Sprintf(`
		resource "vtm_virtual_server" "my_vs" {
			name = "%s"
			pool = "discard"
			port = 1234
		}`,
		name,
	)
}

func getMissingVirtualServerEnhancedConfig() string {
	return fmt.Sprintf(`
		resource "vtm_virtual_server" "my_vs" {
			pool = "discard"
			port = 1234
		}`,
	)
}

func getEmptyVirtualServerEnhancedConfig() string {
	return fmt.Sprintf(`
		resource "vtm_virtual_server" "my_vs" {
			name = ""
			pool = "discard"
			port = 1234
		}`,
	)
}

func getAdvancedVirtualServerEnhancedConfig(name, protocol string, port int) string {
	return fmt.Sprintf(`
		resource "vtm_virtual_server" "my_vs" {
			name = "%s"
			connect_timeout = 42
			pool = "discard"
			port = %d
			protocol = "%s"
			request_rules = ["rule1", "rule2"]
			gzip_include_mime = ["application/test"]
			web_cache_enabled = true

			ssl_ocsp_issuers {
				issuer = "me"
			}
			# TODO: add this back in when VTM-37687
			ssl_ocsp_issuers {
				issuer = "DEFAULT"
			}
		}`,
		name, port, protocol,
	)
}
