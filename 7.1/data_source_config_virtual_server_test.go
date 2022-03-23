// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Reading unset string/integer/boolean/string list fields returns their defaults
 *   - Reading set string/integer/boolean/string list fields returns their new values
 *
 * NB. A virtual server is automatically created outside of Terraform for the test.  It is automatically deleted upon successful completion.
 */

import (
	"fmt"
	"testing"

    "github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
    "github.com/pulse-vadc/go-vtm/7.1"
)

func TestDataSourceConfigVirtualServer(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestVirtualServer")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: func(s *terraform.State) error { return destroyDataSourceConfigVirtualServerConfig(objName) },
		Steps: []resource.TestStep{
			{
				Config: initDataSourceConfigVirtualServerConfig(t, objName),
				Check: resource.ComposeTestCheckFunc(
					// Check that required integer field is correctly set
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "port", "1234"),
					// Check that required string field is correctly set
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "pool", "discard"),
					// Check that an optional sting parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "protocol", "http"),
					// Check that an optional integer parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "connect_timeout", "10"),
					// Check that an optional boolean parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "gzip_enabled", "false"),
					// Check that default boolean field correctly overridden when specified
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "web_cache_enabled", "true"),
					// Check that default string array field is correctly set
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "gzip_include_mime.#", "2"),
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "gzip_include_mime.4008173114", "text/html"),
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "gzip_include_mime.2435821618", "text/plain"),
					// Check that optional string array field is correctly set
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "request_rules.#", "2"),
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "request_rules.0", "rule1"),
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "request_rules.1", "rule2"),
					// Check that a default-empty table is empty
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "ssl_server_cert_host_mapping.#", "0"),
					// Check populated table
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "ssl_ocsp_issuers.#", "2"),
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "ssl_ocsp_issuers.631393090.issuer", "issuer1"),
					resource.TestCheckResourceAttr("data.vtm_virtual_server.my_virtual_server", "ssl_ocsp_issuers.2658551121.issuer", "issuer2"),
				),
			},
		},
	})
}

func initDataSourceConfigVirtualServerConfig(t *testing.T, name string) string {
	tm, err := getTestVtm()
	if err != nil {
		t.Fatalf("Fatal error: %+v", err)
	}

    var certsTable = vtm.VirtualServerOcspIssuersTable{}
	certsTable = append(certsTable, vtm.VirtualServerOcspIssuers{Issuer: getStringAddr("issuer2"),})
	certsTable = append(certsTable, vtm.VirtualServerOcspIssuers{Issuer: getStringAddr("issuer1"),})

	r1 := tm.NewVirtualServer(name, "discard", 1234)
	r1.Basic.RequestRules = getStringListAddr([]string{"rule1", "rule2"})
	r1.WebCache.Enabled = getBoolAddr(true)
	r1.Ssl.OcspIssuers = &certsTable
	_, applyErr := r1.Apply()
	if applyErr != nil {
		t.Fatalf("Fatal error: %#v", applyErr)
	}
	return getDataSourceConfigVirtualServerConfig(name)
}

func destroyDataSourceConfigVirtualServerConfig(name string) error {
	tm, err := getTestVtm()
	if err != nil {
		return err
	}
	vtmErr := tm.DeleteVirtualServer(name)
	if vtmErr != nil {
		return fmt.Errorf("%#v", vtmErr)
	}
	return nil
}

func getDataSourceConfigVirtualServerConfig(name string) string {
	return fmt.Sprintf(`
		data "vtm_virtual_server" "my_virtual_server" {
			name = "%s"
		}`,
		name,
	)
}
