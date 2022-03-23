// Copyright (C) 2018-2022, Pulse Secure, LLC.
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
 *   - Re-ordering a REST list field causes a config change
 *   - Re-ordering a REST set field does not cause a config change
 *   - Re-ordering a REST list field in a table causes a config change
 *   - Re-ordering a REST set field in a table does not cause a config change
 */

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/pulse-vadc/go-vtm/7.0"
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
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.4008173114", "text/html"),
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.2435821618", "text/plain"),
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
					resource.TestCheckResourceAttr("vtm_virtual_server.my_vs", "gzip_include_mime.2372034088", "application/json"),
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

	// Test re-ordering of entries in list and set fields
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckVirtualServerEnhancedDestroy,
		Steps: []resource.TestStep{
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithListsAndSets(objName, "rule1", "rule2", "text/type1", "text/type2"),
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithListsAndSets(objName, "rule1", "rule2", "text/type1", "text/type2"),
				PlanOnly: true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithListsAndSets(objName, "rule2", "rule1", "text/type1", "text/type2"),
				PlanOnly: true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithListsAndSets(objName, "rule1", "rule2", "text/type2", "text/type1"),
				PlanOnly: true,
				ExpectNonEmptyPlan: false,
			},
		},
	})

	// Test re-ordering of entries in list and set fields within tables
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckVirtualServerEnhancedDestroyWithCerts,
		Steps: []resource.TestStep{
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithTableListsAndSets(t, objName, "cert1", "cert2", "1.com", "2.com"),
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithTableListsAndSets(t, objName, "cert1", "cert2", "1.com", "2.com"),
				PlanOnly: true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithTableListsAndSets(t, objName, "cert2", "cert1", "1.com", "2.com"),
				PlanOnly: true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: getAdvancedVirtualServerEnhancedConfigWithTableListsAndSets(t, objName, "cert1", "cert2", "2.com", "1.com"),
				PlanOnly: true,
				ExpectNonEmptyPlan: false,
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

func testAccCheckVirtualServerEnhancedDestroyWithCerts(s *terraform.State) error {
	err := testAccCheckVirtualServerEnhancedDestroy(s)
	if err != nil {
		return err
	}

	tm, err := getTestVtm()
	if err != nil {
        return err
    }

	for _, certName := range []string{"cert1", "cert2", "cert3"} {
	    deleteErr := tm.DeleteSslServerKey(certName)
		if deleteErr != nil {
			return fmt.Errorf(deleteErr.ErrorText)
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
			gzip_include_mime = ["application/json"]
			web_cache_enabled = true

			ssl_ocsp_issuers {
				issuer = "me"
			}
			ssl_ocsp_issuers {
				issuer = "DEFAULT"
			}
		}`,
		name, port, protocol,
	)
}

func getAdvancedVirtualServerEnhancedConfigWithListsAndSets(name, listVal1, listVal2, setVal1, setVal2 string) string {
	return fmt.Sprintf(`
		resource "vtm_virtual_server" "my_vs" {
			name = "%s"
			pool = "discard"
			port = 80
			request_rules = ["%s", "%s"]
			gzip_include_mime = ["%s", "%s"]
		}`,
		name, listVal1, listVal2, setVal1, setVal2,
	)
}

func getAdvancedVirtualServerEnhancedConfigWithTableListsAndSets(t *testing.T, name, listVal1, listVal2, setVal1, setVal2 string) string {
	tm, err := getTestVtm()
	if err != nil {
		t.Fatalf("%#v", err)
	}

	private := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEApEPRlK+xJbQfUenl9H4nLEkQaH5L8/9F+pcjJW14EdlSkI3s
6bPe+eGtWf0XSzDXzOqAufERWrKyhw21c+UYoTA64i43T9nwvlRtxXxcok+VqmqC
HMCT5V7d82DKXnEEE6J5LwmHo48MsaQsBrjeyGVA8n40JDoM3qC1IlYxEoqouRf8
5eYWYAugL1PSnMT71fZy6VUAaeFRVRwREc3RFxkKa9GEraCaDGp7jfmdrNH1A8Pn
ns3um6kWuRHIliewFhUmc1gTxoQurVTtQh/FQViA6UbQtVCcScYarjqo9dgcuz7R
ABCEBnTx7gcmDeB6VR7luN3MGTc8gupJOjNEawIDAQABAoIBAHl+s8/ulu7VJ+k1
P+EzQZQOwnUXHORuZfrvuI4hRpKlE91ZK+a7JGvcEJSjjowNpz+oHufotrZHv6YG
bLQ4uZvXCWZrWnvULa0I01wjHHzssj0mo+/SPFGFdlJhv6xUmPhQzqMMwGcoEfJ+
BBZAvH6p7Xyt/bDhws0TPoYUDB2yg0VN0lgdjg3S/xR2od8ggZBWow5DV3S0j5ta
QlLojcDgHh6MQ1VOHIUHhillHUKuhlHLhukUHUKhkHKLldMPUrqhmJCaGVSDGr9+
2pjPHz04fp7CZ264rmUyHCGhwhjz4FH1KqkVM5LxoKhbOobwivhrhI/g4skgPxfb
Y7lwxsECgYEA2JgEzk6tnCZO8UfiR+FSvCLWmFJAlHuFasUy8B0jpZIlRNxt88iZ
BhsHIJadC09fmMF6WdE1KTZgNnMnm675FDSSKjk12DhGzU/zRqaBh0NE/Lemqe8/
wwn3oLd3Z++zcRJj7P6NCoQN8BEIJ0voiqje+ppEkumfTQ8VEHxGEuECgYEAwiaN
F4W5Z0Y2EEnkwbz1w+Fzaur0g3balipfjt/Up4xWDnsMdP7xPzny2rGzfqfOpUOF
dRR2YwXGhAcTMpo+Nblg9/0YpJ500RDxMMYEj8bYjTaEFJQ4a7SSvki35pFM0/pT
smhyWA04U/ttbs3+XosN335JsbcopZfT3zF3zMsCgYBWDniCXAJgs1vURAJlGuKb
e6AV30BnfnhxBq8Jdhpus5V5Obe6D661HVIEobL+BmhuMhlhzFy55i/jeq9ua398
p7pn/x998Yb0FlsLbCa0zoZ/fpyKklOcM76eraaUtklumKb5R95UGknLY4kAzAk1
5ojJuzeZw5cWr/JnnWjeIQKBgE09explmBpPI4kdbMXrADeaxQk/SmHW8iWV3AiC
Yh76RO5j49PT7XSDAGwjEE8OQbccAsdOib7heFXkXq3eEWvcQYjHh3tOkxjtzZbi
4MO2j0a27pslUMEAyPStB4TSP6eByrSKuxruv38h4yqXB2Djn3RP0M/EF4axvZfp
HUk7AoGAL2OaOtwy5lk/Oc6bwuPjTAR0wmBX9zelgsLIPiON2jHY287syVzh7lPm
vQGRYZlbGMseXj++s9nQJ24gLTokX2FwGioKvXwFX1ujah7ccJR9iVEwKpQMtDY5
cTiUZkme5oO3Idw6IO115A2EB1/BPpoWBP0M+y2BQYuTGk8F2LU=
-----END RSA PRIVATE KEY-----`

	public := `-----BEGIN CERTIFICATE-----
MIIDIDCCAgigAwIBAgIJAMD7f7Ux92lVMA0GCSqGSIb3DQEBCwUAMD4xCzAJBgNV
BAYTAkdCMRAwDgYDVQQHEwdkYXNkYXNkMQ0wCwYDVQQKEwRCbGFoMQ4wDAYDVQQD
EwVhLmIuYzAeFw0xODAxMjUyMzI3MDNaFw0yODAxMjUyMzI3MDNaMD4xCzAJBgNV
BAYTAkdCMRAwDgYDVQQHEwdkYXNkYXNkMQ0wCwYDVQQKEwRCbGFoMQ4wDAYDVQQD
EwVhLmIuYzCCASIwDQYJKoZIhvcNAQEhkhdakdhJLUihiQoCggEBAKRD0ZSvsSW0
H1Hp5fR+JyxJEWERWEewfrRtIyVteBHZUpCN7Omz3vnhrVn9F0sw18zqgLnxEVqy
socNtXPlGKEwOuIuN0/Z8L5UbcV8XKJPlapqghzAk+Ve3fNgyl5xBBOieS8Jh6OP
DLGkLAa43shlQPJ+NCQ6DN6gtSJWMRKKqLkX/OXmFmALoC9T0pzE+9X2culVAGnh
UVUcERHN0RcZCmvRhK2gmgxqe435nazR9QPD557N7pupFrkRyJYnsBYVJnNYE8aE
Lq1U7UIfxUFYgOlG0LVQnEnGGq46qPXYHLs+0QAQhAZ08e4HJg3gelUe5bjdzBk3
PILqSTozRGsCAwEAAaMhMB8wHQYDVR0OBBYEFOsQUOxzga482TRQfgcvWsOXHu3k
MA0GCSqGSIb3DQEBCwUAA4IBAQAOufUIugke4ZHRAXYmgM5cUX1MbBUs5S71u+Ao
79RfGkDL1kfvPdAoQx1/EoWc7LRIzvbuIZu6BiarU+/Te6mirmjF+dFdCfEka7cY
ZR5/BvU/+xJNEFDz2bEL0f4LTKnEiloEcUsHAt3vaqRdBGNt3vvpJ5FjyaDXjmpA
idvAjkqXEbUUBgt0kWuaQU8CDCv5FiGr9XhmK8YnoABCsyALbF+NP41EyUfZzt0Z
bj25+V9mexgCGRR6HJI9whhz33v51SXjxlAX5vsDiXRhfhLST7MBGamE6nqew2k9
cMbhPHfTIYYM1ijaqFU/LEXOQ6jTieldVIvC0KVSue7+eQtn
-----END CERTIFICATE----- `

	for _, certName := range []string{"cert1", "cert2", "cert3"} {
		cert := tm.NewSslServerKey(certName, "", private, public, "")
		_, applyErr := cert.Apply()
		if applyErr != nil {
			t.Fatalf(applyErr.ErrorText)
		}
	}

	return fmt.Sprintf(`
		resource "vtm_virtual_server" "my_vs" {
			name = "%s"
			pool = "discard"
			port = 80
			ssl_server_cert_host_mapping {
				host = "www.testing.com"
				certificate = "cert1"
				alt_certificates = ["%s", "%s"]
			}
			aptimizer_profile {
				name = "test"
				urls = ["%s", "%s"]
			}
		}`,
		name, listVal1, listVal2, setVal1, setVal2,
	)
}
