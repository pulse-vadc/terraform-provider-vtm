// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *    - Checks read function correctly returns configured property fields
 *    - Checks read function correctly returns dynamic counters
 *
 * NB. A virtual server and a TrafficSript rule are automaically created by this test.  They are automatically deleted
 * upon successful completion of the test.  The virtual server is hit with a random number of HTTP requests to test
 * the dynamic counters.
 */

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

    "github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestDataSourceStatisticsVirtualServerEnhanced(t *testing.T) {
	objName := acctest.RandomWithPrefix("MyVirtualServer")
	testRequestCount := acctest.RandIntRange(2, 20)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: func(s *terraform.State) error { return destroyDataSourceStatisticsVirtualServerEnhancedConfig(objName) },
		Steps: []resource.TestStep{
			{
				Config: initDataSourceStatisticsVirtualServerEnhancedConfig(t, objName, testRequestCount),
				Check: resource.ComposeTestCheckFunc(
					// Check integer field is correctly set
					resource.TestCheckResourceAttr("data.vtm_virtual_server_stats.my_virtual_server", "port", "1234"),
					// Check string field is correctly set
					resource.TestCheckResourceAttr("data.vtm_virtual_server_stats.my_virtual_server", "protocol", "http"),
					// Check counter field is correctly calculated
					resource.TestCheckResourceAttr("data.vtm_virtual_server_stats.my_virtual_server", "total_http_requests", strconv.Itoa(testRequestCount)),
				),
			},
		},
	})
}

func initDataSourceStatisticsVirtualServerEnhancedConfig(t *testing.T, name string, reqCount int) string {
	tm, err := getTestVtm()
	if err != nil {
		t.Fatalf("Fatal error: %+v", err)
	}
	tm.SetRule(fmt.Sprintf("TestRule%s", name), "http.sendResponse('200 OK', 'text/plain', 'TEST', '');")
	vs := tm.NewVirtualServer(name, "discard", 1234)
	vs.Basic.RequestRules = getStringListAddr([]string{fmt.Sprintf("TestRule%s", name)})
	vs.Basic.Enabled = getBoolAddr(true)
	_, applyErr := vs.Apply()
	if applyErr != nil {
		t.Fatalf("Fatal error: %#v", applyErr)
	}
	// Send an HTTP request to increment the total_http_requests counter
	time.Sleep(1 * time.Second)
	baseUrl, _, _, _ := getTestEnvVars()
	requestUrl := strings.SplitN(baseUrl, ":", 3)
	for i := 0; i < reqCount; i++ {
		_, err = http.Get("http://" + requestUrl[1][2:] + ":1234/")
		if err != nil {
			t.Fatalf("Fatal error: %+v", err)
		}
	}
	return getDataSourceStatisticsVirtualServerEnhancedConfig(name)
}

func destroyDataSourceStatisticsVirtualServerEnhancedConfig(name string) error {
	tm, err := getTestVtm()
	if err != nil {
		return err
	}
	vtmErr := tm.DeleteVirtualServer(name)
	if vtmErr != nil {
		return fmt.Errorf("%#v", vtmErr)
	}
	vtmErr = tm.DeleteRule(fmt.Sprintf("TestRule%s", name))
	if vtmErr != nil {
		return fmt.Errorf("%#v", vtmErr)
	}
	return nil
}

func getDataSourceStatisticsVirtualServerEnhancedConfig(name string) string {
	return fmt.Sprintf(`
		data "vtm_virtual_server_stats" "my_virtual_server" {
			name = "%s"
		}`,
		name,
	)
}
