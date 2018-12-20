// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Suppression of changes to nodes_table when auto_scaling_enabled is true
 *   - Suppression of changes to nodes_table when nodes_table_json is specified
 *   - Nodes specified in nodes_table_json are configured on the vTM
 *   - auto_scaling_extraargs field is present and working
 */

import (
	"fmt"
	_ "regexp"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/pulse-vadc/go-vtm/4.0"
)

var objName string

func TestResourcePoolEnhanced(t *testing.T) {
	objName = acctest.RandomWithPrefix("TestPool")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPoolEnhancedDestroy,
		Steps: []resource.TestStep{
			{
				Config: getBasicPoolEnhancedConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPoolEnhancedExists,
					// Check that autoscaling is disabled
					resource.TestCheckResourceAttr("vtm_pool.test_vtm_pool", "auto_scaling_enabled", "false"),
					// Check that nodes_table is empty
					resource.TestCheckResourceAttr("vtm_pool.test_vtm_pool", "nodes_table.#", "0"),
				),
			},
			{
				Config: getBasicPoolEnhancedNodesJsonConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPoolEnhancedExists,
					// Check that nodes_table is empty
					resource.TestCheckResourceAttr("vtm_pool.test_vtm_pool", "nodes_table.#", "0"),
					// Check that nodes from JSON have been created
					testAccCheckPoolEnhancedHasNodes,
				),
				// Test that diff suppression on nodes_table works
				ExpectNonEmptyPlan: false,
			},
			{
				PreConfig: initPoolConfig,
				Config: getBasicPoolEnhancedConfig(objName),
				PlanOnly: true,
				// Check that the plan is not empty (ie. contains the nodes added externally)
				ExpectNonEmptyPlan: true,
			},
			{
				PreConfig: initPoolConfig,
				Config: getBasicPoolEnhancedAsEnabledConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					// Check that autoscaling is enabled
					resource.TestCheckResourceAttr("vtm_pool.test_vtm_pool", "auto_scaling_enabled", "true"),
					// Check that nodes_table has the correct number of entries (ie. hasn't overwritten them with an empty set)
					resource.TestCheckResourceAttr("vtm_pool.test_vtm_pool", "nodes_table.#", "2"),
				),
			},
			{
				Config: getBasicPoolEnhancedExtraargsConfig(objName),
				Check: resource.ComposeTestCheckFunc(
					// Check that auto_scaling_extraargs is present and has expected value
					resource.TestCheckResourceAttr("vtm_pool.test_vtm_pool", "auto_scaling_extraargs", "--foo=bar"),
				),
			},
		},
	})
}

func testAccCheckPoolEnhancedExists(s *terraform.State) error {

	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_pool" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetPool(objectName); err != nil {
			return fmt.Errorf("Pool %s does not exist: %#v", objectName, err)
		}
	}

	return nil
}

func testAccCheckPoolEnhancedDestroy(s *terraform.State) error {

	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_pool" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if _, err := tm.GetPool(objectName); err == nil {
			return fmt.Errorf("Pool %s still exists", objectName)
		}
	}

	return nil
}

func testAccCheckPoolEnhancedHasNodes(s *terraform.State) error {

	for _, tfResource := range s.RootModule().Resources {
		if tfResource.Type != "vtm_pool" {
			continue
		}
		objectName := tfResource.Primary.Attributes["name"]
		tm := testAccProvider.Meta().(*vtm.VirtualTrafficManager)
		if pool, err := tm.GetPool(objectName); err != nil {
			return fmt.Errorf("Pool %s does not exist: %#v", objectName, err)
		} else if len(*pool.Basic.NodesTable) != 3 {
			return fmt.Errorf("Pool does not contain the nodes specified in nodes_table_json")
		}
	}

	return nil
}

func initPoolConfig() {
    tm, _ := getTestVtm()

    var nodesTable = vtm.PoolNodesTableTable{}
    nodesTable = append(nodesTable, vtm.PoolNodesTable{Node: getStringAddr("192.168.0.1:80"),})
    nodesTable = append(nodesTable, vtm.PoolNodesTable{Node: getStringAddr("192.168.0.2:80"),})

    p := tm.NewPool(objName)
	p.Basic.NodesTable = &nodesTable
    _, _ = p.Apply()
}


func getBasicPoolEnhancedConfig(name string) string {
	return fmt.Sprintf(`
		resource "vtm_pool" "test_vtm_pool" {
			name = "%s"
		}`,
		name,
	)
}

func getBasicPoolEnhancedAsEnabledConfig(name string) string {
	return fmt.Sprintf(`
		resource "vtm_pool" "test_vtm_pool" {
			name = "%s"
			auto_scaling_enabled = true
			auto_scaling_external = true
		}`,
		name,
	)
}

func getBasicPoolEnhancedExtraargsConfig(name string) string {
	return fmt.Sprintf(`
		resource "vtm_pool" "test_vtm_pool" {
			name = "%s"
			auto_scaling_extraargs = "--foo=bar"
		}`,
		name,
	)
}

func getBasicPoolEnhancedNodesJsonConfig(name string) string {
	return fmt.Sprintf(`
		resource "vtm_pool" "test_vtm_pool" {
			name = "%s"
			nodes_table_json = <<EOF
[{"node": "10.0.0.1:80"},{"node": "10.0.0.2:80"}, {"node": "10.0.0.3:80"}]
EOF
		}`,
		name,
	)
}
