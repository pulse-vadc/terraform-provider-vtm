// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following case:
 *   - When no filter applied, return all items in list
 *   - For each of the starts_with, ends_with, contains and regex_match filters...
 *     * If a matching filter is specified, return the subset of matching list items
 *     * If an empty filter is specified, return all list items
 *     * If a non-matching filter is specified, return an empty list
 *
 * NB. Five rules are created outside of Terraform for this test.  The rules are automatically deleted upon successful completion.
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestDataSourceConfigRateList(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: destroyDataSourceConfigRateListConfig,
		Steps: []resource.TestStep{
			{
				// Check list with no filter
				Config: initDataSourceConfigRateListConfig(t, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "5"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.2", "completely_different"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.4", "rate2"),
				),
			},
			{
				// Check list with starts_with filter
				Config: getDataSourceConfigRateListConfig("starts_with = \"rate\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "2"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "rate1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.1", "rate2"),
				),
			},
			{
				// Check list with empty starts_with filter
				Config: getDataSourceConfigRateListConfig("starts_with = \"\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "5"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.2", "completely_different"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.4", "rate2"),
				),
			},
			{
				// Check list with non-matching starts_with filter
				Config: getDataSourceConfigRateListConfig("starts_with = \"NOT_HERE\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "0"),
				),
			},
			{
				// Check list with ends_with filter
				Config: getDataSourceConfigRateListConfig("ends_with = \"2\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "2"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate2"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.1", "rate2"),
				),
			},
			{
				// Check list with empty ends_with filter
				Config: getDataSourceConfigRateListConfig("ends_with = \"\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "5"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.2", "completely_different"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.4", "rate2"),
				),
			},
			{
				// Check list with non-matching ends_with filter
				Config: getDataSourceConfigRateListConfig("ends_with = \"NOT_HERE\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "0"),
				),
			},
			{
				// Check list with contains filter
				Config: getDataSourceConfigRateListConfig("contains = \"diff\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "completely_different"),
				),
			},
			{
				// Check list with empty contains filter
				Config: getDataSourceConfigRateListConfig("contains = \"\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "5"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.2", "completely_different"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.4", "rate2"),
				),
			},
			{
				// Check list with non-matching contains filter
				Config: getDataSourceConfigRateListConfig("contains = \"NOT_HERE\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "0"),
				),
			},
			{
				// Check list with matching regex filter
				Config: getDataSourceConfigRateListConfig("regex_match = \"^a.*1$\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate1"),
				),
			},
			{
				// Check list with empty regex filter
				Config: getDataSourceConfigRateListConfig("regex_match = \"\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "5"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.0", "another_rate1"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.2", "completely_different"),
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.4", "rate2"),
				),
			},
			{
				// Check list with non-matching regex filter
				Config: getDataSourceConfigRateListConfig("regex_match = \"^NOT_HERE$\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rate_list.rate_list", "object_list.#", "0"),
				),
			},
		},
	})
}

func initDataSourceConfigRateListConfig(t *testing.T, filter string) string {
	tm, err := getTestVtm()
	if err != nil {
		t.Fatalf("Fatal error: %+v", err)
	}
	r1 := tm.NewRate("rate1")
	r1.Apply()
	r2 := tm.NewRate("rate2")
	r2.Apply()
	r3 := tm.NewRate("another_rate1")
	r3.Apply()
	r4 := tm.NewRate("another_rate2")
	r4.Apply()
	r5 := tm.NewRate("completely_different")
	r5.Apply()
	return getDataSourceConfigRateListConfig(filter)
}

func destroyDataSourceConfigRateListConfig(s *terraform.State) error {
	tm, _ := getTestVtm()
	_ = tm.DeleteRate("rate1")
	_ = tm.DeleteRate("rate2")
	_ = tm.DeleteRate("another_rate1")
	_ = tm.DeleteRate("another_rate2")
	_ = tm.DeleteRate("completely_different")

	return nil
}

func getDataSourceConfigRateListConfig(filter string) string {
	return fmt.Sprintf(`
		data "vtm_rate_list" "rate_list" {
			%s
		}`,
		filter,
	)
}
