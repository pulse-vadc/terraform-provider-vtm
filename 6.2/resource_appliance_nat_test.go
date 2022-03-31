// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_appliance_nat object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
)

func TestResourceApplianceNat(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicApplianceNatConfig(),
			},
		},
	})
}

func getBasicApplianceNatConfig() string {
	return fmt.Sprintf(`
        resource "vtm_appliance_nat" "test_vtm_appliance_nat" {
        }`,
	)
}
