// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - Creation and deletion of a vtm_global_settings object with minimal configuration
 */

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
)

func TestResourceGlobalSettings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: getBasicGlobalSettingsConfig(),
			},
		},
	})
}

func getBasicGlobalSettingsConfig() string {
	return fmt.Sprintf(`
        resource "vtm_global_settings" "test_vtm_global_settings" {
        }`,
	)
}
