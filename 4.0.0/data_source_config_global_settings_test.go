// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *   - cRUd (create and delete are dummies) operations on a singleton, standard config object
 *   - Check that default values for int/string/bool/string set are correctly set
 *   - Check that non-default values for int/string/bool are correctly set
 *
 * NB. Altered settings are rolled back to their pre-test (NOT default!) values upon successful test completion
 */
import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

// Define variables for storing state and rolling back
var testGlobalSettingsAcceptingDelayValue *int
var testGlobalSettingsAdminSsl3AllowRehandshakeValue *string
var testGlobalSettingsGlbVerboseValue *bool

func TestDataSourceConfigGlobalSettings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: rollbackDataSourceConfigGlobalSettingsConfig,
		Steps: []resource.TestStep{
			{
				Config: initDataSourceConfigGlobalSettingsConfig(t),
				Check: resource.ComposeTestCheckFunc(
					// Check that edited integer field is correctly set
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "accepting_delay", "60"),
					// Check that edited string field is correctly set
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "admin_ssl3_allow_rehandshake", "safe"),
					// Check that edited boolean field is correctly set
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "glb_verbose", "true"),
					// Check that integer parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "cluster_comms_state_sync_interval", "3"),
					// Check that string parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "fault_tolerance_heartbeat_method", "unicast"),
					// Check that boolean parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "fault_tolerance_verbose", "false"),
					// Check that string set parameter has the correct default
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "fault_tolerance_frontend_check_ips.#", "1"),
					resource.TestCheckResourceAttr("data.vtm_global_settings.my_global_settings", "fault_tolerance_frontend_check_ips.0", "%gateway%"),
				),
			},
		},
	})
}

func initDataSourceConfigGlobalSettingsConfig(t *testing.T) string {
	// Get vTM instance
	tm, err := getTestVtm()
	if err != nil {
		t.Fatalf("Fatal error: %+v", err)
	}
	// Save existing settings and set new ones
	globalSettings, errGlobalSettings := tm.GetGlobalSettings()
	if errGlobalSettings != nil {
		t.Fatalf("Fatal error: %+v", errGlobalSettings)
	}
	testGlobalSettingsAcceptingDelayValue = globalSettings.Basic.AcceptingDelay
	globalSettings.Basic.AcceptingDelay = getIntAddr(60)
	testGlobalSettingsAdminSsl3AllowRehandshakeValue = globalSettings.Admin.Ssl3AllowRehandshake
	globalSettings.Admin.Ssl3AllowRehandshake = getStringAddr("safe")
	testGlobalSettingsGlbVerboseValue = globalSettings.Glb.Verbose
	globalSettings.Glb.Verbose = getBoolAddr(true)
	// Apply new settings to vTM
	_, applyErr := globalSettings.Apply()
	if applyErr != nil {
		t.Fatalf("Fatal error: %#v", applyErr)
	}
	// Get and return the TF template
	return getDataSourceConfigGlobalSettingsConfig()
}

func rollbackDataSourceConfigGlobalSettingsConfig(s *terraform.State) error {
	// Get vTM instance
	tm, err := getTestVtm()
	if err != nil {
		fmt.Errorf("Fatal error: %+v", err)
	}
	// Set changed fields back to the stored values
	globalSettings, errGlobalSettings := tm.GetGlobalSettings()
	if errGlobalSettings != nil {
		fmt.Errorf("Fatal error: %+v", errGlobalSettings)
	}
	globalSettings.Basic.AcceptingDelay = testGlobalSettingsAcceptingDelayValue
	globalSettings.Admin.Ssl3AllowRehandshake = testGlobalSettingsAdminSsl3AllowRehandshakeValue
	globalSettings.Glb.Verbose = testGlobalSettingsGlbVerboseValue
	// Apply saved settings to vTM
	_, applyErr := globalSettings.Apply()
    if applyErr != nil {
        return fmt.Errorf("Fatal error: %#v", applyErr)
    }
    return nil
}

func getDataSourceConfigGlobalSettingsConfig() string {
	return fmt.Sprintf(`
		data "vtm_global_settings" "my_global_settings" {
		}`,
	)
}
