// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

/*
 * This test covers the following cases:
 *    -  Data source read function of an existing raw text resource
 *
 * NB. a rule object is created outside of Terraform. This rule is deleted upon successful completion of the test.
 */

import (
	"fmt"
	"testing"

    "github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestDataSourceConfigRule(t *testing.T) {
	objName := acctest.RandomWithPrefix("TestRule")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: func(s *terraform.State) error { return destroyDataSourceConfigRuleConfig(objName) },
		Steps: []resource.TestStep{
			{
				Config: initDataSourceConfigRuleConfig(t, objName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vtm_rule.my_rule", "content", "log.info('rule1');"),
				),
			},
		},
	})
}

func initDataSourceConfigRuleConfig(t *testing.T, name string) string {
	tm, err := getTestVtm()
	if err != nil {
		t.Fatalf("Fatal error: %+v", err)
	}
	setErr := tm.SetRule(name, "log.info('rule1');")
	if setErr != nil {
		t.Fatalf("Fatal error: %+v", setErr)
	}
	return getDataSourceConfigRuleConfig(name)
}

func destroyDataSourceConfigRuleConfig(name string) error {
	tm, err := getTestVtm()
	if err != nil {
		return err
	}
	vtmErr := tm.DeleteRule(name)
	if vtmErr != nil {
		return fmt.Errorf("%#v", vtmErr)
	}
	return nil
}

func getDataSourceConfigRuleConfig(name string) string {
	return fmt.Sprintf(`
		data "vtm_rule" "my_rule" {
			name = "%s"
		}`,
		name,
	)
}
