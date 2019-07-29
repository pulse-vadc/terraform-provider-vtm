// Copyright (C) 2018-2019, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/pulse-vadc/go-vtm/6.1"
)


var testList = []string{
	"entry_one",
	"entry_two",
	"another_entry_one",
	"another_entry_two",
	"lets_try_this",
	"lets_try_this_as_well",
}

var testAccProviders map[string]terraform.ResourceProvider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider().(*schema.Provider)
	testAccProviders = map[string]terraform.ResourceProvider{
		"vtm": testAccProvider,
	}
	_, err := getTestVtm()
	if err != nil {
		panic(err)
	}
}

func getTestEnvVars() (baseUrl, username, password string, envError error) {
	requiredEnvVar := []string{"VTM_BASE_URL", "VTM_USERNAME", "VTM_PASSWORD"}
	for _, envVar := range requiredEnvVar {
		if os.Getenv(envVar) == "" {
			return "", "", "", fmt.Errorf("Environment variable %s must be set.", envVar)
		}
	}
	baseUrl = os.Getenv("VTM_BASE_URL")
	username = os.Getenv("VTM_USERNAME")
	password = os.Getenv("VTM_PASSWORD")
	envError = nil
	return
}

func getTestVtm() (*vtm.VirtualTrafficManager, error) {
	baseUrl, username, password, err := getTestEnvVars()
	if err != nil {
		return nil, err
	}
	verifySslCert := false
	tm, contactable, contactErr := vtm.NewVirtualTrafficManager(baseUrl, username, password, verifySslCert, false)
	if contactable != true {
		return nil, fmt.Errorf("Failed to contact vTM %s: %v", baseUrl, contactErr.ErrorText)
	}
    return tm, nil
}

func testAccPreCheck(t *testing.T) {
    _, err := getTestVtm()
    if err != nil {
        t.Fatalf("Fatal error: %+v", err)
    }
}

func regexReplace(regex, haystack, newVal string) string {
	re := regexp.MustCompile(regex)
	needle := re.FindStringSubmatch(haystack)[1]
	return strings.Replace(haystack, needle, newVal, 1)
}

func TestProvider(t *testing.T) {
	if err := Provider().(*schema.Provider).InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestGetVtmIncorrectSettings(t *testing.T) {
	baseUrl, username, password, err := getTestEnvVars()
	if err != nil {
		t.Fatalf("Failed to get env vars: %s", err)
	}
	tables := []struct {
		url string
		pass string
		err string
	}{
		{baseUrl, "NotThePassword", "auth.invalid"},
		{regexReplace("https?://([^:/]+)", baseUrl, "invalid-vtm-host.net"), password, "no such host"},
		{regexReplace("https?://[a-zA-Z1-9-.]+:([0-9]+)/", baseUrl, "6969"), password, "connection refused"},
		{regexReplace("https?://[a-zA-Z1-9-.]+:[0-9]+/(api)", baseUrl, "blah"), password, "resource.not_found"},
	}
	verifySslCert := false
	for _, table := range tables {
		_, _, contactErr := vtm.NewVirtualTrafficManager(table.url, username, table.pass, verifySslCert, false)
		if ! strings.Contains(contactErr.ErrorId, table.err) {
			t.Fatalf("Error check failed: expected '%s', got '%s'", table.err, contactErr)
		}
	}
}

func TestGetStringAddr(t *testing.T) {
	inputString := "Hello"
	outputStringPtr := getStringAddr(inputString)
	if *outputStringPtr != inputString {
		t.Errorf("getStringAddr returned wrong value: %s -> %s", *outputStringPtr, inputString)
	}
}

func TestGetStringListAddr(t *testing.T) {
	inputStringList := []string{"Hello", "World"}
	outputStringListPtr := getStringListAddr(inputStringList)
	if ! reflect.DeepEqual(*outputStringListPtr, inputStringList) {
		t.Errorf("getStringListAddr returned wrong value: %s -> %s", *outputStringListPtr, inputStringList)
	}
}

func TestGetIntAddr(t *testing.T) {
	inputInt := 42
	outputIntPtr := getIntAddr(inputInt)
	if *outputIntPtr != inputInt {
		t.Errorf("getIntAddr returned wrong value: %d -> %d", *outputIntPtr, inputInt)
	}
}

func TestGetBoolAddr(t *testing.T) {
	inputBool := true
	outputBoolPtr := getBoolAddr(inputBool)
	if *outputBoolPtr != inputBool {
		t.Errorf("getBoolAddr returned wrong value: %t -> %t", *outputBoolPtr, inputBool)
	}
}

func TestGetStringListStartingWith(t *testing.T) {
	tables := []struct {
		prefix string
		result []string
	}{
		{"entry", []string{"entry_one", "entry_two"}},
		{"another", []string{"another_entry_one", "another_entry_two"}},
		{"notthere", []string{}},
		{"", []string{"entry_one", "entry_two", "another_entry_one", "another_entry_two", "lets_try_this", "lets_try_this_as_well"}},
	}

	var filteredList *[]string

	for _, table := range tables {
		filteredList = getStringListStartingWith(&testList, table.prefix)
		if ! reflect.DeepEqual(*filteredList, table.result) {
			t.Errorf("Starts with failed: %s -> %s\n", table.prefix, *filteredList)
		}
	}
}

func TestGetStringListEndingWith(t *testing.T) {
	tables := []struct {
		suffix string
		result []string
	}{
		{"one", []string{"entry_one", "another_entry_one"}},
		{"this", []string{"lets_try_this"}},
		{"notthere", []string{}},
		{"", []string{"entry_one", "entry_two", "another_entry_one", "another_entry_two", "lets_try_this", "lets_try_this_as_well"}},
	}

	var filteredList *[]string

	for _, table := range tables {
		filteredList = getStringListEndingWith(&testList, table.suffix)
		if ! reflect.DeepEqual(*filteredList, table.result) {
			t.Errorf("Ends with failed: %s -> %s\n", table.suffix, *filteredList)
		}
	}
}

func TestGetStringListContaining(t *testing.T) {
	tables := []struct {
		contains string
		result []string
	}{
		{"entry", []string{"entry_one", "entry_two", "another_entry_one", "another_entry_two"}},
		{"_t", []string{"entry_two", "another_entry_two", "lets_try_this", "lets_try_this_as_well"}},
		{"notthere", []string{}},
		{"", []string{"entry_one", "entry_two", "another_entry_one", "another_entry_two", "lets_try_this", "lets_try_this_as_well"}},
	}

	var filteredList *[]string

	for _, table := range tables {
		filteredList = getStringListContaining(&testList, table.contains)
		if ! reflect.DeepEqual(*filteredList, table.result) {
			t.Errorf("Contains failed: %s -> %s\n", table.contains, *filteredList)
		}
	}
}

func TestGetStringListMatchingRegex(t *testing.T) {
	tables := []struct {
		regex string
		result []string
	}{
		{"_t", []string{"entry_two", "another_entry_two", "lets_try_this", "lets_try_this_as_well"}},
		{"en", []string{"entry_one", "entry_two", "another_entry_one", "another_entry_two"}},
		{"^en", []string{"entry_one", "entry_two"}},
		{"^[ae].*?o$", []string{"entry_two", "another_entry_two"}},
		{"^[ae.*?o$", []string{"INVALID_REGEX"}},
		{"notthere", []string{}},
		{"", []string{"entry_one", "entry_two", "another_entry_one", "another_entry_two", "lets_try_this", "lets_try_this_as_well"}},
	}

	for _, table := range tables {
		filteredList, err := getStringListMatchingRegex(&testList, table.regex)
		if err != nil {
			if ! reflect.DeepEqual(table.result, []string{"INVALID_REGEX"}) {
				t.Errorf("Valid regex '%s' failed compilation", table.regex)
			}
		} else {
			if ! reflect.DeepEqual(*filteredList, table.result) {
				t.Errorf("Regex failed: %s -> %s\n", table.regex, *filteredList)
			}
		}
	}
}
