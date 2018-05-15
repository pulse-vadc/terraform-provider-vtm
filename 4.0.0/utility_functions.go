// Copyright (C) 2018, Pulse Secure, LLC. 
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
)

func validateTableJson(tableStruct interface{}, requiredFields []string) schema.SchemaValidateFunc {
	return func (i interface{}, k string) (s []string, es []error) {
		err := json.Unmarshal(i.([]byte), tableStruct)
		if err != nil {
			es = append(es, fmt.Errorf("Failed to parse table JSON"))
			return
		}
		return
	}
}

func suppressTableDiffs(tableName string) schema.SchemaDiffSuppressFunc {
	return func (k, old, new string, d *schema.ResourceData) bool {
		if _, ok := d.GetOk(tableName + "_json"); ok {
			return true
		}
		return false
	}
}

func suppressHashedDiffs(fieldName string) schema.SchemaDiffSuppressFunc {
	return func (k, old, new string, d *schema.ResourceData) bool {
		fieldValue := d.Get(fieldName)
		fieldValueHash := sha256.New()
		fieldValueHash.Write([]byte(fieldValue.(string)))
		if base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s", fieldValueHash.Sum(nil)))) == old {
			return true
		}
		return false
	}
}

func getStringAddr(target string) *string {
	return &target
}

func getStringListAddr(target []string) *[]string {
	return &target
}

func getIntAddr(target int) *int {
	return &target
}

func getBoolAddr(target bool) *bool {
	return &target
}

func setBool(target **bool, d *schema.ResourceData, key string) {
	value := d.Get(key).(bool)
	*target = &value
}

func setInt(target **int, d *schema.ResourceData, key string) {
	value := d.Get(key).(int)
	*target = &value
}

func setString(target **string, d *schema.ResourceData, key string) {
	value := d.Get(key).(string)
	*target = &value
}

func setFloat(target **float64, d *schema.ResourceData, key string) {
	value := d.Get(key).(float64)
	*target = &value
}

func setStringList(target **[]string, d *schema.ResourceData, key string) {
	list := expandStringList(d.Get(key).([]interface{}))
	*target = &list
}

func expandStringList(interfaceList []interface{}) []string {
	strList := make([]string, 0, len(interfaceList))
	for _, value := range interfaceList {
		strVal, ok := value.(string)
		if ok && strVal != "" {
			strList = append(strList, strVal)
		}
	}
	return strList
}

func getStringListStartingWith(stringList *[]string, prefix string) *[]string {
	filteredList := []string{}
	for _, s := range *stringList {
		if strings.HasPrefix(s, prefix) {
			filteredList = append(filteredList, s)
		}
	}
	return &filteredList
}

func getStringListEndingWith(stringList *[]string, suffix string) *[]string {
	filteredList := []string{}
	for _, s := range *stringList {
		if strings.HasSuffix(s, suffix) {
			filteredList = append(filteredList, s)
		}
	}
	return &filteredList
}

func getStringListContaining(stringList *[]string, needle string) *[]string {
	filteredList := []string{}
	for _, s := range *stringList {
		if strings.Contains(s, needle) {
			filteredList = append(filteredList, s)
		}
	}
	return &filteredList
}

func getStringListMatchingRegex(stringList *[]string, needle string) (*[]string, error) {
	regex, err := regexp.Compile(needle)
	if err != nil {
		return nil, fmt.Errorf("Failed to compile regular expression for data source vtm_pool_list filtering")
	}

	filteredList := []string{}
	for _, s := range *stringList {
		if regex.MatchString(s) {
			filteredList = append(filteredList, s)
		}
	}
	return &filteredList, nil
}
