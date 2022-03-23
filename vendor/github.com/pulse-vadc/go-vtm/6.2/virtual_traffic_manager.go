// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

// Copyright (C) 2018-2022, Pulse Secure, LLC.
// Licensed under the terms of the MPL 2.0. See LICENSE file for details.

package vtm

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	TEXT_ONLY_OBJ = true
	STANDARD_OBJ  = false
)

type vtmObjectChild struct {
	Name string `json:"name"`
	Href string `json:"href"`
}

type vtmObjectChildren struct {
	Children []vtmObjectChild `json:"children"`
}

type vtmErrorResponse struct {
	ErrorId   string      `json:"error_id"`
	ErrorText string      `json:"error_text"`
	ErrorInfo interface{} `json:"error_info"`
}

//********************************************

type vtmConnector struct {
	url           string
	client        *http.Client
	username      string
	password      string
	verifySslCert bool
	textOnly      bool
	contentType   string
	expectedCodes map[string][]int
	readOnly      bool
	verbose       bool
}

func (c vtmConnector) getChildConnector(path string) *vtmConnector {
	newUrl := c.url + path
	conn := newConnector(newUrl, c.username, c.password, c.verifySslCert, c.verbose, c.client)
	return conn
}

func (c vtmConnector) get() (io.Reader, bool) {
	request, err := http.NewRequest("GET", c.url, nil)
	if c.verbose {
		reqDump, _ := httputil.DumpRequestOut(request, false)
		log.Printf("REST GET REQUEST: %s\n", reqDump)
	}
	request.SetBasicAuth(c.username, c.password)
	response, err := c.client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	if c.verbose {
		resDump, _ := httputil.DumpResponse(response, true)
		log.Printf("REST GET RESPONSE: %q\n", resDump)
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	bodyReader := bytes.NewReader(responseBody)
	if response.StatusCode == 200 {
		return bodyReader, true
	}
	return bodyReader, false
}

func (c vtmConnector) put(body string, isTextObject bool) (io.Reader, bool) {
	var contentType string
	if isTextObject == true {
		contentType = "application/octet-stream"
	} else {
		contentType = "application/json"
	}
	request, err := http.NewRequest("PUT", c.url, strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	if c.verbose {
		reqDump, _ := httputil.DumpRequestOut(request, true)
		log.Printf("REST PUT REQUEST: %q\n", reqDump)
	}
	request.SetBasicAuth(c.username, c.password)
	response, err := c.client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	if c.verbose {
		resDump, _ := httputil.DumpResponse(response, true)
		log.Printf("REST PUT RESPONSE: %q\n", resDump)
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	bodyReader := bytes.NewReader(responseBody)
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return bodyReader, true
	}
	return bodyReader, false
}

func (c vtmConnector) delete() (io.Reader, bool) {
	request, err := http.NewRequest("DELETE", c.url, nil)
	if c.verbose {
		reqDump, _ := httputil.DumpRequestOut(request, false)
		log.Printf("REST DELETE REQUEST: %s\n", reqDump)
	}
	request.SetBasicAuth(c.username, c.password)
	response, err := c.client.Do(request)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	if c.verbose {
		resDump, _ := httputil.DumpResponse(response, false)
		log.Printf("REST DELETE RESPONSE: %s\n", resDump)
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	bodyReader := bytes.NewReader(responseBody)
	if response.StatusCode == 204 {
		return bodyReader, true
	}
	return bodyReader, false
}

func newConnector(url, username, password string, verifySslCert, verbose bool, client *http.Client) *vtmConnector {
	if client == nil {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySslCert},
		}
		client = &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	conn := &vtmConnector{
		url:           url,
		username:      username,
		password:      password,
		verifySslCert: verifySslCert,
		verbose:       verbose,
		client:        client,
	}
	return conn
}

/*
VirtualTrafficManager is the central struct in the go-vtm library through which all tasks are performed.
*/
type VirtualTrafficManager struct {
	connector *vtmConnector
}

func (tm VirtualTrafficManager) testConnectivityOnce() (ok bool, err *vtmErrorResponse) {
	ok = false
	defer func() {
		if r := recover(); r != nil {
			switch e := r.(type) {
			case *url.Error:
				err = &vtmErrorResponse{
					ErrorId:   e.Err.Error(),
					ErrorText: e.Err.Error(),
				}
			default:
				err = &vtmErrorResponse{
					ErrorId:   fmt.Sprintf("%s", e),
					ErrorText: fmt.Sprintf("%s", e),
				}
			}
		}
	}()
	data, ok := tm.connector.get()
	if ok != true {
		object := new(vtmErrorResponse)
		json.NewDecoder(data).Decode(object)
		return false, object
	}
	return ok, nil
}

func (tm VirtualTrafficManager) testConnectivity() (bool, *vtmErrorResponse) {
	var err *vtmErrorResponse
	for i := 1; i <= 3; i++ {
		var ok bool
		ok, err = tm.testConnectivityOnce()
		if ok == true {
			return true, nil
		}
		time.Sleep(time.Duration(i) * time.Second)
	}
	return false, err
}

/*
NewVirtualTrafficManager creates an instance of VirtualTrafficManager and returns it, together with its reachability status.

Params:
	url				(string) The base URL of the target vTM, upto, but not including, the API verion portion.
						eg.	For direct connection to a vTM:
							https://my-vtm-1:9070/api
						For connection via a Services Director proxy:
							https://my-sd-1:8100/api/tmcm/<VER>/instances/<INSTANCE_ID>
	username		(string) Username to use for the connection.
						ie.	For direct connection to a vTM:
							Username on vTM with sufficient permissions to perform required operations.
						For connections via a Services Director proxy:
							Username on ServicesDirector with sufficient permissions to perform required operations.
	password		(string) Password to use for the connection.
						ie.	For direct connection to a vTM:
							vTM password for the user specified in the 'username' parameter.
						For connections via a Services Director proxy:
							Services Director password for the user specified in the 'username' parameter.
	verifySslCert	(bool) Whether to perform verification on on the SSL certificate presented by the RESP API.
	verbose			(bool) Whether to write verbose logs to STDOUT.

Returns:
	*VirtualTrafficManager		The newly-instantiated object
	bool						true if the target vTM is reachable with the provided parameters, else false
	*vtmErrorResponse			An error object if failed to create new VirtualTrafficManager, else nil
*/
func NewVirtualTrafficManager(url, username, password string, verifySslCert, verbose bool) (*VirtualTrafficManager, bool, *vtmErrorResponse) {
	vtm := new(VirtualTrafficManager)
	conn := newConnector(url, username, password, verifySslCert, verbose, nil)
	vtm.connector = conn
	contactable, contactErr := vtm.testConnectivity()
	return vtm, contactable, contactErr
}
