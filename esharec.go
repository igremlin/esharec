package main

// http://polyglot.ninja/golang-making-http-requests/

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"
)

var _proxy string
var _insecureSkipVerify = false

func main() {

	//_proxy = "http://127.0.0.1:8888"

	var authInfo = map[string]interface{}{
		"authtoken":    "eyJ0eXAiOiAiTkNDIn0.eyJ2IjogIllCYUR0SjZ4WWNwZSJ9",
		"computername": "superbeast",
		"email":        "i@ncryptedcloud.com",
	}
	_ = authInfo

	//message := map[string]interface{}{}
	message := map[string]interface{}{
		"app-version":             "1.1.40.1",
		"notifications-timestamp": 0,
		"os-version":              "Windows 10 x64",
		"platform":                "Windows",
	}

	var v = map[string]interface{}{
		"app-version": "1.1.40.1",
		"auth-info":   authInfo,
		"message":     message,
		"message-id":  "{9dd4c98d-f34a-4db1-b5c2-50b63968a0f1}",
		//"message-type": "device/heartbeat/",
		"ver": "1.0",
	}

	client := http.Client{
		Timeout: time.Second * 60,
	}

	var transport = http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: _insecureSkipVerify}}

	if len(_proxy) > 0 {
		proxyURL, _ := url.Parse(_proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client.Transport = &transport

	url := "https://files.e-share.us/api/2.0/device/validate-token/"

	byteMessage, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		log.Fatal(errMarshal)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(byteMessage))

	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/json")

	res, getErr := client.Do(req)

	if getErr != nil {
		log.Fatal(getErr)
	}
	defer res.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(res.Body).Decode(&result)

	log.Println(result)
}
