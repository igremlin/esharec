package eshareclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Type of shares
//
const (
	SharesByMe   = "by-me"
	SharesWithMe = "with-me"
)

// Factory of e-Share clients
type Factory struct {
	token      string
	deviceName string
	email      string
	baseURL    string
	transport  *http.Transport
}

// EShareClient defines interface of e-Share client
type EShareClient interface {
	ValidateToken() (map[string]interface{}, error)
	ListShares(SharesType string) (map[string]interface{}, error)
}

// Client sends messages to e-Share server
type Client struct {
	token      string
	deviceName string
	email      string
	baseURL    string

	httpClient http.Client

	HTTPStatus     string // e.g. "200 OK"
	HTTPStatusCode int    // e.g. 200

}

func getProtocol(ssl bool) string {
	if ssl {
		return "https"
	}

	return "http"
}

// New method creates a new instance of EShareClient
func New(Token string, DeviceName string, Email string, HostName string, UseHTTPS bool, ProxyRawURL string, IgnoreSSLErrors bool) (*Factory, error) {
	if 0 == len(HostName) {
		return nil, errors.New("host name is missing")
	}

	var factory = Factory{token: Token, deviceName: DeviceName, email: Email}

	factory.baseURL = fmt.Sprintf("%s://%s", getProtocol(UseHTTPS), HostName)

	factory.transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: IgnoreSSLErrors},
	}

	if len(ProxyRawURL) > 0 {
		proxyURL, err := url.Parse(ProxyRawURL)
		if err != nil {
			return nil, err
		}

		factory.transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &factory, nil
}

// NewClient instansiates a new instance of e-share client
func (c *Factory) NewClient(timeoutInSeconds time.Duration) EShareClient {

	var client = Client{}
	client.httpClient = http.Client{Timeout: timeoutInSeconds * time.Second}
	client.httpClient.Transport = c.transport

	client.token = c.token
	client.deviceName = c.deviceName
	client.email = c.email
	client.baseURL = c.baseURL

	return &client
}

func createMessage(c *Client, messageType string, message map[string]interface{}) map[string]interface{} {
	var v = map[string]interface{}{
		"app-version": "1.0.0.1",
		"message-id":  uuid.New().String(),
		"ver":         "1.0",
	}

	var authInfo = map[string]interface{}{
		"authtoken":    c.token,
		"computername": c.deviceName,
		"email":        c.email,
	}

	v["auth-info"] = authInfo

	if 0 != len(messageType) {
		v["message-type"] = messageType
	}

	if nil != message {
		v["message"] = message
	}

	return v
}

func (c *Client) newRequest(methodType string, messageHandlerRawURL string, useAuthenticationHeader bool, byteMessage []byte) (*http.Request, error) {

	url := fmt.Sprintf("%s/%s", c.baseURL, messageHandlerRawURL)

	req, errNewRequest := http.NewRequest(methodType, url, bytes.NewBuffer(byteMessage))

	if errNewRequest != nil {
		return nil, errNewRequest
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Content-Type", "application/json")

	if useAuthenticationHeader {
		if strings.HasPrefix(messageHandlerRawURL, "api/3.0") || strings.HasPrefix(messageHandlerRawURL, "api/3.1") {
			v := fmt.Sprintf("NCC token=%s", c.token)
			req.Header.Set("Authorization", v)
		} else {
			req.Header.Set("NCC-AUTH-TOKEN", c.token)
		}
	}

	return req, nil
}

func (c *Client) sendMessage(methodType string, messageHandlerRawURL string, useMessageEnvelope bool, message map[string]interface{}) (map[string]interface{}, error) {
	c.HTTPStatus = ""
	c.HTTPStatusCode = 0

	var v map[string]interface{}
	if useMessageEnvelope {
		v = createMessage(c, "", message)
	} else if 0 != len(message) {
		v = message
	}

	var byteMessage []byte
	if nil != v {
		var errMarshal error
		byteMessage, errMarshal = json.Marshal(v)
		if errMarshal != nil {
			return nil, errMarshal
		}
	}

	req, errNewRequest := c.newRequest(methodType, messageHandlerRawURL, !useMessageEnvelope, byteMessage)
	if errNewRequest != nil {
		return nil, errNewRequest
	}

	res, getErr := c.httpClient.Do(req)

	c.HTTPStatus = res.Status
	c.HTTPStatusCode = res.StatusCode

	if getErr != nil {
		return nil, getErr
	}

	defer res.Body.Close()

	var result map[string]interface{}
	var errDecode = json.NewDecoder(res.Body).Decode(&result)
	if nil != errDecode {
		return nil, errDecode
	}

	var messageout map[string]interface{}
	if useMessageEnvelope {
		var ok bool
		messageout, ok = result["message"].(map[string]interface{})
		if nil == messageout {
			messageout = make(map[string]interface{})
		}

		errorCode, ok := result["error-code"].(float64)
		if ok {
			messageout["error-code"] = errorCode
			if 0 != errorCode {
				var errorDetails, ok = result["error-details"].(map[string]interface{})
				if ok {
					var errorDescription, ok = errorDetails["description"].(string)
					if ok && 0 != len(errorDescription) {
						messageout["error-description"] = errorDescription
					}
				}
			}
		} else {
			if c.HTTPStatusCode != 200 {
				messageout["error-code"] = -1
				errDescription, ok := result["detail"].(string)
				if ok {
					messageout["error-description"] = errDescription
				}
			}
		}
	} else {
		messageout = result
	}

	return messageout, nil
}

// ValidateToken velidates client token with e-Share server
func (c *Client) ValidateToken() (map[string]interface{}, error) {

	message := map[string]interface{}{
		"app-version":             "1.1.40.1",
		"notifications-timestamp": 0,
		"os-version":              "Windows 10 x64",
		"platform":                "Windows",
	}

	return c.sendMessage(http.MethodPost, "api/2.0/device/validate-token/", true, message)
}

// ListShares returns list of shares
func (c *Client) ListShares(SharesType string) (map[string]interface{}, error) {

	var sharesType string
	switch SharesType {
	case SharesByMe:
		fallthrough
	case SharesWithMe:
		sharesType = SharesType
	}

	if 0 == len(sharesType) {
		return nil, errors.New("Invalid share type")
	}

	url := fmt.Sprintf("api/3.0/shares/%s/?include_url=false&include_can_read=true&include_can_download=true", sharesType)

	return c.sendMessage(http.MethodGet, url, false, nil)
}
