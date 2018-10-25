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
	CreateShare(shareAttr ShareAttributes, sharingPolicy SharingPolicy, recipients []string, notification *NotificationMessage, sendNow bool) (map[string]interface{}, error)
}

// SharingPolicy defines settings of shared data
type SharingPolicy struct {
	CanCreate           bool
	CanDownload         bool
	OneTimeLink         bool
	CanEdit             bool
	CanRead             bool
	ExpirationInSeconds float64
	LoginRequired       bool
	RequireTermsOfUse   bool
	SecureMessageBody   bool
	SendPinOnEmail      bool
	ShowTermsOnce       bool
	UseTrackingID       bool
	Watermark           bool
	CanDelete           bool
	Pin                 string
}

// EMailContent defines content of email
type EMailContent struct {
	FromEMailAddress string
	Subject          string
	Body             string
	SecureBody       bool
}

// ShareAttributes defines attributes of a new share
type ShareAttributes struct {
	OwnerIdentityID string
	RootMountID     string
	ShareID         string
	ShareName       string
	FolderPath      string
}

// NotificationMessage defines notification content
type NotificationMessage struct {
	EmailContent *EMailContent
	Text         string
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
		MaxIdleConnsPerHost:   100,
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

// CreateShare creates a new trusted share
func (c *Client) CreateShare(shareAttr ShareAttributes, sharingPolicy SharingPolicy, recipients []string,
	notification *NotificationMessage, sendNow bool) (map[string]interface{}, error) {
	if 0 == len(shareAttr.OwnerIdentityID) {
		return nil, errors.New("Invalid identity id")
	}
	if 0 == len(shareAttr.ShareName) {
		return nil, errors.New("Invalid share name")
	}

	if 0 == len(recipients) {
		return nil, errors.New("Invalid recipients")
	}
	if nil != notification && nil != notification.EmailContent &&
		(0 == len(notification.EmailContent.FromEMailAddress) || 0 == len(notification.EmailContent.Subject) || 0 == len(notification.EmailContent.Body)) {
		return nil, errors.New("Invalid email content")
	}

	params := make(map[string]interface{})
	params["identity_id"] = shareAttr.OwnerIdentityID

	paramsOptions := make(map[string]interface{})
	paramsOptions["can_create"] = sharingPolicy.CanCreate
	paramsOptions["can_download"] = sharingPolicy.CanDownload
	paramsOptions["can_delete"] = sharingPolicy.CanDelete
	paramsOptions["one_time_link"] = sharingPolicy.OneTimeLink
	paramsOptions["can_edit"] = sharingPolicy.CanEdit
	paramsOptions["can_read"] = sharingPolicy.CanRead
	paramsOptions["expiration"] = sharingPolicy.ExpirationInSeconds

	paramsOptions["login_required"] = sharingPolicy.LoginRequired
	paramsOptions["require_terms_of_use"] = sharingPolicy.RequireTermsOfUse
	paramsOptions["secure_message_body"] = sharingPolicy.SecureMessageBody
	paramsOptions["send_pin_on_email"] = sharingPolicy.SendPinOnEmail
	paramsOptions["show_terms_once"] = sharingPolicy.ShowTermsOnce
	paramsOptions["use_tracking_id"] = sharingPolicy.UseTrackingID
	paramsOptions["watermark"] = sharingPolicy.Watermark
	if 0 < len(sharingPolicy.Pin) {
		paramsOptions["pin"] = sharingPolicy.Pin
	}
	params["options"] = paramsOptions

	if nil != notification {
		if nil != notification.EmailContent {
			emailOptions := make(map[string]interface{})
			emailOptions["secure_body"] = notification.EmailContent.SecureBody
			emailOptions["subject"] = notification.EmailContent.Subject
			emailOptions["body"] = notification.EmailContent.Body
			emailOptions["mail_from_name"] = notification.EmailContent.FromEMailAddress

			params["mail_content"] = emailOptions
		}

		if 0 < len(notification.Text) {
			params["message"] = notification.Text
		}
	}

	params["recipients"] = recipients
	params["share_id"] = shareAttr.ShareID
	params["share_name"] = shareAttr.ShareName
	params["send_now"] = sendNow

	if 0 < len(shareAttr.FolderPath) {
		params["create_private_folder"] = shareAttr.FolderPath
	}

	if 0 < len(shareAttr.RootMountID) {
		params["root_mount_id"] = shareAttr.RootMountID
	}
	return c.sendMessage(http.MethodPost, "api/3.1/shares/", false, params)
}
