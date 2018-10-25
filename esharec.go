package main

// http://polyglot.ninja/golang-making-http-requests/

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/igremlin/esharec/pkg"
)

var _proxy string
var _insecureSkipVerify = false

func randomString() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	s := make([]rune, 8)
	r := []rune(chars)
	_ = s
	for i := 0; i < len(s); i++ {
		s[i] = r[rand.Intn(len(chars))]
	}

	return string(s)
}

func randomShareName() string {
	return fmt.Sprintf("testShare_%s", randomString())
}

func randomFolderName() string {
	return fmt.Sprintf("testFolder_%s", randomString())
}

func randomShareID() string {
	return uuid.New().String()
}

func parsePEM(pemString []byte, password []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(pemString)
	if len(rest) > 0 {
		return nil, errors.New("Extra data included in key")
	}

	if x509.IsEncryptedPEMBlock(block) {
		der, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}

		parseResult, errParse := x509.ParsePKCS1PrivateKey(der)
		if errParse != nil {
			return nil, errParse
		}

		return parseResult, nil
	}

	parseResult, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if parseResult != nil {
		return parseResult, nil
	}

	privateKey, errParse := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errParse != nil {
		return nil, errParse
	}

	return privateKey.(*rsa.PrivateKey), nil
}

func main() {

	rand.Seed(time.Now().UTC().UnixNano())

	//https://rietta.com/blog/2012/01/27/openssl-generating-rsa-key-from-command/
	//
	// openssl genrsa -aes256 -out private.pem 2048
	// openssl rsa -in private.pem -outform PEM -pubout -out public.pem

	// password: S$cr$t!
	//
	pemStringEncrypted := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,55AD290D7B0569544254AB191989C023
	
Ax7v+3WSlgqicoSsDkptWBDdNjHhcQmD0taQB7PPwlCB4yrZ024TuKGS8I85WQrb
X+ZeIq09dgaFe5urCPwv/LEku4tw2M/gzKEupSzlzAPV7RFNl74Luji+SToiEM2U
a5Nx3aR0x+A2Yb24ZYuZ4TqhCEWsYH8nXLg30gQ4wj8EvJNPFk/ApVuBOMYjIK4y
2CAUOA7YHE5jtJ+GMX9aaldlhLay4Aqk2m6QW/tBgjLY4twrYxthRlm+31u4YAx4
+oxlVYp4nuGBrhT11F4WDOb38gBjR6FevKY0glb8K/z0YgLBhtYt2B16APGqrxdQ
7E3h8t3YSr3IaLvAee/ZEeHScPzbugH7bvGaRrO8IT8hrYNIus430ChR7q05kpCB
orOX+dK2hjcB9IzupWkrCdBQz+McoBAegwS+8xQkCggrhX606NE5g4BqBPA++emm
/DllifWKFsjRPtaKwwad4xmvePlvID2UAuhRj2Ei9VcikayHB6X1jh2B8DytSUpD
50prhumvDAoqg6jJpmKcdg0qW0g0imaLt6LJWKUVbsHJpF4rpOgI6JHz3Ua2c0Ja
WNefl8kyHHt+wCAQ7HiTSvM77yxrOEoZWJ65z1bT7T2Q8QQ4cjF7NwEUzJfwDJz0
QaH7p8Z97iCWoM3imVhx/zy3N9sQC9QwuyKJLf26HboLJZUFQ2INsokDeQgz2bW+
wh4mrKjc3p6GFW3iwgbiG8iLJp2g67/fDWE+Jq5lFOPHbidruhHHawa4+no4J2je
L77te9pzFFKV8MCNbIx2y9GQFoK3CjO/0cV80HJlVB1B2t6QtMyGrfI8i/KXew9O
2i6NK2pkkuyWmX07uYijHwa0Xq3nF6S8BkfUP/q5tvFhyo6Yko+N5PCUAo5ryiX9
MP1F6WsjFjLSpu38RrQVKeXxshzGz3EL1GjqP0vvqvegH133UCWcs5XgLW3OQRS/
KHCk94nj6R4+oo46nLzDPE4J5RaWrrfUaHHm9x/rIPwL1njPMPwdnmgr2IrL8zqK
3Wq36/ZG8jzhBwmMkkuCLxpj3a6SPJtm/KQBD3T6HTMvd+8Xlx3zRToftHQ6iIBm
W64ewmfx9nUM8oRNrvjgIGyB3sriblPtFPT23vBtcLRJL2tcTzAWfl4qjzKy9WMs
m9er16zzBrOEVhRuu9XzelvMVwLEX/rzBrNIeSB/Q8i50vqcHYtr1ub6NdnRW+j0
L9nmekpieS+x8BbsngVOkueHn7xwCx3t3hyC+ECf/6VHMgeHVuuUlDaXOFr91t2x
cGi+cRFjOGPnqqqPvQDsr3q2SNZiRE70U4h8jjxVThvxV3SngsUonz14YCbirP/O
3aT1BO2KlxF7NTT17dhM7HD9/6hQRy86eK2vfk8QgRF2+1Nd4hSOVgETniW+3Yg4
WWE8s6b9OOjyAxtbF8t6+63XEwz3gf/fsV9+tJ5OBrRM1r/OyZflecHsGxD7CtOx
HI/FOWGE849/FiPKdq/224DD6+GB33oD4frVmWYoV3eAb3BPRqYK+3AItllhuHyW
I92XufvxtdO+igN6C43fNRmqcx6+VE+zdM0u4P1RT5Z/V/l7QQGAYaXoPvx5W4YV
-----END RSA PRIVATE KEY-----`

	pemString := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqCih/pdOWq5D0uaLrC9q3CyXSeH4aO8G/whGDeShPtHmjYo9
KMlYsL9QbkFuIPzKQZjj8ZMyCSrMQFBDfADAXwTVOjnzgdI2xlRZo3peenvhEUT3
72ScKaNMST3vKT/EhWiNQHRh1460YniQdgvtINMWz6+y22Reey3qHS+jp40UA31w
F/APFenLImufGVtLbJaYY5qmU7t2nzlCwqfY1KZlB+ayPN5ui9DEnD71WsVwYdZT
ShbjAwYc8vxhoId7myq8L3hsbQQ+iuGmyaEySd5Tjk10l5Oas2dW55lynD5+dwbc
g15JjOdhLIf52AwR9s3lJhR6N8ZAWawqM/iChQIDAQABAoIBAEbiafcR/PuIvhpn
CLWaf2c0fMmuMbK6H67d4/nzSG1cud0sSr+osHRBETyI5E2PggrI0j2BGPR4UAVE
UE4zWuQy+1dCGn29CU3tPKQG71Cea6+F7SXCuXlr1rqBGxG+Sa8a9YAYDy54f12L
CQpZ2KmfkdwWakTFOHagUjHfZRM5XApO/oCbfXHJs4h+URtmjJSLfXSGvsHWYUXb
ht8YK2hSM8WUqSFBWMyjeHqQi/slHU11dnhRmIxaymq8QoEYf520AbDi6hZhP3am
f9Wa0t7DEmPOWQo7RGGqLLSzNtmc0uQVLnGXgGJs+pRJkYBZpD5IkHs0KgfaBlVH
/MLjWXkCgYEA17Ci+pfmU09LFJPh7RnZrIAVMqRPLN86vG2JYYilcWk/3U00La+q
tEOWQsPn0jiTjU79rOqzD2T/v48bNyR6ds16r0UeOCHG6CWljjNUVvrK1k30VOeK
XaIBemiLJZe2Onj7ROmiKygBLjIITu45KA3sprfM5InDCe2l2hM2JY8CgYEAx5Xv
JzNnLYCu755w2IzFIz3BMF8Mujk0UqpBzdEG/t5r7Cm+oceA2BVx5I2MlQX6IoH2
89M9o9uGPLhsCvJp3SPx7FzdIf1U+AZmfuPIHfVWriJMg2jnDrnlrotTXCbXI3VE
5GUszRuf5KUrkMz+etvq6UEIsJvBu5vDbRGd1KsCgYAS/+dLZcgPPKPjeydiqG1J
SbsUS+8Bh+R3prp8Ufoo5FmQ1/UptRi3amC5HuKz3PH6d6PW8JG3YHE64ZNHJzp2
bqFJATCpRyhrWK2duh3Kz6rAd/t24zKIDvZMXxsqw5N00SVpK59yZ8K63ANpWIjG
Y3ueMACnfQ8mN73tWNXjNwKBgCoPU8XMFFtHehYvKpLIH6dMlVDPRwxbj8Y38QQh
n7rIPrAXIABR3bor0sOafNzO1Ka/Ar7hbmUAlypmpwYrjdm3gH0SGNvX2jcmiiUF
dZ+ymyC5Q6yRx9eXn2qIG/oYiVAEn48OL0HOJ4T0tdifCqXzgG7FcMJfIJWbvrRW
eQ9fAoGBANMwqhWmjib1VQ3tKRlxdmmNIZRCzaJlfaZSWXFEsKb07OV/+LK/oRcc
NUcaBnINO1FVVOYvjDIPgGwkRX8X8OM6Dxwhn/9pApDw4hGwvEFlLeAI8MvdGSja
ljIrEBWiZWbVnchGoScM8mbhzz6Htt9h4EjVtABCK7VHv19TN6/S
-----END RSA PRIVATE KEY-----`

	pemStringPKCS8 := `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKhPSTDs4cpKfnMc
p86fCkpnuER7bGc+mGkhkw6bE+BnROfrDCFBSjrENLS5JcsenANQ1kYGt9iVW2fd
ZAWUdDoj+t7g6+fDpzY1BzPSUls421Dmu7joDPY8jSdMzFCeg7Lyj0I36bJJ7ooD
VPW6Q0XQcb8FfBiFPAKuY4elj/YDAgMBAAECgYBo2GMWmCmbM0aL/KjH/KiTawMN
nfkMY6DbtK9/5LjADHSPKAt5V8ueygSvI7rYSiwToLKqEptJztiO3gnls/GmFzj1
V/QEvFs6Ux3b0hD2SGpGy1m6NWWoAFlMISRkNiAxo+AMdCi4I1hpk4+bHr9VO2Bv
V0zKFxmgn1R8qAR+4QJBANqKxJ/qJ5+lyPuDYf5s+gkZWjCLTC7hPxIJQByDLICw
iEnqcn0n9Gslk5ngJIGQcKBXIp5i0jWSdKN/hLxwgHECQQDFKGmo8niLzEJ5sa1r
spww8Hc2aJM0pBwceshT8ZgVPnpgmITU1ENsKpJ+y1RTjZD6N0aj9gS9UB/UXdTr
HBezAkEAqkDRTYOtusH9AXQpM3zSjaQijw72Gs9/wx1RxOSsFtVwV6U97CLkV1S+
2HG1/vn3w/IeFiYGfZXLKFR/pA5BAQJAbFeu6IaGM9yFUzaOZDZ8mnAqMp349t6Q
DB5045xJxLLWsSpfJE2Y12H1qvO1XUzYNIgXq5ZQOHBFbYA6txBy/QJBAKDRQN47
6YClq9652X+1lYIY/h8MxKiXpVZVncXRgY6pbj4pmWEAM88jra9Wq6R77ocyECzi
XCqi18A/sl6ymWc=
-----END PRIVATE KEY-----`

	key, errParse := parsePEM([]byte(pemStringEncrypted), []byte("S$cr$t!"))
	if errParse != nil {
		fmt.Println(errParse)
	} else {
		fmt.Println(key.N)
	}
	key, errParse = parsePEM([]byte(pemString), nil)
	if errParse != nil {
		fmt.Println(errParse)
	} else {
		fmt.Println(key.N)
	}
	key, errParse = parsePEM([]byte(pemStringPKCS8), nil)
	if errParse != nil {
		fmt.Println(errParse)
	} else {
		fmt.Println(key.N)
	}

	//_proxy = "http://127.0.0.1:8888"

	var eshareClientToken, eshareClientDevice, eshareClientEmail, eshareClientServer string

	if 0 == len(eshareClientToken) {
		eshareClientToken = os.Getenv("ESHARECLIENT_TOKEN")
	}
	if 0 == len(eshareClientDevice) {
		eshareClientDevice = os.Getenv("ESHARECLIENT_DEVICE")
	}
	if 0 == len(eshareClientEmail) {
		eshareClientEmail = os.Getenv("ESHARECLIENT_EMAIL")
	}
	if 0 == len(eshareClientServer) {
		eshareClientServer = os.Getenv("ESHARECLIENT_SERVER")
	}

	var factory, errNewFactory = eshareclient.New(eshareClientToken, eshareClientDevice, eshareClientEmail, eshareClientServer, true, _proxy, false)
	if nil != errNewFactory {
		log.Fatal(errNewFactory)
	}

	var c1 = factory.NewClient(30)
	var c2 = factory.NewClient(30)

	var r1, r2 map[string]interface{}
	var err1, err2 error
	ch1 := make(chan int)
	go func(c chan int) {
		r1, err1 = c1.ValidateToken()
		c <- 1
	}(ch1)

	ch2 := make(chan int)
	go func(c chan int) {
		r2, err2 = c2.ListShares(eshareclient.SharesByMe)
		c <- 1
	}(ch2)

	<-ch1
	var identityID string
	if nil != err1 {
		log.Println(err1)
	} else {
		log.Println(r1)

		a, ok := r1["identities"].([]interface{})
		if ok {
			for _, v := range a {
				email := v.(map[string]interface{})["name"]
				if email == eshareClientEmail {
					identityID = v.(map[string]interface{})["id"].(string)
					break
				}
			}
		}
	}

	<-ch2
	if nil != err2 {
		log.Println(err2)
	} else {
		log.Println(r2)
	}

	sharingPolicy := eshareclient.SharingPolicy{
		CanCreate:           true,
		CanDownload:         true,
		OneTimeLink:         false,
		CanEdit:             true,
		CanRead:             true,
		ExpirationInSeconds: 60 * 60 * 24 * 30,
		LoginRequired:       false,
		RequireTermsOfUse:   false,
		SecureMessageBody:   false,
		SendPinOnEmail:      false,
		ShowTermsOnce:       false,
		UseTrackingID:       false,
		Watermark:           false,
		CanDelete:           true,
	}

	shareAttributes := eshareclient.ShareAttributes{
		OwnerIdentityID: identityID,
		ShareID:         randomShareID(),
		ShareName:       randomShareName(),
	}

	recipients := []string{"igremlin.ma@gmail.com"}

	emailContent := eshareclient.EMailContent{
		FromEMailAddress: "i@ncryptedcloud.com",
		Subject:          "this is a test subject",
		Body:             "this is a test message body",
		SecureBody:       true,
	}

	notificationMessage := eshareclient.NotificationMessage{
		//Text: "Hello, World...from GOLANG client!",
		EmailContent: &emailContent,
	}
	_ = notificationMessage

	var c3 = factory.NewClient(30)
	var r3 map[string]interface{}
	var err3 error
	ch3 := make(chan int)
	go func(c chan int) {
		r3, err3 = c3.CreateShare(shareAttributes, sharingPolicy, recipients, &notificationMessage, true)
		c <- 1
	}(ch3)

	<-ch3
	if nil != err3 {
		log.Println(err3)
	} else {
		log.Println(r3)
	}
}
