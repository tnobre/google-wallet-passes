package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2/google"
)

var issuerID = ""
var classSuffix = "codelab_class"
var objectSuffix = "codelab_object"
var objectID = issuerID + "." + objectSuffix
var keyFilePath = ""

func main() {
	loadPropertiesFromFile()
	createJWTTokenWithEmbeddedGenericPass()
}

func loadPropertiesFromFile() {
	properties, err := os.ReadFile("properties.json")
	var parametersData map[string]interface{}
	err = json.Unmarshal(properties, &parametersData)
	if err != nil {
		fmt.Println("Error reading properties file:", err)
		return
	}
	issuerID = parametersData["issuer_id"].(string)
	keyFilePath = parametersData["key_file_path"].(string)
}

func createJWTTokenWithEmbeddedGenericPass() {
	credentialsJSON, err := os.ReadFile(keyFilePath)
	if err != nil {
		fmt.Println("Error reading credentials file:", err)
		return
	}

	config, err := google.JWTConfigFromJSON(credentialsJSON, "https://www.googleapis.com/auth/wallet_object.issuer")
	if err != nil {
		fmt.Println("Error creating JWT config:", err)
		return
	}

	var keyData map[string]interface{}
	err = json.Unmarshal(credentialsJSON, &keyData)
	if err != nil {
		fmt.Println("Error parsing credentials JSON:", err)
		return
	}

	pemPrivateKey, ok := keyData["private_key"].(string)
	if !ok {
		fmt.Println("Private key not found in credentials JSON")
		return
	}

	block, _ := pem.Decode([]byte(pemPrivateKey))
	if block == nil {
		fmt.Println("Error decoding private key PEM block")
		return
	}

	parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	rsaPrivateKey, ok := parsedPrivateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Println("Error converting private key to RSA format")
		return
	}

	genericObject := buildGenericPassObject()

	claims := jwt.MapClaims{
		"iss": config.Email,
		"aud": "google",
		"origins": []string{
			"http://localhost:3000",
		},
		"typ": "savetowallet",
		"payload": map[string]interface{}{
			"genericObjects": []map[string]interface{}{genericObject},
		},
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		fmt.Println("Error signing the token:", err)
		return
	}

	fmt.Println(signedToken)
}

func buildGenericPassObject() map[string]interface{} {
	return map[string]interface{}{
		"id":                 objectID,
		"classId":            issuerID + "." + classSuffix,
		"genericType":        "GENERIC_TYPE_UNSPECIFIED",
		"hexBackgroundColor": "#4285f4",
		"logo": map[string]interface{}{
			"sourceUri": map[string]interface{}{
				"uri": "https://storage.googleapis.com/wallet-lab-tools-codelab-artifacts-public/pass_google_logo.jpg",
			},
		},
		"cardTitle": map[string]interface{}{
			"defaultValue": map[string]interface{}{
				"language": "en-US",
				"value":    "Google I/O '22",
			},
		},
		"subheader": map[string]interface{}{
			"defaultValue": map[string]interface{}{
				"language": "en-US",
				"value":    "Attendee",
			},
		},
		"header": map[string]interface{}{
			"defaultValue": map[string]interface{}{
				"language": "en-US",
				"value":    "Alex McJacobs",
			},
		},
		"barcode": map[string]interface{}{
			"type":  "QR_CODE",
			"value": objectID,
		},
		"heroImage": map[string]interface{}{
			"sourceUri": map[string]interface{}{
				"uri": "https://storage.googleapis.com/wallet-lab-tools-codelab-artifacts-public/google-io-hero-demo-only.jpg",
			},
		},
		"textModulesData": []map[string]interface{}{
			{
				"header": "POINTS",
				"body":   "1234",
				"id":     "points",
			},
			{
				"header": "CONTACTS",
				"body":   "20",
				"id":     "contacts",
			},
		},
	}
}
