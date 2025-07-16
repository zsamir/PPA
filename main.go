package main

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/dromara/dongle/openssl"
)

type publicKeyInfo struct {
	EncryptionKeyID     string
	EncryptionPublicKey string
}

// Static public key info
var latestPublicKeyInfo = publicKeyInfo{
	EncryptionKeyID: "static-key-id", // use actual key ID if available
	EncryptionPublicKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3kOM8fTXa7oMdYxGCa9u8Z6ym2Ldczt2x7kAmHKV9jT8YG7PaGxv4E5nRjZnT9OU0fZZAGUGng1RDrRaCFwcZpOD5m56sG1LaYQ8dkaxSG2M1BynLeK9XRiZEmx1JhD0Pk4mm5sIFIg3Oa486CWMVrjgCpsF1VIgT7yGoNOk8tdOqPZ206ATXd+5BxArQ3aup9ziD0nsk66CRchXVCgF7Gc/ySEsc+B3GhF4qqFSvZbAJ4hG1uc1/8G2XbKoJIdpgc4QavnvtADATJBmqyHio70ds76gQJAMs8uMpgN9FOqYqj5XSEX9K/WbHQBnqjBoprZPngq8hzHukbx8XhqrfQIDAQAB",
}

func main() {
	instrumentDetails := InstrumentDetails{
		CardNumber:      "4111111111111111",
		ExpiryMonth:     "03",
		ExpiryYear:      "30",
		SecurityCode:    "737",
		HolderName:      "John Doe",
		HolderReference: "Payrails Product assessment",
	}

	instrumentDetailsJSON, err := json.Marshal(instrumentDetails)
	if err != nil {
		panic(err)
	}
	fmt.Println("🔓 JSON to encrypt:\n", string(instrumentDetailsJSON))

	encryptedCardData, err := jweEncrypt(instrumentDetailsJSON)
	if err != nil {
		panic(err)
	}
	fmt.Println("🔐 Encrypted JWE data:\n", encryptedCardData)
}

// InstrumentDetails represents the instrument details to be encrypted
type InstrumentDetails struct {
	CardNumber      string `json:"cardNumber"`
	ExpiryMonth     string `json:"expiryMonth"`
	ExpiryYear      string `json:"expiryYear"`
	SecurityCode    string `json:"securityCode,omitempty"`
	HolderName      string `json:"holderName"`
	HolderReference string `json:"holderReference"`
}

func jweEncrypt(jsonData []byte) (string, error) {
	// Convert base64-encoded public key string to RSA public key (PKCS8)
	publicKey, err := openssl.RSA.ParsePublicKey(
		openssl.RSA.FormatPublicKey(openssl.PKCS8, []byte(latestPublicKeyInfo.EncryptionPublicKey)),
	)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	recipient := jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       publicKey,
		KeyID:     latestPublicKeyInfo.EncryptionKeyID,
	}

	encrypter, err := jose.NewEncrypter(jose.A256CBC_HS512, recipient, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	encrypted, err := encrypter.Encrypt(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	return encrypted.CompactSerialize()
}
