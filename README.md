# libcipher

libbipher provides high-level abstractions for common cryptographic operations.
It is designed to facilitate sensitive message handling such as encryption, decryption, and signing.

## Features

- **AES-CBC**: Provides secure encryption with HMAC for integrity checking.
- **AES-GCM**: Offers authenticated encryption with built-in integrity verification.
- **Key Generation**: Supports custom key lengths and key generation.

## Installation

To install the library, run:

```bash
go get github.com/cecmp/libcipher
```

## Usage

### AES-CBC Encryption/Decryption with HMAC

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/cecmp/libcipher"
)

func main() {
	// Generate a 64-byte key (32 bytes for encryption, 32 bytes for integrity).
	key, err := libcipher.GenerateKey(64)
	if err != nil {
		log.Fatal("Error generating key:", err)
	}

	encryptionKey := key[:32]
	integrityKey := key[32:]

	// Example plaintext.
	plaintext := []byte("This is a secret message.")

	// Encrypt the plaintext.
	encryptor, err := libcipher.NewCBCHMACEncryptor(encryptionKey, integrityKey, sha256.New, rand.Reader)
	if err != nil {
		log.Fatal("Error creating encryptor:", err)
	}
	ciphertext, err := encryptor.Crypt(plaintext, nil)
	if err != nil {
		log.Fatal("Error encrypting message:", err)
	}

	// Encode ciphertext in base64 for easier transmission/storage.
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("Encrypted (base64):", ciphertextBase64)

	// Decrypt the ciphertext.
	decryptor, err := libcipher.NewCBCHMACDecryptor(encryptionKey, integrityKey, sha256.New)
	if err != nil {
		log.Fatal("Error creating decryptor:", err)
	}
	decodedCiphertext, _ := base64.StdEncoding.DecodeString(ciphertextBase64)
	decryptedText, _, err := decryptor.Crypt(decodedCiphertext)
	if err != nil {
		log.Fatal("Error decrypting message:", err)
	}

	fmt.Println("Decrypted message:", string(decryptedText))
}
```
For other cryptographic primitives such as AES-GCM, refer to the [tests](cipher_test.go/) for more detailed usage.

## Roadmap
- **planned: asymmetric encryption**
- **planned: higher key lengths support for AES-GCM**
- **planned: tokens and signed data**
- **planned: better documentation**
- **planned: key derivation functions**
- **planned: (maybe) linked records**
