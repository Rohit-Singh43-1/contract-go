// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSealSecretWorkload tests sealing a workload secret.
func TestSealSecretWorkload(t *testing.T) {
	result, err := SealSecret("test-secret", WorkloadSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal secret")

	// Verify sealed secret format
	assert.True(t, strings.HasPrefix(result.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify sealed secret has JWS structure (sealed.header.payload.signature)
	parts := strings.Split(result.SealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret (sealed.header.payload.signature)")

	// Verify all keys are present
	assert.NotEmpty(t, result.DecryptionKeyPEM, "Decryption key is empty")
	assert.NotEmpty(t, result.VerificationKeyPEM, "Verification key is empty")

	// Verify keys are in PEM format
	assert.Contains(t, string(result.DecryptionKeyPEM), "BEGIN", "Decryption key not in PEM format")
	assert.Contains(t, string(result.VerificationKeyPEM), "BEGIN PUBLIC KEY", "Verification key not in PEM format")
}

// TestSealSecretEnv tests sealing an environment secret.
func TestSealSecretEnv(t *testing.T) {
	result, err := SealSecret("test-secret", EnvSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal secret")

	assert.True(t, strings.HasPrefix(result.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify JWS structure
	parts := strings.Split(result.SealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret")
}

// TestSealSecretEmptySecret tests that empty secrets are rejected.
func TestSealSecretEmptySecret(t *testing.T) {
	_, err := SealSecret("", WorkloadSecret, nil, nil)
	assert.Error(t, err, "Expected error for empty secret")
	assert.Contains(t, err.Error(), "empty", "Expected error message to mention 'empty'")
}

// TestSealSecretInvalidType tests that invalid secret types are rejected.
func TestSealSecretInvalidType(t *testing.T) {
	_, err := SealSecret("test", SecretType("invalid"), nil, nil)
	assert.Error(t, err, "Expected error for invalid secret type")
	assert.Contains(t, err.Error(), "invalid secret type", "Expected error message to mention 'invalid secret type'")
}

// TestSealSecretDifferentSecrets tests that different secrets produce different results.
func TestSealSecretDifferentSecrets(t *testing.T) {
	result1, err := SealSecret("secret1", WorkloadSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal first secret")

	result2, err := SealSecret("secret2", WorkloadSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal second secret")

	// Sealed secrets should be different
	assert.NotEqual(t, result1.SealedSecret, result2.SealedSecret, "Different secrets produced identical sealed secrets")

	// Keys should be different (freshly generated each time)
	assert.NotEqual(t, string(result1.DecryptionKeyPEM), string(result2.DecryptionKeyPEM), "Different calls produced identical decryption keys")
}

// TestSealSecretLongSecret tests sealing a longer secret.
func TestSealSecretLongSecret(t *testing.T) {
	longSecret := strings.Repeat("This is a long secret. ", 100)
	result, err := SealSecret(longSecret, WorkloadSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal long secret")
	assert.True(t, strings.HasPrefix(result.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")
}

// TestSealSecretSpecialCharacters tests sealing secrets with special characters.
func TestSealSecretSpecialCharacters(t *testing.T) {
	specialSecrets := []string{
		"password!@#$%^&*()",
		"key with spaces",
		"unicode: 你好世界",
		"newlines\nand\ttabs",
		`{"json": "value"}`,
	}

	for _, secret := range specialSecrets {
		t.Run(secret, func(t *testing.T) {
			result, err := SealSecret(secret, WorkloadSecret, nil, nil)
			assert.NoError(t, err, "Failed to seal secret with special characters")
			assert.True(t, strings.HasPrefix(result.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")
		})
	}
}

// BenchmarkSealSecret benchmarks the complete seal secret operation.
func BenchmarkSealSecret(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := SealSecret("benchmark-secret", WorkloadSecret, nil, nil)
		assert.NoError(b, err, "Failed to seal secret")
	}
}

// TestDecryptWithGoCrypto demonstrates that sealed secrets created with native Go crypto
// can be decrypted using Go's crypto packages (AES-256-GCM + RSA-OAEP-SHA512).
func TestDecryptWithGoCrypto(t *testing.T) {
	originalSecret := "my-test-password-123"

	// Step 1: Create sealed secret using our package
	result, err := SealSecret(originalSecret, WorkloadSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal secret")

	t.Logf("Original secret: %s", originalSecret)
	t.Logf("Sealed secret: %s", result.SealedSecret[:50]+"...")

	// Step 2: Parse the JWS format (sealed.header.payload.signature)
	parts := strings.Split(result.SealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Invalid sealed secret format")
	assert.Equal(t, "sealed", parts[0], "Invalid sealed secret format")

	// Step 3: Decode the payload (envelope)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	assert.NoError(t, err, "Failed to decode payload")

	// Define envelope structure for decryption
	type envelope struct {
		Version       string `json:"version"`
		Type          string `json:"type"`
		KeyID         string `json:"key_id"`
		EncryptedKey  string `json:"encrypted_key"`
		EncryptedData string `json:"encrypted_data"`
		WrapType      string `json:"wrap_type"`
		IV            string `json:"iv"`
		Provider      string `json:"provider"`
	}

	var env envelope
	err = json.Unmarshal(payloadBytes, &env)
	assert.NoError(t, err, "Failed to unmarshal envelope")

	t.Logf("Envelope version: %s", env.Version)
	t.Logf("Wrap type: %s", env.WrapType)

	// Verify it's using GCM
	assert.Equal(t, "A256GCM", env.WrapType, "Expected wrap_type A256GCM")

	// Step 4: Decode the encrypted AES key
	encryptedAESKey, err := base64.StdEncoding.DecodeString(env.EncryptedKey)
	assert.NoError(t, err, "Failed to decode encrypted AES key")

	// Step 5: Parse the RSA private key (decryption key)
	block, _ := pem.Decode(result.DecryptionKeyPEM)
	assert.NotNil(t, block, "Failed to parse PEM block")

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		assert.NoError(t, err, "Failed to parse private key")
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	assert.True(t, ok, "Not an RSA private key")

	// Step 6: Decrypt the AES key using RSA PKCS#1 v1.5 (same as agent-interceptor)
	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, encryptedAESKey)
	assert.NoError(t, err, "Failed to decrypt AES key")

	t.Logf("Decrypted AES key length: %d bytes", len(aesKey))

	// Step 7: Decode the encrypted data and IV
	encryptedData, err := base64.StdEncoding.DecodeString(env.EncryptedData)
	assert.NoError(t, err, "Failed to decode encrypted data")

	iv, err := base64.StdEncoding.DecodeString(env.IV)
	assert.NoError(t, err, "Failed to decode IV")

	// Step 8: Decrypt the data using AES-256-GCM (Go crypto)
	block2, err := aes.NewCipher(aesKey)
	assert.NoError(t, err, "Failed to create AES cipher")

	gcm, err := cipher.NewGCM(block2)
	assert.NoError(t, err, "Failed to create GCM")

	// GCM decrypt (nonce is the IV, ciphertext includes auth tag)
	decryptedData, err := gcm.Open(nil, iv, encryptedData, nil)
	assert.NoError(t, err, "Failed to decrypt data with GCM")

	decryptedSecret := string(decryptedData)
	t.Logf("Decrypted secret: %s", decryptedSecret)

	// Step 9: Verify the decrypted secret matches the original
	assert.Equal(t, originalSecret, decryptedSecret, "Decrypted secret doesn't match original")
	t.Log("✓ SUCCESS: Decrypted secret matches original!")
}

// TestVerifySignatureWithGoCrypto demonstrates signature verification using Go crypto.
func TestVerifySignatureWithGoCrypto(t *testing.T) {
	// Step 1: Create sealed secret
	result, err := SealSecret("test-secret", WorkloadSecret, nil, nil)
	assert.NoError(t, err, "Failed to seal secret")

	// Step 2: Parse JWS (format: sealed.header.payload.signature)
	parts := strings.Split(result.SealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Invalid JWS format")

	// Step 3: Get the signature
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	assert.NoError(t, err, "Failed to decode signature")

	// Step 4: Parse the verification key (RSA public key)
	block, _ := pem.Decode(result.VerificationKeyPEM)
	assert.NotNil(t, block, "Failed to parse PEM block")

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "Failed to parse public key")

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	assert.True(t, ok, "Not an RSA public key")

	// Step 5: Construct the signing input (header.payload)
	// Per JWS spec, signature is computed over: BASE64URL(header) || '.' || BASE64URL(payload)
	signingInput := parts[1] + "." + parts[2]

	// Step 6: Verify the signature using Go crypto (RSA-SHA512)
	hashed := sha512.Sum512([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA512, hashed[:], signatureBytes)
	assert.NoError(t, err, "Signature verification failed")

	t.Log("✓ SUCCESS: Signature verified using Go crypto!")
}

// TestSealSecretWithProvidedKeys tests sealing with user-provided encryption and signing keys.
func TestSealSecretWithProvidedKeys(t *testing.T) {
	// Generate keys to use
	_, encPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate encryption key pair")

	_, signPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate signing key pair")

	// Seal secret with provided keys
	result, err := SealSecret("test-secret", WorkloadSecret, encPrivKey, signPrivKey)
	assert.NoError(t, err, "Failed to seal secret with provided keys")

	// Verify sealed secret format
	assert.True(t, strings.HasPrefix(result.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify the returned keys match what we provided
	assert.Equal(t, string(encPrivKey), string(result.DecryptionKeyPEM), "Returned decryption key doesn't match provided encryption key")

	// Verify the sealed secret is not empty and has correct format
	parts := strings.Split(result.SealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret")
}

// TestSealSecretWithPartialKeys tests that providing only one key generates the other.
func TestSealSecretWithPartialKeys(t *testing.T) {
	// Generate only encryption key
	_, encPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate encryption key pair")

	// Seal with only encryption key provided (signing key should be generated)
	result1, err := SealSecret("test-secret", WorkloadSecret, encPrivKey, nil)
	assert.NoError(t, err, "Failed to seal secret with partial keys")

	// Verify sealed secret was created
	assert.True(t, strings.HasPrefix(result1.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify encryption key matches what we provided
	assert.Equal(t, string(encPrivKey), string(result1.DecryptionKeyPEM), "Returned decryption key doesn't match provided encryption key")

	// Verify signing key was generated (should not be empty)
	assert.NotEmpty(t, result1.VerificationKeyPEM, "Verification key should have been generated but is empty")

	// Generate only signing key
	_, signPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate signing key pair")

	// Seal with only signing key provided (encryption key should be generated)
	result2, err := SealSecret("test-secret", EnvSecret, nil, signPrivKey)
	assert.NoError(t, err, "Failed to seal secret with partial keys")

	// Verify sealed secret was created
	assert.True(t, strings.HasPrefix(result2.SealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify encryption key was generated (should not be empty)
	assert.NotEmpty(t, result2.DecryptionKeyPEM, "Decryption key should have been generated but is empty")
}

// Helper function to generate RSA key pair for testing
func generateRSAKeyPairNative() (publicKeyPEM, privateKeyPEM []byte, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return publicKeyPEM, privateKeyPEM, nil
}

// ExampleSealSecret_withGeneratedKeys demonstrates sealing a secret with auto-generated keys.
func ExampleSealSecret_withGeneratedKeys() {
	// When nil is passed for both keys, new keys are generated automatically
	result, err := SealSecret("my-database-password", WorkloadSecret, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sealed secret created with auto-generated keys")
	fmt.Printf("Sealed secret format: %s\n", result.SealedSecret[:7])
	fmt.Printf("Has decryption key: %t\n", len(result.DecryptionKeyPEM) > 0)
	fmt.Printf("Has verification key: %t\n", len(result.VerificationKeyPEM) > 0)

	// Output:
	// Sealed secret created with auto-generated keys
	// Sealed secret format: sealed.
	// Has decryption key: true
	// Has verification key: true
}

// ExampleSealSecret_withProvidedKeys demonstrates sealing a secret with user-provided keys.
func ExampleSealSecret_withProvidedKeys() {
	// Generate your own keys
	_, encryptionKey, err := generateRSAKeyPairNative()
	if err != nil {
		log.Fatal(err)
	}

	_, signingKey, err := generateRSAKeyPairNative()
	if err != nil {
		log.Fatal(err)
	}

	// Use your own keys for sealing
	result, err := SealSecret("my-api-key", EnvSecret, encryptionKey, signingKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sealed secret created with provided keys")
	fmt.Printf("Sealed secret format: %s\n", result.SealedSecret[:7])
	fmt.Printf("Encryption key matches: %t\n", string(result.DecryptionKeyPEM) == string(encryptionKey))

	// Output:
	// Sealed secret created with provided keys
	// Sealed secret format: sealed.
	// Encryption key matches: true
}

// ExampleSealSecret_withPartialKeys demonstrates sealing with only one key provided.
func ExampleSealSecret_withPartialKeys() {
	// Generate only encryption key
	_, encryptionKey, err := generateRSAKeyPairNative()
	if err != nil {
		log.Fatal(err)
	}

	// Provide only encryption key, signing key will be auto-generated
	result, err := SealSecret("my-secret", WorkloadSecret, encryptionKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sealed secret created with partial keys")
	fmt.Printf("Sealed secret format: %s\n", result.SealedSecret[:7])
	fmt.Printf("Encryption key provided: %t\n", string(result.DecryptionKeyPEM) == string(encryptionKey))
	fmt.Printf("Signing key generated: %t\n", len(result.VerificationKeyPEM) > 0)

	// Output:
	// Sealed secret created with partial keys
	// Sealed secret format: sealed.
	// Encryption key provided: true
	// Signing key generated: true
}
