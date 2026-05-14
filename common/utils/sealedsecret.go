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
	"fmt"

	"github.com/ibm-hyper-protect/contract-go/v2/common/encrypt"
)

// SecretType defines the type of secret being sealed.
type SecretType string

const (
	// WorkloadSecret indicates a secret for workload configuration (key IDs: "workload_decrypt" and "workload_verify")
	WorkloadSecret SecretType = "workload"

	// EnvSecret indicates a secret for environment configuration (key IDs: "env_decrypt" and "env_verify")
	EnvSecret SecretType = "env"
)

// SealedSecretResult contains the sealed secret and keys for decryption and verification.
type SealedSecretResult struct {
	// SealedSecret is the encrypted secret in JWS compact serialization format (sealed.<header>.<payload>.<signature>)
	SealedSecret string

	// DecryptionKeyPEM is the RSA private key for decryption (PEM format) - store securely
	DecryptionKeyPEM []byte

	// VerificationKeyPEM is the RSA public key for signature verification (PEM format)
	VerificationKeyPEM []byte
}

// SealSecret encrypts a secret using AES-256-GCM with RSA key wrapping and RSA-SHA512 signing.
//
// Use this function to create sealed secrets for IBM Confidential Computing workload or environment
// configurations. The function performs the complete encryption workflow: generates or uses provided
// RSA key pairs, encrypts the secret with AES-256-GCM, wraps the AES key with RSA, and signs the
// result with RSA-SHA512. The output is in JWS compact serialization format compatible with IBM
// Confidential Computing contracts.
//
// Parameters:
//   - secret: The plaintext secret to encrypt (must not be empty)
//   - secretType: Either WorkloadSecret or EnvSecret, determines key IDs used in the sealed secret
//   - encryptionKeyPEM: Optional RSA private key for encryption (PEM format). If nil, generates new key.
//   - signingKeyPEM: Optional RSA private key for signing (PEM format). If nil, generates new key.
//
// Returns:
//   - SealedSecretResult containing the sealed secret and all keys (provided or generated)
//   - Error if encryption fails, keys cannot be generated/parsed, or inputs are invalid
func SealSecret(secret string, secretType SecretType, encryptionKeyPEM, signingKeyPEM []byte) (*SealedSecretResult, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	if secretType != WorkloadSecret && secretType != EnvSecret {
		return nil, fmt.Errorf("invalid secret type: must be WorkloadSecret or EnvSecret")
	}

	var encPubKey, encPrivKey, signPubKey, signPrivKey []byte
	var err error

	// Handle encryption key - use provided or generate new
	if len(encryptionKeyPEM) > 0 {
		encPrivKey = encryptionKeyPEM
		encPubKey, err = encrypt.ExtractPublicKeyFromPrivateNative(encPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to extract public key from encryption private key: %w", err)
		}
	} else {
		encPubKey, encPrivKey, err = encrypt.GenerateRSAKeyPairNative()
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key pair: %w", err)
		}
	}

	// Handle signing key - use provided or generate new
	if len(signingKeyPEM) > 0 {
		signPrivKey = signingKeyPEM
		signPubKey, err = encrypt.ExtractPublicKeyFromPrivateNative(signPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to extract public key from signing private key: %w", err)
		}
	} else {
		signPubKey, signPrivKey, err = encrypt.GenerateRSAKeyPairNative()
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key pair: %w", err)
		}
	}

	sealedSecret, err := encrypt.EncryptSecretNative(secret, encPubKey, signPrivKey, string(secretType))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	return &SealedSecretResult{
		SealedSecret:       sealedSecret,
		DecryptionKeyPEM:   encPrivKey,
		VerificationKeyPEM: signPubKey,
	}, nil
}
