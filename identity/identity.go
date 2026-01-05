// Copyright (C) 2026 Edge Network Technologies Limited
// Use of this source code is governed by a GNU GPL-style license
// that can be found in the LICENSE.md file. All rights reserved.

package identity

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/xeprotocol/utils/wallet"
	"golang.org/x/crypto/argon2"
)

// PublicIdentity represents a public-safe version of an identity
// This is the structure stored on-chain in wallet.identity
type PublicIdentity struct {
	T int64    `json:"t"` // timestamp
	S []string `json:"s"` // signatures
	C []int    `json:"c"` // solutions
}

// Identity represents a proof-of-work identity for a wallet
type Identity struct {
	privateKey    string
	walletAddress string
	Timestamp     int64
	S             []string // signatures
	C             []int    // solutions
}

// argon2idHash applies Argon2id memory-hard function
func argon2idHash(input, salt string) []byte {
	return argon2.IDKey(
		[]byte(input),
		[]byte(salt),
		3,       // time cost
		64*1024, // memory cost (64 MiB)
		1,       // parallelism
		32,      // hash length
	)
}

// calculateDifficulty calculates the difficulty for a given challenge number
func calculateDifficulty(challenge int) int {
	value := 2 + int(float64(challenge)*0.4)
	if value < 2 {
		return 2
	}
	if value > 4 {
		return 4
	}
	return value
}

// mineSignature mines a signature by trying solutions until finding one with required leading zeros
// Includes Argon2id memory-hard step for GPU resistance (run once per challenge)
func mineSignature(privateKey, message string, difficulty, challenge int) (string, int, error) {
	target := strings.Repeat("0", difficulty)
	salt := fmt.Sprintf("xe-challenge-%d", challenge)

	// Run Argon2id ONCE per challenge to generate seed
	seed := argon2idHash(message, salt)
	seedHex := hex.EncodeToString(seed)

	solution := 0
	for {
		// Cheap operation: just append solution to seed
		signatureInput := fmt.Sprintf("%s%d", seedHex, solution)
		signature, err := wallet.GenerateSignature(privateKey, signatureInput)
		if err != nil {
			return "", 0, err
		}

		if strings.HasPrefix(signature, target) {
			return signature, solution, nil
		}
		solution++
	}
}

// NewIdentity creates a new Identity instance
func NewIdentity(privateKey, walletAddress string, timestamp int64, s []string, c []int) *Identity {
	return &Identity{
		privateKey:    privateKey,
		walletAddress: walletAddress,
		Timestamp:     timestamp,
		S:             s,
		C:             c,
	}
}

// AddChallenge adds one more proof-of-work challenge to this identity
func (id *Identity) AddChallenge() error {
	nextIndex := len(id.S)
	difficulty := calculateDifficulty(nextIndex)

	var message string
	if nextIndex == 0 {
		message = fmt.Sprintf("%s:%d", id.walletAddress, id.Timestamp)
	} else {
		message = id.S[len(id.S)-1]
	}

	signature, solution, err := mineSignature(id.privateKey, message, difficulty, nextIndex)
	if err != nil {
		return err
	}

	id.S = append(id.S, signature)
	id.C = append(id.C, solution)

	return nil
}

// GetPublicIdentity returns a public-safe version of this identity
// This is what gets stored on-chain in the wallet.identity field
func (id *Identity) GetPublicIdentity() PublicIdentity {
	s := make([]string, len(id.S))
	copy(s, id.S)
	c := make([]int, len(id.C))
	copy(c, id.C)

	return PublicIdentity{
		T: id.Timestamp,
		S: s,
		C: c,
	}
}

// GetWalletAddress returns the wallet address
func (id *Identity) GetWalletAddress() string {
	return id.walletAddress
}

// GetPrivateKey returns the private key (use with caution)
func (id *Identity) GetPrivateKey() string {
	return id.privateKey
}

// GenerateIdentityForWallet generates an identity with a proof-of-work chain for an existing wallet
func GenerateIdentityForWallet(w *wallet.Wallet, challenges int) (*Identity, error) {
	if w == nil || w.Address == "" || w.PrivateKey == "" {
		return nil, fmt.Errorf("wallet must have address and privateKey")
	}

	if challenges <= 0 {
		challenges = 10
	}

	timestamp := time.Now().UnixMilli()
	s := make([]string, 0, challenges)
	c := make([]int, 0, challenges)

	for i := 0; i < challenges; i++ {
		var message string
		if i == 0 {
			message = fmt.Sprintf("%s:%d", w.Address, timestamp)
		} else {
			message = s[i-1]
		}

		difficulty := calculateDifficulty(i)
		signature, solution, err := mineSignature(w.PrivateKey, message, difficulty, i)
		if err != nil {
			return nil, err
		}

		s = append(s, signature)
		c = append(c, solution)
	}

	return NewIdentity(w.PrivateKey, w.Address, timestamp, s, c), nil
}

// VerifyIdentity verifies an identity's proof-of-work chain against a wallet address
func VerifyIdentity(identity *PublicIdentity, walletAddress string) bool {
	if identity == nil || walletAddress == "" {
		return false
	}

	if len(identity.S) == 0 || len(identity.C) == 0 {
		return false
	}

	if len(identity.S) != len(identity.C) {
		return false
	}

	challenges := len(identity.S)

	for i := 0; i < challenges; i++ {
		signature := identity.S[i]
		solution := identity.C[i]
		difficulty := calculateDifficulty(i)
		target := strings.Repeat("0", difficulty)

		if !strings.HasPrefix(signature, target) {
			return false
		}

		var message string
		if i == 0 {
			message = fmt.Sprintf("%s:%d", walletAddress, identity.T)
		} else {
			message = identity.S[i-1]
		}

		salt := fmt.Sprintf("xe-challenge-%d", i)
		seed := argon2idHash(message, salt)
		seedHex := hex.EncodeToString(seed)

		signatureInput := fmt.Sprintf("%s%d", seedHex, solution)

		if !wallet.VerifySignatureAddress(signatureInput, signature, walletAddress) {
			return false
		}
	}

	return true
}
