// Copyright (C) 2026 Edge Network Technologies Limited
// Use of this source code is governed by a GNU GPL-style license
// that can be found in the LICENSE.md file. All rights reserved.

package identity

import (
	"strings"
	"testing"

	"github.com/xeprotocol/utils/wallet"
)

func TestCalculateDifficulty(t *testing.T) {
	tests := []struct {
		challenge int
		expected  int
	}{
		{0, 2},
		{1, 2},
		{2, 2},
		{3, 3},
		{4, 3},
		{5, 4},
		{10, 4}, // Should cap at 4
		{100, 4},
	}

	for _, tt := range tests {
		result := calculateDifficulty(tt.challenge)
		if result != tt.expected {
			t.Errorf("calculateDifficulty(%d) = %d; want %d", tt.challenge, result, tt.expected)
		}
	}
}

func TestGenerateIdentityForWallet(t *testing.T) {
	w, err := wallet.GenerateWallet()
	if err != nil {
		t.Fatalf("Failed to generate wallet: %v", err)
	}

	// Generate identity with just 2 challenges for speed in tests
	identity, err := GenerateIdentityForWallet(w, 2)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	if identity.Timestamp == 0 {
		t.Error("Timestamp should not be zero")
	}

	if len(identity.S) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(identity.S))
	}

	if len(identity.C) != 2 {
		t.Errorf("Expected 2 solutions, got %d", len(identity.C))
	}

	// Check that signatures have the required leading zeros
	for i, sig := range identity.S {
		difficulty := calculateDifficulty(i)
		target := strings.Repeat("0", difficulty)
		if !strings.HasPrefix(sig, target) {
			t.Errorf("Signature %d should have %d leading zeros, got: %s", i, difficulty, sig[:10])
		}
	}

	if identity.GetWalletAddress() != w.Address {
		t.Errorf("Wallet address mismatch. Expected: %s, Got: %s", w.Address, identity.GetWalletAddress())
	}

	if identity.GetPrivateKey() != w.PrivateKey {
		t.Error("Private key mismatch")
	}
}

func TestGetPublicIdentity(t *testing.T) {
	w, err := wallet.GenerateWallet()
	if err != nil {
		t.Fatalf("Failed to generate wallet: %v", err)
	}

	identity, err := GenerateIdentityForWallet(w, 2)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	pub := identity.GetPublicIdentity()

	if pub.T != identity.Timestamp {
		t.Error("Timestamp mismatch")
	}

	if len(pub.S) != len(identity.S) {
		t.Error("Signatures length mismatch")
	}

	if len(pub.C) != len(identity.C) {
		t.Error("Solutions length mismatch")
	}

	// Verify that modifying the returned slices doesn't affect the original
	pub.S[0] = "modified"
	if identity.S[0] == "modified" {
		t.Error("GetPublicIdentity should return copies, not references")
	}
}

func TestVerifyIdentity(t *testing.T) {
	w, err := wallet.GenerateWallet()
	if err != nil {
		t.Fatalf("Failed to generate wallet: %v", err)
	}

	identity, err := GenerateIdentityForWallet(w, 2)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	pub := identity.GetPublicIdentity()

	// Verify against correct wallet address
	if !VerifyIdentity(&pub, w.Address) {
		t.Error("Identity should verify against the correct wallet address")
	}

	// Verify against wrong wallet address
	otherWallet, _ := wallet.GenerateWallet()
	if VerifyIdentity(&pub, otherWallet.Address) {
		t.Error("Identity should not verify against a different wallet address")
	}

	// Test with nil identity
	if VerifyIdentity(nil, w.Address) {
		t.Error("Nil identity should not verify")
	}

	// Test with empty wallet address
	if VerifyIdentity(&pub, "") {
		t.Error("Empty wallet address should not verify")
	}

	// Test with tampered signature
	tamperedPub := identity.GetPublicIdentity()
	if len(tamperedPub.S) > 0 {
		tamperedPub.S[0] = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		if VerifyIdentity(&tamperedPub, w.Address) {
			t.Error("Tampered identity should not verify")
		}
	}
}

func TestAddChallenge(t *testing.T) {
	w, err := wallet.GenerateWallet()
	if err != nil {
		t.Fatalf("Failed to generate wallet: %v", err)
	}

	identity, err := GenerateIdentityForWallet(w, 1)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	initialCount := len(identity.S)

	err = identity.AddChallenge()
	if err != nil {
		t.Fatalf("Failed to add challenge: %v", err)
	}

	if len(identity.S) != initialCount+1 {
		t.Errorf("Expected %d signatures after AddChallenge, got %d", initialCount+1, len(identity.S))
	}

	if len(identity.C) != initialCount+1 {
		t.Errorf("Expected %d solutions after AddChallenge, got %d", initialCount+1, len(identity.C))
	}

	// Verify the new identity is still valid
	pub := identity.GetPublicIdentity()
	if !VerifyIdentity(&pub, w.Address) {
		t.Error("Identity should still be valid after adding challenge")
	}
}

func TestGenerateIdentityForWalletWithInvalidWallet(t *testing.T) {
	// Test with nil wallet
	_, err := GenerateIdentityForWallet(nil, 2)
	if err == nil {
		t.Error("Should error with nil wallet")
	}

	// Test with empty address
	w := &wallet.Wallet{
		PrivateKey: "somekey",
		PublicKey:  "somepubkey",
		Address:    "",
	}
	_, err = GenerateIdentityForWallet(w, 2)
	if err == nil {
		t.Error("Should error with empty address")
	}

	// Test with empty private key
	w = &wallet.Wallet{
		PrivateKey: "",
		PublicKey:  "somepubkey",
		Address:    "xe_1234567890123456789012345678901234567890",
	}
	_, err = GenerateIdentityForWallet(w, 2)
	if err == nil {
		t.Error("Should error with empty private key")
	}
}
