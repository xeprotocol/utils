// Copyright (C) 2026 Edge Network Technologies Limited
// Use of this source code is governed by a GNU GPL-style license
// that can be found in the LICENSE.md file. All rights reserved.

package wallet

import (
	"strings"
	"testing"
)

func TestGenerateWallet(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	if wallet.PrivateKey == "" {
		t.Error("PrivateKey should not be empty")
	}

	if wallet.PublicKey == "" {
		t.Error("PublicKey should not be empty")
	}

	if !strings.HasPrefix(wallet.Address, "xe_") {
		t.Errorf("Address should start with 'xe_', got: %s", wallet.Address)
	}

	if len(wallet.Address) != 43 { // "xe_" + 40 hex chars
		t.Errorf("Address should be 43 chars, got: %d", len(wallet.Address))
	}
}

func TestChecksumAddressIsValid(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	if !ChecksumAddressIsValid(wallet.Address) {
		t.Errorf("Generated address should be valid: %s", wallet.Address)
	}

	// Test invalid addresses
	if ChecksumAddressIsValid("invalid") {
		t.Error("'invalid' should not be a valid address")
	}

	// Create an intentionally wrong checksum by modifying case
	testAddr := "xe_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	correctChecksum := GenerateChecksumAddress(testAddr)
	// Flip the case of a letter that should be uppercase
	wrongChecksum := strings.Replace(correctChecksum, "A", "a", 1)
	if wrongChecksum == correctChecksum {
		// If no A was replaced, flip a lowercase to uppercase
		wrongChecksum = strings.Replace(correctChecksum, "a", "A", 1)
	}
	if ChecksumAddressIsValid(wrongChecksum) && wrongChecksum != correctChecksum {
		t.Error("Address with wrong checksum should be invalid")
	}
}

func TestRestoreWalletFromPrivateKey(t *testing.T) {
	original, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	restored, err := RestoreWalletFromPrivateKey(original.PrivateKey)
	if err != nil {
		t.Fatalf("RestoreWalletFromPrivateKey failed: %v", err)
	}

	if original.Address != restored.Address {
		t.Errorf("Addresses should match. Original: %s, Restored: %s", original.Address, restored.Address)
	}

	if original.PublicKey != restored.PublicKey {
		t.Errorf("Public keys should match. Original: %s, Restored: %s", original.PublicKey, restored.PublicKey)
	}
}

func TestSignatureGenerationAndVerification(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	msg := "Hello, Edge Network!"
	signature, err := GenerateSignature(wallet.PrivateKey, msg)
	if err != nil {
		t.Fatalf("GenerateSignature failed: %v", err)
	}

	if len(signature) != 130 {
		t.Errorf("Signature should be 130 hex chars (r:64 + s:64 + v:2), got: %d", len(signature))
	}

	if !VerifySignatureAddress(msg, signature, wallet.Address) {
		t.Error("Signature verification failed for valid signature")
	}

	// Test with wrong message
	if VerifySignatureAddress("Wrong message", signature, wallet.Address) {
		t.Error("Signature verification should fail for wrong message")
	}

	// Test with wrong address
	otherWallet, _ := GenerateWallet()
	if VerifySignatureAddress(msg, signature, otherWallet.Address) {
		t.Error("Signature verification should fail for wrong address")
	}
}

func TestRecoverAddressFromSignedMessage(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	msg := "Test message for recovery"
	signature, err := GenerateSignature(wallet.PrivateKey, msg)
	if err != nil {
		t.Fatalf("GenerateSignature failed: %v", err)
	}

	recoveredAddress, err := RecoverAddressFromSignedMessage(msg, signature)
	if err != nil {
		t.Fatalf("RecoverAddressFromSignedMessage failed: %v", err)
	}

	if recoveredAddress != wallet.Address {
		t.Errorf("Recovered address should match. Expected: %s, Got: %s", wallet.Address, recoveredAddress)
	}
}

func TestXeStringFromMicroXe(t *testing.T) {
	tests := []struct {
		mxe      int64
		format   bool
		expected string
	}{
		{1000000, false, "1.000000"},
		{1500000, false, "1.500000"},
		{500000, false, "0.500000"},
		{123456789, false, "123.456789"},
		{1234567890123, false, "1234567.890123"},
		{1234567890123, true, "1,234,567.890123"},
	}

	for _, tt := range tests {
		result := XeStringFromMicroXe(tt.mxe, tt.format)
		if result != tt.expected {
			t.Errorf("XeStringFromMicroXe(%d, %v) = %s; want %s", tt.mxe, tt.format, result, tt.expected)
		}
	}
}

func TestToMicroXe(t *testing.T) {
	tests := []struct {
		xe       string
		expected int64
	}{
		{"1.000000", 1000000},
		{"1.5", 1500000},
		{"0.5", 500000},
		{"123.456789", 123456789},
		{"1234567.890123", 1234567890123},
		{"100", 100000000},
	}

	for _, tt := range tests {
		result, err := ToMicroXe(tt.xe)
		if err != nil {
			t.Errorf("ToMicroXe(%s) error: %v", tt.xe, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("ToMicroXe(%s) = %d; want %d", tt.xe, result, tt.expected)
		}
	}
}

func TestFormatXe(t *testing.T) {
	result, err := FormatXe("1.5", false)
	if err != nil {
		t.Fatalf("FormatXe failed: %v", err)
	}
	if result != "1.500000" {
		t.Errorf("FormatXe(1.5, false) = %s; want 1.500000", result)
	}
}

func TestGetShortAddress(t *testing.T) {
	address := "xe_1234567890abcdef1234567890abcdef12345678"
	short := GetShortAddress(address)
	expected := "xe_1234...5678"
	if short != expected {
		t.Errorf("GetShortAddress(%s) = %s; want %s", address, short, expected)
	}
}

func TestPrivateKeyToPublicKey(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	publicKey, err := PrivateKeyToPublicKey(wallet.PrivateKey)
	if err != nil {
		t.Fatalf("PrivateKeyToPublicKey failed: %v", err)
	}

	if publicKey != wallet.PublicKey {
		t.Errorf("Public keys should match. Expected: %s, Got: %s", wallet.PublicKey, publicKey)
	}
}

func TestPrivateKeyToChecksumAddress(t *testing.T) {
	wallet, err := GenerateWallet()
	if err != nil {
		t.Fatalf("GenerateWallet failed: %v", err)
	}

	address, err := PrivateKeyToChecksumAddress(wallet.PrivateKey)
	if err != nil {
		t.Fatalf("PrivateKeyToChecksumAddress failed: %v", err)
	}

	if address != wallet.Address {
		t.Errorf("Addresses should match. Expected: %s, Got: %s", wallet.Address, address)
	}
}
