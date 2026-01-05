// Copyright (C) 2026 Edge Network Technologies Limited
// Use of this source code is governed by a GNU GPL-style license
// that can be found in the LICENSE.md file. All rights reserved.

package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Wallet represents an XE blockchain wallet
type Wallet struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Address    string `json:"address"`
}

// GenerateKeyPair generates a new secp256k1 key pair
func GenerateKeyPair() (*secp256k1.PrivateKey, error) {
	return secp256k1.GeneratePrivateKey()
}

// GenerateWallet generates a new XE wallet
func GenerateWallet() (*Wallet, error) {
	privKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	privateKeyHex := hex.EncodeToString(privKey.Serialize())
	publicKey := privKey.PubKey()
	publicKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())
	address := PublicKeyToChecksumAddress(publicKeyHex)

	return &Wallet{
		PrivateKey: privateKeyHex,
		PublicKey:  publicKeyHex,
		Address:    address,
	}, nil
}

// keccak256 computes the Keccak-256 hash of the input
func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// GenerateChecksumAddress creates a checksummed XE address from an address
func GenerateChecksumAddress(address string) string {
	addr := address[3:] // Remove "xe_" prefix
	addrLower := strings.ToLower(addr)
	addrHash := hex.EncodeToString(keccak256([]byte(addrLower)))

	result := make([]byte, len(addr))
	for i := 0; i < len(addr); i++ {
		hashChar, _ := strconv.ParseInt(string(addrHash[i]), 16, 64)
		c := addrLower[i]
		if hashChar >= 8 && c >= 'a' && c <= 'f' {
			result[i] = c - 32 // Convert to uppercase
		} else {
			result[i] = c
		}
	}

	return "xe_" + string(result)
}

// ChecksumAddressIsValid validates an XE address
func ChecksumAddressIsValid(address string) bool {
	pattern := regexp.MustCompile(`^(xe_[a-fA-F0-9]{40})$`)
	if !pattern.MatchString(address) {
		return false
	}
	return address == GenerateChecksumAddress(address)
}

// RestoreWalletFromPrivateKey restores a wallet from a private key
func RestoreWalletFromPrivateKey(privateKeyHex string) (*Wallet, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}

	privKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
	publicKey := privKey.PubKey()
	publicKeyHex := hex.EncodeToString(publicKey.SerializeCompressed())
	address := PublicKeyToChecksumAddress(publicKeyHex)

	return &Wallet{
		PrivateKey: privateKeyHex,
		PublicKey:  publicKeyHex,
		Address:    address,
	}, nil
}

// PublicKeyToChecksumAddress converts a public key to a checksummed XE address
func PublicKeyToChecksumAddress(publicKeyHex string) string {
	// Hash the hex string directly (as UTF-8 bytes), matching JS behavior
	hash := keccak256([]byte(publicKeyHex))
	hashHex := hex.EncodeToString(hash)
	addr := "xe_" + hashHex[len(hashHex)-40:]
	return GenerateChecksumAddress(addr)
}

// PrivateKeyToPublicKey converts a private key to a public key
func PrivateKeyToPublicKey(privateKeyHex string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}

	privKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
	publicKey := privKey.PubKey()
	return hex.EncodeToString(publicKey.SerializeCompressed()), nil
}

// PrivateKeyToChecksumAddress converts a private key to a checksummed XE address
func PrivateKeyToChecksumAddress(privateKeyHex string) (string, error) {
	publicKeyHex, err := PrivateKeyToPublicKey(privateKeyHex)
	if err != nil {
		return "", err
	}
	return PublicKeyToChecksumAddress(publicKeyHex), nil
}

// GenerateSignature signs a message with a private key
func GenerateSignature(privateKeyHex, msg string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}

	privKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)

	// SHA256 hash of the message
	msgHash := sha256.Sum256([]byte(msg))

	// Sign the hash
	sig := ecdsa.SignCompact(privKey, msgHash[:], false)

	// sig[0] is the recovery ID, sig[1:33] is R, sig[33:65] is S
	recoveryParam := sig[0] - 27
	r := sig[1:33]
	s := sig[33:65]

	// Format as r + s + recovery param (like the JS version)
	return hex.EncodeToString(r) + hex.EncodeToString(s) + fmt.Sprintf("%02x", recoveryParam), nil
}

// VerifySignatureAddress verifies a signature against a message and address
func VerifySignatureAddress(msg, signature, address string) bool {
	publicKeyHex, err := RecoverPublicKeyFromSignedMessage(msg, signature)
	if err != nil {
		return false
	}
	derivedAddress := PublicKeyToChecksumAddress(publicKeyHex)
	return address == derivedAddress
}

// RecoverPublicKeyFromSignedMessage recovers the public key from a signed message
func RecoverPublicKeyFromSignedMessage(msg, signature string) (string, error) {
	if len(signature) != 130 {
		return "", errors.New("invalid signature length")
	}

	rHex := signature[0:64]
	sHex := signature[64:128]
	recoveryHex := signature[128:130]

	rBytes, err := hex.DecodeString(rHex)
	if err != nil {
		return "", err
	}
	sBytes, err := hex.DecodeString(sHex)
	if err != nil {
		return "", err
	}
	recoveryParam, err := strconv.ParseInt(recoveryHex, 16, 64)
	if err != nil {
		return "", err
	}

	// SHA256 hash of the message
	msgHash := sha256.Sum256([]byte(msg))

	// Reconstruct the compact signature format expected by RecoverCompact
	compactSig := make([]byte, 65)
	compactSig[0] = byte(27 + recoveryParam)
	copy(compactSig[1:33], rBytes)
	copy(compactSig[33:65], sBytes)

	// Recover the public key
	pubKey, _, err := ecdsa.RecoverCompact(compactSig, msgHash[:])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(pubKey.SerializeCompressed()), nil
}

// RecoverAddressFromSignedMessage recovers the address from a signed message
func RecoverAddressFromSignedMessage(msg, signature string) (string, error) {
	publicKeyHex, err := RecoverPublicKeyFromSignedMessage(msg, signature)
	if err != nil {
		return "", err
	}
	return PublicKeyToChecksumAddress(publicKeyHex), nil
}

// XeStringFromMicroXe formats microXE to XE string
func XeStringFromMicroXe(mxe int64, format bool) string {
	s := strconv.FormatInt(mxe, 10)

	var fraction string
	var whole string

	if len(s) <= 6 {
		fraction = strings.Repeat("0", 6-len(s)) + s
		whole = "0"
	} else {
		fraction = s[len(s)-6:]
		whole = s[:len(s)-6]
	}

	if format {
		// Format whole part with commas
		wholeInt, _ := strconv.ParseInt(whole, 10, 64)
		whole = formatWithCommas(wholeInt)
	}

	return whole + "." + fraction
}

// formatWithCommas formats a number with commas as thousand separators
func formatWithCommas(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}

	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
		if len(s) > remainder {
			result.WriteString(",")
		}
	}

	for i := remainder; i < len(s); i += 3 {
		result.WriteString(s[i : i+3])
		if i+3 < len(s) {
			result.WriteString(",")
		}
	}

	return result.String()
}

// ToMicroXe converts XE string/number to microXE
func ToMicroXe(xe string) (int64, error) {
	parts := strings.Split(xe, ".")
	whole := parts[0]

	var fraction string
	if len(parts) > 1 {
		fraction = parts[1]
		if len(fraction) > 6 {
			fraction = fraction[:6]
		} else {
			fraction = fraction + strings.Repeat("0", 6-len(fraction))
		}
	} else {
		fraction = "000000"
	}

	combined := whole + fraction
	return strconv.ParseInt(combined, 10, 64)
}

// FormatXe formats an XE value
func FormatXe(xe string, format bool) (string, error) {
	mxe, err := ToMicroXe(xe)
	if err != nil {
		return "", err
	}
	return XeStringFromMicroXe(mxe, format), nil
}

// GetShortAddress returns a shortened version of an address
func GetShortAddress(address string) string {
	if len(address) < 11 {
		return address
	}
	return address[:7] + "..." + address[len(address)-4:]
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
