// Copyright (C) 2026 Edge Network Technologies Limited
// Use of this source code is governed by a GNU GPL-style license
// that can be found in the LICENSE.md file. All rights reserved.

package utils

import (
	"github.com/xeprotocol/utils/identity"
	"github.com/xeprotocol/utils/wallet"
)

// Re-export wallet types
type (
	Wallet = wallet.Wallet
)

// Re-export identity types
type (
	Identity       = identity.Identity
	PublicIdentity = identity.PublicIdentity
)

// Wallet functions
var (
	GenerateWallet                    = wallet.GenerateWallet
	GenerateKeyPair                   = wallet.GenerateKeyPair
	RestoreWalletFromPrivateKey       = wallet.RestoreWalletFromPrivateKey
	GenerateChecksumAddress           = wallet.GenerateChecksumAddress
	ChecksumAddressIsValid            = wallet.ChecksumAddressIsValid
	PublicKeyToChecksumAddress        = wallet.PublicKeyToChecksumAddress
	PrivateKeyToChecksumAddress       = wallet.PrivateKeyToChecksumAddress
	PrivateKeyToPublicKey             = wallet.PrivateKeyToPublicKey
	GenerateSignature                 = wallet.GenerateSignature
	VerifySignatureAddress            = wallet.VerifySignatureAddress
	RecoverPublicKeyFromSignedMessage = wallet.RecoverPublicKeyFromSignedMessage
	RecoverAddressFromSignedMessage   = wallet.RecoverAddressFromSignedMessage
	XeStringFromMicroXe               = wallet.XeStringFromMicroXe
	ToMicroXe                         = wallet.ToMicroXe
	FormatXe                          = wallet.FormatXe
	GetShortAddress                   = wallet.GetShortAddress
)

// Identity functions
var (
	NewIdentity               = identity.NewIdentity
	GenerateIdentityForWallet = identity.GenerateIdentityForWallet
	VerifyIdentity            = identity.VerifyIdentity
)
