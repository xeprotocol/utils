# utils

Utility library including wallet utilities for the XE blockchain and more

## Features

- **wallet**: XE blockchain wallet generation, address validation, signature, and conversion utilities
- **identity**: Proof-of-work identity generation and verification using Argon2id

## Installation

```sh
go get github.com/xeprotocol/utils
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/xeprotocol/utils/wallet"
    "github.com/xeprotocol/utils/identity"
)

func main() {
    // Generate a new wallet
    w, err := wallet.GenerateWallet()
    if err != nil {
        panic(err)
    }
    fmt.Println("Address:", w.Address)

    // Generate an identity for the wallet
    id, err := identity.GenerateIdentityForWallet(w, 10)
    if err != nil {
        panic(err)
    }
    fmt.Println("Identity generated with", len(id.S), "challenges")

    // Verify the identity
    pub := id.GetPublicIdentity()
    valid := identity.VerifyIdentity(&pub, w.Address)
    fmt.Println("Identity valid:", valid)
}
```

## API

### wallet

- `GenerateWallet()`: Generate a new XE wallet (address, publicKey, privateKey)
- `GenerateKeyPair()`: Generate a secp256k1 key pair
- `GenerateChecksumAddress(address)`: Create a checksummed XE address
- `ChecksumAddressIsValid(address)`: Validate a XE address
- `RestoreWalletFromPrivateKey(privateKey)`: Restore wallet from private key
- `PublicKeyToChecksumAddress(publicKey)`: Convert public key to XE address
- `PrivateKeyToPublicKey(privateKey)`: Convert private key to public key
- `PrivateKeyToChecksumAddress(privateKey)`: Convert private key to XE address
- `GenerateSignature(privateKey, msg)`: Sign a message
- `VerifySignatureAddress(msg, signature, address)`: Verify a signature
- `RecoverPublicKeyFromSignedMessage(msg, signature)`: Recover public key from signed message
- `RecoverAddressFromSignedMessage(msg, signature)`: Recover address from signed message
- `XeStringFromMicroXe(mxe, format)`: Format microXE to XE string
- `ToMicroXe(xe)`: Convert XE string to microXE
- `FormatXe(xe, format)`: Format XE value
- `GetShortAddress(address)`: Get shortened address for display

### identity

- `GenerateIdentityForWallet(wallet, challenges)`: Generate proof-of-work identity chain
- `VerifyIdentity(identity, walletAddress)`: Verify identity against wallet address
- `NewIdentity(...)`: Create a new Identity instance
- `Identity.AddChallenge()`: Add one more proof-of-work challenge
- `Identity.GetPublicIdentity()`: Get public-safe identity for on-chain storage

## Testing

```sh
go test ./...
```
