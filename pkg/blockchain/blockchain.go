package blockchain

// import (
// 	"github.com/ethereum/go-ethereum/crypto"
// 	"github.com/portto/solana-go-sdk/common"
// )

// type BlockchainType int

// const (
// 	Ethereum BlockchainType = iota
// 	Solana
// )

// func VerifySignature(blockchain BlockchainType, address, message, signature string) bool {
// 	switch blockchain {
// 	case Ethereum:

// 		prefix := "\x19Ethereum Signed Message:\n" + len(message)
// 		message = prefix + message

// 		// Recover public key from the signature.
// 		publicKey, err := crypto.Ecrecover(crypto.Keccak256([]byte(message)), []byte(signature))
// 		if err != nil {
// 			return false
// 		}

// 		// Recover address from the public key.
// 		recoveredAddress := crypto.PubkeyToAddress(publicKey).Hex()

// 		// Compare recovered address with the original one.
// 		return recoveredAddress == address
// 	case Solana:
// 		// Solana signature verification code
// 		pubKey := common.PublicKeyFromString(address)
// 		return pubKey.VerifySignature([]byte(message), []byte(signature))
// 	default:
// 		return false
// 	}
// }

// func ValidateAddress(blockchain BlockchainType, address string) bool {
// 	switch blockchain {
// 	case Ethereum:
// 		return crypto.IsHexAddress(address)
// 	case Solana:
// 		pubKey := common.PublicKeyFromString(address)
// 		return pubKey != nil
// 	default:
// 		return false
// 	}
// }
