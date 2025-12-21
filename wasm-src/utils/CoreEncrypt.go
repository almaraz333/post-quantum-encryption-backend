package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type EncryptionResult struct {
	EncryptedBlob []byte
	PrivateKey    []byte
}

func CoreEncrypt(plaintext []byte, symAlgo, pqcAlgo string) (*EncryptionResult, error) {
	var kemCiphertext []byte
	var sharedSecret []byte
	var privateKeyBytes []byte
	var err error

	switch pqcAlgo {
	case AlgoMLKEM768:
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %v", err)
		}

		ek := dk.EncapsulationKey()

		sharedSecret, kemCiphertext = ek.Encapsulate()

		privateKeyBytes = dk.Bytes()

	case AlgoMLKEM1024:
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %v", err)
		}

		ek := dk.EncapsulationKey()
		sharedSecret, kemCiphertext = ek.Encapsulate()
		privateKeyBytes = dk.Bytes()

	default:
		return nil, fmt.Errorf("unknown quantum algorithm: %s", pqcAlgo)
	}

	keyMaterial := sha256.Sum256(sharedSecret)

	var aead cipher.AEAD

	switch symAlgo {
	case AlgoChaCha20:
		aead, err = chacha20poly1305.New(keyMaterial[:])
		if err != nil {
			return nil, err
		}

	case AlgoAESGCM:
		block, err := aes.NewCipher(keyMaterial[:])
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unknown symmetric algorithm: %s", symAlgo)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	encryptedPayload := aead.Seal(nil, nonce, plaintext, nil)

	finalBlob := make([]byte, 0, 4+len(kemCiphertext)+len(nonce)+len(encryptedPayload))

	kemLen := make([]byte, 4)
	binary.BigEndian.PutUint32(kemLen, uint32(len(kemCiphertext)))
	finalBlob = append(finalBlob, kemLen...)

	finalBlob = append(finalBlob, kemCiphertext...)

	finalBlob = append(finalBlob, nonce...)

	finalBlob = append(finalBlob, encryptedPayload...)

	return &EncryptionResult{
		EncryptedBlob: finalBlob,
		PrivateKey:    privateKeyBytes,
	}, nil
}
