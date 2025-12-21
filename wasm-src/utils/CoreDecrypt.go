package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func CoreDecrypt(encryptedBlob, privateKeyBytes []byte, symAlgo, pqcAlgo string) ([]byte, error) {
	if len(encryptedBlob) < 4 {
		return nil, fmt.Errorf("blob too short")
	}

	kemLen := binary.BigEndian.Uint32(encryptedBlob[0:4])
	offset := 4

	kemCiphertext := encryptedBlob[offset : offset+int(kemLen)]
	offset += int(kemLen)

	var sharedSecret []byte
	var err error

	switch pqcAlgo {
	case AlgoMLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %v", err)
		}
		sharedSecret, err = dk.Decapsulate(kemCiphertext)
		if err != nil {
			return nil, err
		}

	case AlgoMLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %v", err)
		}
		sharedSecret, err = dk.Decapsulate(kemCiphertext)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unknown algorithm")
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
	}

	nonceSize := aead.NonceSize()
	nonce := encryptedBlob[offset : offset+nonceSize]
	offset += nonceSize

	ciphertext := encryptedBlob[offset:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
}
