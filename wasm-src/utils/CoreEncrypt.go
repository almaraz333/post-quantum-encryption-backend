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
	// ─────────────────────────────────────────────────────────
	// STEP 1: Generate a Fresh Keypair (Post-Quantum)
	// ─────────────────────────────────────────────────────────
	// WHY? We need a keypair to perform Key Encapsulation.
	// The PUBLIC key encrypts a secret.
	// The PRIVATE key decrypts that secret later.

	var kemCiphertext []byte
	var sharedSecret []byte
	var privateKeyBytes []byte
	var err error

	switch pqcAlgo {
	case AlgoMLKEM768:
		// Generate a new ML-KEM-768 keypair
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %v", err)
		}

		// Extract the public key (Encapsulation Key)
		ek := dk.EncapsulationKey()

		// Use the public key to "encapsulate" a shared secret
		sharedSecret, kemCiphertext = ek.Encapsulate()

		// Save the private key so we can decrypt later
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

	// ─────────────────────────────────────────────────────────
	// STEP 2: Derive the File Encryption Key
	// ─────────────────────────────────────────────────────────
	// WHY? The "shared secret" from KEM is raw entropy.
	// We hash it to create a clean, uniform 32-byte key.

	keyMaterial := sha256.Sum256(sharedSecret) // [32]byte

	// ─────────────────────────────────────────────────────────
	// STEP 3: Encrypt the File (Symmetric AEAD)
	// ─────────────────────────────────────────────────────────
	// WHY? We can't encrypt gigabytes with Kyber directly.
	// We use AES or ChaCha20 (fast symmetric ciphers).

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

	// Generate a nonce (Number Used Once)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	// Encrypt the file
	// Seal() = Encrypt + Authenticate (prevents tampering)
	encryptedPayload := aead.Seal(nil, nonce, plaintext, nil)

	// ─────────────────────────────────────────────────────────
	// STEP 4: Package Everything into a Single Blob
	// ─────────────────────────────────────────────────────────
	// WHY? The decryptor needs to know:
	// - How long is the KEM ciphertext?
	// - What is the nonce?
	// - Where does the encrypted file start?

	// Format: [KEM_LEN (4 bytes)] [KEM Ciphertext] [Nonce] [Encrypted File]

	finalBlob := make([]byte, 0, 4+len(kemCiphertext)+len(nonce)+len(encryptedPayload))

	// Write KEM length (4 bytes, big-endian)
	kemLen := make([]byte, 4)
	binary.BigEndian.PutUint32(kemLen, uint32(len(kemCiphertext)))
	finalBlob = append(finalBlob, kemLen...)

	// Write KEM ciphertext
	finalBlob = append(finalBlob, kemCiphertext...)

	// Write Nonce
	finalBlob = append(finalBlob, nonce...)

	// Write Encrypted Payload
	finalBlob = append(finalBlob, encryptedPayload...)

	return &EncryptionResult{
		EncryptedBlob: finalBlob,
		PrivateKey:    privateKeyBytes,
	}, nil
}
