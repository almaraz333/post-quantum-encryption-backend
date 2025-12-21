package utils

import (
	"encoding/hex"
	"syscall/js"
)

const (
	AlgoAESGCM    = "AES-GCM"
	AlgoChaCha20  = "ChaCha20"
	AlgoMLKEM768  = "ML-KEM-768"
	AlgoMLKEM1024 = "ML-KEM-1024"
)

func EncryptFileWrapper(this js.Value, args []js.Value) interface{} {
	config := args[0]
	symAlgo := config.Get("symmetricAlgo").String()
	pqcAlgo := config.Get("quantumAlgo").String()

	jsData := args[1]
	dataLen := jsData.Get("length").Int()
	fileBytes := make([]byte, dataLen)
	js.CopyBytesToGo(fileBytes, jsData)

	result, err := CoreEncrypt(fileBytes, symAlgo, pqcAlgo)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	encryptedData := js.Global().Get("Uint8Array").New(len(result.EncryptedBlob))
	js.CopyBytesToJS(encryptedData, result.EncryptedBlob)

	return map[string]interface{}{
		"success":    true,
		"data":       encryptedData,
		"privateKey": hex.EncodeToString(result.PrivateKey),
		"algorithm":  pqcAlgo,
	}
}
