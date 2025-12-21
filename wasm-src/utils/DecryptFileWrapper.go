package utils

import (
	"encoding/hex"
	"syscall/js"
)

func DecryptFileWrapper(this js.Value, args []js.Value) interface{} {
	config := args[0]
	privateKeyHex := config.Get("privateKey").String()
	symAlgo := config.Get("symmetricAlgo").String()
	pqcAlgo := config.Get("quantumAlgo").String()

	jsData := args[1]
	dataLen := jsData.Get("length").Int()
	encryptedBlob := make([]byte, dataLen)
	js.CopyBytesToGo(encryptedBlob, jsData)

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return map[string]interface{}{"error": "Invalid private key"}
	}

	plaintext, err := CoreDecrypt(encryptedBlob, privateKeyBytes, symAlgo, pqcAlgo)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	decryptedData := js.Global().Get("Uint8Array").New(len(plaintext))
	js.CopyBytesToJS(decryptedData, plaintext)

	return map[string]interface{}{
		"success": true,
		"data":    decryptedData,
	}
}
