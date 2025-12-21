package main

import (
	"fmt"
	"syscall/js"

	"github.com/almaraz333/post-quantum-encryption-backend/wasm-src/utils"
)

func main() {
	c := make(chan struct{}, 0)

	js.Global().Set("EncryptFile", js.FuncOf(utils.EncryptFileWrapper))
	js.Global().Set("DecryptFile", js.FuncOf(utils.DecryptFileWrapper))

	fmt.Println("Quantum Crypto Core Loaded.")

	<-c
}
