build-wasm:
	GOOS=js GOARCH=wasm go build -o static/main.wasm wasm-src/main.go && cp static/main.wasm ../post-quantum-encryption-frontend/public
