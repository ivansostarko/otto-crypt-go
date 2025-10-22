# OTTO Crypt — Go package + CLI

Go implementation of the **OTTO** encryption format that is **wire-compatible with the Laravel/PHP SDK**.

- AES-256-GCM (tag 16B), AAD = OTTO header
- HKDF-SHA256 per-object keys: `encKey`, `nonceKey`
- HKDF-SIV-style **deterministic 12-byte nonces** per chunk
- Streaming container for large files: `header || [u32_be ct_len || ct || tag16]*`
- Optional X25519 helpers via Go stdlib `crypto/ecdh`

## Install
```bash
go mod tidy
```

## Library usage
```go
import (
    "fmt"
    "crypto/rand"
    "github.com/ivansostarko/otto-crypt-go/otto"
)

// 32-byte key
key := make([]byte, 32)
rand.Read(key)

res, _ := otto.EncryptString([]byte("Hello OTTO"), key)
pt, _ := otto.DecryptString(res.CipherAndTag, res.Header, key)
fmt.Println(string(pt))
```

Files (photo/audio/video/any):
```go
_ = otto.EncryptFile("movie.mp4", "movie.mp4.otto", key, 1<<20)
_ = otto.DecryptFile("movie.mp4.otto", "movie.dec.mp4", key)
```

## CLI
```bash
go build -o otto-cli ./cmd/otto-cli

# 32-byte key
export OTTO_RAWKEY_B64=$(base64 -w0 <(openssl rand -out /dev/stdout 32))

# Text
./otto-cli enc-str --key-b64 "$OTTO_RAWKEY_B64" --message "hello from go"  | tee /tmp/out.txt
HEADER_B64=$(grep HEADER_B64 /tmp/out.txt | cut -d= -f2)
CIPHER_B64=$(grep CIPHER_B64 /tmp/out.txt | cut -d= -f2)
./otto-cli dec-str --key-b64 "$OTTO_RAWKEY_B64" --header-b64 "$HEADER_B64" --cipher-b64 "$CIPHER_B64"

# Files
./otto-cli enc-file --key-b64 "$OTTO_RAWKEY_B64" --in ./photo.jpg --out ./photo.jpg.otto
./otto-cli dec-file --key-b64 "$OTTO_RAWKEY_B64" --in ./photo.jpg.otto --out ./photo.jpg.dec
```

## Format (interop with Laravel)
- **Header**: `"OTTO1"|0xA1|0x02|flags|0x00|u16_be(16)|file_salt[16]`
- **Keys**: HKDF-SHA256 → `encKey`, `nonceKey` (salt = file_salt)
- **Nonces**: `HKDF(nonceKey, salt="", info="OTTO-CHUNK-NONCE"||counter_be64, 12)`
- **AEAD**: AES-256-GCM (tag 16B), **AAD = header**
- **Streaming**: `header || [u32_be ct_len || ct || tag16]*`

MIT © 2025 Ivan Doe
