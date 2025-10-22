package otto

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

const (
	algoID      = 0xA1
	kdfRaw      = 0x02
	flagChunked = 0x01

	fixedHdrLen = 11
	fileSaltLen = 16
	tagLen      = 16
	nonceLen    = 12
)

var magic = []byte{'O','T','T','O','1'}

type Result struct {
	Header       []byte // AAD
	CipherAndTag []byte // ct || tag(16)
}

// ====== Public API: in-memory message ======

func EncryptString(plaintext, rawKey32 []byte) (*Result, error) {
	if len(rawKey32) != 32 {
		return nil, errors.New("rawKey32 must be 32 bytes")
	}
	fileSalt := make([]byte, fileSaltLen)
	if _, err := io.ReadFull(rand.Reader, fileSalt); err != nil { return nil, err }
	header := buildHeader(fileSalt, false)

	encKey, nonceKey, err := deriveKeys(rawKey32, fileSalt)
	if err != nil { return nil, err }
	nonce, err := deriveChunkNonce(nonceKey, 0)
	if err != nil { return nil, err }
	ctTag, err := aesGCMEncrypt(encKey, nonce, header, plaintext)
	if err != nil { return nil, err }
	return &Result{Header: header, CipherAndTag: ctTag}, nil
}

func DecryptString(cipherAndTag, header, rawKey32 []byte) ([]byte, error) {
	if len(rawKey32) != 32 { return nil, errors.New("rawKey32 must be 32 bytes") }
	ph, err := parseHeader(header)
	if err != nil { return nil, err }
	encKey, nonceKey, err := deriveKeys(rawKey32, ph.fileSalt)
	if err != nil { return nil, err }
	nonce, err := deriveChunkNonce(nonceKey, 0)
	if err != nil { return nil, err }
	pt, err := aesGCMDecrypt(encKey, nonce, header, cipherAndTag)
	if err != nil { return nil, err }
	return pt, nil
}

// ====== Public API: files / streaming ======

func EncryptFile(inputPath, outputPath string, rawKey32 []byte, chunkBytes int) error {
	if len(rawKey32) != 32 { return errors.New("rawKey32 must be 32 bytes") }
	if chunkBytes <= 0 { chunkBytes = 1<<20 }
	fileSalt := make([]byte, fileSaltLen)
	if _, err := io.ReadFull(rand.Reader, fileSalt); err != nil { return err }
	header := buildHeader(fileSalt, true)

	encKey, nonceKey, err := deriveKeys(rawKey32, fileSalt)
	if err != nil { return err }

	in, err := os.Open(inputPath)
	if err != nil { return err }
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil { return err }
	defer func(){ _ = out.Close() }()

	if _, err := out.Write(header); err != nil { return err }
	buf := make([]byte, chunkBytes)
	var counter uint64 = 0
	for {
		n, er := in.Read(buf)
		if n > 0 {
			pt := buf[:n]
			nonce, err := deriveChunkNonce(nonceKey, counter); if err != nil { return err }
			counter++
			ctTag, err := aesGCMEncrypt(encKey, nonce, header, pt); if err != nil { return err }
			ct := ctTag[:len(ctTag)-tagLen]
			if err := binary.Write(out, binary.BigEndian, uint32(len(ct))); err != nil { return err }
			if _, err := out.Write(ct); err != nil { return err }
			if _, err := out.Write(ctTag[len(ctTag)-tagLen:]); err != nil { return err }
		}
		if er == io.EOF { break }
		if er != nil { return er }
	}
	return out.Sync()
}

func DecryptFile(inputPath, outputPath string, rawKey32 []byte) error {
	if len(rawKey32) != 32 { return errors.New("rawKey32 must be 32 bytes") }

	in, err := os.Open(inputPath)
	if err != nil { return err }
	defer in.Close()

	br := bufio.NewReader(in)
	fixed := make([]byte, fixedHdrLen)
	if _, err := io.ReadFull(br, fixed); err != nil { return err }
	if string(fixed[:5]) != string(magic) { return errors.New("bad magic") }
	if fixed[5] != algoID || fixed[6] != kdfRaw { return errors.New("algo/kdf mismatch") }
	varLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	varPart := make([]byte, varLen)
	if _, err := io.ReadFull(br, varPart); err != nil { return err }
	header := append(fixed, varPart...)

	ph, err := parseHeader(header)
	if err != nil { return err }
	encKey, nonceKey, err := deriveKeys(rawKey32, ph.fileSalt)
	if err != nil { return err }

	out, err := os.Create(outputPath)
	if err != nil { return err }
	defer func(){ _ = out.Close() }()

	var counter uint64 = 0
	for {
		lenb := make([]byte, 4)
		if _, err := io.ReadFull(br, lenb); err != nil {
			if errors.Is(err, io.EOF) { break }
			return err
		}
		clen := int(binary.BigEndian.Uint32(lenb))
		if clen == 0 { break }
		ct := make([]byte, clen)
		if _, err := io.ReadFull(br, ct); err != nil { return err }
		tag := make([]byte, tagLen)
		if _, err := io.ReadFull(br, tag); err != nil { return err }
		nonce, err := deriveChunkNonce(nonceKey, counter); if err != nil { return err }
		counter++
		cat := append(ct, tag...)
		pt, err := aesGCMDecrypt(encKey, nonce, header, cat); if err != nil { return err }
		if _, err := out.Write(pt); err != nil { return err }
	}
	return out.Sync()
}

// ====== Optional X25519 helpers (Go 1.20+) ======

func X25519Generate() (priv, pub []byte, err error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil { return nil, nil, err }
	return x.Bytes(), x.PublicKey().Bytes(), nil
}

func X25519Shared(myPriv, theirPub []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(myPriv)
	if err != nil { return nil, err }
	pub, err := ecdh.X25519().NewPublicKey(theirPub)
	if err != nil { return nil, err }
	return k.ECDH(pub)
}

func HKDFSession(shared, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, salt, []byte("OTTO-P2P-SESSION"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil { return nil, err }
	return out, nil
}

// ====== internals ======

type parsedHeader struct {
	fileSalt []byte
	chunked  bool
}

func buildHeader(fileSalt []byte, chunked bool) []byte {
	h := make([]byte, 0, fixedHdrLen+fileSaltLen)
	h = append(h, magic...)
	h = append(h, algoID)
	h = append(h, kdfRaw)
	flag := byte(0x00)
	if chunked { flag = flagChunked }
	h = append(h, flag)
	h = append(h, 0x00) // reserved
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, uint16(fileSaltLen))
	h = append(h, v...)
	h = append(h, fileSalt...)
	return h
}

func parseHeader(header []byte) (*parsedHeader, error) {
	if len(header) < fixedHdrLen { return nil, errors.New("header too short") }
	if string(header[:5]) != string(magic) { return nil, errors.New("bad magic") }
	if header[5] != algoID { return nil, errors.New("algo mismatch") }
	if header[6] != kdfRaw { return nil, errors.New("kdf mismatch") }
	varLen := int(binary.BigEndian.Uint16(header[9:11]))
	if len(header) != fixedHdrLen + varLen { return nil, errors.New("header len mismatch") }
	if varLen < fileSaltLen { return nil, errors.New("missing file salt") }
	fileSalt := header[fixedHdrLen:fixedHdrLen+fileSaltLen]
	chunked := (header[7] & flagChunked) != 0
	return &parsedHeader{fileSalt: fileSalt, chunked: chunked}, nil
}

func deriveKeys(rawKey32, fileSalt []byte) (encKey, nonceKey []byte, err error) {
	r1 := hkdf.New(sha256.New, rawKey32, fileSalt, []byte("OTTO-ENC-KEY"))
	r2 := hkdf.New(sha256.New, rawKey32, fileSalt, []byte("OTTO-NONCE-KEY"))
	encKey = make([]byte, 32); nonceKey = make([]byte, 32)
	if _, err = io.ReadFull(r1, encKey); err != nil { return }
	if _, err = io.ReadFull(r2, nonceKey); err != nil { return }
	return
}

func deriveChunkNonce(nonceKey []byte, counter uint64) ([]byte, error) {
	label := []byte("OTTO-CHUNK-NONCE")
	info := make([]byte, 0, len(label)+8)
	info = append(info, label...)
	ctr := make([]byte, 8)
	binary.BigEndian.PutUint64(ctr, counter)
	info = append(info, ctr...)
	r := hkdf.New(sha256.New, nonceKey, nil, info) // HKDF-SIV-style (salt = nil)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil { return nil, err }
	return nonce, nil
}

func aesGCMEncrypt(encKey, nonce, aad, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil { return nil, err }
	g, err := cipher.NewGCMWithTagSize(block, tagLen)
	if err != nil { return nil, err }
	return g.Seal(nil, nonce, pt, aad), nil // ct||tag
}

func aesGCMDecrypt(encKey, nonce, aad, ctAndTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil { return nil, err }
	g, err := cipher.NewGCMWithTagSize(block, tagLen)
	if err != nil { return nil, err }
	return g.Open(nil, nonce, ctAndTag, aad)
}

// Utility helpers for examples
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func FromB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
