package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"github.com/ivansostarko/otto-crypt-go/otto"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage(); os.Exit(1)
	}
	switch os.Args[1] {
	case "enc-str": encStr()
	case "dec-str": decStr()
	case "enc-file": encFile()
	case "dec-file": decFile()
	default: usage(); os.Exit(1)
	}
}

func usage() {
	fmt.Println("otto-cli") 
	fmt.Println("USAGE:") 
	fmt.Println("  otto-cli enc-str  --key-b64 <key> --message <utf8>") 
	fmt.Println("  otto-cli dec-str  --key-b64 <key> --header-b64 <b64> --cipher-b64 <b64>")
	fmt.Println("  otto-cli enc-file --key-b64 <key> --in <path> --out <path> [--chunk <bytes>]")
	fmt.Println("  otto-cli dec-file --key-b64 <key> --in <path> --out <path>")
}

func encStr() {
	fs := flag.NewFlagSet("enc-str", flag.ExitOnError)
	keyB64 := fs.String("key-b64", "", "Base64 32-byte key")
	msg := fs.String("message", "", "UTF-8 plaintext")
	_ = fs.Parse(os.Args[2:])
	if *keyB64 == "" || *msg == "" { usage(); os.Exit(2) }
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	res, err := otto.EncryptString([]byte(*msg), key); if err != nil { log.Fatal(err) }
	fmt.Printf("HEADER_B64=%s\n", otto.B64(res.Header))
	fmt.Printf("CIPHER_B64=%s\n", otto.B64(res.CipherAndTag))
}

func decStr() {
	fs := flag.NewFlagSet("dec-str", flag.ExitOnError)
	keyB64 := fs.String("key-b64", "", "Base64 32-byte key")
	hB64 := fs.String("header-b64", "", "Base64 header")
	cB64 := fs.String("cipher-b64", "", "Base64 ct||tag")
	_ = fs.Parse(os.Args[2:])
	if *keyB64=="" || *hB64=="" || *cB64=="" { usage(); os.Exit(2) }
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	header, err := otto.FromB64(*hB64); if err != nil { log.Fatal(err) }
	cipher, err := otto.FromB64(*cB64); if err != nil { log.Fatal(err) }
	pt, err := otto.DecryptString(cipher, header, key); if err != nil { log.Fatal(err) }
	fmt.Printf("%s\n", string(pt))
}

func encFile() {
	fs := flag.NewFlagSet("enc-file", flag.ExitOnError)
	keyB64 := fs.String("key-b64", "", "Base64 32-byte key")
	in := fs.String("in", "", "input path")
	out := fs.String("out", "", "output path (.otto)")
	chunk := fs.Int("chunk", 1<<20, "chunk bytes")
	_ = fs.Parse(os.Args[2:])
	if *keyB64=="" || *in=="" { usage(); os.Exit(2) }
	if *out=="" { *out = *in + ".otto" }
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	if err := otto.EncryptFile(*in, *out, key, *chunk); err != nil { log.Fatal(err) }
	fmt.Println("OK")
}

func decFile() {
	fs := flag.NewFlagSet("dec-file", flag.ExitOnError)
	keyB64 := fs.String("key-b64", "", "Base64 32-byte key")
	in := fs.String("in", "", "input .otto path")
	out := fs.String("out", "", "output path")
	_ = fs.Parse(os.Args[2:])
	if *keyB64=="" || *in=="" { usage(); os.Exit(2) }
	if *out=="" {
		base := filepath.Base(*in)
		*out = base + ".dec"
	}
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	if err := otto.DecryptFile(*in, *out, key); err != nil { log.Fatal(err) }
	fmt.Println("OK")
}

// avoid unused imports warning (when building without commands)
var _ io.Reader
