package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
	"os"
	"strings"
)

//https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt
// generate public key - PUBKEY is the 32 bytes ed25519 master pubkey of the hidden service.
// checksum is truncated to two bytes before inserting it in onion_address
// version default value '\x03'
// onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
// checksum = H(".onion checksum" | PUBKEY | VERSION)[:2]
// Expansion from A.2. Tor's key derivation scheme bitwise operations

type Keys struct {
	Pub   ed25519.PublicKey
	Pri   ed25519.PrivateKey
	Onion *string
}

type MakeKeys func(reader io.Reader) Keys
type ExpandBlindKey func(key ed25519.PrivateKey) [64]byte

func errorChecker(err error) {
	panic(err)
}

func genKeys(rand io.Reader) Keys {
	pubk, prik, err := ed25519.GenerateKey(rand)
	if err != nil {
		log.Fatal(err.Error())
	}
	return Keys{Pub: pubk, Pri: prik, Onion: nil}
}

func onionMaker(c chan Keys, genKeys MakeKeys, rand io.Reader) {
	var checksumHashBuf bytes.Buffer
	var onionUrlHash bytes.Buffer
	var checksumVersion = []byte{0x03}
	var checksumString = []byte(".onion checksum")

	k := genKeys(rand)
	// checksum
	_, _ = checksumHashBuf.Write(checksumString)
	_, _ = checksumHashBuf.Write(k.Pub)
	_, _ = checksumHashBuf.Write(checksumVersion)
	checksumSha := sha3.Sum256(checksumHashBuf.Bytes())

	// onion
	_, _ = onionUrlHash.Write(k.Pub)
	_, _ = onionUrlHash.Write(checksumSha[:2])
	_, _ = onionUrlHash.Write(checksumVersion)
	onionUrl := strings.ToLower(base32.StdEncoding.EncodeToString(onionUrlHash.Bytes()))
	//fmt.Println(onionUrl)

	c <- Keys{Pub: k.Pub, Pri: k.Pri, Onion: &onionUrl}

}

// https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2268-L2327
func expandPrivateKey(prik ed25519.PrivateKey) [64]byte {
	h := sha512.Sum512(prik[:32])
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	return h
}

func SaveOnionKeys(expand ExpandBlindKey, k Keys) string {
	privateKeyExpanded := expand(k.Pri)
	publicKeyBuf := bytes.NewBufferString("== ed25519v1-public: type0 ==\x00\x00\x00")
	privateKeyBuf := bytes.NewBufferString("== ed25519v1-secret: type0 ==\x00\x00\x00")

	publicKeyBuf.Write(k.Pub)
	privateKeyBuf.Write(privateKeyExpanded[:])

	os.WriteFile("./onion_dir/hs_ed25519_public_key", publicKeyBuf.Bytes(), 0600)
	os.WriteFile("./onion_dir/hs_ed25519_secret_key", privateKeyBuf.Bytes(), 0600)
	os.WriteFile("./onion_dir/hostname", []byte(fmt.Sprintf("%s.onion", *k.Onion)), 0600)

	return "onionFound"
}

func main() {
	// add string
	onionMatchString := ""
	if os.Getenv("PREFIX") != "" {
		onionMatchString = os.Getenv("PREFIX")
	}
	keyChannel := make(chan Keys)

	for {
		go onionMaker(keyChannel, genKeys, nil)
		keyOnion := <-keyChannel
		if strings.HasPrefix(*keyOnion.Onion, strings.ToLower(onionMatchString)) {
			SaveOnionKeys(expandPrivateKey, keyOnion)
			close(keyChannel)
			break
		}
	}
}
