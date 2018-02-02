/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"crypto/sm"
	"crypto/x509/pkix"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"hash"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"reflect"
	"math/big"
	"crypto/md5"
)

// struct to hold info required for PKCS#8
type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// reference to https://www.rfc-editor.org/rfc/rfc5958.txt
type EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm Pbes2Algorithms
	EncryptedData       []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	Pbes2Params Pbes2Params
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Params struct {
	KeyDerivationFunc Pbes2KDfs // PBES2-KDFs
	EncryptionScheme  Pbes2Encs // PBES2-Encs
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2KDfs struct {
	IdPBKDF2    asn1.ObjectIdentifier
	Pkdf2Params Pkdf2Params
}

type Pbes2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pkdf2Params struct {
	Salt           []byte
	IterationCount int
	Prf            pkix.AlgorithmIdentifier
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}

	oidPBES1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}  // pbeWithMD5AndDES-CBC(PBES1)
	oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} // id-PBES2(PBES2)
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} // id-PBKDF2

	oidKEYMD5 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidKEYSHA1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidKEYSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidKEYSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case sm.P256Sm2():
		return oidNamedCurveP256SM2, true
	}
	return nil, false
}

// PrivateKeyToDER marshals a private key to der
func PrivateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
	}

	return x509.MarshalECPrivateKey(privateKey)
}

// PrivateKeyToPEM converts the private key to PEM format.
// EC private keys are converted to PKCS#8 format.
// RSA private keys are converted to PKCS#1 format.
func PrivateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if(pwd==nil||len(pwd)==0){
		pwd=nil
	}
	if len(pwd) != 0 {
		return PrivateKeyToEncryptedPEM(privateKey, pwd)
	}

	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
		}

		// get the oid for the curve
		oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("unknown elliptic curve")
		}

		// based on https://golang.org/src/crypto/x509/sec1.go
		privateKeyBytes := k.D.Bytes()
		paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen() + 7) / 8)
		copy(paddedPrivateKey[len(paddedPrivateKey) - len(privateKeyBytes):], privateKeyBytes)
		// omit NamedCurveOID for compatibility as it's optional
		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
		})

		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}

		var pkcs8Key pkcs8Info
		pkcs8Key.Version = 0
		pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
		pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkcs8Key.PrivateKey = asn1Bytes

		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil
	case *rsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid rsa private key. It must be different from nil.")
		}
		raw := x509.MarshalPKCS1PrivateKey(k)

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: raw,
			},
		), nil
	case *sm.PrivateKey:
		return writeSM2PrivateKeytoMem(k, pwd)
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PrivateKey or *rsa.PrivateKey")
	}
}

func writeSM2PrivateKeytoMem(key *sm.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block

	der, err := marshalSm2PrivateKey(key, pwd)
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	return pem.EncodeToMemory(block), nil
}

func marshalSm2PrivateKey(key *sm.PrivateKey, pwd []byte) ([]byte, error) {
	if pwd == nil {
		return marshalSm2UnecryptedPrivateKey(key)
	}
	return marshalSm2EcryptedPrivateKey(key, pwd)
}

func marshalSm2UnecryptedPrivateKey(key *sm.PrivateKey) ([]byte, error) {
	var r pkcs8
	var priv sm2PrivateKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	//algo.Parameters.FullBytes = asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	priv.Version = 1
	priv.NamedCurveOID = oidNamedCurveP256SM2
	priv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	priv.PrivateKey = key.D.Bytes()
	r.Version = 0
	r.Algo = algo
	r.PrivateKey, _ = asn1.Marshal(priv)
	return asn1.Marshal(r)
}

// copy from crypto/pbkdf2.go
func pbkdf(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks * hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk) - hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

func marshalSm2EcryptedPrivateKey(PrivKey *sm.PrivateKey, pwd []byte) ([]byte, error) {
	der, err := marshalSm2UnecryptedPrivateKey(PrivKey)
	if err != nil {
		return nil, err
	}
	iter := 2048
	salt := make([]byte, 8)
	iv := make([]byte, 16)
	rand.Reader.Read(salt)
	rand.Reader.Read(iv)
	key := pbkdf(pwd, salt, iter, 32, sha1.New) // 默认是SHA1
	padding := aes.BlockSize - len(der) % aes.BlockSize
	if padding > 0 {
		n := len(der)
		der = append(der, make([]byte, padding)...)
		for i := 0; i < padding; i++ {
			der[n + i] = byte(padding)
		}
	}
	encryptedKey := make([]byte, len(der))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedKey, der)
	var algorithmIdentifier pkix.AlgorithmIdentifier
	algorithmIdentifier.Algorithm = oidKEYSHA1
	algorithmIdentifier.Parameters.Tag = 5
	algorithmIdentifier.Parameters.IsCompound = false
	algorithmIdentifier.Parameters.FullBytes = []byte{5, 0}
	keyDerivationFunc := Pbes2KDfs{
		oidPBKDF2,
		Pkdf2Params{
			salt,
			iter,
			algorithmIdentifier,
		},
	}
	encryptionScheme := Pbes2Encs{
		oidAES256CBC,
		iv,
	}
	pbes2Algorithms := Pbes2Algorithms{
		oidPBES2,
		Pbes2Params{
			keyDerivationFunc,
			encryptionScheme,
		},
	}
	encryptedPkey := EncryptedPrivateKeyInfo{
		pbes2Algorithms,
		encryptedKey,
	}
	return asn1.Marshal(encryptedPkey)
}

// PrivateKeyToEncryptedPEM converts a private key to an encrypted PEM
func PrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid private key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
		}
		raw, err := x509.MarshalECPrivateKey(k)

		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PRIVATE KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)

		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil
	case *sm.PrivateKey:
		return writeSM2PrivateKeytoMem(k, pwd)
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PrivateKey")
	}
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, *sm.PrivateKey:
			return
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivareKey or ecdsa.PrivateKey")
}

// PEMtoPrivateKey unmarshals a pem to private key
func PEMtoPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption [%s]", err)
		}

		key, err := DERToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := DERToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// PEMtoAES extracts from the PEM an AES key
func PEMtoAES(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Password must be different fom nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

// AEStoPEM encapsulates an AES key in the PEM format
func AEStoPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

// AEStoEncryptedPEM encapsulates an AES key in the encrypted PEM format
func AEStoEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return AEStoPEM(raw), nil
	}

	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"AES PRIVATE KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

// PublicKeyToPEM marshals a public key to the pem format
func PublicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return PublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil
	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid rsa public key. It must be different from nil.")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	case *sm.PublicKey:
		return writeSM2PublicKeytoMem(k)
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey or *rsa.PublicKey")
	}
}

func writeSM2PublicKeytoMem(key *sm.PublicKey) ([]byte, error) {
	der, err := marshalSm2PublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func marshalSm2PublicKey(key *sm.PublicKey) ([]byte, error) {
	var r pkixPublicKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	r.Algo = algo
	r.BitString = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	return asn1.Marshal(r)
}

// PublicKeyToDER marshals a public key to the der format
func PublicKeyToDER(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return PubASN1, nil

	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid rsa public key. It must be different from nil.")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return PubASN1, nil

	case *sm.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid rsa public key. It must be different from nil.")
		}
		PubASN1, err := marshalSm2PublicKey(k)
		if err != nil {
			return nil, err
		}

		return PubASN1, nil
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey or *rsa.PublicKey")
	}
}

// PublicKeyToEncryptedPEM converts a public key to encrypted pem
func PublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}
	if len(pwd) == 0 {
		return nil, errors.New("Invalid password. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PUBLIC KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)

		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	case *sm.PublicKey:
		return writeEncryptoSM2PublicKeytoMem(k, pwd)
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}

func writeEncryptoSM2PublicKeytoMem(key *sm.PublicKey, pwd []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("Invalid sm2 public key. It must be different from nil.")
	}
	raw, err := marshalSm2PublicKey(key)
	if err != nil {
		return nil, err
	}

	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"PUBLIC KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

// PEMtoPublicKey unmarshals a pem to public key
func PEMtoPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key
	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Password must be different from nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}

		key, err := DERToPublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := DERToPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// DERToPublicKey unmarshals a der to public key
func DERToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := x509.ParsePKIXPublicKey(raw)

	return key, err
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func ParseSm2PublicKey(der []byte) (*sm.PublicKey, error) {
	var pubkey pkixPublicKey

	if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(pubkey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	curve := sm.P256Sm2()
	x, y := elliptic.Unmarshal(curve, pubkey.BitString.Bytes)
	pub := sm.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return &pub, nil
}

func ParseSm2PrivateKey(der []byte) (*sm.PrivateKey, error) {
	var privKey sm2PrivateKey

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	curve := sm.P256Sm2()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(sm.PrivateKey)
	priv.Curve = curve
	priv.D = k
	privateKey := make([]byte, (curveOrder.BitLen() + 7) / 8)
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	copy(privateKey[len(privateKey) - len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
	return priv, nil
}

func ParsePKCS8UnecryptedPrivateKey(der []byte) (*sm.PrivateKey, error) {
	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(privKey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	return ParseSm2PrivateKey(privKey.PrivateKey)
}

func ParsePKCS8EcryptedPrivateKey(der, pwd []byte) (*sm.PrivateKey, error) {
	var keyInfo EncryptedPrivateKeyInfo

	_, err := asn1.Unmarshal(der, &keyInfo)
	if err != nil {
		return nil, errors.New("x509: unknown format")
	}
	if !reflect.DeepEqual(keyInfo.EncryptionAlgorithm.IdPBES2, oidPBES2) {
		return nil, errors.New("x509: only support PBES2")
	}
	encryptionScheme := keyInfo.EncryptionAlgorithm.Pbes2Params.EncryptionScheme
	keyDerivationFunc := keyInfo.EncryptionAlgorithm.Pbes2Params.KeyDerivationFunc
	if !reflect.DeepEqual(keyDerivationFunc.IdPBKDF2, oidPBKDF2) {
		return nil, errors.New("x509: only support PBKDF2")
	}
	pkdf2Params := keyDerivationFunc.Pkdf2Params
	if !reflect.DeepEqual(encryptionScheme.EncryAlgo, oidAES128CBC) &&
		!reflect.DeepEqual(encryptionScheme.EncryAlgo, oidAES256CBC) {
		return nil, errors.New("x509: unknow encryption algorithm")
	}
	iv := encryptionScheme.IV
	salt := pkdf2Params.Salt
	iter := pkdf2Params.IterationCount
	encryptedKey := keyInfo.EncryptedData
	var key []byte
	switch {
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYMD5):
		key = pbkdf(pwd, salt, iter, 32, md5.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA1):
		key = pbkdf(pwd, salt, iter, 32, sha1.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA256):
		key = pbkdf(pwd, salt, iter, 32, sha256.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA512):
		key = pbkdf(pwd, salt, iter, 32, sha512.New)
		break
	default:
		return nil, errors.New("x509: unknown hash algorithm")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedKey, encryptedKey)
	rKey, err := ParsePKCS8UnecryptedPrivateKey(encryptedKey)
	if err != nil {
		return nil, errors.New("pkcs8: incorrect password")
	}
	return rKey, nil
}

func ParsePKCS8PrivateKey(der, pwd []byte) (*sm.PrivateKey, error) {
	if pwd == nil {
		return ParsePKCS8UnecryptedPrivateKey(der)
	}
	return ParsePKCS8EcryptedPrivateKey(der, pwd)
}