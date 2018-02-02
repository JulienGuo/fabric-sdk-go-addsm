package sw

import (
	"github.com/hyperledger/fabric/bccsp"
	"fmt"
	"crypto/sm"
	"log"
)

type sm4Encryptor struct{}

func (*sm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	switch opts.(type) {
	case *bccsp.SM4ModeOpts, bccsp.SM4ModeOpts:
		c, err := sm.NewCipher((k.(*sm4PrivateKey)).privKey)
		if err != nil {
			log.Fatal(err)
		}
		c.Encrypt(ciphertext, plaintext)
		return ciphertext, nil
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type sm4Decryptor struct{}

func (*sm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// check for mode
	switch opts.(type) {
	case *bccsp.SM4ModeOpts, bccsp.SM4ModeOpts:
		c, err := sm.NewCipher((k.(*sm4PrivateKey)).privKey)
		if err != nil {
			log.Fatal(err)
		}
		c.Decrypt(plaintext, ciphertext)
		return plaintext, nil
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}