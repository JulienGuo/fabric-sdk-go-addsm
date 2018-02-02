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
package sw

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"crypto/sm"
)

func signECDSA(k *ecdsa.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return MarshalSignature(r, s)
}

func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	r, s, err := UnmarshalSignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := IsLowS(k, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, curveHalfOrders[k.Curve])
	}

	return ecdsa.Verify(k, digest, r, s), nil
}

type ecdsaSigner struct{}

func (s *ecdsaSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	switch k.(type){
	case *ecdsaPrivateKey:
		if k.(*ecdsaPrivateKey).privKey.PublicKey.Curve == sm.P256Sm2() {
			smpriv:=&sm.PrivateKey{
				PublicKey:sm.PublicKey{
					Curve:sm.P256Sm2(),
					X:k.(*ecdsaPrivateKey).privKey.PublicKey.X,
					Y:k.(*ecdsaPrivateKey).privKey.PublicKey.Y,
				},
				D:k.(*ecdsaPrivateKey).privKey.D,
			}
			return signSM2(smpriv, digest, opts)
		}
		return signECDSA(k.(*ecdsaPrivateKey).privKey, digest, opts)
	case *sm2PrivateKey:
		return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
	default:
		return nil, errors.New("key type not found")
	}
}

type ecdsaPrivateKeyVerifier struct{}

func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	switch k.(type){
	case *ecdsaPrivateKey:
		if k.(*ecdsaPrivateKey).privKey.PublicKey.Curve == sm.P256Sm2() {
			smpub:=&sm.PublicKey{
				Curve:sm.P256Sm2(),
				X:k.(*ecdsaPrivateKey).privKey.PublicKey.X,
				Y:k.(*ecdsaPrivateKey).privKey.PublicKey.Y,
			}
			return verifySM2(smpub, signature, digest, opts)
		}
		return verifyECDSA(&(k.(*ecdsaPrivateKey).privKey.PublicKey), signature, digest, opts)
	case *sm2PrivateKey:
		return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey), signature, digest, opts)
	default:
		return false, errors.New("key type not found")
	}
}

type ecdsaPublicKeyKeyVerifier struct{}

func (v *ecdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	switch k.(type){
	case *ecdsaPublicKey:
		if k.(*ecdsaPublicKey).pubKey.Curve == sm.P256Sm2() {
			smpub:=&sm.PublicKey{
				Curve:sm.P256Sm2(),
				X:k.(*ecdsaPublicKey).pubKey.X,
				Y:k.(*ecdsaPublicKey).pubKey.Y,
			}
			return verifySM2(smpub, signature, digest, opts)
		}
		return verifyECDSA(k.(*ecdsaPublicKey).pubKey, signature, digest, opts)
	case *sm2PublicKey:
		return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
	default:
		return false, errors.New("key type not found")
	}
}
