/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"github.com/hyperledger/fabric/bccsp"
	"fmt"
	"crypto/sm"
)

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
}

func signSM2(k *sm.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	r, s, err := sm.Sign(k, digest)
	if err != nil {
		return nil, err
	}

	//s, _, err = ToLowSSM(&k.PublicKey, s)
	//if err != nil {
	//	return nil, err
	//}

	return MarshalSignature(r, s)
}

func verifySM2(k *sm.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	r, s, err := UnmarshalSignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	//lowS, err := IsLowSSM(k, s)
	//if err != nil {
	//	return false, err
	//}
	//
	//if !lowS {
	//	return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, curveHalfOrders[k.Curve])
	//}

	return sm.Verify(k, digest, r, s), nil
}