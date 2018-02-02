package sw

import (
	"math/big"
	"encoding/asn1"
	"fmt"
	"errors"
	"crypto/elliptic"
	//"crypto/sm"
	"crypto/ecdsa"
)

type Signature struct {
	R, S *big.Int
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
		//sm.P256Sm2(): new(big.Int).Rsh(sm.P256Sm2().Params().N, 1),
	}
)

func MarshalSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(Signature{r, s})
}

func UnmarshalSignature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("Invalid signature. R must be different from nil.")
	}
	if sig.S == nil {
		return nil, nil, errors.New("Invalid signature. S must be different from nil.")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature. R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature. S must be larger than zero")
	}

	return sig.R, sig.S, nil
}


// IsLow checks that s is a low-S
//func IsLowSSM(k *sm.PublicKey, s *big.Int) (bool, error) {
//	var halfOrder *big.Int
//	var ok bool
//	halfOrder, ok = curveHalfOrders[k.Curve]
//	if !ok {
//		return false, fmt.Errorf("Curve not recognized [%s]", k.Curve)
//	}
//	return s.Cmp(halfOrder) != 1, nil
//}

//func ToLowSSM(k *sm.PublicKey, s *big.Int) (*big.Int, bool, error) {
//	lowS, err := IsLowSSM(k, s)
//	if err != nil {
//		return nil, false, err
//	}
//
//	if !lowS {
//		// Set s to N - s that will be then in the lower part of signature space
//		// less or equal to half order
//
//		s.Sub(k.Params().N, s)
//
//		return s, true, nil
//	}
//
//	return s, false, nil
//}

// IsLow checks that s is a low-S
func IsLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	var halfOrder *big.Int
	var ok bool
	halfOrder, ok = curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("Curve not recognized [%s]", k.Curve)
	}
	return s.Cmp(halfOrder) != 1, nil
}

func ToLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order

		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}

func SignatureToLowS(k *ecdsa.PublicKey, signature []byte) ([]byte, error) {
	r, s, err := UnmarshalSignature(signature)
	if err != nil {
		return nil, err
	}

	s, modified, err := ToLowS(k, s)
	if err != nil {
		return nil, err
	}

	if modified {
		return MarshalSignature(r, s)
	}

	return signature, nil
}

//func SignatureToLowSSM(k *sm.PublicKey, signature []byte) ([]byte, error) {
//	fmt.Println("SignatureToLowSSM 1")
//	_, _, err := UnmarshalSignature(signature)
//	if err != nil {
//		return nil, err
//	}
	//fmt.Println("SignatureToLowSSM 2")
	//s, modified, err := ToLowSSM(k, s)
	//if err != nil {
	//	return nil, err
	//}
	//fmt.Println("SignatureToLowSSM 3")
	//if modified {
	//	return MarshalSignature(r, s)
	//}
//	fmt.Println("SignatureToLowSSM 4")
//	return signature, nil
//}