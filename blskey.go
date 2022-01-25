package eth2deposit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

const (
	K = 32
	L = K * 255
)

var (
	salt = sha256.Sum256([]byte("BLS-SIG-KEYGEN-SALT-"))
	R, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
)

func _flip_bits(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = ^in[i]
	}
}

func _IKM_to_lamport_SK(IKM []byte, salt []byte) ([][]byte, error) {
	PRK := hkdf.Extract(sha256.New, []byte(IKM), []byte(salt))
	okmReader := hkdf.Expand(sha256.New, PRK, nil)

	var lamport_SK [][]byte
	for i := 0; i < L/K; i++ {
		chunk := make([]byte, K)
		_, err := io.ReadFull(okmReader, chunk)
		if err != nil {
			return nil, err
		}

		lamport_SK = append(lamport_SK, chunk)
	}

	return lamport_SK, nil
}

func _parent_SK_to_lamport_PK(parent_SK *big.Int, index uint32) ([]byte, error) {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	IKM := make([]byte, K)
	parent_SK.FillBytes(IKM)

	lamport_0, err := _IKM_to_lamport_SK(IKM, salt)
	if err != nil {
		return nil, err
	}

	_flip_bits(IKM)
	lamport_1, err := _IKM_to_lamport_SK(IKM, salt)
	if err != nil {
		return nil, err
	}

	var lamport_PK []byte
	for i := 0; i < len(lamport_0); i++ {
		sum := sha256.Sum256(lamport_0[i])
		lamport_PK = append(lamport_PK, sum[:]...)
	}

	for i := 0; i < len(lamport_1); i++ {
		sum := sha256.Sum256(lamport_1[i])
		lamport_PK = append(lamport_PK, sum[:]...)
	}

	compressed_lamport_PK := sha256.Sum256(lamport_PK)
	return compressed_lamport_PK[:], nil
}

// 1. salt = "BLS-SIG-KEYGEN-SALT-"
// 2. SK = 0
// 3. while SK == 0:
// 4.     salt = H(salt)
// 5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
// 6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
// 7.     SK = OS2IP(OKM) mod r
// 8. return SK
func _HKDF_mod_r(IKM []byte, key_info []byte) *big.Int {
	L := 48

	infoExtra := make([]byte, 2)
	binary.BigEndian.PutUint16(infoExtra, uint16(L))

	SK := new(big.Int)
	for SK.BitLen() == 0 {
		// PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
		ikm := make([]byte, len(IKM))
		copy(ikm, IKM)
		ikm = append(ikm, 0) // I20SP(0,1)

		PRK := hkdf.Extract(sha256.New, ikm, salt[:])

		//  OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
		info := make([]byte, len(key_info))
		copy(info, key_info)
		info = append(info, infoExtra...)
		okmReader := hkdf.Expand(sha256.New, PRK, info)

		OKM := make([]byte, L)
		_, err := io.ReadFull(okmReader, OKM)
		if err != nil {
			panic(err)
		}

		SK = new(big.Int).SetBytes(OKM)
		SK.Mod(SK, R)
	}

	return SK
}

func _derive_child_SK(parent_SK *big.Int, index uint32) (child_SK *big.Int, err error) {
	compressed_lamport_PK, err := _parent_SK_to_lamport_PK(parent_SK, index)
	if err != nil {
		return nil, err
	}
	return _HKDF_mod_r(compressed_lamport_PK, nil), nil
}

func _derive_master_SK(seed []byte) (SK *big.Int, err error) {
	if len(seed) < 32 {
		return nil, errors.New("`len(seed)` should be greater than or equal to 32.")
	}

	return _HKDF_mod_r(seed, nil), nil
}
