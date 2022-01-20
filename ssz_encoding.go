// Code generated by fastssz. DO NOT EDIT.
// Hash: e52d7fd0c7e81813cd82264c3678d12887a0fedad5b85f957863ce10fbd09dc8
package main

import (
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the SigningData object
func (s *SigningData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SigningData object to a target array
func (s *SigningData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	return
}

// UnmarshalSSZ ssz unmarshals the SigningData object
func (s *SigningData) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 4 {
		return ssz.ErrSize
	}

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SigningData object
func (s *SigningData) SizeSSZ() (size int) {
	size = 4
	return
}

// HashTreeRoot ssz hashes the SigningData object
func (s *SigningData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SigningData object with a hasher
func (s *SigningData) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	hh.Merkleize(indx)
	return
}

// MarshalSSZ ssz marshals the ForkData object
func (f *ForkData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(f)
}

// MarshalSSZTo ssz marshals the ForkData object to a target array
func (f *ForkData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	return
}

// UnmarshalSSZ ssz unmarshals the ForkData object
func (f *ForkData) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 4 {
		return ssz.ErrSize
	}

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the ForkData object
func (f *ForkData) SizeSSZ() (size int) {
	size = 4
	return
}

// HashTreeRoot ssz hashes the ForkData object
func (f *ForkData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(f)
}

// HashTreeRootWith ssz hashes the ForkData object with a hasher
func (f *ForkData) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	hh.Merkleize(indx)
	return
}

// MarshalSSZ ssz marshals the DepositMessage object
func (d *DepositMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(d)
}

// MarshalSSZTo ssz marshals the DepositMessage object to a target array
func (d *DepositMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	return
}

// UnmarshalSSZ ssz unmarshals the DepositMessage object
func (d *DepositMessage) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 4 {
		return ssz.ErrSize
	}

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the DepositMessage object
func (d *DepositMessage) SizeSSZ() (size int) {
	size = 4
	return
}

// HashTreeRoot ssz hashes the DepositMessage object
func (d *DepositMessage) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(d)
}

// HashTreeRootWith ssz hashes the DepositMessage object with a hasher
func (d *DepositMessage) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	hh.Merkleize(indx)
	return
}

// MarshalSSZ ssz marshals the DepositData object
func (d *DepositData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(d)
}

// MarshalSSZTo ssz marshals the DepositData object to a target array
func (d *DepositData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'Pubkey'
	dst = append(dst, d.Pubkey[:]...)

	// Field (1) 'WithdrawalCredentials'
	dst = append(dst, d.WithdrawalCredentials[:]...)

	// Field (2) 'Amount'
	dst = ssz.MarshalUint64(dst, d.Amount)

	// Field (3) 'Signature'
	dst = append(dst, d.Signature[:]...)

	return
}

// UnmarshalSSZ ssz unmarshals the DepositData object
func (d *DepositData) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 184 {
		return ssz.ErrSize
	}

	// Field (0) 'Pubkey'
	copy(d.Pubkey[:], buf[0:48])

	// Field (1) 'WithdrawalCredentials'
	copy(d.WithdrawalCredentials[:], buf[48:80])

	// Field (2) 'Amount'
	d.Amount = ssz.UnmarshallUint64(buf[80:88])

	// Field (3) 'Signature'
	copy(d.Signature[:], buf[88:184])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the DepositData object
func (d *DepositData) SizeSSZ() (size int) {
	size = 184
	return
}

// HashTreeRoot ssz hashes the DepositData object
func (d *DepositData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(d)
}

// HashTreeRootWith ssz hashes the DepositData object with a hasher
func (d *DepositData) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// Field (0) 'Pubkey'
	hh.PutBytes(d.Pubkey[:])

	// Field (1) 'WithdrawalCredentials'
	hh.PutBytes(d.WithdrawalCredentials[:])

	// Field (2) 'Amount'
	hh.PutUint64(d.Amount)

	// Field (3) 'Signature'
	hh.PutBytes(d.Signature[:])

	hh.Merkleize(indx)
	return
}