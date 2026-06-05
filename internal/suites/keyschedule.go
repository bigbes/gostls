package suites

import (
	"crypto/subtle"
	"errors"
)

// ErrInvalidRandomLen is returned when a random value is not the required 32 bytes.
var ErrInvalidRandomLen = errors.New("suites/keyschedule: random values must be 32 bytes each")

// ErrZeroKeyBlock is returned when the total key material requested is zero.
var ErrZeroKeyBlock = errors.New("suites/keyschedule: key block length must be greater than zero")

// MasterSecret derives the 48-byte TLS 1.2 master secret per RFC 5246 §8.1:
//
//	master_secret = PRF(pre_master_secret, "master secret",
//	                    ClientHello.random + ServerHello.random)[0..47]
//
// preMaster must be the pre-master secret (length is suite-dependent).
// clientRandom and serverRandom must each be exactly 32 bytes.
// The PRF hash is taken from suite.PRF.Hash.
func MasterSecret(suite *Suite, preMaster, clientRandom, serverRandom []byte) ([]byte, error) {
	if len(clientRandom) != 32 || len(serverRandom) != 32 {
		return nil, ErrInvalidRandomLen
	}

	seed := make([]byte, 64)
	copy(seed[:32], clientRandom)
	copy(seed[32:], serverRandom)

	return PRF(suite.PRF.Hash, preMaster, []byte("master secret"), seed, 48)
}

// KeyMaterial holds the derived key material for one TLS session direction.
type KeyMaterial struct {
	ClientMACKey []byte // MAC key for client→server records (nil for AEAD)
	ServerMACKey []byte // MAC key for server→client records (nil for AEAD)
	ClientEncKey []byte // encryption key for client→server records
	ServerEncKey []byte // encryption key for server→client records
	ClientIV     []byte // implicit IV for client→server records
	ServerIV     []byte // implicit IV for server→client records
}

// KeyExpansion derives the key material per RFC 5246 §6.3:
//
//	key_block = PRF(master_secret, "key expansion",
//	                ServerHello.random + ClientHello.random)
//
// The key_block is split into:
//
//	client_write_MAC_key[mac_key_len]
//	server_write_MAC_key[mac_key_len]
//	client_write_key[enc_key_len]
//	server_write_key[enc_key_len]
//	client_write_IV[fixed_iv_len]
//	server_write_IV[fixed_iv_len]
//
// Note: server_random is prepended to client_random (opposite of MasterSecret).
// clientRandom and serverRandom must each be exactly 32 bytes.
func KeyExpansion(suite *Suite, masterSecret, clientRandom, serverRandom []byte) (*KeyMaterial, error) {
	if len(clientRandom) != 32 || len(serverRandom) != 32 {
		return nil, ErrInvalidRandomLen
	}

	// key expansion seed is server_random || client_random per RFC 5246 §6.3.
	seed := make([]byte, 64)
	copy(seed[:32], serverRandom)
	copy(seed[32:], clientRandom)

	macKeyLen := suite.MAC.KeyLen
	encKeyLen := suite.Cipher.KeyLen
	ivLen := suite.Cipher.FixedIVLen

	totalLen := 2*macKeyLen + 2*encKeyLen + 2*ivLen
	if totalLen == 0 {
		return nil, ErrZeroKeyBlock
	}

	keyBlock, err := PRF(suite.PRF.Hash, masterSecret, []byte("key expansion"), seed, totalLen)
	if err != nil {
		return nil, err
	}

	km := &KeyMaterial{}
	off := 0

	if macKeyLen > 0 {
		km.ClientMACKey = keyBlock[off : off+macKeyLen]
		off += macKeyLen
		km.ServerMACKey = keyBlock[off : off+macKeyLen]
		off += macKeyLen
	}

	km.ClientEncKey = keyBlock[off : off+encKeyLen]
	off += encKeyLen
	km.ServerEncKey = keyBlock[off : off+encKeyLen]
	off += encKeyLen

	if ivLen > 0 {
		km.ClientIV = keyBlock[off : off+ivLen]
		off += ivLen
		km.ServerIV = keyBlock[off : off+ivLen]
	}

	return km, nil
}

// FinishedVerifyData computes the verify_data for a Finished message per
// RFC 5246 §7.4.9:
//
//	verify_data = PRF(master_secret, finished_label,
//	                  Hash(handshake_messages))[0..verify_data_length-1]
//
// Length is 12 bytes for standard TLS 1.2, overridden to 32 bytes for the
// GOST 2018 key-exchange suites (0xC100 / 0xC101) per OpenSSL's
// ssl/t1_enc.c:tls1_final_finish_mac:
//
//	if (s->s3.tmp.new_cipher->algorithm_mkey & SSL_kGOST18)
//	    finished_size = 32;
//
// label must be either "client finished" or "server finished".
// transcriptHash is the current transcript hash (output of Hash(all handshake messages)).
// The PRF hash is taken from suite.PRF.Hash.
func FinishedVerifyData(suite *Suite, masterSecret []byte, label string, transcriptHash []byte) ([]byte, error) {
	vdLen := 12
	if suite.KX == KexGOST2018_256 {
		vdLen = 32
	}
	return PRF(suite.PRF.Hash, masterSecret, []byte(label), transcriptHash, vdLen)
}

// EqualVerifyData reports whether a and b are equal verify_data values using
// a constant-time comparison to prevent timing side-channels.
//
// Constant-time guarantee: this function uses crypto/subtle.ConstantTimeCompare,
// which runs in time proportional to min(len(a), len(b)) regardless of where
// the first differing byte is. Callers must not use == for verify_data comparison.
func EqualVerifyData(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
