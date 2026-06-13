package suites

import (
	"crypto/sha256"
	"crypto/sha512"
)

// This file registers all non-GOST TLS 1.2 cipher suites supported by
// github.com/bigbes/gostls. Exactly 27 suites are registered here.
// GOST suites are registered in Phase 6.
//
// Suite IDs are IANA TLS cipher suite numbers.
// Suite names are OpenSSL-style names matching Tarantool's configuration.
//
// Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

// ---- Suite ID constants (IANA) ------------------------------------------------.

// ECDHE-ECDSA suites.
const (
	suiteECDHEECDSAAES256GCMSHA384  uint16 = 0xC02C
	suiteECDHEECDSACHACHA20POLY1305 uint16 = 0xCCA9
	suiteECDHEECDSAAES128GCMSHA256  uint16 = 0xC02B
	suiteECDHEECDSAAES256SHA384     uint16 = 0xC024
	suiteECDHEECDSAAES128SHA256     uint16 = 0xC023
	suiteECDHEECDSAAES256SHA        uint16 = 0xC00A
	suiteECDHEECDSAAES128SHA        uint16 = 0xC009
)

// ECDHE-RSA suites.
const (
	suiteECDHERSAAES256GCMSHA384  uint16 = 0xC030
	suiteECDHERSACHACHA20POLY1305 uint16 = 0xCCA8
	suiteECDHERSAAES128GCMSHA256  uint16 = 0xC02F
	suiteECDHERSAAES256SHA384     uint16 = 0xC028
	suiteECDHERSAAES128SHA256     uint16 = 0xC027
	suiteECDHERSAAES256SHA        uint16 = 0xC014
	suiteECDHERSAAES128SHA        uint16 = 0xC013
)

// DHE-RSA suites.
const (
	suiteDHERSAAES256GCMSHA384  uint16 = 0x009F
	suiteDHERSACHACHA20POLY1305 uint16 = 0xCCAA
	suiteDHERSAAES128GCMSHA256  uint16 = 0x009E
	suiteDHERSAAES256SHA256     uint16 = 0x006B
	suiteDHERSAAES128SHA256     uint16 = 0x0067
	suiteDHERSAAES256SHA        uint16 = 0x0039
	suiteDHERSAAES128SHA        uint16 = 0x0033
)

// RSA key-exchange suites.
const (
	suiteRSAAES256GCMSHA384 uint16 = 0x009D
	suiteRSAAES128GCMSHA256 uint16 = 0x009C
	suiteRSAAES256SHA256    uint16 = 0x003D
	suiteRSAAES128SHA256    uint16 = 0x003C
	suiteRSAAES256SHA       uint16 = 0x0035
	suiteRSAAES128SHA       uint16 = 0x002F
)

// ---- Cipher spec key/IV/tag size constants -------------------------------------.

const (
	// AES-128: 16-byte key.
	aes128KeyLen = 16
	// AES-256 / ChaCha20: 32-byte key.
	aes256KeyLen = 32
	// AES-GCM implicit salt (FixedIVLen = 4 per RFC 5288 §3).
	aesgcmFixedIVLen = 4
	// AES-GCM explicit nonce on the wire (8 bytes per RFC 5288 §3).
	aesgcmExplicitIVLen = 8
	// AES-GCM / ChaCha20-Poly1305 tag length (16 bytes).
	aeadTagLen = 16
	// ChaCha20-Poly1305 implicit nonce length (12 bytes, RFC 7905 §2).
	chachaNonceLen = 12
	// AES-CBC IV length equals the AES block size (16 bytes).
	aesCBCIVLen = 16
	// HMAC-SHA384 key/output length in bytes.
	hmacSHA384Len = 48
	// HMAC-SHA256 key/output length in bytes.
	hmacSHA256Len = 32
	// HMAC-SHA1 key/output length in bytes.
	hmacSHA1Len = 20
)

func init() {
	registerECDHESuites()
	registerDHERSASuites()
	registerRSAKxSuites()
}

// ---- shared cipher/MAC/PRF specs -------------------------------------------.

var (
	// AES-128-GCM: 16-byte key, 4-byte implicit salt, 8-byte explicit nonce.
	specAES128GCM = CipherSpec{
		Name:          "AES-128-GCM",
		KeyLen:        aes128KeyLen,
		FixedIVLen:    aesgcmFixedIVLen,
		ExplicitIVLen: aesgcmExplicitIVLen,
		AEAD:          true,
		TagLen:        aeadTagLen,
	}

	// AES-256-GCM: 32-byte key, 4-byte implicit salt, 8-byte explicit nonce.
	specAES256GCM = CipherSpec{
		Name:          "AES-256-GCM",
		KeyLen:        aes256KeyLen,
		FixedIVLen:    aesgcmFixedIVLen,
		ExplicitIVLen: aesgcmExplicitIVLen,
		AEAD:          true,
		TagLen:        aeadTagLen,
	}

	// CHACHA20-POLY1305: 32-byte key, 12-byte fully-implicit IV (RFC 7905).
	// ExplicitIVLen = 0: no bytes prepended to the wire record.
	// The 12-byte nonce is write_IV XOR (seq padded to 12 bytes). Phase 8
	// must handle this differently from AES-GCM when assembling Protectors.
	specCHACHA20POLY1305 = CipherSpec{
		Name:          "CHACHA20-POLY1305",
		KeyLen:        aes256KeyLen,
		FixedIVLen:    chachaNonceLen,
		ExplicitIVLen: 0,
		AEAD:          true,
		TagLen:        aeadTagLen,
	}

	// AES-256-CBC: 32-byte key, 16-byte IV derived from key block (RFC 5246 §6.3),
	// 16-byte explicit IV prepended to each record.
	specAES256CBC = CipherSpec{
		Name:          "AES-256-CBC",
		KeyLen:        aes256KeyLen,
		FixedIVLen:    aesCBCIVLen,
		ExplicitIVLen: aesCBCIVLen,
		AEAD:          false,
	}

	// AES-128-CBC: 16-byte key, 16-byte IV derived from key block (RFC 5246 §6.3),
	// 16-byte explicit IV prepended to each record.
	specAES128CBC = CipherSpec{
		Name:          "AES-128-CBC",
		KeyLen:        aes128KeyLen,
		FixedIVLen:    aesCBCIVLen,
		ExplicitIVLen: aesCBCIVLen,
		AEAD:          false,
	}

	// HMAC-SHA384: 48-byte key, 48-byte MAC.
	specHMACSHA384 = MACSpec{
		Hash:   sha512.New384,
		KeyLen: hmacSHA384Len,
		MACLen: hmacSHA384Len,
	}

	// HMAC-SHA256: 32-byte key, 32-byte MAC.
	specHMACSHA256 = MACSpec{
		Hash:   sha256.New,
		KeyLen: hmacSHA256Len,
		MACLen: hmacSHA256Len,
	}

	// HMAC-SHA: 20-byte key, 20-byte MAC (SHA-1).
	specHMACSHA1 = MACSpec{
		Hash:   sha1New,
		KeyLen: hmacSHA1Len,
		MACLen: hmacSHA1Len,
	}

	// AEAD has no MAC.
	specNoMAC = MACSpec{}

	// PRF using SHA-256 (default for most TLS 1.2 suites).
	specPRFSHA256 = PRFSpec{Hash: sha256.New}

	// PRF using SHA-384 (for *-SHA384 suites).
	specPRFSHA384 = PRFSpec{Hash: sha512.New384}
)

// sha1New is defined in a separate file to avoid importing crypto/sha1 here
// while keeping this file readable. See sha1_helper.go.

// ---- ECDHE suites (14) ------------------------------------------------------.

func registerECDHESuites() {
	// ECDHE-ECDSA with AEAD.
	register(&Suite{
		ID: suiteECDHEECDSAAES256GCMSHA384, Name: "ECDHE-ECDSA-AES256-GCM-SHA384",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: suiteECDHEECDSACHACHA20POLY1305, Name: "ECDHE-ECDSA-CHACHA20-POLY1305",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specCHACHA20POLY1305, MAC: specNoMAC, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteECDHEECDSAAES128GCMSHA256, Name: "ECDHE-ECDSA-AES128-GCM-SHA256",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// ECDHE-RSA with AEAD.
	register(&Suite{
		ID: suiteECDHERSAAES256GCMSHA384, Name: "ECDHE-RSA-AES256-GCM-SHA384",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: suiteECDHERSACHACHA20POLY1305, Name: "ECDHE-RSA-CHACHA20-POLY1305",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specCHACHA20POLY1305, MAC: specNoMAC, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteECDHERSAAES128GCMSHA256, Name: "ECDHE-RSA-AES128-GCM-SHA256",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// ECDHE-ECDSA with CBC-SHA384.
	register(&Suite{
		ID: suiteECDHEECDSAAES256SHA384, Name: "ECDHE-ECDSA-AES256-SHA384",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES256CBC, MAC: specHMACSHA384, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: suiteECDHEECDSAAES128SHA256, Name: "ECDHE-ECDSA-AES128-SHA256",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})

	// ECDHE-RSA with CBC-SHA384.
	register(&Suite{
		ID: suiteECDHERSAAES256SHA384, Name: "ECDHE-RSA-AES256-SHA384",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA384, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: suiteECDHERSAAES128SHA256, Name: "ECDHE-RSA-AES128-SHA256",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})

	// ECDHE-ECDSA with CBC-SHA1.
	register(&Suite{
		ID: suiteECDHEECDSAAES256SHA, Name: "ECDHE-ECDSA-AES256-SHA",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteECDHEECDSAAES128SHA, Name: "ECDHE-ECDSA-AES128-SHA",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})

	// ECDHE-RSA with CBC-SHA1.
	register(&Suite{
		ID: suiteECDHERSAAES256SHA, Name: "ECDHE-RSA-AES256-SHA",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteECDHERSAAES128SHA, Name: "ECDHE-RSA-AES128-SHA",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
}

// ---- DHE-RSA suites (7) -----------------------------------------------------.

func registerDHERSASuites() {
	// DHE-RSA with AEAD.
	register(&Suite{
		ID: suiteDHERSAAES256GCMSHA384, Name: "DHE-RSA-AES256-GCM-SHA384",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: suiteDHERSACHACHA20POLY1305, Name: "DHE-RSA-CHACHA20-POLY1305",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specCHACHA20POLY1305, MAC: specNoMAC, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteDHERSAAES128GCMSHA256, Name: "DHE-RSA-AES128-GCM-SHA256",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// DHE-RSA with CBC.
	register(&Suite{
		ID: suiteDHERSAAES256SHA256, Name: "DHE-RSA-AES256-SHA256",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteDHERSAAES128SHA256, Name: "DHE-RSA-AES128-SHA256",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteDHERSAAES256SHA, Name: "DHE-RSA-AES256-SHA",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteDHERSAAES128SHA, Name: "DHE-RSA-AES128-SHA",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
}

// ---- RSA key exchange suites (6) --------------------------------------------.

func registerRSAKxSuites() {
	// RSA kx with AEAD.
	register(&Suite{
		ID: suiteRSAAES256GCMSHA384, Name: "AES256-GCM-SHA384",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: suiteRSAAES128GCMSHA256, Name: "AES128-GCM-SHA256",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// RSA kx with CBC.
	register(&Suite{
		ID: suiteRSAAES256SHA256, Name: "AES256-SHA256",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteRSAAES128SHA256, Name: "AES128-SHA256",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteRSAAES256SHA, Name: "AES256-SHA",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: suiteRSAAES128SHA, Name: "AES128-SHA",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
}
