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

func init() {
	registerECDHESuites()
	registerDHERSASuites()
	registerRSAKxSuites()
}

// ---- shared cipher/MAC/PRF specs -------------------------------------------

var (
	// AES-128-GCM: 16-byte key, 4-byte implicit salt, 8-byte explicit nonce.
	specAES128GCM = CipherSpec{
		Name:          "AES-128-GCM",
		KeyLen:        16,
		FixedIVLen:    4,
		ExplicitIVLen: 8,
		AEAD:          true,
		TagLen:        16,
	}

	// AES-256-GCM: 32-byte key, 4-byte implicit salt, 8-byte explicit nonce.
	specAES256GCM = CipherSpec{
		Name:          "AES-256-GCM",
		KeyLen:        32,
		FixedIVLen:    4,
		ExplicitIVLen: 8,
		AEAD:          true,
		TagLen:        16,
	}

	// CHACHA20-POLY1305: 32-byte key, 12-byte fully-implicit IV (RFC 7905).
	// ExplicitIVLen = 0: no bytes prepended to the wire record.
	// The 12-byte nonce is write_IV XOR (seq padded to 12 bytes). Phase 8
	// must handle this differently from AES-GCM when assembling Protectors.
	specCHACHA20POLY1305 = CipherSpec{
		Name:          "CHACHA20-POLY1305",
		KeyLen:        32,
		FixedIVLen:    12,
		ExplicitIVLen: 0,
		AEAD:          true,
		TagLen:        16,
	}

	// AES-256-CBC: 32-byte key, 16-byte IV derived from key block (RFC 5246 §6.3),
	// 16-byte explicit IV prepended to each record.
	specAES256CBC = CipherSpec{
		Name:          "AES-256-CBC",
		KeyLen:        32,
		FixedIVLen:    16,
		ExplicitIVLen: 16,
		AEAD:          false,
	}

	// AES-128-CBC: 16-byte key, 16-byte IV derived from key block (RFC 5246 §6.3),
	// 16-byte explicit IV prepended to each record.
	specAES128CBC = CipherSpec{
		Name:          "AES-128-CBC",
		KeyLen:        16,
		FixedIVLen:    16,
		ExplicitIVLen: 16,
		AEAD:          false,
	}

	// HMAC-SHA384: 48-byte key, 48-byte MAC.
	specHMACSHA384 = MACSpec{
		Hash:   sha512.New384,
		KeyLen: 48,
		MACLen: 48,
	}

	// HMAC-SHA256: 32-byte key, 32-byte MAC.
	specHMACSHA256 = MACSpec{
		Hash:   sha256.New,
		KeyLen: 32,
		MACLen: 32,
	}

	// HMAC-SHA: 20-byte key, 20-byte MAC (SHA-1).
	specHMACSHA1 = MACSpec{
		Hash:   sha1New,
		KeyLen: 20,
		MACLen: 20,
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

// ---- ECDHE suites (14) ------------------------------------------------------

func registerECDHESuites() {
	// ECDHE-ECDSA with AEAD
	register(&Suite{
		ID: 0xC02C, Name: "ECDHE-ECDSA-AES256-GCM-SHA384",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: 0xCCA9, Name: "ECDHE-ECDSA-CHACHA20-POLY1305",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specCHACHA20POLY1305, MAC: specNoMAC, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0xC02B, Name: "ECDHE-ECDSA-AES128-GCM-SHA256",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// ECDHE-RSA with AEAD
	register(&Suite{
		ID: 0xC030, Name: "ECDHE-RSA-AES256-GCM-SHA384",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: 0xCCA8, Name: "ECDHE-RSA-CHACHA20-POLY1305",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specCHACHA20POLY1305, MAC: specNoMAC, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0xC02F, Name: "ECDHE-RSA-AES128-GCM-SHA256",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// ECDHE-ECDSA with CBC-SHA384
	register(&Suite{
		ID: 0xC024, Name: "ECDHE-ECDSA-AES256-SHA384",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES256CBC, MAC: specHMACSHA384, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: 0xC023, Name: "ECDHE-ECDSA-AES128-SHA256",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})

	// ECDHE-RSA with CBC-SHA384
	register(&Suite{
		ID: 0xC028, Name: "ECDHE-RSA-AES256-SHA384",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA384, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: 0xC027, Name: "ECDHE-RSA-AES128-SHA256",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})

	// ECDHE-ECDSA with CBC-SHA1
	register(&Suite{
		ID: 0xC00A, Name: "ECDHE-ECDSA-AES256-SHA",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0xC009, Name: "ECDHE-ECDSA-AES128-SHA",
		KX: KexECDHE, Auth: AuthECDSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})

	// ECDHE-RSA with CBC-SHA1
	register(&Suite{
		ID: 0xC014, Name: "ECDHE-RSA-AES256-SHA",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0xC013, Name: "ECDHE-RSA-AES128-SHA",
		KX: KexECDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
}

// ---- DHE-RSA suites (7) -----------------------------------------------------

func registerDHERSASuites() {
	// DHE-RSA with AEAD
	register(&Suite{
		ID: 0x009F, Name: "DHE-RSA-AES256-GCM-SHA384",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: 0xCCAA, Name: "DHE-RSA-CHACHA20-POLY1305",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specCHACHA20POLY1305, MAC: specNoMAC, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x009E, Name: "DHE-RSA-AES128-GCM-SHA256",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// DHE-RSA with CBC
	register(&Suite{
		ID: 0x006B, Name: "DHE-RSA-AES256-SHA256",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x0067, Name: "DHE-RSA-AES128-SHA256",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x0039, Name: "DHE-RSA-AES256-SHA",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x0033, Name: "DHE-RSA-AES128-SHA",
		KX: KexDHE, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
}

// ---- RSA key exchange suites (6) --------------------------------------------

func registerRSAKxSuites() {
	// RSA kx with AEAD
	register(&Suite{
		ID: 0x009D, Name: "AES256-GCM-SHA384",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES256GCM, MAC: specNoMAC, PRF: specPRFSHA384,
	})
	register(&Suite{
		ID: 0x009C, Name: "AES128-GCM-SHA256",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES128GCM, MAC: specNoMAC, PRF: specPRFSHA256,
	})

	// RSA kx with CBC
	register(&Suite{
		ID: 0x003D, Name: "AES256-SHA256",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x003C, Name: "AES128-SHA256",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA256, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x0035, Name: "AES256-SHA",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES256CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
	register(&Suite{
		ID: 0x002F, Name: "AES128-SHA",
		KX: KexRSA, Auth: AuthRSA,
		Cipher: specAES128CBC, MAC: specHMACSHA1, PRF: specPRFSHA256,
	})
}
