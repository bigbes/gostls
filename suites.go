package gostls

import "github.com/bigbes/gostls/internal/suites"

// SuiteInfo is a minimal descriptor of a registered TLS cipher suite,
// exported for use by callers outside this module's internal packages.
type SuiteInfo struct {
	// ID is the IANA TLS cipher suite number.
	ID uint16
	// Name is the OpenSSL-style name (e.g. "ECDHE-RSA-AES128-GCM-SHA256").
	Name string
}

// AllSuites returns info about every registered cipher suite.
// The order is stable but unspecified (registration order).
func AllSuites() []SuiteInfo {
	all := suites.All()
	out := make([]SuiteInfo, len(all))

	for i, s := range all {
		out[i] = SuiteInfo{ID: s.ID, Name: s.Name}
	}

	return out
}

// LookupSuiteByName returns the IANA ID and true for the named suite,
// or 0 and false if the name is not registered.
func LookupSuiteByName(name string) (uint16, bool) {
	s, ok := suites.LookupByName(name)
	if !ok {
		return 0, false
	}

	return s.ID, true
}
