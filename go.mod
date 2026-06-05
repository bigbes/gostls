module github.com/bigbes/gostls

go 1.24

require (
	filippo.io/bigmod v0.1.0
	github.com/bigbes/gostcrypto v0.0.0
	golang.org/x/crypto v0.16.0
)

require golang.org/x/sys v0.15.0 // indirect

// gostcrypto is co-developed and not yet published; wired in by replace until a
// real version is pinned at release. Check it out as a sibling directory.
replace github.com/bigbes/gostcrypto => ../gostcrypto
