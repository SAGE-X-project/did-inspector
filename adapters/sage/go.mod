module github.com/sage-x-project/did-inspector/adapters/sage

go 1.26.0

toolchain go1.26.8

require (
	github.com/sage-x-project/did-go v0.0.0-20261012015322-ed54c505eafe
	github.com/sage-x-project/did-go/advanced/sage v0.0.0-20261012020818-2ef282b40ccf
	github.com/sage-x-project/did-inspector v0.0.0
)

require (
	github.com/bits-and-blooms/bitset v1.26.0 // indirect
	github.com/nlnwa/whatwg-url v0.6.2 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/sage-x-project/did-inspector => ../..
