module github.com/sage-x-project/did-inspector/adapters/didgo

go 1.26.0

toolchain go1.26.8

require github.com/sage-x-project/did-inspector v0.0.0

require github.com/sage-x-project/did-go v0.0.0-20261011184433-82160c9bc606

// The adapter is developed together with the inspector core in this
// repository and always builds against the core in the same checkout.
replace github.com/sage-x-project/did-inspector => ../..
