package main

import (
	"fmt"
	"io"
	"os"

	"github.com/sage-x-project/did-inspector/adapters/sageexpansion"
)

func main() { os.Exit(run(os.Stdout, os.Stderr, os.Getenv("INSPECTOR_REVISION"), sageexpansion.Write)) }

func run(stdout, stderr io.Writer, revision string, inspect func(io.Writer, string) error) int {
	if err := inspect(stdout, revision); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
