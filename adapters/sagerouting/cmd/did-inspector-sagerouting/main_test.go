package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRun(t *testing.T) {
	for _, fail := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		code := run(&stdout, &stderr, "observer", func(out io.Writer, revision string) error {
			if revision != "observer" {
				t.Fatal("revision lost")
			}
			if fail {
				return errors.New("identity rejected")
			}
			_, err := io.WriteString(out, "receipt")
			return err
		})
		if fail {
			if code != 1 || stdout.Len() != 0 || stderr.String() != "identity rejected\n" {
				t.Fatal("failure hidden")
			}
		} else if code != 0 || stdout.String() != "receipt" || stderr.Len() != 0 {
			t.Fatal("successful output lost")
		}
	}
}
