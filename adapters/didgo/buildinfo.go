package didgo

import (
	"runtime/debug"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

var readBuildInfo = debug.ReadBuildInfo

// describe finds did-go among the dependencies of the running binary and
// returns its module version and the revision that version names.
func describe(read func() (*debug.BuildInfo, bool)) core.SubjectInfo {
	info := core.SubjectInfo{Name: Name, Version: "unknown", Revision: "unknown"}
	bi, ok := read()
	if !ok || bi == nil {
		return info
	}
	for _, dep := range bi.Deps {
		if dep.Path != ModulePath {
			continue
		}
		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}
		if mod.Version != "" {
			info.Version = mod.Version
			info.Revision = revisionOf(mod.Version)
		}
		if dep.Replace != nil {
			info.Version += " (replaced by " + dep.Replace.Path + ")"
		}
		return info
	}
	return info
}

// revisionOf returns the VCS revision a module version names: the commit
// hash of a pseudo-version (vX.Y.Z-yyyymmddhhmmss-abcdefabcdef, possibly
// with +incompatible), or the version itself for a tagged release.
func revisionOf(version string) string {
	v, _, _ := strings.Cut(version, "+")
	parts := strings.Split(v, "-")
	if len(parts) >= 3 {
		hash := parts[len(parts)-1]
		stamp := parts[len(parts)-2]
		stamp = stamp[strings.LastIndex(stamp, ".")+1:]
		if len(hash) == 12 && isHex(hash) && len(stamp) == 14 && isDigits(stamp) {
			return hash
		}
	}
	return version
}

func isHex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
