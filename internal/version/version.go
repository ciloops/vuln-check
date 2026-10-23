package version

import (
	"strconv"
	"strings"
)

type token struct {
	num     uint64
	str     string
	numeric bool
}

func tokenize(v string) []token {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	var out []token
	var cur strings.Builder
	curNumeric := false
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		s := cur.String()
		if curNumeric {
			n, err := strconv.ParseUint(strings.TrimLeft(s, "0"), 10, 64)
			if err != nil {
				n = 0
			}
			out = append(out, token{num: n, numeric: true})
		} else {
			out = append(out, token{str: strings.ToLower(s)})
		}
		cur.Reset()
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if cur.Len() > 0 && !curNumeric {
				flush()
			}
			curNumeric = true
			cur.WriteRune(r)
		case r == '.' || r == '-' || r == '+' || r == '~' || r == '_' || r == ':' || r == ' ':
			flush()
		default:
			if cur.Len() > 0 && curNumeric {
				flush()
			}
			curNumeric = false
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// Compare returns -1, 0 or 1. It is an approximation that works for semver,
// PEP 440 release segments, Maven, dpkg and rpm EVR. A trailing alphabetic
// segment ranks lower than its absence (1.0.0-rc1 < 1.0.0); a trailing numeric
// segment ranks higher (1.0 < 1.0-1).
func Compare(a, b string) int {
	ea, a := splitEpoch(a)
	eb, b := splitEpoch(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	ta, tb := tokenize(a), tokenize(b)
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		switch {
		case i >= len(ta):
			if tb[i].numeric {
				return -1
			}
			return 1
		case i >= len(tb):
			if ta[i].numeric {
				return 1
			}
			return -1
		}
		x, y := ta[i], tb[i]
		switch {
		case x.numeric && y.numeric:
			if x.num != y.num {
				if x.num < y.num {
					return -1
				}
				return 1
			}
		case x.numeric && !y.numeric:
			return 1
		case !x.numeric && y.numeric:
			return -1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return 0
}

func Less(a, b string) bool { return Compare(a, b) < 0 }

func Major(v string) (uint64, bool) {
	for _, t := range tokenize(v) {
		if t.numeric {
			return t.num, true
		}
	}
	return 0, false
}

func Minor(v string) (uint64, bool) {
	seen := 0
	for _, t := range tokenize(v) {
		if !t.numeric {
			continue
		}
		seen++
		if seen == 2 {
			return t.num, true
		}
	}
	return 0, false
}

func splitEpoch(v string) (int, string) {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ":"); i > 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			return n, v[i+1:]
		}
	}
	return 0, v
}

func stripEpoch(v string) string {
	_, rest := splitEpoch(v)
	return rest
}

// Breaking reports whether moving from current to target crosses a major
// boundary. For zero-major versions in ecosystems that treat 0.x minors as
// breaking (npm, cargo, golang), a minor change also counts.
func Breaking(current, target, purlType string) bool {
	cm, okc := Major(stripEpoch(current))
	tm, okt := Major(stripEpoch(target))
	if !okc || !okt {
		return false
	}
	if cm != tm {
		return true
	}
	if cm == 0 {
		switch purlType {
		case "npm", "cargo", "golang":
			cmi, _ := Minor(current)
			tmi, _ := Minor(target)
			return cmi != tmi
		}
	}
	return false
}
