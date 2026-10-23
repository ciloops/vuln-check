package osv

import (
	"math"
	"strings"
)

// BaseScoreV3 computes the CVSS v3.0/v3.1 base score from a vector string.
// Returns 0 when the vector is not a complete v3 base vector.
func BaseScoreV3(vector string) float64 {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10))
	}
	return roundUp(math.Min(impact+exploitability, 10))
}

func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}

func SeverityFromScore(s float64) string {
	switch {
	case s == 0:
		return ""
	case s >= 9:
		return "CRITICAL"
	case s >= 7:
		return "HIGH"
	case s >= 4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
