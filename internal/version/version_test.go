package version

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.9", 1},
		{"v1.2.3", "1.2.3", 0},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0-2", -1},
		{"5.6.0-0.2", "5.6.1+really5.4.5-1ubuntu0.1", -1},
		{"3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.11", -1},
		{"1:1.2.3", "1.2.4", 1},
		{"4.17.20", "4.17.21", -1},
		{"2.31.0", "2.32.0", -1},
		{"1.2.5", "1.2.6", -1},
		{"0.9", "0.10", -1},
		{"2:1.0", "1:9.9", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestBreaking(t *testing.T) {
	cases := []struct {
		cur, target, typ string
		want             bool
	}{
		{"4.17.20", "4.17.21", "npm", false},
		{"4.19.2", "5.0.0", "npm", true},
		{"0.5.1", "0.6.0", "npm", true},
		{"0.5.1", "0.5.9", "npm", false},
		{"0.5.1", "0.6.0", "pypi", false},
		{"2.31.0", "3.0", "pypi", true},
		{"1:1.2.3", "1:2.0.0", "deb", true},
		{"1:1.2.3", "1:1.9.0", "deb", false},
		{"v1.2.3", "v2.0.0", "golang", true},
		{"rc", "1.0", "npm", false},
	}
	for _, c := range cases {
		if got := Breaking(c.cur, c.target, c.typ); got != c.want {
			t.Errorf("Breaking(%q,%q,%q) = %v, want %v", c.cur, c.target, c.typ, got, c.want)
		}
	}
}
