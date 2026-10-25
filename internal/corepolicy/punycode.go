package corepolicy

import (
	"strings"
	"unicode/utf8"
)

// IsASCII says if s holds only ASCII bytes. The lists and core.hosts
// compare names as ASCII bytes. A query, an SNI and a feed carry a name
// that is not ASCII in its xn-- form. Thus a line that is not ASCII never
// matches, and the code refuses it.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// ALabels gives name with each label that is not ASCII in its xn-- form
// (RFC 3492). It is only for the text of a refusal: it lowercases, and it
// does not do the other IDNA mapping steps. The policy never reads its
// result as a name.
func ALabels(name string) string {
	labels := strings.Split(name, ".")
	for i, l := range labels {
		if IsASCII(l) {
			labels[i] = strings.ToLower(l)
		} else {
			labels[i] = "xn--" + punycode(strings.ToLower(l))
		}
	}
	return strings.Join(labels, ".")
}

// ASCIIHint is the part of a refusal that tells the operator what to write
// for a name that is not ASCII.
func ASCIIHint(name string) string {
	return "a name that is not ASCII never matches: write its xn-- form, " + ALabels(name)
}

// The parameters of the Punycode bootstring (RFC 3492 section 5).
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

// punycode encodes one label (RFC 3492 section 6.3), without "xn--".
func punycode(label string) string {
	runes := []rune(label)
	var out []byte
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h := basic; h < len(runes); {
		m := int(utf8.MaxRune) + 1
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
				continue
			}
			if int(r) > n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := min(max(k-bias, pcTMin), pcTMax)
				if q < t {
					break
				}
				out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out = append(out, pcDigit(q))
			bias = pcAdapt(delta, h+1, h == basic)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return string(out)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// pcAdapt is the bias adaptation of RFC 3492 section 6.1.
func pcAdapt(delta, points int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
