package fence

import (
	"strings"

	"pi-fortress/internal/corepolicy"
	"pi-fortress/internal/pctdecode"
)

// A git smart-HTTP push is two requests. The fence refuses both unless the
// repo is in git_push.allow (docs/git_push.md):
//
//	GET  /<repo>[.git]/info/refs?service=git-receive-pack
//	POST /<repo>[.git]/git-receive-pack
//
// A refusal of the first request makes git fail before it builds a pack.
// Clone and fetch (git-upload-pack) are not affected.
//
// The agent writes the target. Thus the question is never "is this the
// canonical shape" but "could an origin read this as a push". A target is
// push-shaped when, fully percent-decoded and lowercased, its path mentions
// receive-pack under a method other than GET or HEAD, or receive-pack, in
// the path or the query, follows the last "refs" of the path.
// The fence then parses a push-shaped target strictly: a raw path of
// [A-Za-z0-9._-/] only, no empty, "." or ".." segment, and an end of
// git-receive-pack or info/refs. The fence refuses all other push-shaped
// targets, whatever the list says, because there is no single repo to examine.

const receivePack = "receive-pack"

// GitPushTarget classifies one request. push is false for all requests
// that are not push-shaped. ok is false for a push-shaped target that is
// not a clean push, and repo is then empty. repo is the path before the
// git suffix, lowercased, with one ".git" removed: "acme/widget",
// "grp/sub/repo".
func GitPushTarget(method, target string) (repo string, push, ok bool) {
	if !mayPush(target) {
		return "", false, false
	}
	t := target
	if hasPrefixFold(t, "https://") || hasPrefixFold(t, "http://") {
		t = t[strings.Index(t, "//")+2:]
		if i := strings.IndexAny(t, "/?"); i >= 0 {
			t = t[i:]
		} else {
			t = ""
		}
	}
	rawPath, rawQuery, _ := strings.Cut(t, "?")
	dp, stable := unescapeAll(rawPath)
	dq, stableQ := unescapeAll(rawQuery)
	if !stable || !stableQ {
		return "", true, false
	}
	dp, dq = strings.ToLower(dp), strings.ToLower(dq)
	shaped := method != "GET" && method != "HEAD" && strings.Contains(dp, receivePack)
	if i := strings.LastIndex(dp, "refs"); !shaped && i >= 0 {
		shaped = strings.Contains(dp[i:], receivePack) || strings.Contains(dq, receivePack)
	}
	if !shaped {
		return "", false, false
	}
	repo, ok = pushRepo(rawPath)
	return repo, true, ok
}

// GitPushRefused is the decision that the broker acts on. The broker
// forwards a push only when it is clean and list allows its repo on the
// Host and, when there is an SNI, on the SNI. The two can be different,
// and the SNI selects the origin.
func GitPushRefused(list *corepolicy.GitPush, host, sni, method, target string) (refused bool, repo string, clean bool) {
	repo, push, clean := GitPushTarget(method, target)
	switch {
	case !push:
		return false, "", false
	case !clean:
		return true, "", false
	case !list.Allowed(host, repo), sni != "" && !list.Allowed(sni, repo):
		return true, repo, true
	}
	return false, repo, true
}

// mayPush is the hot path: it is false unless the target, fully decoded,
// can mention receive-pack. It decodes one level in place, without an
// allocation. A decoded "%XX" means that another level exists. Then the
// answer is true, so the slow path decodes the remainder.
func mayPush(target string) bool {
	m := 0
	var p1, p2 byte
	for i := 0; i < len(target); i++ {
		c := target[i]
		if c == '%' && i+2 < len(target) && pctdecode.IsHex(target[i+1]) && pctdecode.IsHex(target[i+2]) {
			c = pctdecode.Unhex(target[i+1])<<4 | pctdecode.Unhex(target[i+2])
			i += 2
		}
		if p2 == '%' && pctdecode.IsHex(p1) && pctdecode.IsHex(c) {
			return true
		}
		p2, p1 = p1, c
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		// 'r' starts the pattern and does not occur anywhere else in it.
		// Thus after a mismatch, a new match can start only on an 'r'.
		switch {
		case c == receivePack[m]:
			m++
			if m == len(receivePack) {
				return true
			}
		case c == 'r':
			m = 1
		default:
			m = 0
		}
	}
	return false
}

// unescapeAll decodes until nothing changes. An invalid escape stays
// literal. stable is false when a few rounds did not give a stable result.
func unescapeAll(s string) (string, bool) {
	for range 4 {
		d := pctdecode.Once(s)
		if d == s {
			return s, true
		}
		s = d
	}
	return s, pctdecode.Once(s) == s
}

// pushRepo is the strict parse of a push-shaped raw path.
func pushRepo(p string) (string, bool) {
	if len(p) < 2 || p[0] != '/' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' && c != '/' {
			return "", false
		}
	}
	segs := strings.Split(strings.ToLower(p[1:]), "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", false
		}
	}
	n := len(segs)
	switch {
	case segs[n-1] == "git-"+receivePack:
		segs = segs[:n-1]
	case n >= 2 && segs[n-2] == "info" && segs[n-1] == "refs":
		segs = segs[:n-2]
	default:
		return "", false
	}
	if len(segs) == 0 {
		return "", false
	}
	last := strings.TrimSuffix(segs[len(segs)-1], ".git")
	if last == "" || last == "." || last == ".." {
		return "", false
	}
	segs[len(segs)-1] = last
	return strings.Join(segs, "/"), true
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
