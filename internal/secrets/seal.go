package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"

	"pi-fortress/internal/secretscan"
)

// Sealing exists for exactly two threats: the SD card pulled and imaged,
// and the whole box carried off. It gives no protection against root on
// a box that runs. After the store is unlocked, the key is in the memory
// of the broker, and root reads it, or asks the broker. It protects the
// powered-off state. For an appliance in a house, that is the realistic
// physical attack.
//
// The key comes from a human, one time for each boot. A headless gateway
// that could derive its own key would give that key to the holder of
// the card. There are only three places to break that symmetry: another
// device, a human, or nothing. To ship the third and claim the first is
// worse than plaintext, because people trust a security claim.
//
// The file is sealed or it is not. There is no per-value mixing. A
// plaintext value that stays valid inside a sealed store would be a
// silent downgrade. Anything that can write the file could put a value
// back in the clear, and the value would still work. The file would
// still look sealed, because the header is still there. Thus a plaintext
// value in a sealed file is a fault that stops the whole store. The way
// back is pf enroll unseal: an explicit rewrite, not a state that a file
// can drift into.

const (
	// sealedHeader is a comment to each reader that is older than sealing.
	// That makes the file safe to give to an old build. For exactly that
	// reason, a build that does understand sealing must refuse a version
	// that it does not know. It must not fall through to the values below
	// it.
	sealedHeader = "#pf-sealed"
	// sealedMark is the start of a sealed value. It starts with '#' on
	// purpose: ValidLive rejects '#', and loadFile cuts a line at its first
	// '#'. Thus a build without sealing reads the slot as present and
	// empty, not as a well-formed live value. Base64 alone would have
	// passed ValidLive with no change, and gone into live traffic as
	// though it were a token.
	sealedMark = "#pf1."
	sealVer    = "v1"
	saltLen    = 16
	// The canary is sealed under the same key and stored in the header.
	// Thus a passphrase can be checked against a store that holds no
	// values yet.
	canaryPlain = "pi-fortress sealed store"
	canaryAAD   = "pf-sealed/canary"
)

var (
	ErrSealedVersion = errors.New("secrets: unsupported sealed format version")
	ErrSealedHeader  = errors.New("secrets: malformed sealed header")
	ErrLocked        = errors.New("secrets: store is sealed and no passphrase has been entered")
	ErrPassphrase    = errors.New("secrets: passphrase does not open this store")
	ErrPlainInSealed = errors.New("secrets: sealed store holds a plaintext value")
)

var b64 = base64.RawURLEncoding

// KDF params. scrypt and not PBKDF2 (which is in the standard library as
// of Go 1.27), because the threat is offline cracking of a stolen card,
// and PBKDF2 is GPU-friendly. scrypt and not argon2, because
// x/crypto/argon2 pulls blake2b and thus x/sys. x/crypto/scrypt adds no
// module beyond x/crypto itself. This was checked, not assumed.
type kdfParams struct{ N, R, P int }

var defaultKDF = kdfParams{N: 1 << 15, R: 8, P: 1}

// The header is plaintext, and it is on the card. Unlock must derive
// the key before the canary can say that the header was ever ours. Thus
// the cost that the header names is a cost that an unauthenticated file
// can demand of a gateway with a couple of gigabytes of RAM. N=1<<24 at
// r=8 asks for sixteen gigabytes. That is not a wrong-passphrase answer:
// it is the box gone. These bounds are an order of magnitude above the
// default in each direction. Thus a future stronger default still fits,
// and a substituted one does not.
const (
	maxKDFMem   = 256 << 20
	maxKDFR     = 32
	maxKDFP     = 16
	maxKDFN     = 1 << 22
	scryptBlock = 128
)

// Header is the first line of a sealed store. It is plaintext, because
// none of it is secret, and all of it is necessary to try a passphrase.
type Header struct {
	Ver    string
	KDF    string
	Params kdfParams
	Salt   []byte
	Canary []byte
}

func (h Header) String() string {
	return fmt.Sprintf("%s %s %s N=%d r=%d p=%d salt=%s canary=%s",
		sealedHeader, h.Ver, h.KDF, h.Params.N, h.Params.R, h.Params.P,
		b64.EncodeToString(h.Salt), b64.EncodeToString(h.Canary))
}

func isSealedHeader(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), sealedHeader+" ")
}

// ParseHeader reads a header line. An unrecognised version is
// ErrSealedVersion, not a parse that continues. '#' is a comment to each
// older reader, so the header alone protects nothing. A build that
// ignored a version that it did not know would read the values under it
// as if they were plain.
func ParseHeader(line string) (Header, error) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 3 || f[0] != sealedHeader {
		return Header{}, ErrSealedHeader
	}
	h := Header{Ver: f[1], KDF: f[2]}
	if h.Ver != sealVer {
		return Header{}, fmt.Errorf("%w %q", ErrSealedVersion, h.Ver)
	}
	if h.KDF != "scrypt" {
		return Header{}, fmt.Errorf("%w: kdf %q", ErrSealedVersion, h.KDF)
	}
	for _, kv := range f[3:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || h.setField(k, v) != nil {
			return Header{}, ErrSealedHeader
		}
	}
	if err := h.check(); err != nil {
		return Header{}, err
	}
	return h, nil
}

// setField sets one key=value field of the header. Each error is a
// malformed header.
func (h *Header) setField(k, v string) error {
	var err error
	switch k {
	case "N", "r", "p":
		var n int
		if n, err = strconv.Atoi(v); err != nil || n <= 0 {
			return ErrSealedHeader
		}
		switch k {
		case "N":
			h.Params.N = n
		case "r":
			h.Params.R = n
		case "p":
			h.Params.P = n
		}
	case "salt":
		h.Salt, err = b64.DecodeString(v)
	case "canary":
		h.Canary, err = b64.DecodeString(v)
	default:
		return ErrSealedHeader
	}
	return err
}

// check refuses a header with fields that are missing, malformed, or
// that ask for more work than the box does before it can authenticate.
func (h Header) check() error {
	if h.Params.N <= 1 || h.Params.R <= 0 || h.Params.P <= 0 || len(h.Salt) != saltLen || len(h.Canary) == 0 {
		return ErrSealedHeader
	}
	// N must be a power of two, or scrypt refuses it. This check stops a
	// malformed header from looking like a wrong passphrase.
	if h.Params.N&(h.Params.N-1) != 0 {
		return ErrSealedHeader
	}
	if h.Params.N > maxKDFN || h.Params.R > maxKDFR || h.Params.P > maxKDFP {
		return fmt.Errorf("%w: N=%d r=%d p=%d asks for more work than this box will do unauthenticated", ErrSealedHeader, h.Params.N, h.Params.R, h.Params.P)
	}
	if int64(h.Params.N)*int64(h.Params.R)*scryptBlock > maxKDFMem {
		return fmt.Errorf("%w: N=%d r=%d wants %d bytes", ErrSealedHeader, h.Params.N, h.Params.R, int64(h.Params.N)*int64(h.Params.R)*scryptBlock)
	}
	return nil
}

// Sealer holds the derived key. It is only in memory: the passphrase
// is not written down, and the derived key is not written down.
type Sealer struct {
	aead cipher.AEAD
	hdr  Header
}

func (h Header) derive(passphrase []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key(passphrase, h.Salt, h.Params.N, h.Params.R, h.Params.P, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Open derives the key and checks it against the canary of the header.
// Thus a wrong passphrase is one answer, not a store that decrypts to
// nothing and looks empty.
//
// This is the only place where a key is derived. Thus it is the only
// place for a key source that is not a human: a TPM or a USB token that
// supplies the material without a passphrase. That would defeat card
// theft and keep unattended boot. An earlier plan wanted that interface
// now, because the seam is cheap and the rewrite is not. It is not
// built. An interface with one implementation and no second caller is a
// guess about the shape of the second one. One function, named here, is
// cheaper to change than an abstraction that fits the wrong device.
func (h Header) Open(passphrase []byte) (*Sealer, error) {
	aead, err := h.derive(passphrase)
	if err != nil {
		return nil, err
	}
	s := &Sealer{aead: aead, hdr: h}
	plain, err := s.open(h.Canary, canaryAAD)
	if err != nil {
		return nil, ErrPassphrase
	}
	if subtle.ConstantTimeCompare([]byte(plain), []byte(canaryPlain)) != 1 {
		return nil, ErrPassphrase
	}
	return s, nil
}

// NewHeader mints a salt, derives from it and seals the canary.
func NewHeader(passphrase []byte) (*Sealer, error) {
	h := Header{Ver: sealVer, KDF: "scrypt", Params: defaultKDF, Salt: make([]byte, saltLen)}
	if _, err := rand.Read(h.Salt); err != nil {
		return nil, err
	}
	aead, err := h.derive(passphrase)
	if err != nil {
		return nil, err
	}
	s := &Sealer{aead: aead}
	h.Canary = s.seal([]byte(canaryPlain), canaryAAD)
	s.hdr = h
	return s, nil
}

func (s *Sealer) Header() Header { return s.hdr }

func (s *Sealer) seal(plain []byte, aad string) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("secrets: no entropy: " + err.Error())
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(aad))
}

func (s *Sealer) open(blob []byte, aad string) (string, error) {
	n := s.aead.NonceSize()
	if len(blob) < n {
		return "", ErrPassphrase
	}
	out, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Seal encodes one value. envKey is the associated data. Thus a
// ciphertext carries the slot and kind that it was written for. If a
// sealed value moves from one slot line to another, it fails to open.
// One slot does not silently answer with the credential of another.
func (s *Sealer) Seal(envKey, live string) string {
	return sealedMark + b64.EncodeToString(s.seal([]byte(live), envKey))
}

// Unseal is the inverse of Seal. A value that does not open is an error.
// It is never an empty slot that quietly reads as "no credential yet".
func (s *Sealer) Unseal(envKey, value string) (string, error) {
	raw, ok := strings.CutPrefix(value, sealedMark)
	if !ok {
		return "", ErrPlainInSealed
	}
	blob, err := b64.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("secrets: %s: %w", envKey, ErrPassphrase)
	}
	live, err := s.open(blob, envKey)
	if err != nil {
		return "", fmt.Errorf("secrets: %s: %w", envKey, ErrPassphrase)
	}
	return live, nil
}

func isSealedValue(v string) bool { return strings.HasPrefix(v, sealedMark) }

var ErrAlreadySealed = errors.New("secrets: store is already sealed")

// ErrLegacyUnslotted is a store that was asked to seal while it still
// holds a row from before the slot model. The running store ignores such
// a row, and that made this quiet. The broker never served the value, so
// nothing complained. Sealing then copied it in the clear into the one
// file that is meant to be safe on a stolen card.
//
// A refusal is better than to discard the row. It may be the only copy
// of a credential that the operator still uses. A seal that silently ate
// it would trade a leak for a loss. A refusal is also better than a seal
// in place. A value under a key that no slot can name would unseal to
// something that nothing can serve. That is a credential kept alive in a
// form that only helps the thief.
var ErrLegacyUnslotted = errors.New("secrets: store holds an unslotted secret; run pf enroll migrate first")

// legacyUnslotted names each row that has a value that no slot claims.
// It omits empty rows: a bare name is a leftover, not a credential, and
// it must not stand between an operator and a sealed store.
func legacyUnslotted(lines []string) []string {
	var keys []string
	for _, raw := range lines {
		key, value, ok := parseLineKV(raw)
		if !ok || value == "" {
			continue
		}
		if _, _, slotted := ParseEnvKey(key); slotted {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

// ErrPlainSecretLine is a store that was asked to seal while a line that
// sealing would copy as it is holds something shaped like a credential.
// Such a line is a comment, a line with no '=', a row that no slot
// claims, or the note after a value. A rotated token kept as
// "# old=ghp_..." is the usual one. To seal it through would leave a key
// in the clear in the one file meant to be safe on a stolen card. Thus
// the error names the rows, by line number only, and the operator removes them.
var ErrPlainSecretLine = errors.New("secrets: a line sealing keeps in the clear holds something secret-shaped; remove it first")

// minSecretRun is the shortest run of token bytes that counts as a
// possible credential in text that sealing keeps as it is. No key that
// this fence knows is shorter, and prose words are shorter.
const minSecretRun = 20

// splitComment cuts raw at its first '#', the same way that loadFile
// reads an unsealed store. text is the remainder. note is the comment,
// '#' included and trimmed, or "" for none. A value can hold no '#'
// (ValidLive), so the cut is never inside a value.
func splitComment(raw string) (text, note string) {
	i := strings.IndexByte(raw, '#')
	if i < 0 {
		return raw, ""
	}
	return raw[:i], strings.TrimSpace(raw[i:])
}

// plainSecretLines names, 1-based, each line whose clear-text part looks
// like it carries a credential: a secretscan match, or a run of
// minSecretRun bytes that ValidLive would accept. The value of a slot
// row is sealed, so the code does not examine it. It examines its note.
func plainSecretLines(lines []string) []string {
	var bad []string
	for i, raw := range lines {
		clear := raw
		text, note := splitComment(raw)
		if key, _, ok := parseLineKV(text); ok {
			if _, _, slotted := ParseEnvKey(key); slotted {
				clear = note
			}
		}
		if secretShaped(clear) {
			bad = append(bad, strconv.Itoa(i+1))
		}
	}
	return bad
}

func secretShaped(s string) bool {
	if len(secretscan.Scan([]byte(s))) > 0 {
		return true
	}
	run := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' || c == '#' || c == '"' || c == '\'' {
			run = 0
			continue
		}
		if run++; run >= minSecretRun {
			return true
		}
	}
	return false
}

// Seal rewrites the whole store under a new passphrase. Every value
// goes, or none does: there is no per-value migration, because a
// plaintext value left valid inside a sealed store is a downgrade
// anything with write access could take.
//
// Lines that are not slots (the comments of an operator) stay as they
// are. A note after a value moves to a separate line above the value.
// They are not secret. A sealed store without them would be harder to
// read, with no gain. A line that looks secret refuses the seal
// (ErrPlainSecretLine).
func (s *Store) Seal(passphrase []byte) error {
	sealer, err := NewHeader(passphrase)
	if err != nil {
		return err
	}
	return s.withLock(func() error {
		lines, err := readLines(s.path)
		if err != nil {
			return err
		}
		for _, raw := range lines {
			if isSealedHeader(raw) {
				return ErrAlreadySealed
			}
		}
		// Before anything is written, because the purpose of the answer
		// is that the file of the operator is still where they left it.
		// pf enroll migrate claims each row that it can name a kind for.
		// Only a human can identify what it leaves. Thus the error names
		// the rows, and does not guess.
		if stale := legacyUnslotted(lines); len(stale) > 0 {
			return fmt.Errorf("%w (%s)", ErrLegacyUnslotted, strings.Join(stale, ", "))
		}
		if bad := plainSecretLines(lines); len(bad) > 0 {
			return fmt.Errorf("%w (line %s)", ErrPlainSecretLine, strings.Join(bad, ", "))
		}
		out, err := sealLines(lines, sealer)
		if err != nil {
			return err
		}
		if err := writeLines(s.path, out); err != nil {
			return err
		}
		s.mu.Lock()
		s.sealer = sealer
		s.mu.Unlock()
		return nil
	})
}

// sealLines gives the sealed file: the header, then each line with each
// slot value sealed under sealer.
func sealLines(lines []string, sealer *Sealer) ([]string, error) {
	out := []string{sealer.Header().String()}
	for _, raw := range lines {
		text, note := splitComment(raw)
		key, value, ok := parseLineKV(text)
		if !ok {
			out = append(out, raw)
			continue
		}
		id, kind, slotted := ParseEnvKey(key)
		if !slotted {
			out = append(out, raw)
			continue
		}
		envKey := EnvKey(id, kind)
		// The note goes on a separate line: a sealed value is read
		// whole, so text after it would break the ciphertext.
		if note != "" {
			out = append(out, note)
		}
		if value == "" {
			out = append(out, envKey+"=")
			continue
		}
		if !ValidLive(value) {
			return nil, fmt.Errorf("%s: %w", envKey, ErrBadLive)
		}
		out = append(out, envKey+"="+sealer.Seal(envKey, value))
	}
	return out, nil
}

// Unseal is the way back. On purpose, it is the whole file and an
// explicit verb. It is not a state that a store can drift into, and a
// writer cannot do it to one value.
func (s *Store) Unseal(passphrase []byte) error {
	hdr, err := s.header()
	if err != nil {
		return err
	}
	sealer, err := hdr.Open(passphrase)
	if err != nil {
		return err
	}
	return s.withLock(func() error {
		lines, err := readLines(s.path)
		if err != nil {
			return err
		}
		var out []string
		for _, raw := range lines {
			if isSealedHeader(raw) {
				continue
			}
			key, value, ok := parseLineKV(raw)
			if !ok {
				out = append(out, raw)
				continue
			}
			id, kind, slotted := ParseEnvKey(key)
			if !slotted || value == "" {
				out = append(out, raw)
				continue
			}
			envKey := EnvKey(id, kind)
			live, err := sealer.Unseal(envKey, value)
			if err != nil {
				return err
			}
			out = append(out, envKey+"="+live)
		}
		if err := writeLines(s.path, out); err != nil {
			return err
		}
		s.mu.Lock()
		s.sealer = nil
		s.mu.Unlock()
		return nil
	})
}

// The unlock protocol. It is here, in the package that both ends
// already import. Thus the listener of the broker and the operator
// tools cannot become different on a verb name or a socket path.
//
// AdminBudget is not about the key, but it belongs on the same socket.
// The per-slot hour that it reads is only in the memory of the broker.
// Thus no tool that reads the store on disk can answer it.
const (
	AdminSock   = "/run/pi-fortress/broker/admin.sock"
	AdminUnlock = "UNLOCK"
	AdminLock   = "LOCK"
	AdminState  = "STATE"
	AdminBudget = "BUDGET"
)
