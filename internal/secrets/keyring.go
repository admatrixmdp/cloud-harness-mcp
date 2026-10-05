package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// Context is the AES-GCM associated data. Changing any field must fail closed.
type Context struct {
	PrincipalID   string
	EnvironmentID string
	Name          string
	Version       int
}

// Encrypted is ciphertext plus the key version that produced it.
type Encrypted struct {
	KeyVersion int
	Nonce      []byte
	Ciphertext []byte
	AuthTag    []byte
}

// KeyConfig is one 256-bit key, raw or standard-base64.
type KeyConfig struct {
	Version int
	Key     []byte
}

// Keyring is AES-256-GCM with per-secret associated data. Plaintext must never
// be logged. Ciphertext stays on the runner.
type Keyring struct {
	active int
	keys   map[int][]byte
}

// NewKeyring requires the active version to be present and every key 32 bytes.
func NewKeyring(activeVersion int, configured []KeyConfig) (*Keyring, error) {
	if activeVersion < 1 {
		return nil, fmt.Errorf("invalid active secret key version")
	}
	keys := make(map[int][]byte, len(configured))
	for _, item := range configured {
		if item.Version < 1 {
			return nil, fmt.Errorf("invalid secret key version")
		}
		if _, ok := keys[item.Version]; ok {
			return nil, fmt.Errorf("duplicate secret key version %d", item.Version)
		}
		key, err := decodeKey(item.Key)
		if err != nil {
			return nil, err
		}
		keys[item.Version] = key
	}
	if _, ok := keys[activeVersion]; !ok {
		return nil, fmt.Errorf("active secret key version %d is unavailable", activeVersion)
	}
	return &Keyring{active: activeVersion, keys: keys}, nil
}

// ActiveVersion is the key used for new ciphertext.
func (k *Keyring) ActiveVersion() int { return k.active }

func decodeKey(value []byte) ([]byte, error) {
	if len(value) == 32 {
		out := make([]byte, 32)
		copy(out, value)
		return out, nil
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Decode(decoded, value)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("secret key must decode to exactly 32 bytes")
	}
	return decoded[:32], nil
}

func associatedData(ctx Context) []byte {
	raw, _ := json.Marshal([]any{ctx.PrincipalID, ctx.EnvironmentID, ctx.Name, ctx.Version})
	return raw
}

func (k *Keyring) gcm(version int) (cipher.AEAD, error) {
	key, ok := k.keys[version]
	if !ok {
		return nil, fmt.Errorf("unknown secret key version %d", version)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext bound to ctx. The input buffer is not retained.
func (k *Keyring) Encrypt(value []byte, ctx Context) (Encrypted, error) {
	gcm, err := k.gcm(k.active)
	if err != nil {
		return Encrypted{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Encrypted{}, err
	}
	sealed := gcm.Seal(nil, nonce, value, associatedData(ctx))
	overhead := gcm.Overhead()
	if len(sealed) < overhead {
		return Encrypted{}, fmt.Errorf("cipher produced short output")
	}
	return Encrypted{
		KeyVersion: k.active,
		Nonce:      nonce,
		Ciphertext: sealed[:len(sealed)-overhead],
		AuthTag:    sealed[len(sealed)-overhead:],
	}, nil
}

// EncryptString encrypts UTF-8 plaintext.
func (k *Keyring) EncryptString(value string, ctx Context) (Encrypted, error) {
	buf := []byte(value)
	defer zero(buf)
	return k.Encrypt(buf, ctx)
}

// Decrypt opens ciphertext. Wrong associated data or unknown key version fails closed.
func (k *Keyring) Decrypt(enc Encrypted, ctx Context) ([]byte, error) {
	gcm, err := k.gcm(enc.KeyVersion)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(enc.Ciphertext)+len(enc.AuthTag))
	sealed = append(sealed, enc.Ciphertext...)
	sealed = append(sealed, enc.AuthTag...)
	plain, err := gcm.Open(nil, enc.Nonce, sealed, associatedData(ctx))
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// DecryptString returns UTF-8 plaintext and zeros the temporary buffer.
func (k *Keyring) DecryptString(enc Encrypted, ctx Context) (string, error) {
	plain, err := k.Decrypt(enc, ctx)
	if err != nil {
		return "", err
	}
	out := string(plain)
	zero(plain)
	return out, nil
}

// Verify decrypts and discards plaintext.
func (k *Keyring) Verify(enc Encrypted, ctx Context) error {
	plain, err := k.Decrypt(enc, ctx)
	if err != nil {
		return err
	}
	zero(plain)
	return nil
}

// Reencrypt decrypts with the stored version and seals with the active version.
func (k *Keyring) Reencrypt(enc Encrypted, ctx Context) (Encrypted, error) {
	plain, err := k.Decrypt(enc, ctx)
	if err != nil {
		return Encrypted{}, err
	}
	defer zero(plain)
	return k.Encrypt(plain, ctx)
}

// AssertAvailableVersions fails closed if any stored ciphertext version is missing.
func (k *Keyring) AssertAvailableVersions(versions []int) error {
	for _, v := range versions {
		if _, ok := k.keys[v]; !ok {
			return fmt.Errorf("unknown secret key version %d", v)
		}
	}
	return nil
}

// Close zeros key material.
func (k *Keyring) Close() {
	for _, key := range k.keys {
		zero(key)
	}
	k.keys = map[int][]byte{}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
