package main

import (
	"path/filepath"
	"strings"
	"testing"
)

type testURI struct {
	path string
}

func (u testURI) String() string    { return "file://" + u.path }
func (u testURI) Extension() string { return filepath.Ext(u.path) }
func (u testURI) Name() string      { return filepath.Base(u.path) }
func (u testURI) MimeType() string  { return "application/octet-stream" }
func (u testURI) Scheme() string    { return "file" }
func (u testURI) Authority() string { return "" }
func (u testURI) Path() string      { return u.path }
func (u testURI) Query() string     { return "" }
func (u testURI) Fragment() string  { return "" }

func TestEncodeDecodeCSVRoundTrip(t *testing.T) {
	entries := []keyEntry{
		{
			ID:           "1",
			Alias:        "alice",
			KeyType:      ownerPrivate,
			KeyData:      b64("private"),
			Fingerprint:  "fp1",
			CreationDate: "2026-03-30T00:00:00Z",
		},
		{
			ID:           "2",
			Alias:        "bob",
			KeyType:      thirdParty,
			KeyData:      b64("public"),
			Fingerprint:  "fp2",
			CreationDate: "2026-03-30T00:00:00Z",
		},
	}

	encoded, err := encodeCSV(entries)
	if err != nil {
		t.Fatalf("encodeCSV failed: %v", err)
	}

	decoded, err := decodeCSV(encoded)
	if err != nil {
		t.Fatalf("decodeCSV failed: %v", err)
	}

	if len(decoded) != len(entries) {
		t.Fatalf("expected %d entries, got %d", len(entries), len(decoded))
	}
	for i := range entries {
		if decoded[i] != entries[i] {
			t.Fatalf("entry mismatch at index %d: got %+v want %+v", i, decoded[i], entries[i])
		}
	}
}

func TestSaveLoadVaultRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "vault.csv.enc")
	pass := []byte("correct horse battery staple")
	entries := []keyEntry{
		{
			ID:           "1",
			Alias:        "owner",
			KeyType:      ownerPublic,
			KeyData:      b64("pub"),
			Fingerprint:  "fp-owner",
			CreationDate: "2026-03-30T00:00:00Z",
		},
	}

	if err := saveVault(path, pass, entries); err != nil {
		t.Fatalf("saveVault failed: %v", err)
	}

	loaded, err := loadVault(path, pass)
	if err != nil {
		t.Fatalf("loadVault failed: %v", err)
	}
	if len(loaded) != len(entries) {
		t.Fatalf("expected %d entries, got %d", len(entries), len(loaded))
	}
	if loaded[0] != entries[0] {
		t.Fatalf("loaded entry mismatch: got %+v want %+v", loaded[0], entries[0])
	}
}

func TestLoadVaultWrongPassphrase(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "vault.csv.enc")
	entries := []keyEntry{{
		ID:           "1",
		Alias:        "owner",
		KeyType:      ownerPublic,
		KeyData:      b64("pub"),
		Fingerprint:  "fp-owner",
		CreationDate: "2026-03-30T00:00:00Z",
	}}

	if err := saveVault(path, []byte("correct passphrase"), entries); err != nil {
		t.Fatalf("saveVault failed: %v", err)
	}

	_, err := loadVault(path, []byte("wrong passphrase"))
	if err == nil {
		t.Fatalf("expected authentication failure error")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeDialogPathDriveLetterPath(t *testing.T) {
	raw := "/C:/Users/example/vault.csv.enc"
	got := normalizeDialogPath(testURI{path: raw})
	want := filepath.Clean(filepath.FromSlash("C:/Users/example/vault.csv.enc"))
	if got != want {
		t.Fatalf("normalizeDialogPath mismatch: got %q want %q", got, want)
	}
}

func TestNormalizeDialogPathUnixPath(t *testing.T) {
	raw := "/home/example/vault.csv.enc"
	got := normalizeDialogPath(testURI{path: raw})
	want := filepath.Clean(filepath.FromSlash(raw))
	if got != want {
		t.Fatalf("normalizeDialogPath mismatch: got %q want %q", got, want)
	}
}

func TestSignAndVerifyCleartextRoundTrip(t *testing.T) {
	priv, pub, _, err := generateOwnerKey("Tester", "tester@example.com")
	if err != nil {
		t.Fatalf("generateOwnerKey failed: %v", err)
	}

	msg := "hello signed world"
	signed, err := signCleartextMessage(msg, priv)
	if err != nil {
		t.Fatalf("signCleartextMessage failed: %v", err)
	}

	plain, sigStatus, err := verifyCleartextMessage(signed, pub)
	if err != nil {
		t.Fatalf("verifyCleartextMessage failed: %v", err)
	}
	if plain != msg {
		t.Fatalf("verified cleartext mismatch: got %q want %q", plain, msg)
	}
	if sigStatus != "Signature: OK" {
		t.Fatalf("unexpected signature status: %s", sigStatus)
	}
}
