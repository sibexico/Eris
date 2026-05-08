package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
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

func mustGenerateOwnerKey(t *testing.T, alias string) (priv, pub string) {
	t.Helper()
	email := strings.ToLower(strings.ReplaceAll(alias, " ", ".")) + "@example.com"
	priv, pub, _, err := generateOwnerKey(alias, email)
	if err != nil {
		t.Fatalf("generateOwnerKey(%q) failed: %v", alias, err)
	}
	return priv, pub
}

func sampleEntries() []keyEntry {
	return []keyEntry{
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
}

func TestEncodeDecodeCSVRoundTrip(t *testing.T) {
	entries := sampleEntries()

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
	priv, pub := mustGenerateOwnerKey(t, "Tester")

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

func TestEncryptDecryptAndVerifyRoundTrip(t *testing.T) {
	recipientPriv, recipientPub := mustGenerateOwnerKey(t, "Recipient")
	signerPriv, signerPub := mustGenerateOwnerKey(t, "Signer")

	plain := "confidential message"
	cipherText, err := encryptAndSign(plain, recipientPub, signerPriv)
	if err != nil {
		t.Fatalf("encryptAndSign failed: %v", err)
	}

	decrypted, sigStatus, err := decryptAndVerify(cipherText, recipientPriv, signerPub)
	if err != nil {
		t.Fatalf("decryptAndVerify failed: %v", err)
	}
	if decrypted != plain {
		t.Fatalf("decrypted mismatch: got %q want %q", decrypted, plain)
	}
	if sigStatus != "Signature: OK" {
		t.Fatalf("unexpected signature status: %s", sigStatus)
	}
}

func TestEncryptAndSignInvalidRecipientKey(t *testing.T) {
	signerPriv, _ := mustGenerateOwnerKey(t, "Signer Invalid Recipient")

	_, err := encryptAndSign("hello", "not-a-key", signerPriv)
	if err == nil {
		t.Fatalf("expected encryptAndSign error for invalid recipient key")
	}
}

func TestEncryptAndSignInvalidSignerKey(t *testing.T) {
	_, recipientPub := mustGenerateOwnerKey(t, "Recipient Invalid Signer")

	_, err := encryptAndSign("hello", recipientPub, "not-a-key")
	if err == nil {
		t.Fatalf("expected encryptAndSign error for invalid signer key")
	}
}

func TestLoadVaultMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.enc")
	_, err := loadVault(path, []byte("pass"))
	if err == nil {
		t.Fatalf("expected error for missing vault file")
	}
	if !strings.Contains(err.Error(), "vault file does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadVaultBadFormat(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "short.enc")
		if err := os.WriteFile(path, []byte("tiny"), 0o600); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		_, err := loadVault(path, []byte("pass"))
		if !errors.Is(err, errBadFormat) {
			t.Fatalf("expected errBadFormat, got %v", err)
		}
	})

	t.Run("bad magic header", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "badmagic.enc")
		blob := make([]byte, len(magicHeader)+saltSize+nonceSize+16)
		copy(blob, []byte("NOPE"))
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			t.Fatalf("os.WriteFile failed: %v", err)
		}

		_, err := loadVault(path, []byte("pass"))
		if !errors.Is(err, errBadFormat) {
			t.Fatalf("expected errBadFormat, got %v", err)
		}
	})
}

func TestDecodeCSVMalformedRowsReturnsError(t *testing.T) {
	data := []byte(strings.Join([]string{
		"ID,Alias,KeyType,KeyData,Fingerprint,CreationDate",
		"1,ok,OWNER_PUBLIC,a2V5,fp,2026-01-01T00:00:00Z",
		"bad,row,with,too,few",
	}, "\n"))

	_, err := decodeCSV(data)
	if err == nil {
		t.Fatalf("expected decodeCSV error for malformed record")
	}
}

func TestDecodeCSVHeaderOnly(t *testing.T) {
	entries, err := decodeCSV([]byte("ID,Alias,KeyType,KeyData,Fingerprint,CreationDate\n"))
	if err != nil {
		t.Fatalf("decodeCSV failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries for header-only CSV, got %d", len(entries))
	}
}

func TestSummariesAndHelpers(t *testing.T) {
	entries := []keyEntry{
		{Alias: "me", KeyType: ownerPublic, Fingerprint: "fp-me"},
		{Alias: "alice", KeyType: thirdParty, Fingerprint: "fp-alice"},
	}

	keys := summarizeKeys(entries)
	if !strings.Contains(keys, "me") || !strings.Contains(keys, "alice") {
		t.Fatalf("unexpected summarizeKeys output: %q", keys)
	}

	contacts := summarizeContacts(entries)
	if !strings.Contains(contacts, "alice") || strings.Contains(contacts, "me") {
		t.Fatalf("unexpected summarizeContacts output: %q", contacts)
	}

	if got := summarizeKeys(nil); got != "No keys saved yet" {
		t.Fatalf("unexpected empty summarizeKeys output: %q", got)
	}
	if got := summarizeContacts(nil); got != "No contact public keys saved" {
		t.Fatalf("unexpected empty summarizeContacts output: %q", got)
	}

	if got := sanitizedPassphrase("secret\n"); got != "secret" {
		t.Fatalf("unexpected sanitized passphrase: %q", got)
	}

	if !containsOption([]string{"a", "b"}, "b") {
		t.Fatalf("expected containsOption to find entry")
	}
	if containsOption([]string{"a", "b"}, "z") {
		t.Fatalf("expected containsOption to miss entry")
	}
}

func TestDeriveKeyAndEncodingHelpers(t *testing.T) {
	pass := []byte("pass")
	salt := []byte("1234567890abcdef")
	k1 := deriveKey(pass, salt)
	k2 := deriveKey(pass, salt)
	if len(k1) != 32 {
		t.Fatalf("unexpected key length: %d", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("deriveKey should be deterministic for same inputs")
	}

	u := newUUID()
	if ok, err := regexp.MatchString("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", u); err != nil || !ok {
		t.Fatalf("newUUID has unexpected format: %q", u)
	}

	if got := deb64(b64("hello")); got != "hello" {
		t.Fatalf("unexpected b64/deb64 round-trip result: %q", got)
	}
	if got := deb64("not-base64"); got != "" {
		t.Fatalf("expected empty result for invalid base64, got %q", got)
	}
}

func TestUIStateKeyHelpers(t *testing.T) {
	s := &uiState{
		entries: []keyEntry{
			{Alias: "owner1", KeyType: ownerPublic, KeyData: b64("owner1-public"), Fingerprint: "fp1"},
			{Alias: "owner1", KeyType: ownerPrivate, KeyData: b64("owner1-private"), Fingerprint: "fp1"},
			{Alias: "contact1", KeyType: thirdParty, KeyData: b64("contact1-public"), Fingerprint: "fp2"},
		},
	}

	if k := s.findKey("owner1", ownerPrivate); k == nil || deb64(k.KeyData) != "owner1-private" {
		t.Fatalf("findKey did not return expected owner private key")
	}
	if k := s.findKey("missing", ownerPrivate); k != nil {
		t.Fatalf("findKey should return nil for missing alias")
	}

	pairs := s.ownerPairs()
	if len(pairs) != 1 {
		t.Fatalf("expected 1 owner pair, got %d", len(pairs))
	}
	if pairs[0].Public != "owner1-public" || pairs[0].Private != "owner1-private" {
		t.Fatalf("unexpected owner pair values: %+v", pairs[0])
	}

	recipients := s.encryptOptionsRecipient()
	if len(recipients) != 2 || recipients[1] != "contact1" {
		t.Fatalf("unexpected recipient options: %#v", recipients)
	}

	signers := s.encryptOptionsSigner()
	if len(signers) != 2 || signers[1] != "owner1" {
		t.Fatalf("unexpected signer options: %#v", signers)
	}
}

func TestHandleCLIArgs(t *testing.T) {
	if !handleCLIArgs([]string{"eris", "--version"}) {
		t.Fatalf("expected --version to be handled")
	}
	if !handleCLIArgs([]string{"eris", "--help"}) {
		t.Fatalf("expected --help to be handled")
	}
	if handleCLIArgs([]string{"eris", "unknown"}) {
		t.Fatalf("did not expect unknown arg to be handled")
	}
	if handleCLIArgs([]string{"eris"}) {
		t.Fatalf("did not expect missing arg to be handled")
	}
}

func TestOpenCreateVaultValidationPaths(t *testing.T) {
	s := &uiState{statusLabel: widget.NewLabel("Ready")}

	s.vaultPathEntry = widget.NewEntry()
	s.passphraseEntry = widget.NewPasswordEntry()
	s.openVault()
	if got := s.statusLabel.Text; got != "Choose a vault file first" {
		t.Fatalf("unexpected status for empty open path: %q", got)
	}

	s.vaultPathEntry.SetText("vault.csv.enc")
	s.passphraseEntry.SetText("short")
	s.openVault()
	if got := s.statusLabel.Text; got != "Passphrase must be at least 8 characters" {
		t.Fatalf("unexpected status for short open passphrase: %q", got)
	}

	s.createPathEntry = widget.NewEntry()
	s.createPassEntry = widget.NewPasswordEntry()
	s.createPassAgainEntry = widget.NewPasswordEntry()
	s.createVault()
	if got := s.statusLabel.Text; got != "Choose where to save the vault" {
		t.Fatalf("unexpected status for empty create path: %q", got)
	}

	s.createPathEntry.SetText("new.enc")
	s.createPassEntry.SetText("short")
	s.createPassAgainEntry.SetText("short")
	s.createVault()
	if got := s.statusLabel.Text; got != "Passphrase must be at least 8 characters" {
		t.Fatalf("unexpected status for short create passphrase: %q", got)
	}

	s.createPassEntry.SetText("long-enough-pass")
	s.createPassAgainEntry.SetText("different-pass")
	s.createVault()
	if got := s.statusLabel.Text; got != "Passphrases do not match" {
		t.Fatalf("unexpected status for mismatched create passphrase: %q", got)
	}
}

func TestRefreshEncryptVisibilityAndMode(t *testing.T) {
	s := &uiState{}
	s.encryptRecipientSelect = widget.NewSelect([]string{"Enter the key", "Alice"}, nil)
	s.encryptSignerSelect = widget.NewSelect([]string{"Enter the key", "Me"}, nil)
	s.encryptRecipientEntry = widget.NewMultiLineEntry()
	s.encryptSignerEntry = widget.NewMultiLineEntry()
	s.encryptRecipientManual = widget.NewLabel("recipient manual")
	s.encryptSignerManual = widget.NewLabel("signer manual")
	s.encryptRecipientBox = container.NewVBox(s.encryptRecipientManual)
	s.encryptSignerBox = container.NewVBox(s.encryptSignerManual)

	s.encryptRecipientSelect.SetSelected("Enter the key")
	s.encryptSignerSelect.SetSelected("Me")
	s.refreshEncryptManualVisibility()
	if !s.encryptRecipientManual.Visible() {
		t.Fatalf("recipient manual input should be visible for Enter the key")
	}
	if s.encryptSignerManual.Visible() {
		t.Fatalf("signer manual input should be hidden for saved key")
	}

	s.encryptModeSep = widget.NewSeparator()
	s.encryptRecipientSep = widget.NewSeparator()
	s.encryptModeLabel = widget.NewLabel("")
	s.encryptModeToggleBtn = widget.NewButton("", nil)
	s.encryptActionBtn = widget.NewButton("", nil)
	s.encryptInputLabel = widget.NewLabel("")
	s.encryptOutputLabel = widget.NewLabel("")

	s.encryptModeSignOnly = false
	s.refreshEncryptActionMode()
	if s.encryptModeLabel.Text != "Mode: Encrypt" || s.encryptActionBtn.Text != "Encrypt message" {
		t.Fatalf("unexpected encrypt mode labels: %q / %q", s.encryptModeLabel.Text, s.encryptActionBtn.Text)
	}
	if !s.encryptRecipientBox.Visible() {
		t.Fatalf("recipient selector should be visible in encrypt mode")
	}

	s.encryptModeSignOnly = true
	s.refreshEncryptActionMode()
	if s.encryptModeLabel.Text != "Mode: Sign" || s.encryptActionBtn.Text != "Sign message" {
		t.Fatalf("unexpected sign mode labels: %q / %q", s.encryptModeLabel.Text, s.encryptActionBtn.Text)
	}
	if s.encryptRecipientBox.Visible() {
		t.Fatalf("recipient selector should be hidden in sign mode")
	}
}

func TestRefreshDecryptVisibilityAndMode(t *testing.T) {
	s := &uiState{}
	s.decryptKeySelect = widget.NewSelect([]string{"Enter the key", "Me"}, nil)
	s.verifyKeySelect = widget.NewSelect([]string{"Enter the key", "Alice"}, nil)
	s.decryptKeyEntry = widget.NewMultiLineEntry()
	s.verifyKeyEntry = widget.NewMultiLineEntry()
	s.decryptKeyManual = widget.NewLabel("decrypt manual")
	s.verifyKeyManual = widget.NewLabel("verify manual")
	s.decryptKeyBox = container.NewVBox(s.decryptKeyManual)
	s.verifyKeyBox = container.NewVBox(s.verifyKeyManual)

	s.decryptKeySelect.SetSelected("Me")
	s.verifyKeySelect.SetSelected("Enter the key")
	s.refreshDecryptManualVisibility()
	if s.decryptKeyManual.Visible() {
		t.Fatalf("decrypt manual input should be hidden for saved key")
	}
	if !s.verifyKeyManual.Visible() {
		t.Fatalf("verify manual input should be visible for Enter the key")
	}

	s.decryptModeLabel = widget.NewLabel("")
	s.decryptModeToggleBtn = widget.NewButton("", nil)
	s.decryptActionBtn = widget.NewButton("", nil)
	s.decryptInputLabel = widget.NewLabel("")
	s.decryptOutputLabel = widget.NewLabel("")
	s.decryptInputSep = widget.NewSeparator()
	s.decryptKeySep = widget.NewSeparator()
	s.cipherInputEntry = widget.NewMultiLineEntry()

	s.decryptModeVerifyOnly = false
	s.refreshDecryptActionMode()
	if s.decryptModeLabel.Text != "Mode: Decrypt" || s.decryptActionBtn.Text != "Decrypt message" {
		t.Fatalf("unexpected decrypt mode labels: %q / %q", s.decryptModeLabel.Text, s.decryptActionBtn.Text)
	}
	if !s.decryptKeyBox.Visible() {
		t.Fatalf("decrypt key selector should be visible in decrypt mode")
	}

	s.decryptModeVerifyOnly = true
	s.refreshDecryptActionMode()
	if s.decryptModeLabel.Text != "Mode: Verify" || s.decryptActionBtn.Text != "Verify message" {
		t.Fatalf("unexpected verify mode labels: %q / %q", s.decryptModeLabel.Text, s.decryptActionBtn.Text)
	}
	if s.decryptKeyBox.Visible() {
		t.Fatalf("decrypt key selector should be hidden in verify mode")
	}
	if got := s.cipherInputEntry.PlaceHolder; got != "Signed cleartext message" {
		t.Fatalf("unexpected verify placeholder: %q", got)
	}
}

func TestRefreshPairDetailsUIWithButtons(t *testing.T) {
	s := &uiState{pairDetailsBox: container.NewVBox()}
	showPub := widget.NewButton("Show public key", nil)
	copyPub := widget.NewButton("Copy", nil)
	showPriv := widget.NewButton("Show private key", nil)
	hidePriv := widget.NewButton("Hide private key", nil)

	s.refreshPairDetailsUIWithButtons(showPub, copyPub, showPriv, hidePriv)
	if len(s.pairDetailsBox.Objects) != 1 {
		t.Fatalf("expected single helper label when nothing selected")
	}

	s.pairs = []ownerPair{{Alias: "me", Fingerprint: "fp-me", Public: "PUB", Private: "PRIV"}}
	s.selectedPairIdx = 0
	s.pairAlias = widget.NewLabel("")
	s.pairFingerprint = widget.NewLabel("")
	s.pairPublic = widget.NewMultiLineEntry()
	s.pairPrivate = widget.NewMultiLineEntry()

	s.refreshPairDetailsUIWithButtons(showPub, copyPub, showPriv, hidePriv)
	if s.pairAlias.Text != "Alias: me" {
		t.Fatalf("unexpected alias label: %q", s.pairAlias.Text)
	}
	if s.pairPrivate.Text != "Private key hidden" {
		t.Fatalf("private key should be hidden by default")
	}

	s.showPublic = true
	s.showPrivate = true
	s.refreshPairDetailsUIWithButtons(showPub, copyPub, showPriv, hidePriv)
	if s.pairPrivate.Text != "PRIV" {
		t.Fatalf("expected visible private key content")
	}
}
