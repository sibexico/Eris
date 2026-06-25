package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"golang.org/x/crypto/argon2"
)

const (
	magicHeader = "PGPM"
	saltSize    = 16
	nonceSize   = 12
	manualKey   = "Enter the key"
)

var errBadFormat = errors.New("invalid vault format")

//go:embed icon.png
var iconPNG []byte

//go:embed VERSION
var appVersion string

var appIcon = fyne.NewStaticResource("icon.png", iconPNG)

//go:embed lang/*.json
var langFiles embed.FS

type localizer struct {
	mu       sync.RWMutex
	lang     string
	messages map[string]map[string]string
}

func newLocalizer() *localizer {
	l := &localizer{messages: make(map[string]map[string]string), lang: "en"}
	if entries, err := langFiles.ReadDir("lang"); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			b, readErr := langFiles.ReadFile("lang/" + e.Name())
			if readErr != nil {
				continue
			}
			m := make(map[string]string)
			if unmarshalErr := json.Unmarshal(b, &m); unmarshalErr != nil {
				continue
			}
			code := strings.TrimSuffix(strings.ToLower(e.Name()), ".json")
			l.messages[code] = m
		}
	}
	for _, candidate := range []string{os.Getenv("LC_ALL"), os.Getenv("LC_MESSAGES"), os.Getenv("LANG")} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		detected := normalizeLanguageCode(candidate)
		if _, ok := l.messages[detected]; ok {
			l.lang = detected
			break
		}
	}
	if _, ok := l.messages[l.lang]; !ok {
		l.lang = "en"
	}
	return l
}

func normalizeLanguageCode(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "en"
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "."); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "_"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "-"); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) < 2 {
		return "en"
	}
	return raw
}

func (l *localizer) Language() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lang
}

func (l *localizer) SetLanguage(code string) bool {
	code = normalizeLanguageCode(code)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.messages[code]; !ok {
		return false
	}
	l.lang = code
	return true
}

func (l *localizer) T(text string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if langMap, ok := l.messages[l.lang]; ok {
		if translated, ok := langMap[text]; ok && translated != "" {
			return translated
		}
	}
	if enMap, ok := l.messages["en"]; ok {
		if translated, ok := enMap[text]; ok && translated != "" {
			return translated
		}
	}
	return text
}

var appLocalizer = newLocalizer()

type keyType string

const (
	ownerPrivate keyType = "OWNER_PRIVATE"
	ownerPublic  keyType = "OWNER_PUBLIC"
	thirdParty   keyType = "THIRD_PARTY_PUBLIC"
)

type keyEntry struct {
	ID           string
	PairID       string
	Alias        string
	Email        string
	KeyType      keyType
	KeyData      string
	Fingerprint  string
	CreationDate string
}

type ownerPair struct {
	PairID      string
	PrivateID   string
	PublicID    string
	Alias       string
	Email       string
	Fingerprint string
	Public      string
	Private     string
}

type vaultSettings struct {
	Language string `json:"language"`
}

type vaultData struct {
	Version  int           `json:"version"`
	Settings vaultSettings `json:"settings"`
	Entries  []keyEntry    `json:"entries"`
}

func defaultVaultSettings() vaultSettings {
	lang := normalizeLanguageCode(appLocalizer.Language())
	if lang == "" {
		lang = "en"
	}
	if !appLocalizer.SetLanguage(lang) {
		lang = "en"
		_ = appLocalizer.SetLanguage(lang)
	}
	return vaultSettings{Language: lang}
}

func normalizeVaultSettings(in vaultSettings) (vaultSettings, bool) {
	out := in
	changed := false
	lang := normalizeLanguageCode(out.Language)
	if lang == "" {
		lang = "en"
		changed = true
	}
	if !appLocalizer.SetLanguage(lang) {
		lang = "en"
		changed = true
	}
	out.Language = lang
	_ = appLocalizer.SetLanguage(lang)
	return out, changed
}

type erisTheme struct{}

func (e erisTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x06, G: 0x0D, B: 0x08, A: 0xFF}
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 0x0D, G: 0x17, B: 0x11, A: 0xFF}
	case theme.ColorNameMenuBackground:
		return color.NRGBA{R: 0x0D, G: 0x17, B: 0x11, A: 0xFF}
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0x0D, G: 0x17, B: 0x11, A: 0xF2}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x13, G: 0x24, B: 0x19, A: 0xFF}
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0x46, G: 0x6E, B: 0x55, A: 0xFF}
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x1B, G: 0x39, B: 0x23, A: 0xFF}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x56, G: 0xC7, B: 0x76, A: 0xFF}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0xE2, G: 0xFD, B: 0xE9, A: 0xFF}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0xA6, G: 0xC8, B: 0xB3, A: 0xFF}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x94, G: 0xAB, B: 0x9D, A: 0xFF}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 0x2A, G: 0x34, B: 0x2C, A: 0xFF}
	case theme.ColorNameForegroundOnPrimary:
		return color.NRGBA{R: 0x05, G: 0x11, B: 0x0B, A: 0xFF}
	case theme.ColorNameForegroundOnSuccess:
		return color.NRGBA{R: 0x05, G: 0x11, B: 0x0B, A: 0xFF}
	case theme.ColorNameHyperlink:
		return color.NRGBA{R: 0x8D, G: 0xDE, B: 0xA5, A: 0xFF}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0x3A, G: 0x54, B: 0x43, A: 0xFF}
	default:
		return theme.DefaultTheme().Color(name, theme.VariantDark)
	}
}

func (e erisTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (e erisTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (e erisTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

type uiState struct {
	app fyne.App
	win fyne.Window

	status string

	vaultPath  string
	passphrase []byte
	entries    []keyEntry
	settings   vaultSettings

	vaultPathEntry       *widget.Entry
	passphraseEntry      *widget.Entry
	createPathEntry      *widget.Entry
	createPassEntry      *widget.Entry
	createPassAgainEntry *widget.Entry

	aliasEntry       *widget.Entry
	emailEntry       *widget.Entry
	importAliasEntry *widget.Entry
	importKeyEntry   *widget.Entry
	contactsList     *widget.List

	pairs           []ownerPair
	pairsList       *widget.List
	selectedPairIdx int
	pairDetailsBox  *fyne.Container
	pairAlias       *widget.Label
	pairFingerprint *widget.Label
	pairPublic      *widget.Entry
	pairPrivate     *widget.Entry
	showPublic      bool
	showPrivate     bool

	encryptRecipientSelect *widget.Select
	encryptSignerSelect    *widget.Select
	encryptRecipientEntry  *widget.Entry
	encryptSignerEntry     *widget.Entry
	plainEntry             *widget.Entry
	cipherEntry            *widget.Entry
	encryptRecipientBox    *fyne.Container
	encryptSignerBox       *fyne.Container

	decryptKeySelect *widget.Select
	verifyKeySelect  *widget.Select
	decryptKeyEntry  *widget.Entry
	verifyKeyEntry   *widget.Entry
	cipherInputEntry *widget.Entry
	plainOutputEntry *widget.Entry
	decryptKeyBox    *fyne.Container
	verifyKeyBox     *fyne.Container

	encryptRecipientManual fyne.CanvasObject
	encryptSignerManual    fyne.CanvasObject
	decryptKeyManual       fyne.CanvasObject
	verifyKeyManual        fyne.CanvasObject

	encryptModeSignOnly   bool
	decryptModeVerifyOnly bool
	encryptModeLabel      *widget.Label
	decryptModeLabel      *widget.Label
	encryptModeToggleBtn  *widget.Button
	decryptModeToggleBtn  *widget.Button
	encryptActionBtn      *widget.Button
	decryptActionBtn      *widget.Button
	encryptInputLabel     *widget.Label
	encryptOutputLabel    *widget.Label
	decryptInputLabel     *widget.Label
	decryptOutputLabel    *widget.Label
	encryptModeSep        *widget.Separator
	encryptRecipientSep   *widget.Separator
	decryptInputSep       *widget.Separator
	decryptKeySep         *widget.Separator

	statusLabel *widget.Label
	languageSel *widget.Select

	recipientOptionToID map[string]string
	signerOptionToID    map[string]string
}

func (s *uiState) tr(text string) string {
	return appLocalizer.T(text)
}

func (s *uiState) trf(text string, args ...any) string {
	return fmt.Sprintf(s.tr(text), args...)
}

func (s *uiState) localizeSignatureStatus(status string) string {
	if status == "Signature: OK" {
		return s.tr("Signature: OK")
	}
	const failPrefix = "Signature: FAILED ("
	if strings.HasPrefix(status, failPrefix) && strings.HasSuffix(status, ")") {
		reason := strings.TrimSuffix(strings.TrimPrefix(status, failPrefix), ")")
		return s.trf("Signature: FAILED (%s)", reason)
	}
	return s.tr(status)
}

func main() {
	if handleCLIArgs(os.Args) {
		return
	}

	hardeningWarning := ""
	if err := hardenProcess(); err != nil {
		hardeningWarning = "Process hardening warning: " + err.Error()
	}

	a := app.NewWithID("eris.pgp.manager")
	a.Settings().SetTheme(erisTheme{})
	a.SetIcon(appIcon)
	w := a.NewWindow("Eris - PGP Workstation")
	w.SetIcon(appIcon)
	w.Resize(fyne.NewSize(760, 520))

	s := newUIState(a, w)
	if hardeningWarning != "" {
		s.setStatus(hardeningWarning)
	}
	s.showStartup()

	w.ShowAndRun()
}

func handleCLIArgs(args []string) bool {
	if len(args) < 2 {
		return false
	}

	switch args[1] {
	case "--version", "-version", "version", "-v":
		fmt.Println(strings.TrimSpace(appVersion))
		return true
	case "--help", "-h", "help":
		fmt.Println("Eris PGP Workstation")
		fmt.Println("Usage:")
		fmt.Println("  eris --version   Print app version")
		fmt.Println("  eris --help      Show this help")
		return true
	default:
		return false
	}
}

func newUIState(a fyne.App, w fyne.Window) *uiState {
	s := &uiState{
		app:                 a,
		win:                 w,
		settings:            defaultVaultSettings(),
		recipientOptionToID: make(map[string]string),
		signerOptionToID:    make(map[string]string),
	}

	s.vaultPathEntry = widget.NewEntry()
	s.vaultPathEntry.SetPlaceHolder(s.tr("Vault file path"))

	s.passphraseEntry = widget.NewPasswordEntry()
	s.passphraseEntry.SetPlaceHolder(s.tr("Passphrase"))
	s.passphraseEntry.OnSubmitted = func(string) { s.openVault() }

	s.createPathEntry = widget.NewEntry()
	s.createPathEntry.SetPlaceHolder(s.tr("New vault path"))

	s.createPassEntry = widget.NewPasswordEntry()
	s.createPassEntry.SetPlaceHolder(s.tr("Passphrase"))
	s.createPassEntry.OnSubmitted = func(string) { s.createVault() }

	s.createPassAgainEntry = widget.NewPasswordEntry()
	s.createPassAgainEntry.SetPlaceHolder(s.tr("Repeat passphrase"))
	s.createPassAgainEntry.OnSubmitted = func(string) { s.createVault() }

	s.aliasEntry = widget.NewEntry()
	s.aliasEntry.SetPlaceHolder(s.tr("Your name"))
	s.emailEntry = widget.NewEntry()
	s.emailEntry.SetPlaceHolder("your@email")

	s.importAliasEntry = widget.NewEntry()
	s.importAliasEntry.SetPlaceHolder(s.tr("Contact name"))
	s.importKeyEntry = widget.NewMultiLineEntry()
	s.importKeyEntry.SetMinRowsVisible(5)
	s.importKeyEntry.SetPlaceHolder(s.tr("Contact public key"))

	s.pairAlias = widget.NewLabel(s.tr("No key pair selected"))
	s.pairFingerprint = widget.NewLabel("")
	s.pairPublic = widget.NewMultiLineEntry()
	s.pairPublic.Disable()
	s.pairPublic.SetMinRowsVisible(5)

	s.pairPrivate = widget.NewMultiLineEntry()
	s.pairPrivate.Disable()
	s.pairPrivate.SetMinRowsVisible(5)
	s.pairPrivate.SetText(s.tr("Private key hidden"))

	s.encryptRecipientEntry = widget.NewMultiLineEntry()
	s.encryptRecipientEntry.SetMinRowsVisible(5)
	s.encryptRecipientEntry.SetPlaceHolder(s.tr("Recipient public key"))

	s.encryptSignerEntry = widget.NewMultiLineEntry()
	s.encryptSignerEntry.SetMinRowsVisible(5)
	s.encryptSignerEntry.SetPlaceHolder(s.tr("Your private key"))

	s.plainEntry = widget.NewMultiLineEntry()
	s.plainEntry.SetMinRowsVisible(5)
	s.plainEntry.SetPlaceHolder(s.tr("Message to encrypt"))

	s.cipherEntry = widget.NewMultiLineEntry()
	s.cipherEntry.Disable()
	s.cipherEntry.SetMinRowsVisible(5)

	s.cipherInputEntry = widget.NewMultiLineEntry()
	s.cipherInputEntry.SetMinRowsVisible(5)
	s.cipherInputEntry.SetPlaceHolder(s.tr("Encrypted message"))

	s.decryptKeyEntry = widget.NewMultiLineEntry()
	s.decryptKeyEntry.SetMinRowsVisible(5)
	s.decryptKeyEntry.SetPlaceHolder(s.tr("Your private key"))

	s.verifyKeyEntry = widget.NewMultiLineEntry()
	s.verifyKeyEntry.SetMinRowsVisible(5)
	s.verifyKeyEntry.SetPlaceHolder(s.tr("Sender public key"))

	s.plainOutputEntry = widget.NewMultiLineEntry()
	s.plainOutputEntry.Disable()
	s.plainOutputEntry.SetMinRowsVisible(5)

	s.statusLabel = widget.NewLabel(s.tr("Ready"))

	s.encryptRecipientSelect = widget.NewSelect([]string{manualKey}, func(_ string) { s.refreshEncryptManualVisibility() })
	s.encryptRecipientSelect.SetSelected(manualKey)

	s.encryptSignerSelect = widget.NewSelect([]string{manualKey}, func(_ string) { s.refreshEncryptManualVisibility() })
	s.encryptSignerSelect.SetSelected(manualKey)

	s.decryptKeySelect = widget.NewSelect([]string{manualKey}, func(_ string) { s.refreshDecryptManualVisibility() })
	s.decryptKeySelect.SetSelected(manualKey)

	s.verifyKeySelect = widget.NewSelect([]string{manualKey}, func(_ string) { s.refreshDecryptManualVisibility() })
	s.verifyKeySelect.SetSelected(manualKey)

	s.encryptRecipientManual = s.multilineField(s.encryptRecipientEntry)
	s.encryptSignerManual = s.multilineField(s.encryptSignerEntry)
	s.decryptKeyManual = s.multilineField(s.decryptKeyEntry)
	s.verifyKeyManual = s.multilineField(s.verifyKeyEntry)

	s.encryptRecipientBox = container.NewVBox(widget.NewLabel(s.tr("Recipient key source")), s.encryptRecipientSelect, s.encryptRecipientManual)
	s.encryptSignerBox = container.NewVBox(widget.NewLabel(s.tr("Signer key source")), s.encryptSignerSelect, s.encryptSignerManual)
	s.decryptKeyBox = container.NewVBox(widget.NewLabel(s.tr("Decrypt key source")), s.decryptKeySelect, s.decryptKeyManual)
	s.verifyKeyBox = container.NewVBox(widget.NewLabel(s.tr("Verify key source")), s.verifyKeySelect, s.verifyKeyManual)

	s.pairsList = widget.NewList(
		func() int { return len(s.pairs) },
		func() fyne.CanvasObject {
			lbl := widget.NewLabel("template")
			btn := widget.NewButton(s.tr("Remove"), nil)
			return container.NewHBox(lbl, layout.NewSpacer(), btn)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			row := o.(*fyne.Container)
			lbl := row.Objects[0].(*widget.Label)
			btn := row.Objects[2].(*widget.Button)
			if i < 0 || i >= len(s.pairs) {
				lbl.SetText("")
				btn.OnTapped = nil
				return
			}
			btn.SetText(s.tr("Remove"))
			email := strings.TrimSpace(s.pairs[i].Email)
			if email == "" {
				email = "-"
			}
			lbl.SetText(fmt.Sprintf("%s | %s | %s", s.pairs[i].Alias, email, s.pairs[i].Fingerprint))
			idx := i
			btn.OnTapped = func() {
				s.removeOwnerPairAt(idx)
			}
		},
	)
	s.pairsList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(s.pairs) {
			return
		}
		s.selectedPairIdx = id
		s.showPublic = false
		s.showPrivate = false
		s.refreshPairDetailsUI()
	}

	s.contactsList = widget.NewList(
		func() int { return len(s.contactEntries()) },
		func() fyne.CanvasObject {
			lbl := widget.NewLabel("template")
			btn := widget.NewButton(s.tr("Remove"), nil)
			return container.NewHBox(lbl, layout.NewSpacer(), btn)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			rows := s.contactEntries()
			row := o.(*fyne.Container)
			lbl := row.Objects[0].(*widget.Label)
			btn := row.Objects[2].(*widget.Button)
			if i < 0 || i >= len(rows) {
				lbl.SetText("")
				btn.OnTapped = nil
				return
			}
			btn.SetText(s.tr("Remove"))
			entry := rows[i]
			lbl.SetText(fmt.Sprintf("%s | %s", entry.Alias, entry.Fingerprint))
			id := entry.ID
			btn.OnTapped = func() {
				s.removeContactByID(id)
			}
		},
	)

	s.refreshKeyDependentViews()
	s.refreshEncryptActionMode()
	s.refreshDecryptActionMode()
	s.applyTranslations()
	return s
}

func (s *uiState) setStatus(msg string) {
	s.status = msg
	if s.statusLabel != nil {
		s.statusLabel.SetText(msg)
	}
}

func (s *uiState) applyTranslations() {
	if s.vaultPathEntry != nil {
		s.vaultPathEntry.SetPlaceHolder(s.tr("Vault file path"))
	}
	if s.passphraseEntry != nil {
		s.passphraseEntry.SetPlaceHolder(s.tr("Passphrase"))
	}
	if s.createPathEntry != nil {
		s.createPathEntry.SetPlaceHolder(s.tr("New vault path"))
	}
	if s.createPassEntry != nil {
		s.createPassEntry.SetPlaceHolder(s.tr("Passphrase"))
	}
	if s.createPassAgainEntry != nil {
		s.createPassAgainEntry.SetPlaceHolder(s.tr("Repeat passphrase"))
	}
	if s.aliasEntry != nil {
		s.aliasEntry.SetPlaceHolder(s.tr("Your name"))
	}
	if s.importAliasEntry != nil {
		s.importAliasEntry.SetPlaceHolder(s.tr("Contact name"))
	}
	if s.importKeyEntry != nil {
		s.importKeyEntry.SetPlaceHolder(s.tr("Contact public key"))
	}
	if s.encryptRecipientEntry != nil {
		s.encryptRecipientEntry.SetPlaceHolder(s.tr("Recipient public key"))
	}
	if s.encryptSignerEntry != nil {
		s.encryptSignerEntry.SetPlaceHolder(s.tr("Your private key"))
	}
	if s.plainEntry != nil {
		s.plainEntry.SetPlaceHolder(s.tr("Message to encrypt"))
	}
	if s.decryptKeyEntry != nil {
		s.decryptKeyEntry.SetPlaceHolder(s.tr("Your private key"))
	}
	if s.verifyKeyEntry != nil {
		s.verifyKeyEntry.SetPlaceHolder(s.tr("Sender public key"))
	}

	if s.encryptRecipientBox != nil {
		s.encryptRecipientBox.Objects = []fyne.CanvasObject{widget.NewLabel(s.tr("Recipient key source")), s.encryptRecipientSelect, s.encryptRecipientManual}
		s.encryptRecipientBox.Refresh()
	}
	if s.encryptSignerBox != nil {
		s.encryptSignerBox.Objects = []fyne.CanvasObject{widget.NewLabel(s.tr("Signer key source")), s.encryptSignerSelect, s.encryptSignerManual}
		s.encryptSignerBox.Refresh()
	}
	if s.decryptKeyBox != nil {
		s.decryptKeyBox.Objects = []fyne.CanvasObject{widget.NewLabel(s.tr("Decrypt key source")), s.decryptKeySelect, s.decryptKeyManual}
		s.decryptKeyBox.Refresh()
	}
	if s.verifyKeyBox != nil {
		s.verifyKeyBox.Objects = []fyne.CanvasObject{widget.NewLabel(s.tr("Verify key source")), s.verifyKeySelect, s.verifyKeyManual}
		s.verifyKeyBox.Refresh()
	}

	s.refreshEncryptActionMode()
	s.refreshDecryptActionMode()
	s.refreshPairDetailsUI()
}

func (s *uiState) wrapWithStatus(content fyne.CanvasObject) fyne.CanvasObject {
	statusBar := container.NewHBox(
		widget.NewLabel(s.tr("Status:")),
		s.statusLabel,
	)
	return container.NewBorder(nil, container.NewPadded(statusBar), nil, nil, content)
}

func (s *uiState) showStartup() {
	openCard := widget.NewCard(s.tr("Open your vault"), s.tr("Pick your file and unlock with passphrase."), container.NewVBox(
		widget.NewLabel(s.tr("Vault file")),
		s.vaultPathEntry,
		container.NewHBox(
			widget.NewButton(s.tr("Select vault file..."), func() { s.pickOpenVaultPath(s.vaultPathEntry) }),
			layout.NewSpacer(),
		),
		widget.NewLabel(s.tr("Passphrase")),
		s.passphraseEntry,
		widget.NewButton(s.tr("Open vault"), s.openVault),
	))

	createCard := widget.NewCard(s.tr("Create a new vault"), s.tr("Set a save path and passphrase."), container.NewVBox(
		widget.NewLabel(s.tr("New vault path")),
		s.createPathEntry,
		container.NewHBox(
			widget.NewButton(s.tr("Choose save location..."), func() { s.pickSaveVaultPath(s.createPathEntry) }),
			layout.NewSpacer(),
		),
		widget.NewLabel(s.tr("Passphrase")),
		s.createPassEntry,
		widget.NewLabel(s.tr("Repeat passphrase")),
		s.createPassAgainEntry,
		widget.NewButton(s.tr("Create vault"), s.createVault),
	))

	tabs := container.NewAppTabs(
		container.NewTabItem(s.tr("Open vault"), container.NewVScroll(s.centerBlock(openCard))),
		container.NewTabItem(s.tr("Create vault"), container.NewVScroll(s.centerBlock(createCard))),
	)
	s.win.SetContent(s.wrapWithStatus(tabs))
}

func (s *uiState) showMainUI() {
	myKeysTab := container.NewTabItem(s.tr("My Keys"), s.buildMyKeysTab())
	keysTab := container.NewTabItem(s.tr("Keys"), s.buildKeysTab())
	encryptTab := container.NewTabItem(s.tr("Encrypt & Sign"), s.buildEncryptTab())
	decryptTab := container.NewTabItem(s.tr("Decrypt & Verify"), s.buildDecryptTab())
	settingsTab := container.NewTabItem(s.tr("Settings"), s.buildSettingsTab())

	tabs := container.NewAppTabs(myKeysTab, keysTab, encryptTab, decryptTab, settingsTab)
	s.win.SetContent(s.wrapWithStatus(tabs))
	s.win.Canvas().Focus(s.aliasEntry)
}

func (s *uiState) buildSettingsTab() fyne.CanvasObject {
	languageLabel := widget.NewLabel(s.tr("Language"))
	s.languageSel = widget.NewSelect([]string{s.tr("English"), s.tr("Spanish")}, func(selected string) {
		code := "en"
		if selected == s.tr("Spanish") {
			code = "es"
		}
		if code == appLocalizer.Language() {
			return
		}
		if appLocalizer.SetLanguage(code) {
			s.settings.Language = code
			s.saveVaultNow()
			s.applyTranslations()
			s.showMainUI()
			s.setStatus(s.tr("Language changed"))
		}
	})
	if appLocalizer.Language() == "es" {
		s.languageSel.SetSelected(s.tr("Spanish"))
	} else {
		s.languageSel.SetSelected(s.tr("English"))
	}

	content := container.NewVBox(
		s.centerBlock(widget.NewCard(s.tr("Vault settings"), s.tr("Switch vault file or rotate the vault passphrase."), container.NewVBox(
			languageLabel,
			s.languageSel,
			widget.NewSeparator(),
			container.NewHBox(
				widget.NewButton(s.tr("Change vault"), s.changeVault),
				layout.NewSpacer(),
			),
			container.NewHBox(
				widget.NewButton(s.tr("Change passphrase"), s.promptChangePassphrase),
				layout.NewSpacer(),
			),
		))),
	)
	return container.NewVScroll(content)
}

func (s *uiState) buildKeysTab() fyne.CanvasObject {
	importForm := widget.NewCard(s.tr("Add contact public key"), s.tr("Store only third-party public keys here."), container.NewVBox(
		widget.NewLabel(s.tr("Contact name")),
		s.importAliasEntry,
		widget.NewLabel(s.tr("Contact public key")),
		s.multilineField(s.importKeyEntry),
		widget.NewButton(s.tr("Add contact public key"), s.addThirdPartyKey),
	))

	content := container.NewVBox(
		s.centerBlock(importForm),
		s.centerBlock(widget.NewCard(s.tr("Saved contacts"), s.tr("Select a row and use Remove for deletion."), s.contactsList)),
	)
	return container.NewVScroll(content)
}

func (s *uiState) buildMyKeysTab() fyne.CanvasObject {
	createForm := widget.NewCard(s.tr("Create my key pair"), s.tr("Generate your own private/public key pair."), container.NewVBox(
		widget.NewLabel(s.tr("Your name")),
		s.aliasEntry,
		widget.NewLabel(s.tr("Your email")),
		s.emailEntry,
		widget.NewButton(s.tr("Generate key pair"), s.generateOwnerKeyPair),
	))

	showPublicBtn := widget.NewButton(s.tr("Show public key"), func() {
		s.showPublic = true
		s.refreshPairDetailsUI()
	})
	copyPublicBtn := widget.NewButton(s.tr("Copy"), func() {
		if s.selectedPairIdx < 0 || s.selectedPairIdx >= len(s.pairs) {
			return
		}
		s.app.Clipboard().SetContent(s.pairs[s.selectedPairIdx].Public)
		s.setStatus(s.tr("Public key copied"))
	})

	revealBtn := widget.NewButton(s.tr("Show private key"), func() {
		s.showPrivate = true
		s.refreshPairDetailsUI()
	})
	hideBtn := widget.NewButton(s.tr("Hide private key"), func() {
		s.showPrivate = false
		s.refreshPairDetailsUI()
	})

	s.pairDetailsBox = container.NewVBox(
		widget.NewLabel(s.tr("Select a key from the list to view details.")),
	)
	detailsCard := widget.NewCard(s.tr("Selected key pair"), s.tr("Public and private key fields appear only when requested."), s.pairDetailsBox)
	s.refreshPairDetailsUIWithButtons(showPublicBtn, copyPublicBtn, revealBtn, hideBtn)

	listHeight := float32(240)
	listSpacer := canvas.NewRectangle(color.Transparent)
	listSpacer.SetMinSize(fyne.NewSize(0, listHeight))
	myKeysListView := container.NewStack(listSpacer, s.pairsList)

	content := container.NewVBox(
		s.centerBlock(createForm),
		s.centerBlock(widget.NewCard(s.tr("My key pairs"), s.tr("Select a row and use Remove for deletion."), myKeysListView)),
		s.centerBlock(detailsCard),
	)
	return container.NewVScroll(content)
}

func (s *uiState) buildEncryptTab() fyne.CanvasObject {
	s.encryptActionBtn = widget.NewButton(s.tr("Encrypt message"), s.encryptMessage)
	s.encryptModeLabel = widget.NewLabel("")
	s.encryptModeToggleBtn = widget.NewButton("", func() {
		s.encryptModeSignOnly = !s.encryptModeSignOnly
		s.refreshEncryptActionMode()
	})
	s.encryptInputLabel = widget.NewLabel(s.tr("Message to encrypt"))
	s.encryptOutputLabel = widget.NewLabel(s.tr("Encrypted output"))
	s.encryptModeSep = widget.NewSeparator()
	s.encryptRecipientSep = widget.NewSeparator()

	copyBtn := widget.NewButton(s.tr("Copy encrypted message"), func() {
		if strings.TrimSpace(s.cipherEntry.Text) == "" {
			s.setStatus(s.tr("Nothing to copy"))
			return
		}
		s.app.Clipboard().SetContent(s.cipherEntry.Text)
		s.setStatus(s.tr("Output copied"))
	})

	content := container.NewVBox(
		s.centerBlock(widget.NewCard(s.tr("Encrypt and sign"), s.tr("Use the mode switch button to move between encrypt and sign workflows."), container.NewVBox(
			container.NewHBox(s.encryptModeLabel, layout.NewSpacer(), s.encryptModeToggleBtn),
			s.encryptModeSep,
			s.encryptRecipientBox,
			s.encryptRecipientSep,
			s.encryptSignerBox,
			widget.NewSeparator(),
			s.encryptInputLabel,
			s.multilineField(s.plainEntry),
			s.encryptActionBtn,
			s.encryptOutputLabel,
			s.multilineField(s.cipherEntry),
			copyBtn,
		))),
	)
	s.refreshEncryptActionMode()
	return container.NewVScroll(content)
}

func (s *uiState) buildDecryptTab() fyne.CanvasObject {
	s.decryptActionBtn = widget.NewButton(s.tr("Decrypt message"), s.decryptMessage)
	s.decryptModeLabel = widget.NewLabel("")
	s.decryptModeToggleBtn = widget.NewButton("", func() {
		s.decryptModeVerifyOnly = !s.decryptModeVerifyOnly
		s.refreshDecryptActionMode()
	})
	s.decryptInputLabel = widget.NewLabel(s.tr("Encrypted message"))
	s.decryptOutputLabel = widget.NewLabel(s.tr("Plain output"))
	s.decryptInputSep = widget.NewSeparator()
	s.decryptKeySep = widget.NewSeparator()

	copyBtn := widget.NewButton(s.tr("Copy plain message"), func() {
		if strings.TrimSpace(s.plainOutputEntry.Text) == "" {
			s.setStatus(s.tr("Nothing to copy"))
			return
		}
		s.app.Clipboard().SetContent(s.plainOutputEntry.Text)
		s.setStatus(s.tr("Plain message copied"))
	})

	content := container.NewVBox(
		s.centerBlock(widget.NewCard(s.tr("Decrypt and verify"), s.tr("Use the mode switch button to move between decrypt and verify workflows."), container.NewVBox(
			container.NewHBox(s.decryptModeLabel, layout.NewSpacer(), s.decryptModeToggleBtn),
			widget.NewSeparator(),
			s.decryptInputLabel,
			s.multilineField(s.cipherInputEntry),
			s.decryptInputSep,
			s.decryptKeyBox,
			s.decryptKeySep,
			s.verifyKeyBox,
			s.decryptActionBtn,
			s.decryptOutputLabel,
			s.multilineField(s.plainOutputEntry),
			copyBtn,
		))),
	)
	s.refreshDecryptActionMode()
	return container.NewVScroll(content)
}

func (s *uiState) multilineField(ed *widget.Entry) fyne.CanvasObject {
	height := float32(140)
	spacer := canvas.NewRectangle(color.Transparent)
	spacer.SetMinSize(fyne.NewSize(0, height))
	scroll := container.NewVScroll(ed)
	box := container.NewStack(spacer, scroll)
	return box
}

func (s *uiState) centerBlock(obj fyne.CanvasObject) fyne.CanvasObject {
	width := s.win.Canvas().Size().Width * 0.8
	if width <= 0 {
		width = 600
	}
	spacer := canvas.NewRectangle(color.Transparent)
	spacer.SetMinSize(fyne.NewSize(width, obj.MinSize().Height))
	host := container.NewStack(spacer, obj)
	return container.NewHBox(layout.NewSpacer(), host, layout.NewSpacer())
}

func (s *uiState) refreshEncryptManualVisibility() {
	if s.encryptRecipientSelect == nil || s.encryptSignerSelect == nil || s.encryptRecipientEntry == nil || s.encryptSignerEntry == nil {
		return
	}
	if s.encryptRecipientManual != nil {
		if s.encryptRecipientSelect.Selected == manualKey {
			s.encryptRecipientManual.Show()
		} else {
			s.encryptRecipientManual.Hide()
		}
	}
	if s.encryptSignerManual != nil {
		if s.encryptSignerSelect.Selected == manualKey {
			s.encryptSignerManual.Show()
		} else {
			s.encryptSignerManual.Hide()
		}
	}
	if s.encryptRecipientBox != nil {
		s.encryptRecipientBox.Refresh()
	}
	if s.encryptSignerBox != nil {
		s.encryptSignerBox.Refresh()
	}
}

func (s *uiState) refreshEncryptActionMode() {
	if s.encryptRecipientBox != nil {
		if s.encryptModeSignOnly {
			s.encryptRecipientBox.Hide()
		} else {
			s.encryptRecipientBox.Show()
		}
		s.encryptRecipientBox.Refresh()
	}
	if s.encryptModeSep != nil {
		if s.encryptModeSignOnly {
			s.encryptModeSep.Hide()
		} else {
			s.encryptModeSep.Show()
		}
		s.encryptModeSep.Refresh()
	}
	if s.encryptRecipientSep != nil {
		s.encryptRecipientSep.Show()
		s.encryptRecipientSep.Refresh()
	}
	if s.encryptModeLabel != nil {
		if s.encryptModeSignOnly {
			s.encryptModeLabel.SetText(s.tr("Mode: Sign"))
		} else {
			s.encryptModeLabel.SetText(s.tr("Mode: Encrypt"))
		}
	}
	if s.encryptModeToggleBtn != nil {
		if s.encryptModeSignOnly {
			s.encryptModeToggleBtn.SetText(s.tr("Switch to encrypt mode"))
		} else {
			s.encryptModeToggleBtn.SetText(s.tr("Switch to sign mode"))
		}
	}
	if s.encryptActionBtn != nil {
		if s.encryptModeSignOnly {
			s.encryptActionBtn.SetText(s.tr("Sign message"))
		} else {
			s.encryptActionBtn.SetText(s.tr("Encrypt message"))
		}
	}
	if s.encryptInputLabel != nil {
		if s.encryptModeSignOnly {
			s.encryptInputLabel.SetText(s.tr("Message to sign"))
		} else {
			s.encryptInputLabel.SetText(s.tr("Message to encrypt"))
		}
	}
	if s.encryptOutputLabel != nil {
		if s.encryptModeSignOnly {
			s.encryptOutputLabel.SetText(s.tr("Signed output"))
		} else {
			s.encryptOutputLabel.SetText(s.tr("Encrypted output"))
		}
	}
	if s.encryptModeLabel != nil {
		s.encryptModeLabel.Refresh()
	}
	if s.encryptModeToggleBtn != nil {
		s.encryptModeToggleBtn.Refresh()
	}
	if s.encryptActionBtn != nil {
		s.encryptActionBtn.Refresh()
	}
	if s.encryptInputLabel != nil {
		s.encryptInputLabel.Refresh()
	}
	if s.encryptOutputLabel != nil {
		s.encryptOutputLabel.Refresh()
	}
	if s.encryptSignerBox != nil {
		s.encryptSignerBox.Refresh()
	}
}

func (s *uiState) refreshDecryptManualVisibility() {
	if s.decryptKeySelect == nil || s.verifyKeySelect == nil || s.decryptKeyEntry == nil || s.verifyKeyEntry == nil {
		return
	}
	if s.decryptKeyManual != nil {
		if s.decryptKeySelect.Selected == manualKey {
			s.decryptKeyManual.Show()
		} else {
			s.decryptKeyManual.Hide()
		}
	}
	if s.verifyKeyManual != nil {
		if s.verifyKeySelect.Selected == manualKey {
			s.verifyKeyManual.Show()
		} else {
			s.verifyKeyManual.Hide()
		}
	}
	if s.decryptKeyBox != nil {
		s.decryptKeyBox.Refresh()
	}
	if s.verifyKeyBox != nil {
		s.verifyKeyBox.Refresh()
	}
}

func (s *uiState) refreshDecryptActionMode() {
	if s.decryptKeyBox != nil {
		if s.decryptModeVerifyOnly {
			s.decryptKeyBox.Hide()
		} else {
			s.decryptKeyBox.Show()
		}
		s.decryptKeyBox.Refresh()
	}
	if s.decryptInputSep != nil {
		if s.decryptModeVerifyOnly {
			s.decryptInputSep.Hide()
		} else {
			s.decryptInputSep.Show()
		}
		s.decryptInputSep.Refresh()
	}
	if s.decryptKeySep != nil {
		s.decryptKeySep.Show()
		s.decryptKeySep.Refresh()
	}
	if s.decryptModeLabel != nil {
		if s.decryptModeVerifyOnly {
			s.decryptModeLabel.SetText(s.tr("Mode: Verify"))
		} else {
			s.decryptModeLabel.SetText(s.tr("Mode: Decrypt"))
		}
	}
	if s.decryptModeToggleBtn != nil {
		if s.decryptModeVerifyOnly {
			s.decryptModeToggleBtn.SetText(s.tr("Switch to decrypt mode"))
		} else {
			s.decryptModeToggleBtn.SetText(s.tr("Switch to verify mode"))
		}
	}
	if s.decryptActionBtn != nil {
		if s.decryptModeVerifyOnly {
			s.decryptActionBtn.SetText(s.tr("Verify message"))
		} else {
			s.decryptActionBtn.SetText(s.tr("Decrypt message"))
		}
	}
	if s.decryptInputLabel != nil {
		if s.decryptModeVerifyOnly {
			s.decryptInputLabel.SetText(s.tr("Signed message"))
			s.cipherInputEntry.SetPlaceHolder(s.tr("Signed cleartext message"))
		} else {
			s.decryptInputLabel.SetText(s.tr("Encrypted message"))
			s.cipherInputEntry.SetPlaceHolder(s.tr("Encrypted message"))
		}
	}
	if s.decryptOutputLabel != nil {
		if s.decryptModeVerifyOnly {
			s.decryptOutputLabel.SetText(s.tr("Verified output"))
		} else {
			s.decryptOutputLabel.SetText(s.tr("Plain output"))
		}
	}
	if s.decryptModeLabel != nil {
		s.decryptModeLabel.Refresh()
	}
	if s.decryptModeToggleBtn != nil {
		s.decryptModeToggleBtn.Refresh()
	}
	if s.decryptActionBtn != nil {
		s.decryptActionBtn.Refresh()
	}
	if s.decryptInputLabel != nil {
		s.decryptInputLabel.Refresh()
	}
	if s.decryptOutputLabel != nil {
		s.decryptOutputLabel.Refresh()
	}
	if s.verifyKeyBox != nil {
		s.verifyKeyBox.Refresh()
	}
	if s.cipherInputEntry != nil {
		s.cipherInputEntry.Refresh()
	}
}

func (s *uiState) refreshPairDetailsUI() {
	if s.pairDetailsBox == nil {
		return
	}
	s.refreshPairDetailsUIWithButtons(
		widget.NewButton(s.tr("Show public key"), func() {
			s.showPublic = true
			s.refreshPairDetailsUI()
		}),
		widget.NewButton(s.tr("Copy"), func() {
			if s.selectedPairIdx < 0 || s.selectedPairIdx >= len(s.pairs) {
				return
			}
			s.app.Clipboard().SetContent(s.pairs[s.selectedPairIdx].Public)
			s.setStatus(s.tr("Public key copied"))
		}),
		widget.NewButton(s.tr("Show private key"), func() {
			s.showPrivate = true
			s.refreshPairDetailsUI()
		}),
		widget.NewButton(s.tr("Hide private key"), func() {
			s.showPrivate = false
			s.refreshPairDetailsUI()
		}),
	)
}

func (s *uiState) refreshPairDetailsUIWithButtons(showPublicBtn, copyPublicBtn, showPrivateBtn, hidePrivateBtn *widget.Button) {
	if s.pairDetailsBox == nil {
		return
	}
	if s.selectedPairIdx < 0 || s.selectedPairIdx >= len(s.pairs) {
		s.pairDetailsBox.Objects = []fyne.CanvasObject{widget.NewLabel(s.tr("Select a key from the list to view details."))}
		s.pairDetailsBox.Refresh()
		return
	}

	pair := s.pairs[s.selectedPairIdx]
	s.pairAlias.SetText(s.tr("Alias: ") + pair.Alias)
	s.pairFingerprint.SetText(s.tr("Fingerprint: ") + pair.Fingerprint)
	s.pairPublic.SetText(pair.Public)
	if s.showPrivate {
		s.pairPrivate.SetText(pair.Private)
	} else {
		s.pairPrivate.SetText(s.tr("Private key hidden"))
	}

	copyFingerprintBtn := widget.NewButton(s.tr("Copy fingerprint"), func() {
		s.app.Clipboard().SetContent(pair.Fingerprint)
		s.setStatus(s.tr("Fingerprint copied"))
	})

	objs := []fyne.CanvasObject{s.pairAlias, container.NewHBox(s.pairFingerprint, copyFingerprintBtn)}
	if s.showPublic {
		objs = append(objs,
			container.NewHBox(widget.NewLabel(s.tr("Public key")), showPublicBtn, copyPublicBtn),
			s.multilineField(s.pairPublic),
		)
	} else {
		objs = append(objs, container.NewHBox(widget.NewLabel(s.tr("Public key")), showPublicBtn))
	}
	objs = append(objs,
		container.NewHBox(showPrivateBtn, hidePrivateBtn),
	)
	if s.showPrivate {
		objs = append(objs,
			widget.NewLabel(s.tr("Private key")),
			s.multilineField(s.pairPrivate),
		)
	}

	s.pairDetailsBox.Objects = objs
	s.pairDetailsBox.Refresh()
}

func (s *uiState) openVault() {
	path := strings.TrimSpace(s.vaultPathEntry.Text)
	if path == "" {
		s.setStatus(s.tr("Choose a vault file first"))
		return
	}
	pass := []byte(sanitizedPassphrase(s.passphraseEntry.Text))
	if len(pass) < 8 {
		s.setStatus(s.tr("Passphrase must be at least 8 characters"))
		zeroBytes(pass)
		return
	}
	entries, settings, migrated, err := loadVault(path, pass)
	if err != nil {
		s.setStatus(s.trf("Unlock failed: %s", err.Error()))
		zeroBytes(pass)
		return
	}
	settings, _ = normalizeVaultSettings(settings)
	_ = appLocalizer.SetLanguage(settings.Language)
	s.settings = settings
	s.applyTranslations()
	s.entries = entries
	s.vaultPath = path
	if len(s.passphrase) > 0 {
		zeroBytes(s.passphrase)
	}
	s.passphrase = pass
	if migrated {
		if err := saveVault(path, pass, entries, s.settings); err != nil {
			s.setStatus(s.trf("Auto-save failed: %s", err.Error()))
			return
		}
	}
	s.refreshKeyDependentViews()
	s.setStatus(s.tr("Vault unlocked"))
	s.showMainUI()
}

func (s *uiState) createVault() {
	path := strings.TrimSpace(s.createPathEntry.Text)
	if path == "" {
		s.setStatus(s.tr("Choose where to save the vault"))
		return
	}
	p1 := sanitizedPassphrase(s.createPassEntry.Text)
	p2 := sanitizedPassphrase(s.createPassAgainEntry.Text)
	if len(p1) < 8 {
		s.setStatus(s.tr("Passphrase must be at least 8 characters"))
		return
	}
	if p1 != p2 {
		s.setStatus(s.tr("Passphrases do not match"))
		return
	}
	pass := []byte(p1)
	settings := defaultVaultSettings()
	if err := saveVault(path, pass, nil, settings); err != nil {
		s.setStatus(s.trf("Create failed: %s", err.Error()))
		zeroBytes(pass)
		return
	}
	s.entries = nil
	s.settings = settings
	s.vaultPath = path
	if len(s.passphrase) > 0 {
		zeroBytes(s.passphrase)
	}
	s.passphrase = pass
	_ = appLocalizer.SetLanguage(settings.Language)
	s.applyTranslations()
	s.refreshKeyDependentViews()
	s.setStatus(s.tr("Created new vault"))
	s.showMainUI()
}

func (s *uiState) saveVaultNow() {
	if s.vaultPath == "" || len(s.passphrase) == 0 {
		return
	}
	if err := saveVault(s.vaultPath, s.passphrase, s.entries, s.settings); err != nil {
		s.setStatus(s.trf("Auto-save failed: %s", err.Error()))
	}
}

func (s *uiState) changeVault() {
	s.showStartup()
	if s.vaultPath != "" {
		s.vaultPathEntry.SetText(s.vaultPath)
	}
	s.passphraseEntry.SetText("")
	s.setStatus(s.tr("Pick the new vault and open it"))
}

func (s *uiState) promptChangePassphrase() {
	if s.vaultPath == "" || len(s.passphrase) == 0 {
		s.setStatus(s.tr("Open a vault before changing passphrase"))
		return
	}

	oldPassEntry := widget.NewPasswordEntry()
	oldPassEntry.SetPlaceHolder(s.tr("Current passphrase"))

	newPassEntry := widget.NewPasswordEntry()
	newPassEntry.SetPlaceHolder(s.tr("New passphrase"))

	newPassAgainEntry := widget.NewPasswordEntry()
	newPassAgainEntry.SetPlaceHolder(s.tr("Repeat new passphrase"))

	var dlg *dialog.FormDialog
	applyChange := func() bool {
		oldPass := []byte(sanitizedPassphrase(oldPassEntry.Text))
		defer zeroBytes(oldPass)
		if subtle.ConstantTimeCompare(oldPass, s.passphrase) != 1 {
			s.setStatus(s.tr("Current passphrase is incorrect"))
			return false
		}

		newPassphrase := sanitizedPassphrase(newPassEntry.Text)
		newPassphraseAgain := sanitizedPassphrase(newPassAgainEntry.Text)
		if len(newPassphrase) < 8 {
			s.setStatus(s.tr("Passphrase must be at least 8 characters"))
			return false
		}
		if newPassphrase != newPassphraseAgain {
			s.setStatus(s.tr("New passphrases do not match"))
			return false
		}

		newPass := []byte(newPassphrase)
		if err := saveVault(s.vaultPath, newPass, s.entries, s.settings); err != nil {
			s.setStatus(s.trf("Passphrase update failed: %s", err.Error()))
			zeroBytes(newPass)
			return false
		}

		if len(s.passphrase) > 0 {
			zeroBytes(s.passphrase)
		}
		s.passphrase = newPass
		s.setStatus(s.tr("Vault passphrase changed"))
		return true
	}

	newPassAgainEntry.OnSubmitted = func(string) {
		if applyChange() && dlg != nil {
			dlg.Hide()
		}
	}

	dlg = dialog.NewForm(
		s.tr("Change vault passphrase"),
		s.tr("Change"),
		s.tr("Cancel"),
		[]*widget.FormItem{
			widget.NewFormItem(s.tr("Current passphrase"), oldPassEntry),
			widget.NewFormItem(s.tr("New passphrase"), newPassEntry),
			widget.NewFormItem(s.tr("Repeat new passphrase"), newPassAgainEntry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			applyChange()
		},
		s.win,
	)
	dlg.Resize(fyne.NewSize(520, 0))
	dlg.Show()
}

func (s *uiState) generateOwnerKeyPair() {
	alias := strings.TrimSpace(s.aliasEntry.Text)
	email := strings.TrimSpace(s.emailEntry.Text)
	if alias == "" || email == "" {
		s.setStatus(s.tr("Please provide name and email"))
		return
	}
	priv, pub, fp, err := generateOwnerKey(alias, email)
	if err != nil {
		s.setStatus(s.trf("Could not generate key: %s", err.Error()))
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	pairID := newUUID()
	s.entries = append(s.entries,
		keyEntry{ID: newUUID(), PairID: pairID, Alias: alias, Email: email, KeyType: ownerPrivate, KeyData: b64(priv), Fingerprint: fp, CreationDate: now},
		keyEntry{ID: newUUID(), PairID: pairID, Alias: alias, Email: email, KeyType: ownerPublic, KeyData: b64(pub), Fingerprint: fp, CreationDate: now},
	)
	s.saveVaultNow()
	s.aliasEntry.SetText("")
	s.emailEntry.SetText("")
	s.refreshKeyDependentViews()
	s.setStatus(s.tr("Key pair generated"))
}

func (s *uiState) addThirdPartyKey() {
	alias := strings.TrimSpace(s.importAliasEntry.Text)
	armored := strings.TrimSpace(s.importKeyEntry.Text)
	if alias == "" || armored == "" {
		s.setStatus(s.tr("Please provide name and public key"))
		return
	}
	k, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		s.setStatus(s.trf("Public key is invalid: %s", err.Error()))
		return
	}
	s.entries = append(s.entries, keyEntry{
		ID:           newUUID(),
		Alias:        alias,
		KeyType:      thirdParty,
		KeyData:      b64(armored),
		Fingerprint:  k.GetFingerprint(),
		CreationDate: time.Now().UTC().Format(time.RFC3339),
	})
	s.saveVaultNow()
	s.importAliasEntry.SetText("")
	s.importKeyEntry.SetText("")
	s.refreshKeyDependentViews()
	s.setStatus(s.tr("Public key added"))
}

func (s *uiState) encryptMessage() {
	signerPriv := ""
	if s.encryptModeSignOnly {
		if s.encryptSignerSelect.Selected == manualKey {
			signerPriv = strings.TrimSpace(s.encryptSignerEntry.Text)
		} else {
			signer := s.findKeyByOption(s.encryptSignerSelect.Selected, ownerPrivate)
			if signer != nil {
				signerPriv = deb64(signer.KeyData)
			}
		}

		if signerPriv == "" {
			s.setStatus(s.tr("Please choose a signer key or enter one manually"))
			return
		}
		signedText, err := signCleartextMessage(s.plainEntry.Text, signerPriv)
		if err != nil {
			s.setStatus(s.trf("Sign failed: %s", err.Error()))
			return
		}
		s.cipherEntry.SetText(signedText)
		s.setStatus(s.tr("Message signed (cleartext)"))
		return
	}

	recipientPub := ""

	if s.encryptRecipientSelect.Selected == manualKey {
		recipientPub = strings.TrimSpace(s.encryptRecipientEntry.Text)
	} else {
		rec := s.findKeyByOption(s.encryptRecipientSelect.Selected, thirdParty)
		if rec != nil {
			recipientPub = deb64(rec.KeyData)
		}
	}

	if s.encryptSignerSelect.Selected == manualKey {
		signerPriv = strings.TrimSpace(s.encryptSignerEntry.Text)
	} else {
		signer := s.findKeyByOption(s.encryptSignerSelect.Selected, ownerPrivate)
		if signer != nil {
			signerPriv = deb64(signer.KeyData)
		}
	}

	if recipientPub == "" || signerPriv == "" {
		s.setStatus(s.tr("Please choose keys or enter keys manually"))
		return
	}
	cipherText, err := encryptAndSign(s.plainEntry.Text, recipientPub, signerPriv)
	if err != nil {
		s.setStatus(s.trf("Encrypt/sign failed: %s", err.Error()))
		return
	}
	s.cipherEntry.SetText(cipherText)
	s.setStatus(s.tr("Message encrypted"))
}

func (s *uiState) decryptMessage() {
	cipherText := s.cipherInputEntry.Text
	if strings.TrimSpace(cipherText) == "" {
		s.setStatus(s.tr("Input message is required"))
		return
	}

	pub := ""
	if s.verifyKeySelect.Selected == manualKey {
		pub = strings.TrimSpace(s.verifyKeyEntry.Text)
	} else {
		ver := s.findKeyByOption(s.verifyKeySelect.Selected, thirdParty)
		if ver != nil {
			pub = deb64(ver.KeyData)
		}
	}

	if s.decryptModeVerifyOnly {
		if pub == "" {
			s.setStatus(s.tr("Please choose sender public key or enter one manually"))
			return
		}
		plain, sigStatus, err := verifyCleartextMessage(cipherText, pub)
		if err != nil {
			s.setStatus(s.trf("Verify failed: %s", err.Error()))
			return
		}
		s.plainOutputEntry.SetText(plain)
		s.setStatus(s.localizeSignatureStatus(sigStatus))
		return
	}

	priv := ""

	if s.decryptKeySelect.Selected == manualKey {
		priv = strings.TrimSpace(s.decryptKeyEntry.Text)
	} else {
		dec := s.findKeyByOption(s.decryptKeySelect.Selected, ownerPrivate)
		if dec != nil {
			priv = deb64(dec.KeyData)
		}
	}

	if priv == "" || pub == "" {
		s.setStatus(s.tr("Please choose keys or enter keys manually"))
		return
	}

	plain, sigStatus, err := decryptAndVerify(cipherText, priv, pub)
	if err != nil {
		s.setStatus(s.trf("Decrypt failed: %s", err.Error()))
		return
	}
	s.plainOutputEntry.SetText(plain)
	s.setStatus(s.localizeSignatureStatus(sigStatus))
}

func (s *uiState) refreshKeyDependentViews() {
	s.pairs = s.ownerPairs()
	if s.pairsList != nil {
		s.pairsList.Refresh()
	}
	if s.contactsList != nil {
		s.contactsList.Refresh()
	}

	recipientOptions, recipientOptionToID := s.encryptOptionsRecipient()
	signerOptions, signerOptionToID := s.encryptOptionsSigner()
	s.recipientOptionToID = recipientOptionToID
	s.signerOptionToID = signerOptionToID

	s.encryptRecipientSelect.SetOptions(recipientOptions)
	s.encryptSignerSelect.SetOptions(signerOptions)
	s.decryptKeySelect.SetOptions(signerOptions)
	s.verifyKeySelect.SetOptions(recipientOptions)

	if !containsOption(recipientOptions, s.encryptRecipientSelect.Selected) {
		s.encryptRecipientSelect.SetSelected(manualKey)
	}
	if !containsOption(signerOptions, s.encryptSignerSelect.Selected) {
		s.encryptSignerSelect.SetSelected(manualKey)
	}
	if !containsOption(signerOptions, s.decryptKeySelect.Selected) {
		s.decryptKeySelect.SetSelected(manualKey)
	}
	if !containsOption(recipientOptions, s.verifyKeySelect.Selected) {
		s.verifyKeySelect.SetSelected(manualKey)
	}

	s.refreshEncryptManualVisibility()
	s.refreshDecryptManualVisibility()

	if len(s.pairs) == 0 {
		s.selectedPairIdx = -1
		s.showPublic = false
		s.showPrivate = false
		s.pairAlias.SetText(s.tr("No key pair selected"))
		s.pairFingerprint.SetText("")
		s.pairPublic.SetText("")
		s.pairPrivate.SetText(s.tr("Private key hidden"))
		s.refreshPairDetailsUI()
		return
	}
	if s.selectedPairIdx < 0 || s.selectedPairIdx >= len(s.pairs) {
		s.selectedPairIdx = 0
	}
	s.refreshPairDetailsUI()
}

func (s *uiState) contactEntries() []keyEntry {
	rows := make([]keyEntry, 0)
	for _, e := range s.entries {
		if e.KeyType == thirdParty {
			rows = append(rows, e)
		}
	}
	return rows
}

func (s *uiState) removeContactByID(id string) {
	filtered := make([]keyEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.ID == id {
			continue
		}
		filtered = append(filtered, e)
	}
	s.entries = filtered
	s.saveVaultNow()
	s.refreshKeyDependentViews()
	s.setStatus(s.tr("Contact key removed"))
}

func (s *uiState) removeOwnerPairAt(i int) {
	if i < 0 || i >= len(s.pairs) {
		return
	}
	p := s.pairs[i]
	filtered := make([]keyEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.ID == p.PrivateID || e.ID == p.PublicID {
			continue
		}
		filtered = append(filtered, e)
	}
	s.entries = filtered
	if s.selectedPairIdx == i {
		s.selectedPairIdx = -1
		s.showPublic = false
		s.showPrivate = false
	}
	s.saveVaultNow()
	s.refreshKeyDependentViews()
	s.setStatus(s.tr("Key pair removed"))
}

func (s *uiState) pickOpenVaultPath(target *widget.Entry) {
	dlg := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil {
			s.setStatus(s.trf("File picker error: %s", err.Error()))
			return
		}
		if rc == nil {
			return
		}
		defer rc.Close()
		target.SetText(normalizeDialogPath(rc.URI()))
		s.setStatus(s.tr("Selected vault file"))
	}, s.win)
	dlg.SetFilter(storage.NewExtensionFileFilter([]string{".enc", ".vault", ".csv"}))
	dlg.Show()
}

func (s *uiState) pickSaveVaultPath(target *widget.Entry) {
	dlg := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil {
			s.setStatus(s.trf("File picker error: %s", err.Error()))
			return
		}
		if wc == nil {
			return
		}
		defer wc.Close()
		target.SetText(normalizeDialogPath(wc.URI()))
		s.setStatus(s.tr("Selected new vault path"))
	}, s.win)
	dlg.SetFileName("vault.csv.enc")
	dlg.Show()
}

func normalizeDialogPath(uri fyne.URI) string {
	if uri == nil {
		return ""
	}
	p := uri.Path()
	if len(p) >= 3 && (p[0] == '/' || p[0] == '\\') && p[2] == ':' {
		drive := p[1]
		if (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z') {
			p = p[1:]
		}
	}
	return filepath.Clean(filepath.FromSlash(p))
}

func containsOption(options []string, want string) bool {
	for _, v := range options {
		if v == want {
			return true
		}
	}
	return false
}

func (s *uiState) findKeyByID(id string, t keyType) *keyEntry {
	for i := range s.entries {
		if s.entries[i].ID == id && s.entries[i].KeyType == t {
			return &s.entries[i]
		}
	}
	return nil
}

func (s *uiState) findKeyByOption(option string, t keyType) *keyEntry {
	if option == manualKey {
		return nil
	}
	id := ""
	if t == thirdParty {
		id = s.recipientOptionToID[option]
	} else {
		id = s.signerOptionToID[option]
	}
	if id == "" {
		return nil
	}
	return s.findKeyByID(id, t)
}

func (s *uiState) ownerPairs() []ownerPair {
	pairByID := make(map[string]ownerPair)
	ordered := make([]string, 0)

	for _, e := range s.entries {
		if e.KeyType != ownerPrivate {
			continue
		}
		pairID := strings.TrimSpace(e.PairID)
		if pairID == "" {
			pairID = e.ID
		}
		pair, exists := pairByID[pairID]
		if !exists {
			ordered = append(ordered, pairID)
		}
		pair.PairID = pairID
		pair.PrivateID = e.ID
		pair.Alias = e.Alias
		pair.Email = e.Email
		pair.Fingerprint = e.Fingerprint
		pair.Private = deb64(e.KeyData)
		pairByID[pairID] = pair
	}

	for _, e := range s.entries {
		if e.KeyType != ownerPublic {
			continue
		}
		pairID := strings.TrimSpace(e.PairID)
		if pairID == "" {
			pairID = e.ID
		}
		pair, exists := pairByID[pairID]
		if !exists {
			ordered = append(ordered, pairID)
		}
		if pair.Alias == "" {
			pair.Alias = e.Alias
		}
		if pair.Email == "" {
			pair.Email = e.Email
		}
		if pair.Fingerprint == "" {
			pair.Fingerprint = e.Fingerprint
		}
		pair.PairID = pairID
		pair.PublicID = e.ID
		pair.Public = deb64(e.KeyData)
		pairByID[pairID] = pair
	}

	pairs := make([]ownerPair, 0, len(ordered))
	for _, pairID := range ordered {
		pair := pairByID[pairID]
		if pair.PrivateID == "" {
			continue
		}
		pairs = append(pairs, pair)
	}
	return pairs
}

func (s *uiState) encryptOptionsRecipient() ([]string, map[string]string) {
	opts := []string{manualKey}
	optionToID := make(map[string]string)
	for _, e := range s.entries {
		if e.KeyType == thirdParty {
			opt := fmt.Sprintf("%s | %s | #%s", e.Alias, e.Fingerprint, e.ID)
			opts = append(opts, opt)
			optionToID[opt] = e.ID
		}
	}
	return opts, optionToID
}

func (s *uiState) encryptOptionsSigner() ([]string, map[string]string) {
	opts := []string{manualKey}
	optionToID := make(map[string]string)
	for _, e := range s.entries {
		if e.KeyType == ownerPrivate {
			email := strings.TrimSpace(e.Email)
			if email == "" {
				email = "-"
			}
			opt := fmt.Sprintf("%s | %s | %s | #%s", e.Alias, email, e.Fingerprint, e.ID)
			opts = append(opts, opt)
			optionToID[opt] = e.ID
		}
	}
	return opts, optionToID
}

func summarizeKeys(entries []keyEntry) string {
	if len(entries) == 0 {
		return "No keys saved yet"
	}
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "- %s | %s | %s | %s\n", e.Alias, e.Email, e.KeyType, e.Fingerprint)
	}
	return b.String()
}

func summarizeContacts(entries []keyEntry) string {
	var b strings.Builder
	for _, e := range entries {
		if e.KeyType != thirdParty {
			continue
		}
		fmt.Fprintf(&b, "- %s | %s\n", e.Alias, e.Fingerprint)
	}
	if b.Len() == 0 {
		return "No contact public keys saved"
	}
	return b.String()
}

func sanitizedPassphrase(s string) string {
	return strings.TrimRight(s, "\r\n")
}

func generateOwnerKey(alias, email string) (string, string, string, error) {
	var (
		priv string
		pub  string
		fp   string
		err  error
	)
	withSecret(func() {
		pgp := crypto.PGP()
		builder := pgp.KeyGeneration().AddUserId(alias, email)
		k, genErr := builder.New().GenerateKey()
		if genErr != nil {
			err = genErr
			return
		}
		priv, err = k.Armor()
		if err != nil {
			return
		}
		pk, toPubErr := k.ToPublic()
		if toPubErr != nil {
			err = toPubErr
			return
		}
		pub, err = pk.Armor()
		if err != nil {
			return
		}
		fp = k.GetFingerprint()
	})
	return priv, pub, fp, err
}

func encryptAndSign(plain, recipientPubArmored, signerPrivArmored string) (string, error) {
	var (
		out string
		err error
	)
	withSecret(func() {
		rec, recErr := crypto.NewKeyFromArmored(recipientPubArmored)
		if recErr != nil {
			err = recErr
			return
		}
		signer, signErr := crypto.NewKeyFromArmored(signerPrivArmored)
		if signErr != nil {
			err = signErr
			return
		}
		h, newErr := crypto.PGP().Encryption().Recipient(rec).SigningKey(signer).New()
		if newErr != nil {
			err = newErr
			return
		}
		msg, encErr := h.Encrypt([]byte(plain))
		if encErr != nil {
			err = encErr
			return
		}
		out, err = msg.Armor()
		h.ClearPrivateParams()
	})
	return out, err
}

func decryptAndVerify(cipherText, decryptPrivArmored, verifyPubArmored string) (string, string, error) {
	var (
		plain     string
		sigStatus string
		err       error
	)
	withSecret(func() {
		decKey, decErr := crypto.NewKeyFromArmored(decryptPrivArmored)
		if decErr != nil {
			err = decErr
			return
		}
		verKey, verErr := crypto.NewKeyFromArmored(verifyPubArmored)
		if verErr != nil {
			err = verErr
			return
		}
		h, newErr := crypto.PGP().Decryption().DecryptionKey(decKey).VerificationKey(verKey).New()
		if newErr != nil {
			err = newErr
			return
		}
		res, decMsgErr := h.Decrypt([]byte(cipherText), crypto.Armor)
		if decMsgErr != nil {
			err = decMsgErr
			return
		}
		plain = string(res.Bytes())
		if serr := res.SignatureError(); serr != nil {
			sigStatus = "Signature: FAILED (" + serr.Error() + ")"
		} else {
			sigStatus = "Signature: OK"
		}
		h.ClearPrivateParams()
	})
	return plain, sigStatus, err
}

func signCleartextMessage(plain, signerPrivArmored string) (string, error) {
	var (
		out string
		err error
	)
	withSecret(func() {
		signer, signErr := crypto.NewKeyFromArmored(signerPrivArmored)
		if signErr != nil {
			err = signErr
			return
		}
		h, newErr := crypto.PGP().Sign().SigningKey(signer).New()
		if newErr != nil {
			err = newErr
			return
		}
		signed, signMsgErr := h.SignCleartext([]byte(plain))
		if signMsgErr != nil {
			err = signMsgErr
			return
		}
		out = string(signed)
		h.ClearPrivateParams()
	})
	return out, err
}

func verifyCleartextMessage(signedText, verifyPubArmored string) (string, string, error) {
	var (
		plain     string
		sigStatus string
		err       error
	)
	withSecret(func() {
		verKey, verErr := crypto.NewKeyFromArmored(verifyPubArmored)
		if verErr != nil {
			err = verErr
			return
		}
		h, newErr := crypto.PGP().Verify().VerificationKey(verKey).New()
		if newErr != nil {
			err = newErr
			return
		}
		res, verifyErr := h.VerifyCleartext([]byte(signedText))
		if verifyErr != nil {
			err = verifyErr
			return
		}
		plain = string(res.Cleartext())
		if serr := res.SignatureError(); serr != nil {
			sigStatus = "Signature: FAILED (" + serr.Error() + ")"
		} else {
			sigStatus = "Signature: OK"
		}
	})
	return plain, sigStatus, err
}

func saveVault(path string, passphrase []byte, entries []keyEntry, settings vaultSettings) error {
	data, err := encodeVaultPayload(entries, settings)
	if err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	k := deriveKey(passphrase, salt)
	defer zeroBytes(k)

	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	blob := append([]byte(magicHeader), salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	zeroBytes(data)
	return nil
}

func loadVault(path string, passphrase []byte) ([]keyEntry, vaultSettings, bool, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, vaultSettings{}, false, fmt.Errorf("vault file does not exist")
		}
		return nil, vaultSettings{}, false, err
	}
	if len(blob) < len(magicHeader)+saltSize+nonceSize+16 {
		return nil, vaultSettings{}, false, errBadFormat
	}
	if string(blob[:len(magicHeader)]) != magicHeader {
		return nil, vaultSettings{}, false, errBadFormat
	}
	salt := blob[len(magicHeader) : len(magicHeader)+saltSize]
	nonce := blob[len(magicHeader)+saltSize : len(magicHeader)+saltSize+nonceSize]
	ciphertext := blob[len(magicHeader)+saltSize+nonceSize:]

	k := deriveKey(passphrase, salt)
	defer zeroBytes(k)

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, vaultSettings{}, false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, vaultSettings{}, false, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, vaultSettings{}, false, fmt.Errorf("authentication failed")
	}
	entries, settings, migrated, err := decodeVaultPayload(plain)
	zeroBytes(plain)
	if err != nil {
		return nil, vaultSettings{}, false, err
	}
	return entries, settings, migrated, nil
}

func encodeVaultPayload(entries []keyEntry, settings vaultSettings) ([]byte, error) {
	settings, _ = normalizeVaultSettings(settings)
	entries, _ = normalizeEntries(entries)
	payload := vaultData{
		Version:  2,
		Settings: settings,
		Entries:  entries,
	}
	return json.Marshal(payload)
}

func decodeVaultPayload(data []byte) ([]keyEntry, vaultSettings, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var payload vaultData
		if err := json.Unmarshal(trimmed, &payload); err != nil {
			return nil, vaultSettings{}, false, err
		}
		settings, changed := normalizeVaultSettings(payload.Settings)
		entries := payload.Entries
		if entries == nil {
			entries = []keyEntry{}
		}
		normalizedEntries, entriesChanged := normalizeEntries(entries)
		return normalizedEntries, settings, changed || entriesChanged, nil
	}

	entries, err := decodeCSV(data)
	if err != nil {
		return nil, vaultSettings{}, false, err
	}
	normalizedEntries, _ := normalizeEntries(entries)
	settings := defaultVaultSettings()
	return normalizedEntries, settings, true, nil
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 1, 32)
}

func encodeCSV(entries []keyEntry) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"ID", "PairID", "Alias", "Email", "KeyType", "KeyData", "Fingerprint", "CreationDate"}); err != nil {
		return nil, err
	}
	for _, e := range entries {
		if err := w.Write([]string{e.ID, e.PairID, e.Alias, e.Email, string(e.KeyType), e.KeyData, e.Fingerprint, e.CreationDate}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decodeCSV(data []byte) ([]keyEntry, error) {
	r := csv.NewReader(bytes.NewReader(data))
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	var entries []keyEntry
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) != 6 && len(row) != 8 {
			continue
		}
		if len(row) == 6 {
			entries = append(entries, keyEntry{
				ID:           row[0],
				Alias:        row[1],
				KeyType:      keyType(row[2]),
				KeyData:      row[3],
				Fingerprint:  row[4],
				CreationDate: row[5],
			})
			continue
		}
		entries = append(entries, keyEntry{
			ID:           row[0],
			PairID:       row[1],
			Alias:        row[2],
			Email:        row[3],
			KeyType:      keyType(row[4]),
			KeyData:      row[5],
			Fingerprint:  row[6],
			CreationDate: row[7],
		})
	}
	return entries, nil
}

func normalizeEntries(entries []keyEntry) ([]keyEntry, bool) {
	if entries == nil {
		return []keyEntry{}, true
	}

	out := make([]keyEntry, len(entries))
	copy(out, entries)
	changed := false

	seenIDs := make(map[string]struct{})
	for i := range out {
		id := strings.TrimSpace(out[i].ID)
		if id == "" {
			id = newUUID()
			changed = true
		}
		for {
			if _, exists := seenIDs[id]; !exists {
				break
			}
			id = newUUID()
			changed = true
		}
		out[i].ID = id
		seenIDs[id] = struct{}{}
	}

	type ownerKey struct {
		alias string
		email string
		fp    string
	}
	ownerKeyOf := func(e keyEntry) ownerKey {
		return ownerKey{alias: e.Alias, email: e.Email, fp: e.Fingerprint}
	}

	pubQueues := make(map[ownerKey][]int)
	for i := range out {
		if out[i].KeyType != ownerPublic {
			continue
		}
		k := ownerKeyOf(out[i])
		pubQueues[k] = append(pubQueues[k], i)
	}

	for i := range out {
		if out[i].KeyType != ownerPrivate {
			continue
		}
		pairID := strings.TrimSpace(out[i].PairID)
		if pairID == "" {
			pairID = out[i].ID
			out[i].PairID = pairID
			changed = true
		}

		k := ownerKeyOf(out[i])
		queue := pubQueues[k]
		for len(queue) > 0 {
			pubIdx := queue[0]
			queue = queue[1:]
			if strings.TrimSpace(out[pubIdx].PairID) == "" {
				out[pubIdx].PairID = pairID
				changed = true
				break
			}
		}
		pubQueues[k] = queue
	}

	for i := range out {
		if out[i].KeyType == ownerPrivate || out[i].KeyType == ownerPublic {
			if strings.TrimSpace(out[i].PairID) == "" {
				out[i].PairID = out[i].ID
				changed = true
			}
		}
	}

	return out, changed
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80
	hexStr := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func deb64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
