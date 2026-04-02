package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
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
)

var errBadFormat = errors.New("invalid vault format")

//go:embed icon.png
var iconPNG []byte

var appIcon = fyne.NewStaticResource("icon.png", iconPNG)

type keyType string

const (
	ownerPrivate keyType = "OWNER_PRIVATE"
	ownerPublic  keyType = "OWNER_PUBLIC"
	thirdParty   keyType = "THIRD_PARTY_PUBLIC"
)

type keyEntry struct {
	ID           string
	Alias        string
	KeyType      keyType
	KeyData      string
	Fingerprint  string
	CreationDate string
}

type ownerPair struct {
	Alias       string
	Fingerprint string
	Public      string
	Private     string
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
}

func main() {
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

func newUIState(a fyne.App, w fyne.Window) *uiState {
	s := &uiState{
		app: a,
		win: w,
	}

	s.vaultPathEntry = widget.NewEntry()
	s.vaultPathEntry.SetPlaceHolder("Vault file path")

	s.passphraseEntry = widget.NewPasswordEntry()
	s.passphraseEntry.SetPlaceHolder("Passphrase")
	s.passphraseEntry.OnSubmitted = func(string) { s.openVault() }

	s.createPathEntry = widget.NewEntry()
	s.createPathEntry.SetPlaceHolder("New vault path")

	s.createPassEntry = widget.NewPasswordEntry()
	s.createPassEntry.SetPlaceHolder("Passphrase")
	s.createPassEntry.OnSubmitted = func(string) { s.createVault() }

	s.createPassAgainEntry = widget.NewPasswordEntry()
	s.createPassAgainEntry.SetPlaceHolder("Repeat passphrase")
	s.createPassAgainEntry.OnSubmitted = func(string) { s.createVault() }

	s.aliasEntry = widget.NewEntry()
	s.aliasEntry.SetPlaceHolder("Your name")
	s.emailEntry = widget.NewEntry()
	s.emailEntry.SetPlaceHolder("your@email")

	s.importAliasEntry = widget.NewEntry()
	s.importAliasEntry.SetPlaceHolder("Contact name")
	s.importKeyEntry = widget.NewMultiLineEntry()
	s.importKeyEntry.SetMinRowsVisible(5)
	s.importKeyEntry.SetPlaceHolder("Contact public key")

	s.pairAlias = widget.NewLabel("No key pair selected")
	s.pairFingerprint = widget.NewLabel("")
	s.pairPublic = widget.NewMultiLineEntry()
	s.pairPublic.Disable()
	s.pairPublic.SetMinRowsVisible(5)

	s.pairPrivate = widget.NewMultiLineEntry()
	s.pairPrivate.Disable()
	s.pairPrivate.SetMinRowsVisible(5)
	s.pairPrivate.SetText("Private key hidden")

	s.encryptRecipientEntry = widget.NewMultiLineEntry()
	s.encryptRecipientEntry.SetMinRowsVisible(5)
	s.encryptRecipientEntry.SetPlaceHolder("Recipient public key")

	s.encryptSignerEntry = widget.NewMultiLineEntry()
	s.encryptSignerEntry.SetMinRowsVisible(5)
	s.encryptSignerEntry.SetPlaceHolder("Your private key")

	s.plainEntry = widget.NewMultiLineEntry()
	s.plainEntry.SetMinRowsVisible(5)
	s.plainEntry.SetPlaceHolder("Message to encrypt")

	s.cipherEntry = widget.NewMultiLineEntry()
	s.cipherEntry.Disable()
	s.cipherEntry.SetMinRowsVisible(5)

	s.cipherInputEntry = widget.NewMultiLineEntry()
	s.cipherInputEntry.SetMinRowsVisible(5)
	s.cipherInputEntry.SetPlaceHolder("Encrypted message")

	s.decryptKeyEntry = widget.NewMultiLineEntry()
	s.decryptKeyEntry.SetMinRowsVisible(5)
	s.decryptKeyEntry.SetPlaceHolder("Your private key")

	s.verifyKeyEntry = widget.NewMultiLineEntry()
	s.verifyKeyEntry.SetMinRowsVisible(5)
	s.verifyKeyEntry.SetPlaceHolder("Sender public key")

	s.plainOutputEntry = widget.NewMultiLineEntry()
	s.plainOutputEntry.Disable()
	s.plainOutputEntry.SetMinRowsVisible(5)

	s.statusLabel = widget.NewLabel("Ready")

	s.encryptRecipientSelect = widget.NewSelect([]string{"Enter the key"}, func(_ string) { s.refreshEncryptManualVisibility() })
	s.encryptRecipientSelect.SetSelected("Enter the key")

	s.encryptSignerSelect = widget.NewSelect([]string{"Enter the key"}, func(_ string) { s.refreshEncryptManualVisibility() })
	s.encryptSignerSelect.SetSelected("Enter the key")

	s.decryptKeySelect = widget.NewSelect([]string{"Enter the key"}, func(_ string) { s.refreshDecryptManualVisibility() })
	s.decryptKeySelect.SetSelected("Enter the key")

	s.verifyKeySelect = widget.NewSelect([]string{"Enter the key"}, func(_ string) { s.refreshDecryptManualVisibility() })
	s.verifyKeySelect.SetSelected("Enter the key")

	s.encryptRecipientManual = s.multilineField(s.encryptRecipientEntry)
	s.encryptSignerManual = s.multilineField(s.encryptSignerEntry)
	s.decryptKeyManual = s.multilineField(s.decryptKeyEntry)
	s.verifyKeyManual = s.multilineField(s.verifyKeyEntry)

	s.encryptRecipientBox = container.NewVBox(widget.NewLabel("Recipient key source"), s.encryptRecipientSelect, s.encryptRecipientManual)
	s.encryptSignerBox = container.NewVBox(widget.NewLabel("Signer key source"), s.encryptSignerSelect, s.encryptSignerManual)
	s.decryptKeyBox = container.NewVBox(widget.NewLabel("Decrypt key source"), s.decryptKeySelect, s.decryptKeyManual)
	s.verifyKeyBox = container.NewVBox(widget.NewLabel("Verify key source"), s.verifyKeySelect, s.verifyKeyManual)

	s.pairsList = widget.NewList(
		func() int { return len(s.pairs) },
		func() fyne.CanvasObject {
			lbl := widget.NewLabel("template")
			btn := widget.NewButton("Remove", nil)
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
			lbl.SetText(fmt.Sprintf("%s | %s", s.pairs[i].Alias, s.pairs[i].Fingerprint))
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
			btn := widget.NewButton("Remove", nil)
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
	return s
}

func (s *uiState) setStatus(msg string) {
	s.status = msg
	if s.statusLabel != nil {
		s.statusLabel.SetText(msg)
	}
}

func (s *uiState) wrapWithStatus(content fyne.CanvasObject) fyne.CanvasObject {
	statusBar := container.NewHBox(
		widget.NewLabel("Status:"),
		s.statusLabel,
	)
	return container.NewBorder(nil, container.NewPadded(statusBar), nil, nil, content)
}

func (s *uiState) showStartup() {
	openCard := widget.NewCard("Open your vault", "Pick your file and unlock with passphrase.", container.NewVBox(
		widget.NewLabel("Vault file"),
		s.vaultPathEntry,
		container.NewHBox(
			widget.NewButton("Select vault file...", func() { s.pickOpenVaultPath(s.vaultPathEntry) }),
			layout.NewSpacer(),
		),
		widget.NewLabel("Passphrase"),
		s.passphraseEntry,
		widget.NewButton("Open vault", s.openVault),
	))

	createCard := widget.NewCard("Create a new vault", "Set a save path and passphrase.", container.NewVBox(
		widget.NewLabel("New vault path"),
		s.createPathEntry,
		container.NewHBox(
			widget.NewButton("Choose save location...", func() { s.pickSaveVaultPath(s.createPathEntry) }),
			layout.NewSpacer(),
		),
		widget.NewLabel("Passphrase"),
		s.createPassEntry,
		widget.NewLabel("Repeat passphrase"),
		s.createPassAgainEntry,
		widget.NewButton("Create vault", s.createVault),
	))

	tabs := container.NewAppTabs(
		container.NewTabItem("Open vault", container.NewVScroll(s.centerBlock(openCard))),
		container.NewTabItem("Create vault", container.NewVScroll(s.centerBlock(createCard))),
	)
	s.win.SetContent(s.wrapWithStatus(tabs))
}

func (s *uiState) showMainUI() {
	myKeysTab := container.NewTabItem("My Keys", s.buildMyKeysTab())
	keysTab := container.NewTabItem("Keys", s.buildKeysTab())
	encryptTab := container.NewTabItem("Encrypt & Sign", s.buildEncryptTab())
	decryptTab := container.NewTabItem("Decrypt & Verify", s.buildDecryptTab())

	tabs := container.NewAppTabs(myKeysTab, keysTab, encryptTab, decryptTab)
	s.win.SetContent(s.wrapWithStatus(tabs))
	s.win.Canvas().Focus(s.aliasEntry)
}

func (s *uiState) buildKeysTab() fyne.CanvasObject {
	importForm := widget.NewCard("Add contact public key", "Store only third-party public keys here.", container.NewVBox(
		widget.NewLabel("Contact name"),
		s.importAliasEntry,
		widget.NewLabel("Contact public key"),
		s.multilineField(s.importKeyEntry),
		widget.NewButton("Add contact public key", s.addThirdPartyKey),
	))

	content := container.NewVBox(
		s.centerBlock(importForm),
		s.centerBlock(widget.NewCard("Saved contacts", "Select a row and use Remove for deletion.", s.contactsList)),
	)
	return container.NewVScroll(content)
}

func (s *uiState) buildMyKeysTab() fyne.CanvasObject {
	createForm := widget.NewCard("Create my key pair", "Generate your own private/public key pair.", container.NewVBox(
		widget.NewLabel("Your name"),
		s.aliasEntry,
		widget.NewLabel("Your email"),
		s.emailEntry,
		widget.NewButton("Generate key pair", s.generateOwnerKeyPair),
	))

	showPublicBtn := widget.NewButton("Show public key", func() {
		s.showPublic = true
		s.refreshPairDetailsUI()
	})
	copyPublicBtn := widget.NewButton("Copy", func() {
		if s.selectedPairIdx < 0 || s.selectedPairIdx >= len(s.pairs) {
			return
		}
		s.app.Clipboard().SetContent(s.pairs[s.selectedPairIdx].Public)
		s.setStatus("Public key copied")
	})

	revealBtn := widget.NewButton("Show private key", func() {
		s.showPrivate = true
		s.refreshPairDetailsUI()
	})
	hideBtn := widget.NewButton("Hide private key", func() {
		s.showPrivate = false
		s.refreshPairDetailsUI()
	})

	s.pairDetailsBox = container.NewVBox(
		widget.NewLabel("Select a key from the list to view details."),
	)
	detailsCard := widget.NewCard("Selected key pair", "Public and private key fields appear only when requested.", s.pairDetailsBox)
	s.refreshPairDetailsUIWithButtons(showPublicBtn, copyPublicBtn, revealBtn, hideBtn)

	content := container.NewVBox(
		s.centerBlock(createForm),
		s.centerBlock(widget.NewCard("My key pairs", "Select a row and use Remove for deletion.", s.pairsList)),
		s.centerBlock(detailsCard),
	)
	return container.NewVScroll(content)
}

func (s *uiState) buildEncryptTab() fyne.CanvasObject {
	s.encryptActionBtn = widget.NewButton("Encrypt message", s.encryptMessage)
	s.encryptModeLabel = widget.NewLabel("")
	s.encryptModeToggleBtn = widget.NewButton("", func() {
		s.encryptModeSignOnly = !s.encryptModeSignOnly
		s.refreshEncryptActionMode()
	})
	s.encryptInputLabel = widget.NewLabel("Message to encrypt")
	s.encryptOutputLabel = widget.NewLabel("Encrypted output")
	s.encryptModeSep = widget.NewSeparator()
	s.encryptRecipientSep = widget.NewSeparator()

	copyBtn := widget.NewButton("Copy encrypted message", func() {
		if strings.TrimSpace(s.cipherEntry.Text) == "" {
			s.setStatus("Nothing to copy")
			return
		}
		s.app.Clipboard().SetContent(s.cipherEntry.Text)
		s.setStatus("Output copied")
	})

	content := container.NewVBox(
		s.centerBlock(widget.NewCard("Encrypt and sign", "Use the mode switch button to move between encrypt and sign workflows.", container.NewVBox(
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
	s.decryptActionBtn = widget.NewButton("Decrypt message", s.decryptMessage)
	s.decryptModeLabel = widget.NewLabel("")
	s.decryptModeToggleBtn = widget.NewButton("", func() {
		s.decryptModeVerifyOnly = !s.decryptModeVerifyOnly
		s.refreshDecryptActionMode()
	})
	s.decryptInputLabel = widget.NewLabel("Encrypted message")
	s.decryptOutputLabel = widget.NewLabel("Plain output")
	s.decryptInputSep = widget.NewSeparator()
	s.decryptKeySep = widget.NewSeparator()

	copyBtn := widget.NewButton("Copy plain message", func() {
		if strings.TrimSpace(s.plainOutputEntry.Text) == "" {
			s.setStatus("Nothing to copy")
			return
		}
		s.app.Clipboard().SetContent(s.plainOutputEntry.Text)
		s.setStatus("Plain message copied")
	})

	content := container.NewVBox(
		s.centerBlock(widget.NewCard("Decrypt and verify", "Use the mode switch button to move between decrypt and verify workflows.", container.NewVBox(
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
	box := container.NewMax(spacer, scroll)
	return box
}

func (s *uiState) centerBlock(obj fyne.CanvasObject) fyne.CanvasObject {
	width := s.win.Canvas().Size().Width * 0.8
	if width <= 0 {
		width = 600
	}
	spacer := canvas.NewRectangle(color.Transparent)
	spacer.SetMinSize(fyne.NewSize(width, obj.MinSize().Height))
	host := container.NewMax(spacer, obj)
	return container.NewHBox(layout.NewSpacer(), host, layout.NewSpacer())
}

func (s *uiState) refreshEncryptManualVisibility() {
	if s.encryptRecipientSelect == nil || s.encryptSignerSelect == nil || s.encryptRecipientEntry == nil || s.encryptSignerEntry == nil {
		return
	}
	if s.encryptRecipientManual != nil {
		if s.encryptRecipientSelect.Selected == "Enter the key" {
			s.encryptRecipientManual.Show()
		} else {
			s.encryptRecipientManual.Hide()
		}
	}
	if s.encryptSignerManual != nil {
		if s.encryptSignerSelect.Selected == "Enter the key" {
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
			s.encryptModeLabel.SetText("Mode: Sign")
		} else {
			s.encryptModeLabel.SetText("Mode: Encrypt")
		}
	}
	if s.encryptModeToggleBtn != nil {
		if s.encryptModeSignOnly {
			s.encryptModeToggleBtn.SetText("Switch to encrypt mode")
		} else {
			s.encryptModeToggleBtn.SetText("Switch to sign mode")
		}
	}
	if s.encryptActionBtn != nil {
		if s.encryptModeSignOnly {
			s.encryptActionBtn.SetText("Sign message")
		} else {
			s.encryptActionBtn.SetText("Encrypt message")
		}
	}
	if s.encryptInputLabel != nil {
		if s.encryptModeSignOnly {
			s.encryptInputLabel.SetText("Message to sign")
		} else {
			s.encryptInputLabel.SetText("Message to encrypt")
		}
	}
	if s.encryptOutputLabel != nil {
		if s.encryptModeSignOnly {
			s.encryptOutputLabel.SetText("Signed output")
		} else {
			s.encryptOutputLabel.SetText("Encrypted output")
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
		if s.decryptKeySelect.Selected == "Enter the key" {
			s.decryptKeyManual.Show()
		} else {
			s.decryptKeyManual.Hide()
		}
	}
	if s.verifyKeyManual != nil {
		if s.verifyKeySelect.Selected == "Enter the key" {
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
			s.decryptModeLabel.SetText("Mode: Verify")
		} else {
			s.decryptModeLabel.SetText("Mode: Decrypt")
		}
	}
	if s.decryptModeToggleBtn != nil {
		if s.decryptModeVerifyOnly {
			s.decryptModeToggleBtn.SetText("Switch to decrypt mode")
		} else {
			s.decryptModeToggleBtn.SetText("Switch to verify mode")
		}
	}
	if s.decryptActionBtn != nil {
		if s.decryptModeVerifyOnly {
			s.decryptActionBtn.SetText("Verify message")
		} else {
			s.decryptActionBtn.SetText("Decrypt message")
		}
	}
	if s.decryptInputLabel != nil {
		if s.decryptModeVerifyOnly {
			s.decryptInputLabel.SetText("Signed message")
			s.cipherInputEntry.SetPlaceHolder("Signed cleartext message")
		} else {
			s.decryptInputLabel.SetText("Encrypted message")
			s.cipherInputEntry.SetPlaceHolder("Encrypted message")
		}
	}
	if s.decryptOutputLabel != nil {
		if s.decryptModeVerifyOnly {
			s.decryptOutputLabel.SetText("Verified output")
		} else {
			s.decryptOutputLabel.SetText("Plain output")
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
		widget.NewButton("Show public key", func() {
			s.showPublic = true
			s.refreshPairDetailsUI()
		}),
		widget.NewButton("Copy", func() {
			if s.selectedPairIdx < 0 || s.selectedPairIdx >= len(s.pairs) {
				return
			}
			s.app.Clipboard().SetContent(s.pairs[s.selectedPairIdx].Public)
			s.setStatus("Public key copied")
		}),
		widget.NewButton("Show private key", func() {
			s.showPrivate = true
			s.refreshPairDetailsUI()
		}),
		widget.NewButton("Hide private key", func() {
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
		s.pairDetailsBox.Objects = []fyne.CanvasObject{widget.NewLabel("Select a key from the list to view details.")}
		s.pairDetailsBox.Refresh()
		return
	}

	pair := s.pairs[s.selectedPairIdx]
	s.pairAlias.SetText("Alias: " + pair.Alias)
	s.pairFingerprint.SetText("Fingerprint: " + pair.Fingerprint)
	s.pairPublic.SetText(pair.Public)
	if s.showPrivate {
		s.pairPrivate.SetText(pair.Private)
	} else {
		s.pairPrivate.SetText("Private key hidden")
	}

	objs := []fyne.CanvasObject{s.pairAlias, s.pairFingerprint}
	if s.showPublic {
		objs = append(objs,
			container.NewHBox(widget.NewLabel("Public key"), showPublicBtn, copyPublicBtn),
			s.multilineField(s.pairPublic),
		)
	} else {
		objs = append(objs, container.NewHBox(widget.NewLabel("Public key"), showPublicBtn))
	}
	objs = append(objs,
		container.NewHBox(showPrivateBtn, hidePrivateBtn),
	)
	if s.showPrivate {
		objs = append(objs,
			widget.NewLabel("Private key"),
			s.multilineField(s.pairPrivate),
		)
	}

	s.pairDetailsBox.Objects = objs
	s.pairDetailsBox.Refresh()
}

func (s *uiState) openVault() {
	path := strings.TrimSpace(s.vaultPathEntry.Text)
	if path == "" {
		s.setStatus("Choose a vault file first")
		return
	}
	pass := []byte(sanitizedPassphrase(s.passphraseEntry.Text))
	if len(pass) < 8 {
		s.setStatus("Passphrase must be at least 8 characters")
		zeroBytes(pass)
		return
	}
	entries, err := loadVault(path, pass)
	if err != nil {
		s.setStatus("Unlock failed: " + err.Error())
		zeroBytes(pass)
		return
	}
	s.entries = entries
	s.vaultPath = path
	if len(s.passphrase) > 0 {
		zeroBytes(s.passphrase)
	}
	s.passphrase = pass
	s.refreshKeyDependentViews()
	s.setStatus("Vault unlocked")
	s.showMainUI()
}

func (s *uiState) createVault() {
	path := strings.TrimSpace(s.createPathEntry.Text)
	if path == "" {
		s.setStatus("Choose where to save the vault")
		return
	}
	p1 := sanitizedPassphrase(s.createPassEntry.Text)
	p2 := sanitizedPassphrase(s.createPassAgainEntry.Text)
	if len(p1) < 8 {
		s.setStatus("Passphrase must be at least 8 characters")
		return
	}
	if p1 != p2 {
		s.setStatus("Passphrases do not match")
		return
	}
	pass := []byte(p1)
	if err := saveVault(path, pass, nil); err != nil {
		s.setStatus("Create failed: " + err.Error())
		zeroBytes(pass)
		return
	}
	s.entries = nil
	s.vaultPath = path
	if len(s.passphrase) > 0 {
		zeroBytes(s.passphrase)
	}
	s.passphrase = pass
	s.refreshKeyDependentViews()
	s.setStatus("Created new vault")
	s.showMainUI()
}

func (s *uiState) saveVaultNow() {
	if s.vaultPath == "" || len(s.passphrase) == 0 {
		return
	}
	if err := saveVault(s.vaultPath, s.passphrase, s.entries); err != nil {
		s.setStatus("Auto-save failed: " + err.Error())
	}
}

func (s *uiState) generateOwnerKeyPair() {
	alias := strings.TrimSpace(s.aliasEntry.Text)
	email := strings.TrimSpace(s.emailEntry.Text)
	if alias == "" || email == "" {
		s.setStatus("Please provide name and email")
		return
	}
	priv, pub, fp, err := generateOwnerKey(alias, email)
	if err != nil {
		s.setStatus("Could not generate key: " + err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	s.entries = append(s.entries,
		keyEntry{ID: newUUID(), Alias: alias, KeyType: ownerPrivate, KeyData: b64(priv), Fingerprint: fp, CreationDate: now},
		keyEntry{ID: newUUID(), Alias: alias, KeyType: ownerPublic, KeyData: b64(pub), Fingerprint: fp, CreationDate: now},
	)
	s.saveVaultNow()
	s.aliasEntry.SetText("")
	s.emailEntry.SetText("")
	s.refreshKeyDependentViews()
	s.setStatus("Key pair generated")
}

func (s *uiState) addThirdPartyKey() {
	alias := strings.TrimSpace(s.importAliasEntry.Text)
	armored := strings.TrimSpace(s.importKeyEntry.Text)
	if alias == "" || armored == "" {
		s.setStatus("Please provide name and public key")
		return
	}
	k, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		s.setStatus("Public key is invalid: " + err.Error())
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
	s.setStatus("Public key added")
}

func (s *uiState) encryptMessage() {
	signerPriv := ""
	if s.encryptModeSignOnly {
		if s.encryptSignerSelect.Selected == "Enter the key" {
			signerPriv = strings.TrimSpace(s.encryptSignerEntry.Text)
		} else {
			signer := s.findKey(s.encryptSignerSelect.Selected, ownerPrivate)
			if signer != nil {
				signerPriv = deb64(signer.KeyData)
			}
		}

		if signerPriv == "" {
			s.setStatus("Please choose a signer key or enter one manually")
			return
		}
		signedText, err := signCleartextMessage(s.plainEntry.Text, signerPriv)
		if err != nil {
			s.setStatus("Sign failed: " + err.Error())
			return
		}
		s.cipherEntry.SetText(signedText)
		s.setStatus("Message signed (cleartext)")
		return
	}

	recipientPub := ""

	if s.encryptRecipientSelect.Selected == "Enter the key" {
		recipientPub = strings.TrimSpace(s.encryptRecipientEntry.Text)
	} else {
		rec := s.findKey(s.encryptRecipientSelect.Selected, thirdParty)
		if rec != nil {
			recipientPub = deb64(rec.KeyData)
		}
	}

	if s.encryptSignerSelect.Selected == "Enter the key" {
		signerPriv = strings.TrimSpace(s.encryptSignerEntry.Text)
	} else {
		signer := s.findKey(s.encryptSignerSelect.Selected, ownerPrivate)
		if signer != nil {
			signerPriv = deb64(signer.KeyData)
		}
	}

	if recipientPub == "" || signerPriv == "" {
		s.setStatus("Please choose keys or enter keys manually")
		return
	}
	cipherText, err := encryptAndSign(s.plainEntry.Text, recipientPub, signerPriv)
	if err != nil {
		s.setStatus("Encrypt/sign failed: " + err.Error())
		return
	}
	s.cipherEntry.SetText(cipherText)
	s.setStatus("Message encrypted")
}

func (s *uiState) decryptMessage() {
	cipherText := s.cipherInputEntry.Text
	if strings.TrimSpace(cipherText) == "" {
		s.setStatus("Input message is required")
		return
	}

	pub := ""
	if s.verifyKeySelect.Selected == "Enter the key" {
		pub = strings.TrimSpace(s.verifyKeyEntry.Text)
	} else {
		ver := s.findKey(s.verifyKeySelect.Selected, thirdParty)
		if ver != nil {
			pub = deb64(ver.KeyData)
		}
	}

	if s.decryptModeVerifyOnly {
		if pub == "" {
			s.setStatus("Please choose sender public key or enter one manually")
			return
		}
		plain, sigStatus, err := verifyCleartextMessage(cipherText, pub)
		if err != nil {
			s.setStatus("Verify failed: " + err.Error())
			return
		}
		s.plainOutputEntry.SetText(plain)
		s.setStatus(sigStatus)
		return
	}

	priv := ""

	if s.decryptKeySelect.Selected == "Enter the key" {
		priv = strings.TrimSpace(s.decryptKeyEntry.Text)
	} else {
		dec := s.findKey(s.decryptKeySelect.Selected, ownerPrivate)
		if dec != nil {
			priv = deb64(dec.KeyData)
		}
	}

	if priv == "" || pub == "" {
		s.setStatus("Please choose keys or enter keys manually")
		return
	}

	plain, sigStatus, err := decryptAndVerify(cipherText, priv, pub)
	if err != nil {
		s.setStatus("Decrypt failed: " + err.Error())
		return
	}
	s.plainOutputEntry.SetText(plain)
	s.setStatus(sigStatus)
}

func (s *uiState) refreshKeyDependentViews() {
	s.pairs = s.ownerPairs()
	if s.pairsList != nil {
		s.pairsList.Refresh()
	}
	if s.contactsList != nil {
		s.contactsList.Refresh()
	}

	recipientOptions := s.encryptOptionsRecipient()
	signerOptions := s.encryptOptionsSigner()

	s.encryptRecipientSelect.SetOptions(recipientOptions)
	s.encryptSignerSelect.SetOptions(signerOptions)
	s.decryptKeySelect.SetOptions(signerOptions)
	s.verifyKeySelect.SetOptions(recipientOptions)

	if !containsOption(recipientOptions, s.encryptRecipientSelect.Selected) {
		s.encryptRecipientSelect.SetSelected("Enter the key")
	}
	if !containsOption(signerOptions, s.encryptSignerSelect.Selected) {
		s.encryptSignerSelect.SetSelected("Enter the key")
	}
	if !containsOption(signerOptions, s.decryptKeySelect.Selected) {
		s.decryptKeySelect.SetSelected("Enter the key")
	}
	if !containsOption(recipientOptions, s.verifyKeySelect.Selected) {
		s.verifyKeySelect.SetSelected("Enter the key")
	}

	s.refreshEncryptManualVisibility()
	s.refreshDecryptManualVisibility()

	if len(s.pairs) == 0 {
		s.selectedPairIdx = -1
		s.showPublic = false
		s.showPrivate = false
		s.pairAlias.SetText("No key pair selected")
		s.pairFingerprint.SetText("")
		s.pairPublic.SetText("")
		s.pairPrivate.SetText("Private key hidden")
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
	s.setStatus("Contact key removed")
}

func (s *uiState) removeOwnerPairAt(i int) {
	if i < 0 || i >= len(s.pairs) {
		return
	}
	p := s.pairs[i]
	filtered := make([]keyEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.Alias == p.Alias && e.Fingerprint == p.Fingerprint && (e.KeyType == ownerPrivate || e.KeyType == ownerPublic) {
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
	s.setStatus("Key pair removed")
}

func (s *uiState) pickOpenVaultPath(target *widget.Entry) {
	dlg := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil {
			s.setStatus("File picker error: " + err.Error())
			return
		}
		if rc == nil {
			return
		}
		defer rc.Close()
		target.SetText(normalizeDialogPath(rc.URI()))
		s.setStatus("Selected vault file")
	}, s.win)
	dlg.SetFilter(storage.NewExtensionFileFilter([]string{".enc", ".vault", ".csv"}))
	dlg.Show()
}

func (s *uiState) pickSaveVaultPath(target *widget.Entry) {
	dlg := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
		if err != nil {
			s.setStatus("File picker error: " + err.Error())
			return
		}
		if wc == nil {
			return
		}
		defer wc.Close()
		target.SetText(normalizeDialogPath(wc.URI()))
		s.setStatus("Selected new vault path")
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

func (s *uiState) findKey(alias string, t keyType) *keyEntry {
	for i := range s.entries {
		if s.entries[i].Alias == alias && s.entries[i].KeyType == t {
			return &s.entries[i]
		}
	}
	return nil
}

func (s *uiState) ownerPairs() []ownerPair {
	pubByAlias := make(map[string]keyEntry)
	for _, e := range s.entries {
		if e.KeyType == ownerPublic {
			pubByAlias[e.Alias] = e
		}
	}
	pairs := make([]ownerPair, 0)
	for _, e := range s.entries {
		if e.KeyType != ownerPrivate {
			continue
		}
		pub := pubByAlias[e.Alias]
		pairs = append(pairs, ownerPair{
			Alias:       e.Alias,
			Fingerprint: e.Fingerprint,
			Public:      deb64(pub.KeyData),
			Private:     deb64(e.KeyData),
		})
	}
	return pairs
}

func (s *uiState) encryptOptionsRecipient() []string {
	opts := []string{"Enter the key"}
	for _, e := range s.entries {
		if e.KeyType == thirdParty {
			opts = append(opts, e.Alias)
		}
	}
	return opts
}

func (s *uiState) encryptOptionsSigner() []string {
	opts := []string{"Enter the key"}
	for _, e := range s.entries {
		if e.KeyType == ownerPrivate {
			opts = append(opts, e.Alias)
		}
	}
	return opts
}

func summarizeKeys(entries []keyEntry) string {
	if len(entries) == 0 {
		return "No keys saved yet"
	}
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "- %s | %s | %s\n", e.Alias, e.KeyType, e.Fingerprint)
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

func saveVault(path string, passphrase []byte, entries []keyEntry) error {
	data, err := encodeCSV(entries)
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

func loadVault(path string, passphrase []byte) ([]keyEntry, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("vault file does not exist")
		}
		return nil, err
	}
	if len(blob) < len(magicHeader)+saltSize+nonceSize+16 {
		return nil, errBadFormat
	}
	if string(blob[:len(magicHeader)]) != magicHeader {
		return nil, errBadFormat
	}
	salt := blob[len(magicHeader) : len(magicHeader)+saltSize]
	nonce := blob[len(magicHeader)+saltSize : len(magicHeader)+saltSize+nonceSize]
	ciphertext := blob[len(magicHeader)+saltSize+nonceSize:]

	k := deriveKey(passphrase, salt)
	defer zeroBytes(k)

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed")
	}
	entries, err := decodeCSV(plain)
	zeroBytes(plain)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 1, 32)
}

func encodeCSV(entries []keyEntry) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"ID", "Alias", "KeyType", "KeyData", "Fingerprint", "CreationDate"}); err != nil {
		return nil, err
	}
	for _, e := range entries {
		if err := w.Write([]string{e.ID, e.Alias, string(e.KeyType), e.KeyData, e.Fingerprint, e.CreationDate}); err != nil {
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
		if len(row) != 6 {
			continue
		}
		entries = append(entries, keyEntry{
			ID:           row[0],
			Alias:        row[1],
			KeyType:      keyType(row[2]),
			KeyData:      row[3],
			Fingerprint:  row[4],
			CreationDate: row[5],
		})
	}
	return entries, nil
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
