![Windows](https://img.shields.io/badge/Windows-Supported-blue?labelColor=gray&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI0ZGRiIgZD0iTTAgMGgxMXYxMUgwek0xMyAwaDExdjExSDEzek0wIDEzaDExdjExSDB6TTEzIDEzaDExdjExSDEzeiIvPjwvc3ZnPg%3D%3D)
 ![Linux](https://img.shields.io/badge/Linux-Supported-yellow?labelColor=gray&logo=linux)

![Go Version](https://img.shields.io/badge/Go-1.26.1-blue?labelColor=gray&logo=go)
 [![Go Report Card](https://goreportcard.com/badge/github.com/sibexico/Eris)](https://goreportcard.com/report/github.com/sibexico/Eris)
 [![Support Me](https://img.shields.io/badge/Support-Me-darkgreen?labelColor=black&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI0ZGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMiAxQzUuOTI1IDEgMSA1LjkyNSAxIDEyczQuOTI1IDExIDExIDExIDExLTQuOTI1IDExLTExUzE4LjA3NSAxIDEyIDF6bTAgNGwyLjUgNi41SDIxbC01LjUgNCAyIDYuNUwxMiAxNy41IDYgMjJsMi02LjUtNS41LTRoNi41TDEyIDV6Ii8%2BPC9zdmc%2B)](https://sibexi.co/support)

[![Tests passed](https://img.shields.io/badge/Tests-Passed-green?labelColor=gray&logo=github)](https://github.com/sibexico/Eris/actions/runs/25575542169)
 [![Tests coverage](https://img.shields.io/badge/Tests%20Coverage-39.3%25-red?labelColor=gray&logo=gitextensions)](https://github.com/sibexico/Eris/actions/runs/25575542169)

# Eris


![Eris](icon512.png)


Eris is a desktop PGP workstation written in Go with Fyne.
It stores keys in an encrypted vault and gives you a clean UI for signing, encryption, decryption, and verification.

## Features
- Encrypted local vault for stored keys
- Generate your own key pairs
- Import and manage contact public keys
- Encrypt and sign messages
- Decrypt and verify incoming messages
- Dedicated sign-only and verify-only modes
- Settings tab for switching vaults and changing vault passphrase

## Install

### Windows (Winget)

Install from WinGet with:

```powershell
winget install sibexico.Eris
```

If you already have Eris installed and want the latest published release:

```powershell
winget upgrade sibexico.Eris
```

### Debian/Ubuntu (.deb from Release)

1. Open the latest Release page and download the `.deb` file from Assets.
2. Install it with:

```bash
sudo apt install ./eris_<version>_linux_<arch>.deb
```

Example:

```bash
sudo apt install ./eris_1.2.3_linux_x86_64.deb
```

If your distribution prefers `dpkg` first:

```bash
sudo dpkg -i eris_<version>_linux_<arch>.deb
sudo apt -f install
```

## Build

Build from source if you want a local binary:

Windows:
```powershell
go build -ldflags "-H=windowsgui" -o eris.exe .
```

Linux:
```bash
go build -o eris .
```

## Run
- Windows: `./eris.exe`
- Linux: `./eris`

## Screenshots

![Eris](screenshots/1.png)

![Eris](screenshots/2.png)
