![Windows](https://img.shields.io/badge/Windows-Supported-blue?labelColor=gray&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI0ZGRiIgZD0iTTAgMGgxMXYxMUgwek0xMyAwaDExdjExSDEzek0wIDEzaDExdjExSDB6TTEzIDEzaDExdjExSDEzeiIvPjwvc3ZnPg%3D%3D)
 ![Linux](https://img.shields.io/badge/Linux-Supported-yellow?labelColor=gray&logo=linux)

[![Product Hunt](https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1113038&amp;theme=dark&amp;t=1775035098003)](https://www.producthunt.com/products/eris)

![Go Version](https://img.shields.io/badge/Go-1.26.1-blue?labelColor=gray&logo=go)
 [![Go Report Card](https://goreportcard.com/badge/github.com/sibexico/Eris)](https://goreportcard.com/report/github.com/sibexico/Eris)
 [![Support Me](https://img.shields.io/badge/Support-Me-darkgreen?labelColor=black&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI0ZGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMiAxQzUuOTI1IDEgMSA1LjkyNSAxIDEyczQuOTI1IDExIDExIDExIDExLTQuOTI1IDExLTExUzE4LjA3NSAxIDEyIDF6bTAgNGwyLjUgNi41SDIxbC01LjUgNCAyIDYuNUwxMiAxNy41IDYgMjJsMi02LjUtNS41LTRoNi41TDEyIDV6Ii8%2BPC9zdmc%2B)](https://sibexi.co/support)

# Eris


![Eris](icon512.png)


Eris is a desktop PGP workstation written in Go with Fyne.
It stores keys in an encrypted vault and gives you a clean UI for signing, encryption, decryption, and verification.

## Features
- Encrypted vault file
- Owner key pair generation and contact public key import
- Encrypt + sign, decrypt + verify
- Sign-only and verify-only message modes
- Dark high-contrast GUI theme

## Build

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