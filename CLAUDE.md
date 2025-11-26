# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**FTA-Manager** is a PowerShell module for managing Windows File Type Associations (FTA) and Protocol Associations (PTA). It works by computing the correct UserChoice hash that Windows requires since Windows 8 to validate registry-based file associations.

## Module Import & Testing

```powershell
# Import the module
Import-Module .\FTA-Manager.psd1 -Force

# Test functions
Get-FTA ".pdf"
Get-AllFTA
Get-PTA "http"
Get-AllPTA
Get-UCPDStatus
```

## Architecture

### Core Hash Algorithm (`FTA-Manager.psm1:36-127`)

The `Get-Hash` function implements Windows' UserChoice hash algorithm:
1. Input: `extension + userSid + progId + timestamp + userExperienceString`
2. UTF-16LE encode with null terminator
3. MD5 hash as seed for keys
4. Two-pass transformation with specific constants (0x0E79A9C1)
5. Base64 encode final result

The magic string is: `"User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"`

### Registry Paths

- **File extensions**: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}\UserChoice`
- **Protocols**: `HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{protocol}\UserChoice`
- **Toast notifications**: `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts`

### UCPD (User Choice Protection Driver)

Windows 10/11 (Feb 2022+) introduced UCPD which blocks programmatic changes to:
- `.pdf` file association
- `http` and `https` protocol associations

UCPD status is at: `HKLM:\SYSTEM\CurrentControlSet\Services\UCPD` (Start=4 means disabled)

## Key Functions

| Function | Purpose |
|----------|---------|
| `Set-FTA` | Set file type association |
| `Get-FTA` | Get current file type association |
| `Set-PTA` | Set protocol association |
| `Get-PTA` | Get current protocol association |
| `Test-UCPDEnabled` | Check if UCPD is blocking changes |
| `Disable-UCPD` | Disable UCPD (requires Admin + Reboot) |
| `Find-ProgIdForExtension` | Find available ProgIds for an extension |

## Common ProgIds

```
# Browsers
ChromeHTML          - Google Chrome
MSEdgeHTM           - Microsoft Edge
FirefoxURL-*        - Mozilla Firefox (GUID suffix varies)

# PDF Readers
AcroExch.Document.DC  - Adobe Acrobat Reader DC
FoxitReader.Document  - Foxit Reader

# General
Applications\notepad.exe   - Notepad
Applications\code.exe      - VS Code
```

## Development Notes

- The hash algorithm is time-sensitive (uses current minute, rounded down)
- Hash must be written atomically with ProgId (delete key first, then recreate)
- `ApplicationAssociationToasts` entry is required for the association to work
- Always use lowercase for hash input string

## References

- [PS-SFTA](https://github.com/DanysysTeam/PS-SFTA) - Original PowerShell implementation
- [SetUserFTA](https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/) - Hash algorithm reverse engineering
