<#
STYLE: Never embed single quotes inside double-quoted strings. PowerShell 5.1
reads this file via the system ANSI codepage when the UTF-8 BOM is missing
(e.g. GitHub zip download), and multi-byte UTF-8 sequences corrupt the
parser's quote-tracking state -- every subsequent ' inside "..." becomes a
fatal parse error. Use `" `"` (escaped double quotes) or restructure instead.

Also: this script must run on PowerShell 5.1 (the default on Windows Server
2016+). Avoid PS 7+ syntax: no ??, no ternary, no pipeline chain operators
(&& / ||). Use if/else and -or/-and instead.

.SYNOPSIS
    Remove an adcs-lens Windows installation.

.DESCRIPTION
    Removes the adcs-lens venv and optionally the shared Python install and
    the install directory itself. adcs-lens stores no persistent state (it
    reads exported directories on demand), so removing the venv is
    sufficient to uninstall. Re-running is safe: missing resources are
    skipped, never errored.

.PARAMETER InstallDir
    Base directory used by the deployment (venv + shared Python).
    Default: C:\ProgramData\adcs-lens

.PARAMETER RemoveData
    When passed, also removes the entire install directory (venv + shared
    Python). Without this flag the directory is preserved so a re-install
    reuses the shared Python.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1 -RemoveData

.NOTES
    This script is not signed. If your execution policy blocks unsigned
    scripts, bypass it per-invocation (see examples above).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\adcs-lens",
    [switch]$RemoveData
)

# Guard: only run the main body when executed directly. Dot-sourcing is safe
# (loads nothing — the uninstaller has no extracted helper functions — and does
# not execute the removal logic).
if ($MyInvocation.InvocationName -ne ".") {

    $ErrorActionPreference = "Stop"

    # --- Must be elevated (we write under ProgramData) ---
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run from an elevated (Administrator) PowerShell."
    }

    # Defense-in-depth: refuse to remove a path that does not look like an
    # adcs-lens install directory (prevents a catastrophic typo like
    # -InstallDir C:\ProgramData).
    if ($InstallDir -notmatch "adcs-lens") {
        throw "Refusing to remove `"$InstallDir`" -- it does not contain `"adcs-lens`" in the path. Pass the correct -InstallDir."
    }

    $venv = Join-Path $InstallDir "venv"

    # 1. Remove the venv
    if (Test-Path $venv) {
        Write-Host "Removing venv at $venv ..."
        Remove-Item $venv -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $venv) {
            Write-Host "  [warn] Some files in $venv could not be removed (they may be in use)."
            Write-Host "         Close any processes using the venv and re-run."
        } else {
            Write-Host "  venv removed."
        }
    } else {
        Write-Host "venv not found at $venv; skipping."
    }

    # 2. Optionally remove the entire install directory (shared Python, etc.)
    if ($RemoveData) {
        if (Test-Path $InstallDir) {
            Write-Host "Removing install directory $InstallDir ..."
            Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $InstallDir) {
                Write-Host "  [warn] Some files in $InstallDir could not be removed."
            } else {
                Write-Host "  Install directory removed."
            }
        } else {
            Write-Host "Install directory $InstallDir not found; skipping."
        }
    } else {
        Write-Host "Install directory $InstallDir preserved (pass -RemoveData to delete shared Python too)."
    }

    Write-Host ""
    Write-Host "Done. adcs-lens removed."
    if (-not $RemoveData) {
        Write-Host "Re-run install-windows.ps1 to reinstall."
    }

} # end dot-source guard
