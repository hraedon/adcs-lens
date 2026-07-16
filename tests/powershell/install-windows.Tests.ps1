# Pester 5 tests for the helper functions extracted from
# scripts/install-windows.ps1.
#
# The script is dot-sourced to load the functions without executing the
# install body. The functions under test are pure (no filesystem or IIS
# interaction) so they run on any host, including the Linux pwsh CI runner.

Describe "install-windows.ps1" {
    BeforeAll {
        $script:SourcePath = "$PSScriptRoot/../../scripts/install-windows.ps1"
        . $script:SourcePath
    }

    Describe "Test-PythonVersion" {
        It "parses a standard version string" {
            $r = Test-PythonVersion -VersionOutput "Python 3.12.1"
            $r | Should -Not -Be $null
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 12
            $r.MeetsMinimum | Should -Be $true
            $r.Raw | Should -Be "Python 3.12.1"
        }

        It "accepts Python 3.13" {
            $r = Test-PythonVersion -VersionOutput "Python 3.13.0"
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 13
            $r.MeetsMinimum | Should -Be $true
        }

        It "accepts Python 3.14" {
            $r = Test-PythonVersion -VersionOutput "Python 3.14.2"
            $r.MeetsMinimum | Should -Be $true
        }

        It "rejects Python 3.11 (below minimum)" {
            $r = Test-PythonVersion -VersionOutput "Python 3.11.9"
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 11
            $r.MeetsMinimum | Should -Be $false
        }

        It "rejects Python 2.7 (below minimum)" {
            $r = Test-PythonVersion -VersionOutput "Python 2.7.18"
            $r.Major | Should -Be 2
            $r.Minor | Should -Be 7
            $r.MeetsMinimum | Should -Be $false
        }

        It "accepts a hypothetical Python 4.0 (major > 3)" {
            $r = Test-PythonVersion -VersionOutput "Python 4.0.0"
            $r.Major | Should -Be 4
            $r.MeetsMinimum | Should -Be $true
        }

        It "handles version output with extra text" {
            $r = Test-PythonVersion -VersionOutput "Python 3.12.1 (main, Oct  8 2024, 10:00:00)"
            $r | Should -Not -Be $null
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 12
            $r.MeetsMinimum | Should -Be $true
        }

        It "picks the first Python-prefixed line from multi-line output" {
            $r = Test-PythonVersion -VersionOutput "warning: something`nPython 3.14.0"
            $r | Should -Not -Be $null
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 14
            $r.MeetsMinimum | Should -Be $true
        }

        It "picks the first Python-prefixed line even when a later line is newer" {
            # The pre-filter takes the first line starting with ^Python, so a
            # prefixed stray line ahead of the real version is selected. This
            # matches the sibling installers; callers should not prepend
            # version-like lines to python --version output.
            $r = Test-PythonVersion -VersionOutput "Python 3.11.9 (deprecated)`nPython 3.14.0"
            $r | Should -Not -Be $null
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 11
            $r.MeetsMinimum | Should -Be $false
        }

        It "falls back to whole-string match when no line starts with Python" {
            $r = Test-PythonVersion -VersionOutput "detected: Python 3.12.1"
            $r | Should -Not -Be $null
            $r.Major | Should -Be 3
            $r.Minor | Should -Be 12
            $r.MeetsMinimum | Should -Be $true
        }

        It "returns `$null for non-Python output" {
            $r = Test-PythonVersion -VersionOutput "not a version string"
            $r | Should -Be $null
        }

        It "returns `$null for an empty string" {
            $r = Test-PythonVersion -VersionOutput ""
            $r | Should -Be $null
        }

        It "returns `$null for a version without the Python prefix" {
            $r = Test-PythonVersion -VersionOutput "3.12.1"
            $r | Should -Be $null
        }

        It "trims whitespace from the Raw field" {
            $r = Test-PythonVersion -VersionOutput "  Python 3.12.1  "
            $r.Raw | Should -Be "Python 3.12.1"
        }
    }

    Describe "Test-NeedsSharedPython" {
        It "returns `$true for a per-user AppData path" {
            $r = Test-NeedsSharedPython -PythonExePath "C:\Users\bob\AppData\Local\Python\pythoncore-3.12.1\python.exe"
            $r | Should -Be $true
        }

        It "returns `$true for a WindowsApps path" {
            $r = Test-NeedsSharedPython -PythonExePath "C:\Users\bob\AppData\Local\Microsoft\WindowsApps\python.exe"
            $r | Should -Be $true
        }

        It "returns `$false for a Program Files path" {
            $r = Test-NeedsSharedPython -PythonExePath "C:\Program Files\Python312\python.exe"
            $r | Should -Be $false
        }

        It "returns `$false for a ProgramData (shared) path" {
            $r = Test-NeedsSharedPython -PythonExePath "C:\ProgramData\adcs-lens\python\python.exe"
            $r | Should -Be $false
        }

        It "returns `$false for an empty string" {
            $r = Test-NeedsSharedPython -PythonExePath ""
            $r | Should -Be $false
        }

        It "returns `$false for a `$null path" {
            $r = Test-NeedsSharedPython -PythonExePath $null
            $r | Should -Be $false
        }
    }
}
