<#
  Pester tests for the OS-independent helpers in Export-AdcsEstate.ps1.

  These run on Linux pwsh (CI) by dot-sourcing the collector with -FunctionsOnly,
  which defines the pure functions and returns before any LDAP/WMI/certutil work.
  The Windows-only paths (_parseAces over System.DirectoryServices, the live
  collection passes) are out of scope here — see WI-009.
#>
BeforeAll {
    . "$PSScriptRoot/../../scripts/Export-AdcsEstate.ps1" -FunctionsOnly
}

Describe '_decode (bit-map decode)' {
    It 'decodes the Schannel UPN bit (0x4) to upn, by key not position' {
        # Regression guard for the [ordered]-int-index bug: 0x4 is the 3rd entry by
        # key (upn) but the 3rd by position would be the same here; the real trap is
        # that $map[4] returns the 5th element. _decode must use the key.
        (_decode 4 $SCHANNEL_BITS) | Should -Be @('upn')
    }
    It 'decodes a combined Schannel value (UPN + S4U2Self-Explicit = 0x14)' {
        (_decode 0x14 $SCHANNEL_BITS) | Should -Be @('upn', 's4u2self_explicit')
    }
    It 'returns no methods for zero' {
        # ,$out wraps an empty result as a 1-element array of @() (which serializes to
        # []); assert emptiness via -join so the wrapper does not skew the check.
        ((_decode 0 $SCHANNEL_BITS) -join ',') | Should -Be ''
    }
    It 'decodes template name flags by key (ENROLLEE_SUPPLIES_SUBJECT = 0x1)' {
        (_decode 0x1 $NAME_FLAGS) | Should -Be @('ENROLLEE_SUPPLIES_SUBJECT')
    }
    It 'decodes the NO_SECURITY_EXTENSION enrollment flag (ESC9, 0x00080000)' {
        (_decode 0x00080000 $ENROLL_FLAGS) | Should -Be @('NO_SECURITY_EXTENSION')
    }
}

Describe '_decodeBinding (StrongCertificateBindingEnforcement)' {
    It 'maps 0 -> disabled' { _decodeBinding 0 | Should -Be 'disabled' }
    It 'maps 1 -> permissive' { _decodeBinding 1 | Should -Be 'permissive' }
    It 'maps 2 -> strict' { _decodeBinding 2 | Should -Be 'strict' }
    It 'maps an unexpected value -> unknown' { _decodeBinding 99 | Should -Be 'unknown' }
}

Describe '_parseCertutilFlagLines' {
    It 'extracts the decoded flag names from certutil -getreg output' {
        $lines = @(
            '  InterfaceFlags REG_DWORD = 641 (1601)',
            '    IF_LOCKICERTREQUEST -- 1',
            '    IF_ENFORCEENCRYPTICERTREQUEST -- 200 (512)'
        )
        (_parseCertutilFlagLines $lines) | Should -Be @('IF_LOCKICERTREQUEST', 'IF_ENFORCEENCRYPTICERTREQUEST')
    }
    It 'returns no flags when no flag lines are present' {
        ((_parseCertutilFlagLines @('some header', 'CertUtil: -getreg command completed.')) -join ',') | Should -Be ''
    }
}

Describe '_parseCertutilDwordLines' {
    It 'reads the first hex DWORD from certutil output' {
        $lines = @('  AuditFilter REG_DWORD = 7f (127)')
        _parseCertutilDwordLines $lines | Should -Be 127
    }
    It 'returns $null when no DWORD line is present' {
        _parseCertutilDwordLines @('CommonName REG_SZ = lab-ca') | Should -Be $null
    }
}

Describe '_epaToken (Extended Protection token)' {
    It 'maps require values' { _epaToken 2 | Should -Be 'require'; _epaToken 'Require' | Should -Be 'require' }
    It 'maps allow values' { _epaToken 1 | Should -Be 'allow' }
    It 'maps none/off/empty values' { _epaToken 0 | Should -Be 'none'; _epaToken '' | Should -Be 'none'; _epaToken 'Off' | Should -Be 'none' }
    It 'maps an unrecognized value to unknown' { _epaToken 'weird' | Should -Be 'unknown' }
}

Describe '_classifyApp (IIS app path -> endpoint kind)' {
    It 'classifies /certsrv as web_enrollment' { _classifyApp '/certsrv' | Should -Be 'web_enrollment' }
    It 'classifies an mscep path as ndes' { _classifyApp '/CertSrv/mscep' | Should -Be 'ndes' }
    It 'classifies a CES/CEP path as ces' { _classifyApp '/ADPolicyProvider_CEP_Kerberos' | Should -Be 'ces' }
    It 'returns $null for an unrelated app' { _classifyApp '/owa' | Should -Be $null }
}
