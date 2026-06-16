<#
.SYNOPSIS
  Read-only AD CS estate collector for adcs-lens (Plan 001 Phase 1).

.DESCRIPTION
  Captures the inputs the adcs-lens deterministic core ingests, READ-ONLY:
    * CA registry config via `certutil -getreg` (policy EditFlags, CA
      InterfaceFlags, AuditFilter) — read locally on the CA host.
    * AD Public Key Services objects via LDAP with EXPLICIT credentials
      (enrollment services, certificate templates, enterprise OIDs).

  It NEVER enrolls, requests, writes, or relays. It only reads. Output is a
  directory of JSON files matching adcs_lens.ingest's contract.

  Auth note: a key-based SSH logon has no network credential (double-hop), so
  LDAP binds use explicit creds passed as base64 (avoids quoting + argv exposure).

.PARAMETER OutDir
  Directory to write the export into (created if absent).

.PARAMETER LdapUserB64 / .PARAMETER LdapPassB64
  Base64 (UTF-8) of the LDAP bind username (UPN or DOMAIN\user) and password.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $OutDir,
  [Parameter(Mandatory)] [string] $LdapUserB64,
  [Parameter(Mandatory)] [string] $LdapPassB64
)

$ErrorActionPreference = 'Stop'
$COLLECTOR_VERSION = '0.1.0'

function _b64([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
$LdapUser = _b64 $LdapUserB64
$LdapPass = _b64 $LdapPassB64

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
# Use JavaScriptSerializer, not ConvertTo-Json: PS 5.1's ConvertTo-Json collapses
# single-element arrays to scalars (top-level AND nested), which would corrupt the
# list fields adcs_lens.ingest requires. JavaScriptSerializer honours the real
# .NET type, so a 1-element array stays a JSON array.
Add-Type -AssemblyName System.Web.Extensions
$script:JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$script:JS.MaxJsonLength = [int]::MaxValue
function _writeJson($obj, [string]$name) {
  $p = Join-Path $OutDir $name
  $dir = Split-Path $p -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [IO.File]::WriteAllText($p, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))
}

# --- LDAP plumbing (explicit creds) -----------------------------------------
function _ldapRoot([string]$container) {
  $cfg = (New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE", $LdapUser, $LdapPass)).configurationNamingContext
  $path = if ($container) { "LDAP://$container,CN=Public Key Services,CN=Services,$cfg" }
          else { "LDAP://CN=Public Key Services,CN=Services,$cfg" }
  New-Object DirectoryServices.DirectoryEntry($path, $LdapUser, $LdapPass)
}
function _search([DirectoryServices.DirectoryEntry]$root, [string]$filter) {
  $s = New-Object DirectoryServices.DirectorySearcher($root)
  $s.Filter = $filter; $s.PageSize = 200; $s.SearchScope = 'Subtree'
  # Request the DACL so nTSecurityDescriptor comes back with ACEs (read-only).
  $s.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl'
  $s.FindAll()
}

# --- bit-flag decoders (emit the documented MS names) -----------------------
$NAME_FLAGS = [ordered]@{
  0x00000001 = 'ENROLLEE_SUPPLIES_SUBJECT'
  0x00010000 = 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS'
  0x00400000 = 'SUBJECT_ALT_REQUIRE_UPN'
  0x00800000 = 'SUBJECT_ALT_REQUIRE_EMAIL'
  0x04000000 = 'SUBJECT_ALT_REQUIRE_DNS'
  0x08000000 = 'SUBJECT_REQUIRE_DNS_AS_CN'
  0x10000000 = 'SUBJECT_REQUIRE_DIRECTORY_PATH'
  0x20000000 = 'SUBJECT_REQUIRE_EMAIL'
  0x40000000 = 'SUBJECT_REQUIRE_COMMON_NAME'
  0x00000008 = 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME'
}
$ENROLL_FLAGS = [ordered]@{
  0x00000002 = 'PEND_ALL_REQUESTS'                 # manager approval
  0x00000008 = 'PUBLISH_TO_DS'
  0x00000020 = 'AUTO_ENROLLMENT'
  0x00000100 = 'USER_INTERACTION_REQUIRED'
  0x00080000 = 'NO_SECURITY_EXTENSION'             # ESC9 (CT_FLAG_NO_SECURITY_EXTENSION)
}
function _decode([int]$value, $map) {
  $out = @()
  # Iterate entries (not $map[$k]): indexing an [ordered] dict with an int key
  # selects BY POSITION, not by key, which silently mis-decodes / yields $null.
  foreach ($e in $map.GetEnumerator()) { if ($value -band $e.Key) { $out += $e.Value } }
  ,$out
}

# --- nTSecurityDescriptor -> ACEs (ESC1/ESC4/ESC5/ESC7 inputs) --------------
# Extended-right GUIDs we care about; an all-zero ObjectType on an ExtendedRight
# ACE means "all extended rights" (which includes Enroll).
$ENROLL_GUID     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AUTOENROLL_GUID = 'a05b8cc2-17b1-4cc8-8b00-94f99c9c2cca'
$ZERO_GUID       = '00000000-0000-0000-0000-000000000000'
function _parseAces([byte[]]$sdBytes) {
  $out = @()
  if (-not $sdBytes -or $sdBytes.Length -eq 0) { return ,$out }
  $sd = New-Object DirectoryServices.ActiveDirectorySecurity
  $sd.SetSecurityDescriptorBinaryForm($sdBytes)
  # Resolve trustees to SIDs (offline-safe); the friendly name is best-effort.
  foreach ($a in $sd.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $sid  = [string]$a.IdentityReference.Value
    $name = ''
    try { $name = [string]$a.IdentityReference.Translate([Security.Principal.NTAccount]).Value } catch { }
    $ot = $a.ObjectType.ToString()
    $rights = @()
    foreach ($flag in ($a.ActiveDirectoryRights.ToString() -split ',\s*')) {
      if ($flag -eq 'ExtendedRight') {
        if     ($ot -eq $ENROLL_GUID)     { $rights += 'Enroll' }
        elseif ($ot -eq $AUTOENROLL_GUID) { $rights += 'AutoEnroll' }
        elseif ($ot -eq $ZERO_GUID)       { $rights += 'AllExtendedRights' }
        else                              { $rights += 'ExtendedRight' }
      } else {
        $rights += $flag
      }
    }
    $out += [ordered]@{
      trustee_sid  = $sid
      trustee_name = $name
      rights       = (@($rights))
      ace_type     = [string]$a.AccessControlType   # 'Allow' | 'Deny'
    }
  }
  ,$out
}

# The CA's own role permissions (ESC7) live in the registry "Security" REG_BINARY,
# not AD. Parse the raw SD so we get SIDs + CA access-mask bits directly (offline),
# rather than certutil's name-resolved text (domain name lookups hit the double-hop).
function _caSecurityAces([string]$caName) {
  $out = @()
  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName")
  if (-not $key) { return ,$out }
  $bytes = $key.GetValue('Security')
  if (-not $bytes) { return ,$out }
  $rsd = New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)
  foreach ($a in $rsd.DiscretionaryAcl) {
    $m = [int]$a.AccessMask
    $rights = @()
    if ($m -band 0x1)   { $rights += 'ManageCA' }            # CA_ACCESS_ADMIN
    if ($m -band 0x2)   { $rights += 'ManageCertificates' }  # CA_ACCESS_OFFICER
    if ($m -band 0x4)   { $rights += 'Auditor' }
    if ($m -band 0x8)   { $rights += 'Operator' }
    if ($m -band 0x100) { $rights += 'Read' }
    if ($m -band 0x200) { $rights += 'Enroll' }
    $type = if ($a.AceQualifier -eq 'AccessDenied') { 'Deny' } else { 'Allow' }
    $out += [ordered]@{
      trustee_sid  = [string]$a.SecurityIdentifier.Value
      trustee_name = ''
      rights       = (@($rights))
      ace_type     = $type
    }
  }
  ,$out
}

# --- CA registry via certutil (local, no network cred needed) ---------------
# Parse certutil's own decoded "FLAG_NAME -- value" lines for EditFlags/InterfaceFlags.
function _certutilFlags([string]$regpath) {
  $out = @()
  foreach ($line in (& certutil -getreg $regpath 2>$null)) {
    if ($line -match '^\s+([A-Z][A-Z0-9_]+)\s+--\s') { $out += $Matches[1] }
  }
  ,$out
}
function _certutilDword([string]$regpath) {
  foreach ($line in (& certutil -getreg $regpath 2>$null)) {
    if ($line -match '=\s*([0-9a-fA-Fx]+)\s*\(') { return [Convert]::ToInt64($Matches[1].Replace('0x',''),16) }
  }
  return $null
}
$caCommonName = ((& certutil -getreg CA\CommonName 2>$null) | Where-Object { $_ -match 'CommonName REG_SZ = (.+)' } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
$editFlags      = _certutilFlags 'policy\EditFlags'
$interfaceFlags = _certutilFlags 'CA\InterfaceFlags'
$auditFilter    = _certutilDword 'CA\AuditFilter'

# --- enrollment services (CAs) ----------------------------------------------
$enrollRoot = _ldapRoot 'CN=Enrollment Services'
$caConfig = @()
$enrollmentServices = [ordered]@{}
foreach ($r in (_search $enrollRoot '(objectClass=pKIEnrollmentService)')) {
  $p = $r.Properties
  $cn = [string]$p['cn'][0]; $dns = [string]$p['dnshostname'][0]
  $templates = @(); foreach ($t in $p['certificatetemplates']) { $templates += [string]$t }
  $enrollmentServices[$cn] = $templates
  $caConfig += [ordered]@{
    name           = $cn
    dns            = $dns
    config_string  = "$dns\$cn"
    kind           = 'issuing'
    edit_flags     = (@($editFlags))
    interface_flags= (@($interfaceFlags))
    audit_filter   = $auditFilter
    validity       = ''
    roles          = @()
  }
}

# --- certificate templates --------------------------------------------------
$tmplRoot = _ldapRoot 'CN=Certificate Templates'
$templates = @()
foreach ($r in (_search $tmplRoot '(objectClass=pKICertificateTemplate)')) {
  $p = $r.Properties
  $nf = if ($p['mspki-certificate-name-flag'].Count) { [int]$p['mspki-certificate-name-flag'][0] } else { 0 }
  $ef = if ($p['mspki-enrollment-flag'].Count) { [int]$p['mspki-enrollment-flag'][0] } else { 0 }
  $ekus = @(); foreach ($e in $p['pkiextendedkeyusage']) { $ekus += [string]$e }
  $pol  = @(); foreach ($o in $p['mspki-certificate-policy']) { $pol += [string]$o }
  $sdb  = if ($p['ntsecuritydescriptor'].Count) { [byte[]]$p['ntsecuritydescriptor'][0] } else { $null }
  $templates += [ordered]@{
    name              = [string]$p['cn'][0]
    display_name      = [string]$p['displayname'][0]
    schema_version    = if ($p['mspki-template-schema-version'].Count) { [int]$p['mspki-template-schema-version'][0] } else { 1 }
    oid               = [string]$p['mspki-cert-template-oid'][0]
    ekus              = (@($ekus))
    name_flags        = (_decode $nf $NAME_FLAGS)
    enrollment_flags  = (_decode $ef $ENROLL_FLAGS)
    min_key_size      = if ($p['mspki-minimal-key-size'].Count) { [int]$p['mspki-minimal-key-size'][0] } else { $null }
    issuance_policy_oids = (@($pol))
    security          = (_parseAces $sdb)   # template DACL → ACEs (ESC1/ESC4)
  }
}

# --- enterprise OID objects (issuance policies) -----------------------------
$oidRoot = _ldapRoot 'CN=OID'
$oids = @()
foreach ($r in (_search $oidRoot '(objectClass=msPKI-Enterprise-Oid)')) {
  $p = $r.Properties
  $gl = if ($p['mspki-oidtogrouplink'].Count) { [string]$p['mspki-oidtogrouplink'][0] } else { $null }
  $oids += [ordered]@{
    oid            = [string]$p['mspki-cert-template-oid'][0]
    name           = [string]$p['displayname'][0]
    group_link_sid = $gl
  }
}

# --- CA role security (ESC7) -------------------------------------------------
# Keyed by the CA name used in ca-config.json so ingest joins them to the CA.
$caSecurity = [ordered]@{}
foreach ($ca in $caConfig) { $caSecurity[$ca.name] = (_caSecurityAces $ca.name) }

# --- manifest ----------------------------------------------------------------
$manifest = [ordered]@{
  collector_version = $COLLECTOR_VERSION
  collected_at      = (Get-Date).ToUniversalTime().ToString('o')
  host              = [string](hostname)
  domain            = ((New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE", $LdapUser, $LdapPass)).defaultNamingContext)
  skipped_passes    = @('pki-acls', 'certs')  # remaining Phase 1b / [certs]
}

# --- write the export (force arrays so single items don't collapse) ---------
_writeJson @($caConfig)  'ca-config.json'
_writeJson @($templates) 'templates.json'
_writeJson @($oids)      'oid-objects.json'
_writeJson @()           'pki-acls.json'
_writeJson $enrollmentServices 'enrollment-services.json'
_writeJson $caSecurity   'ca-security.json'
_writeJson $manifest     'collector-manifest.json'

Write-Output ("OK cas={0} templates={1} oids={2} editflags=[{3}] ca={4}" -f `
  $caConfig.Count, $templates.Count, $oids.Count, ($editFlags -join ','), $caCommonName)
