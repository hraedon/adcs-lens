<#
.SYNOPSIS
  Read-only AD CS estate collector for adcs-lens (Plan 001 Phase 1).

.DESCRIPTION
  Captures the inputs the adcs-lens deterministic core ingests, READ-ONLY:
    * CA registry config via `certutil -getreg` (policy EditFlags, CA
      InterfaceFlags, AuditFilter, policy DisableExtensionList) — read locally
      on the CA host.
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

.PARAMETER CollectDcMapping
  Opt in to the ESC10/ESC14 DC certificate-mapping passes (they widen the export
  footprint beyond the AD CS config). Enables esc14-altsecid (an LDAP read of
  principal altSecurityIdentities). Without it both passes are skipped + noted.

.PARAMETER DcRegistryUserB64 / .PARAMETER DcRegistryPassB64
  Base64 (UTF-8) creds with remote-registry read on the domain controllers, used
  by the esc10-dc-registry pass (KDC StrongCertificateBindingEnforcement + Schannel
  CertificateMappingMethods via WMI). Only used when -CollectDcMapping is set; if
  absent the esc10-dc-registry pass is skipped + noted.
#>
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
  [Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $OutDir,
  [Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $LdapUserB64,
  [Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $LdapPassB64,
  # ESC10/ESC14 DC certificate-mapping passes widen the export footprint, so they
  # are opt-in. When set, esc14-altsecid (LDAP altSecurityIdentities) runs; the
  # esc10-dc-registry pass additionally needs DC-admin creds for remote registry.
  [Parameter(ParameterSetName = 'Collect')] [switch] $CollectDcMapping,
  [Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryUserB64,
  [Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryPassB64,
  # Self-test: define the pure helper functions and return before any collection.
  # Lets the Pester suite dot-source this script and exercise the parsers/decoders
  # on Linux pwsh (the LDAP/WMI/certutil paths need Windows + a live estate).
  [Parameter(Mandatory, ParameterSetName = 'SelfTest')] [switch] $FunctionsOnly
)

$ErrorActionPreference = 'Stop'
$COLLECTOR_VERSION = '0.4.4'

function _b64([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }

# Use JavaScriptSerializer, not ConvertTo-Json: PS 5.1's ConvertTo-Json collapses
# single-element arrays to scalars (top-level AND nested), which would corrupt the
# list fields adcs_lens.ingest requires. JavaScriptSerializer honours the real
# .NET type, so a 1-element array stays a JSON array.
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

# Schannel CertificateMappingMethods bits (TLS registry-settings doc). The UPN bit
# (0x4) is ESC10 case 1. Kept here (not in the DC-mapping block) so the self-test
# can exercise the decode.
$SCHANNEL_BITS = [ordered]@{ 1 = 'subject_issuer'; 2 = 'issuer'; 4 = 'upn'; 8 = 's4u2self'; 16 = 's4u2self_explicit' }

# KDC StrongCertificateBindingEnforcement (0/1/2 -> disabled/permissive/strict).
function _decodeBinding([int]$v) {
  switch ($v) { 0 { 'disabled' } 1 { 'permissive' } 2 { 'strict' } default { 'unknown' } }
}

# Pure parsers for certutil -getreg output (split from the certutil invocation so
# the line-matching can be unit-tested without certutil/Windows).
function _parseCertutilFlagLines($lines) {
  $out = @()
  foreach ($line in $lines) { if ($line -match '^\s+([A-Z][A-Z0-9_]+)\s+--\s') { $out += $Matches[1] } }
  ,$out
}
function _parseCertutilDwordLines($lines) {
  foreach ($line in $lines) {
    if ($line -match '=\s*([0-9a-fA-Fx]+)\s*\(') { return [Convert]::ToInt64($Matches[1].Replace('0x', ''), 16) }
  }
  return $null
}
# Parse certutil -getreg REG_MULTI_SZ output (e.g. policy\DisableExtensionList -> ESC16).
# certutil prints the value name + 'REG_MULTI_SZ' then each string on its own indented
# line; a first value may also follow '=' on the marker line. Captures OID-style tokens
# (no internal spaces); sufficient for DisableExtensionList, whose values are bare OIDs.
function _parseCertutilMultiSzLines($lines) {
  $out = @()
  $inMulti = $false
  foreach ($line in $lines) {
    if ($line -match 'REG_MULTI_SZ') {
      $inMulti = $true
      if ($line -match '=\s*(.+)$') {
        foreach ($tok in ($Matches[1] -split '\s+')) { if ($tok) { $out += $tok } }
      }
      continue
    }
    if ($inMulti) {
      if ($line -match '^\s+(\S+)') { $out += $Matches[1] }
      elseif ($line.Trim().Length) { break }
    }
  }
  ,$out
}

# IIS enrollment-endpoint classifiers (ESC8). Top-level so the self-test reaches
# them; the live IIS pass below calls these.
function _epaToken($v) {
  switch ([string]$v) {
    '2' { 'require' } 'Require' { 'require' }
    '1' { 'allow' }   'Allow'   { 'allow' }
    '0' { 'none' }    'Off' { 'none' } 'None' { 'none' } '' { 'none' }
    default { 'unknown' }
  }
}
function _classifyApp([string]$p) {
  $l = $p.ToLower()
  if ($l -match 'mscep') { return 'ndes' }            # NDES/SCEP
  if ($l -match 'certsrv') { return 'web_enrollment' } # /certsrv
  if ($l -match '_ces_' -or $l -match 'cep') { return 'ces' }
  return $null
}

# --- nTSecurityDescriptor -> ACEs (ESC1/ESC4/ESC5/ESC7 inputs) --------------
# Extended-right GUIDs we care about; an all-zero ObjectType on an ExtendedRight
# ACE means "all extended rights" (which includes Enroll). The same all-zero
# ObjectType on a WriteProperty ACE means "write *all* properties" (blanket) —
# emitted as 'WritePropertyAll' so ESC4 can flag it (a blanket WriteProperty can
# rewrite msPKI-Certificate-Name-Flag → ESC1). A non-zero ObjectType scopes the
# write to one property/property-set and stays plain 'WriteProperty' (benign).
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
      } elseif ($flag -eq 'WriteProperty') {
        if ($ot -eq $ZERO_GUID) { $rights += 'WritePropertyAll' }  # blanket: all properties
        else                    { $rights += 'WriteProperty' }     # scoped to one property/set
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

# --- PKI object DACLs (ESC5) ------------------------------------------------
# Read the nTSecurityDescriptor on a single object (Base scope) and tokenise its
# ACEs via _parseAces. Pure LDAP against the Configuration NC — no certutil, so
# this pass runs from any domain member with the explicit bind creds.
function _objAcl([string]$dn, [string]$kind) {
  $de = New-Object DirectoryServices.DirectoryEntry("LDAP://$dn", $LdapUser, $LdapPass)
  $s = New-Object DirectoryServices.DirectorySearcher($de)
  $s.SearchScope = 'Base'; $s.Filter = '(objectClass=*)'
  $s.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl'
  $r = $null
  try { $r = $s.FindOne() } catch { return $null }   # object absent / no read
  if (-not $r) { return $null }
  $sdb = if ($r.Properties['ntsecuritydescriptor'].Count) { [byte[]]$r.Properties['ntsecuritydescriptor'][0] } else { $null }
  [ordered]@{ object_dn = $dn; kind = $kind; security = (_parseAces $sdb) }
}
# Enumerate child objects under a container and tokenise each one's DACL.
function _childAcls([string]$containerDn, [string]$filter, [string]$kind) {
  $out = @()
  $root = New-Object DirectoryServices.DirectoryEntry("LDAP://$containerDn", $LdapUser, $LdapPass)
  foreach ($r in (_search $root $filter)) {
    $dn  = [string]$r.Properties['distinguishedname'][0]
    $sdb = if ($r.Properties['ntsecuritydescriptor'].Count) { [byte[]]$r.Properties['ntsecuritydescriptor'][0] } else { $null }
    $out += [ordered]@{ object_dn = $dn; kind = $kind; security = (_parseAces $sdb) }
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
function _certutilFlags([string]$regpath) { _parseCertutilFlagLines (& certutil -getreg $regpath 2>$null) }
function _certutilDword([string]$regpath) { _parseCertutilDwordLines (& certutil -getreg $regpath 2>$null) }
function _certutilMultiSz([string]$regpath) { _parseCertutilMultiSzLines (& certutil -getreg $regpath 2>$null) }

# --- self-test boundary -----------------------------------------------------
# Everything above is a pure function/data definition. The Pester suite dot-sources
# this script with -FunctionsOnly and stops here; nothing below runs in that mode.
if ($PSCmdlet.ParameterSetName -eq 'SelfTest') { return }

$LdapUser = _b64 $LdapUserB64
$LdapPass = _b64 $LdapPassB64
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Web.Extensions
$script:JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$script:JS.MaxJsonLength = [int]::MaxValue

$caCommonName = ((& certutil -getreg CA\CommonName 2>$null) | Where-Object { $_ -match 'CommonName REG_SZ = (.+)' } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
$editFlags      = _certutilFlags 'policy\EditFlags'
$interfaceFlags = _certutilFlags 'CA\InterfaceFlags'
$auditFilter    = _certutilDword 'CA\AuditFilter'
$disabledExt    = _certutilMultiSz 'policy\DisableExtensionList'

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
    disabled_extensions = (@($disabledExt))
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
    acl_obtained      = ($null -ne $sdb)    # SD requested & obtained (per-template gap signal)
  }
}

# --- enterprise OID objects (issuance policies) -----------------------------
$oidRoot = _ldapRoot 'CN=OID'
$oids = @()
foreach ($r in (_search $oidRoot '(objectClass=msPKI-Enterprise-Oid)')) {
  $p = $r.Properties
  # The OID->group link (ESC13) is msDS-OIDToGroupLink (a group DN), NOT
  # msPKI-OIDToGroupLink — the latter does not exist, so the old name always
  # read $null and ESC13 could never fire on real data.
  $gl = if ($p['msds-oidtogrouplink'].Count) { [string]$p['msds-oidtogrouplink'][0] } else { $null }
  $oids += [ordered]@{
    oid        = [string]$p['mspki-cert-template-oid'][0]
    name       = [string]$p['displayname'][0]
    group_link = $gl
  }
}

# --- PKI object ACLs (ESC5) --------------------------------------------------
# Capture DACLs on the Public Key Services containers + CA objects. A low-priv
# trustee with object-control rights (WriteDacl/WriteOwner/GenericWrite/
# GenericAll) on any of these is the ESC5 escalation primitive.
$cfgNc = (New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE", $LdapUser, $LdapPass)).configurationNamingContext
$pksDn = "CN=Public Key Services,CN=Services,$cfgNc"
$pkiAcls = @()
foreach ($pair in @(
    @($pksDn,                                        'pks_container'),
    @("CN=NTAuthCertificates,$pksDn",                'ntauth'),
    @("CN=AIA,$pksDn",                               'aia'),
    @("CN=CDP,$pksDn",                               'cdp'),
    @("CN=Certification Authorities,$pksDn",         'pks_container'),
    @("CN=Enrollment Services,$pksDn",               'pks_container'))) {
  $a = _objAcl $pair[0] $pair[1]
  if ($a) { $pkiAcls += $a }
}
# Individual CA objects: trusted roots + issuing enrollment services.
$pkiAcls += _childAcls "CN=Certification Authorities,$pksDn" '(objectClass=certificationAuthority)' 'ca_object'
$pkiAcls += _childAcls "CN=Enrollment Services,$pksDn"       '(objectClass=pKIEnrollmentService)'   'ca_object'

# --- CA role security (ESC7) -------------------------------------------------
# Keyed by the CA name used in ca-config.json so ingest joins them to the CA.
$caSecurity = [ordered]@{}
foreach ($ca in $caConfig) { $caSecurity[$ca.name] = (_caSecurityAces $ca.name) }

# --- HTTP enrollment endpoints (ESC8) ---------------------------------------
# IIS bindings + Windows-auth + Extended Protection on the Web Enrollment
# (/certsrv) and CES apps. Needs WebAdministration on the host; absent off the
# enrollment host, so the pass is skipped + noted (the detector degrades).
$webEndpoints = @()
$endpointsSkipped = $true
try { Import-Module WebAdministration -ErrorAction Stop; $endpointsSkipped = $false } catch { }
if (-not $endpointsSkipped) {
  foreach ($site in (Get-Website)) {
    $protos = @(); foreach ($b in $site.bindings.Collection) { if ($protos -notcontains [string]$b.protocol) { $protos += [string]$b.protocol } }
    foreach ($app in (Get-WebApplication -Site $site.Name)) {
      $kind = _classifyApp ([string]$app.path)
      if (-not $kind) { continue }
      $ps = "IIS:\Sites\$($site.Name)\" + ([string]$app.path).TrimStart('/')
      $wa = (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled -ErrorAction SilentlyContinue).Value
      $tc = (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name 'extendedProtection.tokenChecking' -ErrorAction SilentlyContinue).Value
      $ssl = [string](Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction SilentlyContinue).Value
      $provs = @()
      foreach ($p in (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication/providers' -Name Collection -ErrorAction SilentlyContinue)) {
        if ($p.value) { $provs += ([string]$p.value).ToLower() }
      }
      $webEndpoints += [ordered]@{
        kind           = $kind
        name           = [string]$app.path
        transports     = (@($protos))
        ssl_required   = ($ssl -match 'Ssl')
        windows_auth   = [bool]$wa
        auth_providers = (@($provs))
        epa            = (_epaToken $tc)
      }
    }
  }
}

# --- DC certificate mapping (ESC10 / ESC14) ---------------------------------
# Opt-in (-CollectDcMapping). esc14-altsecid is an LDAP read of principal
# altSecurityIdentities (raw values; the detector classifies the X.509 form).
# esc10-dc-registry reads each DC's KDC StrongCertificateBindingEnforcement and
# Schannel CertificateMappingMethods DWORD via WMI StdRegProv with explicit creds.
$dcConfigs = @()
$principalMappings = @()
$esc10Skipped = $true
$esc14Skipped = $true
if ($CollectDcMapping) {
  $domNc = (New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE", $LdapUser, $LdapPass)).defaultNamingContext

  # esc14-altsecid: every principal carrying an altSecurityIdentities value.
  try {
    $domRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$domNc", $LdapUser, $LdapPass)
    $s = New-Object DirectoryServices.DirectorySearcher($domRoot)
    $s.Filter = '(altSecurityIdentities=*)'; $s.PageSize = 200; $s.SearchScope = 'Subtree'
    [void]$s.PropertiesToLoad.Add('distinguishedName')
    [void]$s.PropertiesToLoad.Add('altSecurityIdentities')
    foreach ($r in $s.FindAll()) {
      $maps = @(); foreach ($m in $r.Properties['altsecurityidentities']) { $maps += [string]$m }
      $principalMappings += [ordered]@{
        dn       = [string]$r.Properties['distinguishedname'][0]
        mappings = (@($maps))
      }
    }
    $esc14Skipped = $false
  } catch { Write-Warning "esc14-altsecid failed: $($_.Exception.Message)" }

  # esc10-dc-registry: per-DC KDC + Schannel registry (needs DC-admin creds).
  if ($DcRegistryUserB64 -and $DcRegistryPassB64) {
    $HKLM = [uint32]2147483650
    $dcCred = New-Object Management.Automation.PSCredential(
      (_b64 $DcRegistryUserB64),
      (ConvertTo-SecureString (_b64 $DcRegistryPassB64) -AsPlainText -Force))
    $localHost = ([string](hostname)).ToLower()
    # Discover DCs from the domain NC (server-trust accounts: UAC bit 0x2000).
    $dcRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$domNc", $LdapUser, $LdapPass)
    $ds = New-Object DirectoryServices.DirectorySearcher($dcRoot)
    $ds.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
    $ds.PageSize = 200; $ds.SearchScope = 'Subtree'; [void]$ds.PropertiesToLoad.Add('dnshostname')
    foreach ($r in $ds.FindAll()) {
      $dcDns = [string]$r.Properties['dnshostname'][0]
      if (-not $dcDns) { continue }
      $binding = 'unknown'; $schannelMethods = @()
      try {
        if ($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) {
          $reg = Get-WmiObject -Namespace 'root\default' -Class StdRegProv -List
        } else {
          $reg = Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\default' -Class StdRegProv -List
        }
        $kdc = $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Services\Kdc', 'StrongCertificateBindingEnforcement')
        if ($kdc.ReturnValue -eq 0 -and $null -ne $kdc.uValue) {
          $binding = _decodeBinding ([int]$kdc.uValue)
        }
        $sch = $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL', 'CertificateMappingMethods')
        if ($sch.ReturnValue -eq 0 -and $null -ne $sch.uValue) {
          # _decode iterates entries by key/value — indexing an [ordered] dict with
          # an int key selects BY POSITION, which silently mis-decodes the bits.
          $schannelMethods = _decode ([int]$sch.uValue) $SCHANNEL_BITS
        }
      } catch { Write-Warning "esc10-dc-registry $dcDns failed: $($_.Exception.Message)" }
      $dcConfigs += [ordered]@{
        name                                   = $dcDns
        strong_certificate_binding_enforcement = $binding
        schannel_mapping_methods               = (@($schannelMethods))
      }
    }
    $esc10Skipped = $false
  }
}

# --- manifest ----------------------------------------------------------------
$skippedPasses = @('certs')                                   # cert/CRL DER ([certs] extra)
if ($endpointsSkipped) { $skippedPasses += 'enrollment-endpoints' }
if ($esc10Skipped) { $skippedPasses += 'esc10-dc-registry' }
if ($esc14Skipped) { $skippedPasses += 'esc14-altsecid' }
$manifest = [ordered]@{
  collector_version = $COLLECTOR_VERSION
  collected_at      = (Get-Date).ToUniversalTime().ToString('o')
  host              = [string](hostname)
  domain            = ((New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE", $LdapUser, $LdapPass)).defaultNamingContext)
  skipped_passes    = (@($skippedPasses))
}

# --- write the export (force arrays so single items don't collapse) ---------
_writeJson @($caConfig)  'ca-config.json'
_writeJson @($templates) 'templates.json'
_writeJson @($oids)      'oid-objects.json'
_writeJson @($pkiAcls)   'pki-acls.json'
_writeJson @($webEndpoints) 'web-endpoints.json'
_writeJson @($dcConfigs) 'dc-config.json'
_writeJson @($principalMappings) 'principal-mappings.json'
_writeJson $enrollmentServices 'enrollment-services.json'
_writeJson $caSecurity   'ca-security.json'
_writeJson $manifest     'collector-manifest.json'

Write-Output ("OK cas={0} templates={1} oids={2} pkiacls={3} endpoints={4} dcs={5} altsecid={6} editflags=[{7}] ca={8}" -f `
  $caConfig.Count, $templates.Count, $oids.Count, $pkiAcls.Count, $webEndpoints.Count, $dcConfigs.Count, $principalMappings.Count, ($editFlags -join ','), $caCommonName)
