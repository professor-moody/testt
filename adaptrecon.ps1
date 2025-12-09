<#
.SYNOPSIS
  ADAPT RECON - Windows System Reconnaissance & Security Auditing Tool
.DESCRIPTION
  Security assessment and enumeration script for authorized penetration testing, CTF challenges,
  security research, lab environments, and systems administration tasks.
.EXAMPLE
  # Default - normal operation with username/password audit in drives/registry
  .\adaptrecon.ps1

  # Include Excel files in search: .xls, .xlsx, .xlsm
  .\adaptrecon.ps1 -ScanExcel

  # Full audit - normal operation with APIs / Keys / Tokens
  ## This will produce false positives ##
  .\adaptrecon.ps1 -DeepScan

  # Add Time stamps to each command
  .\adaptrecon.ps1 -ShowTime

.NOTES
  Version:        2.0
  Purpose:        CTF / Security Research / Lab / SysAdmin
  Compatibility:  PowerShell 5+
#>

######################## CORE FUNCTIONS ########################

[CmdletBinding()]
param(
  [switch]$ShowTime,
  [switch]$DeepScan,
  [switch]$ScanExcel
)

# Extract KB identifiers from patch titles
function Get-PatchIdentifier {
  param(
    [string]$title
  )
  if (($title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value) {
    return (($title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value)
  }
  elseif (($title | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value) {
    return (($title | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value)
  }
}

function Test-PathPermissions {
  param(
    $Target, $ServiceName)
  if ($null -ne $target) {
    try {
      $ACLObject = Get-Acl $target -ErrorAction SilentlyContinue
    }
    catch { $null }

    if ($ACLObject) {
      $Identity = @()
      $Identity += "$env:COMPUTERNAME\$env:USERNAME"
      if ($ACLObject.Owner -like $Identity ) { Write-Host "$Identity has ownership of $Target" -ForegroundColor Red }
      whoami.exe /groups /fo csv | select-object -skip 2 | ConvertFrom-Csv -Header 'group name' | Select-Object -ExpandProperty 'group name' | ForEach-Object { $Identity += $_ }
      $IdentityFound = $false
      foreach ($i in $Identity) {
        $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }
        $UserPermission = ""
        switch -WildCard ($Permission.FileSystemRights) {
          "FullControl" {
            $userPermission = "FullControl"
            $IdentityFound = $true
          }
          "Write*" {
            $userPermission = "Write"
            $IdentityFound = $true
          }
          "Modify" {
            $userPermission = "Modify"
            $IdentityFound = $true
          }
        }
        Switch ($permission.RegistryRights) {
          "FullControl" {
            $userPermission = "FullControl"
            $IdentityFound = $true
          }
        }
        if ($UserPermission) {
          if ($ServiceName) { Write-Host "$ServiceName found with permissions issue:" -ForegroundColor Red }
          Write-Host -ForegroundColor red "Identity $($permission.IdentityReference) has '$userPermission' perms for $Target"
        }
      }
      if ($IdentityFound -eq $false) {
        if ($Target.Length -gt 3) {
          $Target = Split-Path $Target
          Test-PathPermissions $Target -ServiceName $ServiceName
        }
      }
    }
    else {
      $Target = Split-Path $Target
      Test-PathPermissions $Target $ServiceName
    }
  }
}

function Find-UnquotedServicePaths {
  Write-Host "Scanning services for unquoted paths..."
  $services = Get-WmiObject -Class Win32_Service |
    Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") }
  if ($($services | Measure-Object).Count -lt 1) {
    Write-Host "No unquoted service paths detected"
  }
  else {
    $services | ForEach-Object {
      Write-Host "Unquoted Service Path detected!" -ForegroundColor red
      Write-Host Name: $_.Name
      Write-Host PathName: $_.PathName
      Write-Host StartName: $_.StartName
      Write-Host StartMode: $_.StartMode
      Write-Host Running: $_.State
    }
  }
}

function Show-ElapsedTime {
  Write-Host "Elapsed: $($reconTimer.Elapsed.Minutes):$($reconTimer.Elapsed.Seconds)"
}

function Get-ClipboardContent {
  Add-Type -AssemblyName PresentationCore
  $text = [Windows.Clipboard]::GetText()
  if ($text) {
    Write-Host ""
    if ($ShowTime) { Show-ElapsedTime }
    Write-Host -ForegroundColor Blue "=========|| Clipboard Contents:"
    Write-Host $text
  }
}

function Get-ADContext {
  try {
    return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
  }
  catch {
    return $null
  }
}

function Resolve-SidToAccount {
  param(
    $SidInput
  )
  if ($null -eq $SidInput) { return $null }
  try {
    if ($SidInput -is [System.Security.Principal.SecurityIdentifier]) {
      $sidObject = $SidInput
    }
    else {
      $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SidInput)
    }
    return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
  }
  catch {
    try { return $sidObject.Value }
    catch { return [string]$SidInput }
  }
}

function Find-WeakDnsZonePermissions {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  $forestDN = $DomainContext.Forest.RootDomain.GetDirectoryEntry().distinguishedName
  $paths = @(
    "LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN",
    "LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN",
    "LDAP://CN=MicrosoftDNS,$domainDN"
  )
  $weakPatterns = @(
    "authenticated users",
    "everyone",
    "domain users"
  )
  $dangerousRights = @("GenericAll", "GenericWrite", "CreateChild", "WriteProperty", "WriteDacl", "WriteOwner")
  $findings = @()
  foreach ($path in $paths) {
    try {
      $container = New-Object System.DirectoryServices.DirectoryEntry($path)
      $null = $container.NativeGuid
    }
    catch { continue }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($container)
    $searcher.Filter = "(objectClass=dnsZone)"
    $searcher.PageSize = 500
    $results = $searcher.FindAll()
    foreach ($result in $results) {
      try {
        $zoneEntry = $result.GetDirectoryEntry()
        $zoneEntry.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $sd = $zoneEntry.ObjectSecurity
        foreach ($ace in $sd.Access) {
          if ($ace.AccessControlType -ne 'Allow') { continue }
          $principal = Resolve-SidToAccount $ace.IdentityReference
          if (-not $principal) { continue }
          $principalLower = $principal.ToLower()
          if (-not ($weakPatterns | Where-Object { $principalLower -like "*${_}*" })) { continue }
          $rights = $ace.ActiveDirectoryRights.ToString()
          if (-not ($dangerousRights | Where-Object { $rights -like "*${_}*" })) { continue }
          $findings += [pscustomobject]@{
            Zone      = $zoneEntry.Properties["name"].Value
            Partition = $path.Split(',')[1]
            Principal = $principal
            Rights    = $rights
          }
        }
      }
      catch { continue }
    }
  }
  return ($findings | Sort-Object Zone, Principal -Unique)
}

function Get-GmsaPasswordReaders {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher.Filter = "(&(objectClass=msDS-GroupManagedServiceAccount))"
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add("sAMAccountName")
    [void]$searcher.PropertiesToLoad.Add("msDS-GroupMSAMembership")
    $results = $searcher.FindAll()
  }
  catch { return @() }
  $report = @()
  foreach ($result in $results) {
    $name = $result.Properties["samaccountname"]
    $blobs = $result.Properties["msds-groupmsamembership"]
    if (-not $blobs) { continue }
    $principals = @()
    foreach ($blob in $blobs) {
      try {
        $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor (, $blob)
        foreach ($ace in $raw.DiscretionaryAcl) {
          $sid = Resolve-SidToAccount $ace.SecurityIdentifier
          if ($sid) { $principals += $sid }
        }
      }
      catch { continue }
    }
    if ($principals.Count -eq 0) { continue }
    $principals = $principals | Sort-Object -Unique
    $weak = $principals | Where-Object { $_ -match 'Domain Users|Authenticated Users|Everyone' }
    $report += [pscustomobject]@{
      Account        = ($name | Select-Object -First 1)
      Allowed        = ($principals -join ", ")
      WeakPrincipals = if ($weak) { $weak -join ", " } else { "" }
    }
  }
  return $report
}

function Find-PrivilegedSpnAccounts {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  $keywords = @(
    "Domain Admin",
    "Enterprise Admin",
    "Administrators",
    "Exchange",
    "IT_",
    "Schema Admin",
    "Account Operator",
    "Server Operator",
    "Backup Operator",
    "DnsAdmin"
  )
  try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add("sAMAccountName")
    [void]$searcher.PropertiesToLoad.Add("memberOf")
    $results = $searcher.FindAll()
  }
  catch { return @() }
  $findings = @()
  foreach ($res in $results) {
    $groups = $res.Properties["memberof"]
    if (-not $groups) { continue }
    $matchedGroups = @()
    foreach ($group in $groups) {
      $cn = ($group -split ',')[0] -replace '^CN=',''
      if ($keywords | Where-Object { $cn -like "*${_}*" }) {
        $matchedGroups += $cn
      }
    }
    if ($matchedGroups.Count -gt 0) {
      $findings += [pscustomobject]@{
        User   = ($res.Properties["samaccountname"] | Select-Object -First 1)
        Groups = ($matchedGroups | Sort-Object -Unique) -join ', '
      }
    }
  }
  return ($findings | Sort-Object User | Select-Object -First 12)
}

function Get-NtlmConfig {
  try {
    $msv = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction Stop
  }
  catch { return $null }
  $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  return [pscustomobject]@{
    RestrictReceiving = $msv.RestrictReceivingNTLMTraffic
    RestrictSending   = $msv.RestrictSendingNTLMTraffic
    LmCompatibility   = if ($lsa) { $lsa.LmCompatibilityLevel } else { $null }
  }
}

function Get-KerberosTimeOffset {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return $null }
  try {
    $pdc = $DomainContext.PdcRoleOwner.Name
  }
  catch { return $null }
  try {
    $stripchart = w32tm /stripchart /computer:$pdc /dataonly /samples:3 2>$null
    $sample = $stripchart | Where-Object { $_ -match ',' } | Select-Object -Last 1
    if (-not $sample) { return $null }
    $parts = $sample.Split(',')
    if ($parts.Count -lt 2) { return $null }
    $offsetString = $parts[1].Trim().TrimEnd('s')
    [double]$offsetSeconds = 0
    if (-not [double]::TryParse($offsetString, [ref]$offsetSeconds)) { return $null }
    return [pscustomobject]@{
      Source        = $pdc
      OffsetSeconds = $offsetSeconds
      RawSample     = $sample
    }
  }
  catch {
    return $null
  }
}

function Get-CertificateMappingConfig {
  $info = [ordered]@{
    MappingValue = $null
    UpnMapping   = $false
    ServiceState = $null
  }
  try {
    $schannel = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name 'CertificateMappingMethods' -ErrorAction Stop
    $info.MappingValue = $schannel.CertificateMappingMethods
    if (($schannel.CertificateMappingMethods -band 0x4) -eq 0x4) { $info.UpnMapping = $true }
  }
  catch { }
  $svc = Get-Service -Name certsrv -ErrorAction SilentlyContinue
  if ($svc) { $info.ServiceState = $svc.Status }
  return [pscustomobject]$info
}


function Search-ExcelFile {
  [cmdletbinding()]
  Param (
      [parameter(Mandatory, ValueFromPipeline)]
      [ValidateScript({
          Try {
              If (Test-Path -Path $_) {$True}
              Else {Throw "$($_) is not a valid path!"}
          }
          Catch {
              Throw $_
          }
      })]
      [string]$Source,
      [parameter(Mandatory)]
      [string]$SearchText
  )
  $Excel = New-Object -ComObject Excel.Application
  Try {
      $Source = Convert-Path $Source
  }
  Catch {
      Write-Warning "Unable locate full path of $($Source)"
      BREAK
  }
  $Workbook = $Excel.Workbooks.Open($Source)
  ForEach ($Worksheet in @($Workbook.Sheets)) {
      $Found = $WorkSheet.Cells.Find($SearchText)
      If ($Found) {
        try{
          Write-Host "Pattern: '$SearchText' found in $source" -ForegroundColor Blue
          $BeginAddress = $Found.Address(0,0,1,1)
          New-Object -TypeName PSObject -Property ([Ordered]@{
              WorkSheet = $Worksheet.Name
              Column = $Found.Column
              Row =$Found.Row
              TextMatch = $Found.Text
              Address = $BeginAddress
          })
          Do {
              $Found = $WorkSheet.Cells.FindNext($Found)
              $Address = $Found.Address(0,0,1,1)
              If ($Address -eq $BeginAddress) {
                Write-host "Address is same as Begin Address"
                  BREAK
              }
              New-Object -TypeName PSObject -Property ([Ordered]@{
                  WorkSheet = $Worksheet.Name
                  Column = $Found.Column
                  Row =$Found.Row
                  TextMatch = $Found.Text
                  Address = $Address
              })
          } Until ($False)
        }
        catch {
          # Null expression in Found
        }
      }
  }
  try{
  $workbook.close($False)
  [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$excel)
  [gc]::Collect()
  [gc]::WaitForPendingFinalizers()
  }
  catch{
    #Usually an RPC error
  }
  Remove-Variable excel -ErrorAction SilentlyContinue
}

function Get-SoftwareInventory {
[cmdletbinding()]
param(
  [Parameter(DontShow)]
  $keys = @('','\Wow6432Node')
)
  foreach($key in $keys) {
      try {
        $apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
      }
      catch {
        Continue
      }
    foreach($app in $apps) {
        $program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
        $name = $program.GetValue('DisplayName')
      if($name) {
        New-Object -TypeName PSObject -Property ([Ordered]@{
              Computername = $env:COMPUTERNAME
              Software = $name
              Version = $program.GetValue("DisplayVersion")
              Publisher = $program.GetValue("Publisher")
              InstallDate = $program.GetValue("InstallDate")
              UninstallString = $program.GetValue("UninstallString")
              Architecture = $(if($key -eq '\wow6432node') {'x86'}else{'x64'})
              Path = $program.Name
        })
      }
    }
  }
}

function Write-ColorText([String[]]$Text, [ConsoleColor[]]$Color) {
  for ($i = 0; $i -lt $Text.Length; $i++) {
    Write-Host $Text[$i] -Foreground $Color[$i] -NoNewline
  }
  Write-Host
}


######################## BANNER ########################
Write-Host ""
Write-ColorText "    _    ____    _    ____ _____   ____  _____ ____ ___  _   _ " -Color Cyan
Write-ColorText "   / \  |  _ \  / \  |  _ \_   _| |  _ \| ____/ ___/ _ \| \ | |" -Color Cyan
Write-ColorText "  / _ \ | | | |/ _ \ | |_) || |   | |_) |  _|| |  | | | |  \| |" -Color Cyan
Write-ColorText " / ___ \| |_| / ___ \|  __/ | |   |  _ <| |__| |__| |_| | |\  |" -Color Cyan
Write-ColorText "/_/   \_\____/_/   \_\_|    |_|   |_| \_\_____\____\___/|_| \_|" -Color Cyan
Write-ColorText "                                                               " -Color Cyan
Write-ColorText "            Windows Reconnaissance Framework                   " -Color Yellow
Write-ColorText "              Security Assessment Utility                      " -Color DarkGray
Write-Host ""

######################## VARIABLES ########################

$password = $true
$username = $true
$webAuth = $true

$patternSearch = @{}

if ($password) {
  $patternSearch.add("Simple Passwords1", "pass.*[=:].+")
  $patternSearch.add("Simple Passwords2", "pwd.*[=:].+")
  $patternSearch.add("Apr1 MD5", '\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $patternSearch.add("Apache SHA", "\{SHA\}[0-9a-zA-Z/_=]{10,}")
  $patternSearch.add("Blowfish", '\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*')
  $patternSearch.add("Drupal", '\$S\$[a-zA-Z0-9_/\.]{52}')
  $patternSearch.add("Joomlavbulletin", "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
  $patternSearch.add("Linux MD5", '\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $patternSearch.add("phpbb3", '\$H\$[a-zA-Z0-9_/\.]{31}')
  $patternSearch.add("sha512crypt", '\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}')
  $patternSearch.add("Wordpress", '\$P\$[a-zA-Z0-9_/\.]{31}')
  $patternSearch.add("md5", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
  $patternSearch.add("sha1", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
  $patternSearch.add("sha256", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
  $patternSearch.add("sha512", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")
  $patternSearch.add("Base64", "(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")
}

if ($username) {
  $patternSearch.add("Usernames1", "username[=:].+")
  $patternSearch.add("Usernames2", "user[=:].+")
  $patternSearch.add("Usernames3", "login[=:].+")
  $patternSearch.add("Emails", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
  $patternSearch.add("Net user add", "net user .+ /add")
}

if ($DeepScan) {
  $patternSearch.add("Artifactory API Token", "AKC[a-zA-Z0-9]{10,}")
  $patternSearch.add("Artifactory Password", "AP[0-9ABCDEF][a-zA-Z0-9]{8,}")
  $patternSearch.add("Adafruit API Key", "([a-z0-9_-]{32})")
  $patternSearch.add("Adobe Client Id (Oauth Web)", "(adobe[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32})['""]")
  $patternSearch.add("Abode Client Secret", "(p8e-)[a-z0-9]{32}")
  $patternSearch.add("Age Secret Key", "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")
  $patternSearch.add("Airtable API Key", "([a-z0-9]{17})")
  $patternSearch.add("Alchemi API Key", "(alchemi[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9-]{32})['""]")
  $patternSearch.add("Artifactory API Key & Password", "[""']AKC[a-zA-Z0-9]{10,}[""']|[""']AP[0-9ABCDEF][a-zA-Z0-9]{8,}[""']")
  $patternSearch.add("Atlassian API Key", "(atlassian[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{24})['""]")
  $patternSearch.add("Binance API Key", "(binance[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{64})['""]")
  $patternSearch.add("Bitbucket Client Id", "((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""])")
  $patternSearch.add("Bitbucket Client Secret", "((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9_\-]{64})['""])")
  $patternSearch.add("BitcoinAverage API Key", "(bitcoin.?average[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{43})['""]")
  $patternSearch.add("Bitquery API Key", "(bitquery[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9]{32})['""]")
  $patternSearch.add("Bittrex Access Key and Access Key", "([a-z0-9]{32})")
  $patternSearch.add("Birise API Key", "(bitrise[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9_\-]{86})['""]")
  $patternSearch.add("Block API Key", "(block[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})['""]")
  $patternSearch.add("Blockchain API Key", "mainnet[a-zA-Z0-9]{32}|testnet[a-zA-Z0-9]{32}|ipfs[a-zA-Z0-9]{32}")
  $patternSearch.add("Blockfrost API Key", "(blockchain[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[0-9a-f]{12})['""]")
  $patternSearch.add("Box API Key", "(box[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{32})['""]")
  $patternSearch.add("Bravenewcoin API Key", "(bravenewcoin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{50})['""]")
  $patternSearch.add("Clearbit API Key", "sk_[a-z0-9]{32}")
  $patternSearch.add("Clojars API Key", "(CLOJARS_)[a-zA-Z0-9]{60}")
  $patternSearch.add("Coinbase Access Token", "([a-z0-9_-]{64})")
  $patternSearch.add("Coinlayer API Key", "(coinlayer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $patternSearch.add("Coinlib API Key", "(coinlib[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{16})['""]")
  $patternSearch.add("Confluent Access Token & Secret Key", "([a-z0-9]{16})")
  $patternSearch.add("Contentful delivery API Key", "(contentful[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_\-]{43})['""]")
  $patternSearch.add("Covalent API Key", "ckey_[a-z0-9]{27}")
  $patternSearch.add("Charity Search API Key", "(charity.?search[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $patternSearch.add("Databricks API Key", "dapi[a-h0-9]{32}")
  $patternSearch.add("DDownload API Key", "(ddownload[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{22})['""]")
  $patternSearch.add("Defined Networking API token", "(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})")
  $patternSearch.add("Discord API Key, Client ID & Client Secret", "((discord[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-h0-9]{64}|[0-9]{18}|[a-z0-9=_\-]{32})['""])")
  $patternSearch.add("Droneci Access Token", "([a-z0-9]{32})")
  $patternSearch.add("Dropbox API Key", "sl.[a-zA-Z0-9_-]{136}")
  $patternSearch.add("Doppler API Key", "(dp\.pt\.)[a-zA-Z0-9]{43}")
  $patternSearch.add("Dropbox API secret/key, short & long lived API Key", "(dropbox[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{15}|sl\.[a-z0-9=_\-]{135}|[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9_=\-]{43})['""]")
  $patternSearch.add("Duffel API Key", "duffel_(test|live)_[a-zA-Z0-9_-]{43}")
  $patternSearch.add("Dynatrace API Key", "dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64}")
  $patternSearch.add("EasyPost API Key", "EZAK[a-zA-Z0-9]{54}")
  $patternSearch.add("EasyPost test API Key", "EZTK[a-zA-Z0-9]{54}")
  $patternSearch.add("Etherscan API Key", "(etherscan[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{34})['""]")
  $patternSearch.add("Etsy Access Token", "([a-z0-9]{24})")
  $patternSearch.add("Facebook Access Token", "EAACEdEose0cBA[0-9A-Za-z]+")
  $patternSearch.add("Fastly API Key", "(fastly[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_\-]{32})['""]")
  $patternSearch.add("Finicity API Key & Client Secret", "(finicity[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32}|[a-z0-9]{20})['""]")
  $patternSearch.add("Flickr Access Token", "([a-z0-9]{32})")
  $patternSearch.add("Flutterweave Keys", "FLWPUBK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST[a-hA-H0-9]{12}")
  $patternSearch.add("Frame.io API Key", "fio-u-[a-zA-Z0-9_=\-]{64}")
  $patternSearch.add("Freshbooks Access Token", "([a-z0-9]{64})")
  $patternSearch.add("Github", "github(.{0,20})?['""][0-9a-zA-Z]{35,40}")
  $patternSearch.add("Github App Token", "(ghu|ghs)_[0-9a-zA-Z]{36}")
  $patternSearch.add("Github OAuth Access Token", "gho_[0-9a-zA-Z]{36}")
  $patternSearch.add("Github Personal Access Token", "ghp_[0-9a-zA-Z]{36}")
  $patternSearch.add("Github Refresh Token", "ghr_[0-9a-zA-Z]{76}")
  $patternSearch.add("GitHub Fine-Grained Personal Access Token", "github_pat_[0-9a-zA-Z_]{82}")
  $patternSearch.add("Gitlab Personal Access Token", "glpat-[0-9a-zA-Z\-]{20}")
  $patternSearch.add("GitLab Pipeline Trigger Token", "glptt-[0-9a-f]{40}")
  $patternSearch.add("GitLab Runner Registration Token", "GR1348941[0-9a-zA-Z_\-]{20}")
  $patternSearch.add("Gitter Access Token", "([a-z0-9_-]{40})")
  $patternSearch.add("GoCardless API Key", "live_[a-zA-Z0-9_=\-]{40}")
  $patternSearch.add("GoFile API Key", "(gofile[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{32})['""]")
  $patternSearch.add("Google API Key", "AIza[0-9A-Za-z_\-]{35}")
  $patternSearch.add("Google Cloud Platform API Key", "(google|gcp|youtube|drive|yt)(.{0,20})?['""][AIza[0-9a-z_\-]{35}]['""]")
  $patternSearch.add("Google Drive Oauth", "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")
  $patternSearch.add("Google Oauth Access Token", "ya29\.[0-9A-Za-z_\-]+")
  $patternSearch.add("Google (GCP) Service-account", """type.+:.+""service_account")
  $patternSearch.add("Grafana API Key", "eyJrIjoi[a-z0-9_=\-]{72,92}")
  $patternSearch.add("Grafana cloud api token", "glc_[A-Za-z0-9\+/]{32,}={0,2}")
  $patternSearch.add("Grafana service account token", "(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})")
  $patternSearch.add("Hashicorp Terraform user/org API Key", "[a-z0-9]{14}\.atlasv1\.[a-z0-9_=\-]{60,70}")
  $patternSearch.add("Heroku API Key", "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
  $patternSearch.add("Hubspot API Key", "['""][a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12}['""]")
  $patternSearch.add("Instatus API Key", "(instatus[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $patternSearch.add("Intercom API Key & Client Secret/ID", "(intercom[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_]{60}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['""]")
  $patternSearch.add("Ionic API Key", "(ionic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""](ion_[a-z0-9]{42})['""]")
  $patternSearch.add("JSON Web Token", "(ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2})")
  $patternSearch.add("Kraken Access Token", "([a-z0-9\/=_\+\-]{80,90})")
  $patternSearch.add("Kucoin Access Token", "([a-f0-9]{24})")
  $patternSearch.add("Kucoin Secret Key", "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $patternSearch.add("Launchdarkly Access Token", "([a-z0-9=_\-]{40})")
  $patternSearch.add("Linear API Key", "(lin_api_[a-zA-Z0-9]{40})")
  $patternSearch.add("Linear Client Secret/ID", "((linear[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32})['""])")
  $patternSearch.add("LinkedIn Client ID", "linkedin(.{0,20})?['""][0-9a-z]{12}['""]")
  $patternSearch.add("LinkedIn Secret Key", "linkedin(.{0,20})?['""][0-9a-z]{16}['""]")
  $patternSearch.add("Lob API Key", "((lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]((live|test)_[a-f0-9]{35})['""])|((lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]((test|live)_pub_[a-f0-9]{31})['""])")
  $patternSearch.add("Lob Publishable API Key", "((test|live)_pub_[a-f0-9]{31})")
  $patternSearch.add("MailboxValidator", "(mailbox.?validator[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{20})['""]")
  $patternSearch.add("Mailchimp API Key", "[0-9a-f]{32}-us[0-9]{1,2}")
  $patternSearch.add("Mailgun API Key", "key-[0-9a-zA-Z]{32}'")
  $patternSearch.add("Mailgun Public Validation Key", "pubkey-[a-f0-9]{32}")
  $patternSearch.add("Mailgun Webhook signing key", "[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}")
  $patternSearch.add("Mapbox API Key", "(pk\.[a-z0-9]{60}\.[a-z0-9]{22})")
  $patternSearch.add("Mattermost Access Token", "([a-z0-9]{26})")
  $patternSearch.add("MessageBird API Key & API client ID", "(messagebird[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{25}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['""]")
  $patternSearch.add("Microsoft Teams Webhook", "https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}")
  $patternSearch.add("MojoAuth API Key", "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
  $patternSearch.add("Netlify Access Token", "([a-z0-9=_\-]{40,46})")
  $patternSearch.add("New Relic User API Key, User API ID & Ingest Browser API Key", "(NRAK-[A-Z0-9]{27})|((newrelic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{64})['""])|(NRJS-[a-f0-9]{19})")
  $patternSearch.add("Nownodes", "(nownodes[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9]{32})['""]")
  $patternSearch.add("Npm Access Token", "(npm_[a-zA-Z0-9]{36})")
  $patternSearch.add("Nytimes Access Token", "([a-z0-9=_\-]{32})")
  $patternSearch.add("Okta Access Token", "([a-z0-9=_\-]{42})")
  $patternSearch.add("OpenAI API Token", "sk-[A-Za-z0-9]{48}")
  $patternSearch.add("ORB Intelligence Access Key", "['""][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['""]")
  $patternSearch.add("Pastebin API Key", "(pastebin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $patternSearch.add("PayPal Braintree Access Token", 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')
  $patternSearch.add("Picatic API Key", "sk_live_[0-9a-z]{32}")
  $patternSearch.add("Pinata API Key", "(pinata[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{64})['""]")
  $patternSearch.add("Planetscale API Key", "pscale_tkn_[a-zA-Z0-9_\.\-]{43}")
  $patternSearch.add("PlanetScale OAuth token", "(pscale_oauth_[a-zA-Z0-9_\.\-]{32,64})")
  $patternSearch.add("Planetscale Password", "pscale_pw_[a-zA-Z0-9_\.\-]{43}")
  $patternSearch.add("Plaid API Token", "(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $patternSearch.add("Plaid Client ID", "([a-z0-9]{24})")
  $patternSearch.add("Plaid Secret key", "([a-z0-9]{30})")
  $patternSearch.add("Prefect API token", "(pnu_[a-z0-9]{36})")
  $patternSearch.add("Postman API Key", "PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}")
  $patternSearch.add("Private Keys", "\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
  $patternSearch.add("Pulumi API Key", "pul-[a-f0-9]{40}")
  $patternSearch.add("PyPI upload token", "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")
  $patternSearch.add("Quip API Key", "(quip[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{15}=\|[0-9]{10}\|[a-zA-Z0-9\/+]{43}=)['""]")
  $patternSearch.add("RapidAPI Access Token", "([a-z0-9_-]{50})")
  $patternSearch.add("Rubygem API Key", "rubygems_[a-f0-9]{48}")
  $patternSearch.add("Readme API token", "rdme_[a-z0-9]{70}")
  $patternSearch.add("Sendbird Access ID", "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $patternSearch.add("Sendbird Access Token", "([a-f0-9]{40})")
  $patternSearch.add("Sendgrid API Key", "SG\.[a-zA-Z0-9_\.\-]{66}")
  $patternSearch.add("Sendinblue API Key", "xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}")
  $patternSearch.add("Sentry Access Token", "([a-f0-9]{64})")
  $patternSearch.add("Shippo API Key, Access Token, Custom Access Token, Private App Access Token & Shared Secret", "shippo_(live|test)_[a-f0-9]{40}|shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}")
  $patternSearch.add("Sidekiq Secret", "([a-f0-9]{8}:[a-f0-9]{8})")
  $patternSearch.add("Sidekiq Sensitive URL", "([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)")
  $patternSearch.add("Slack Token", "xox[baprs]-([0-9a-zA-Z]{10,48})?")
  $patternSearch.add("Slack Webhook", "https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}")
  $patternSearch.add("Smarksheel API Key", "(smartsheet[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{26})['""]")
  $patternSearch.add("Square Access Token", "sqOatp-[0-9A-Za-z_\-]{22}")
  $patternSearch.add("Square API Key", "EAAAE[a-zA-Z0-9_-]{59}")
  $patternSearch.add("Square Oauth Secret", "sq0csp-[ 0-9A-Za-z_\-]{43}")
  $patternSearch.add("Stytch API Key", "secret-.*-[a-zA-Z0-9_=\-]{36}")
  $patternSearch.add("Stripe Access Token & API Key", "(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}")
  $patternSearch.add("SumoLogic Access ID", "([a-z0-9]{14})")
  $patternSearch.add("SumoLogic Access Token", "([a-z0-9]{64})")
  $patternSearch.add("Telegram Bot API Token", "[0-9]+:AA[0-9A-Za-z\\-_]{33}")
  $patternSearch.add("Travis CI Access Token", "([a-z0-9]{22})")
  $patternSearch.add("Trello API Key", "(trello[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-z]{32})['""]")
  $patternSearch.add("Twilio API Key", "SK[0-9a-fA-F]{32}")
  $patternSearch.add("Twitch API Key", "(twitch[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{30})['""]")
  $patternSearch.add("Twitter Client ID", "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['""][0-9a-z]{18,25}")
  $patternSearch.add("Twitter Bearer Token", "(A{22}[a-zA-Z0-9%]{80,100})")
  $patternSearch.add("Twitter Oauth", "[tT][wW][iI][tT][tT][eE][rR].{0,30}['""\\s][0-9a-zA-Z]{35,44}['""\\s]")
  $patternSearch.add("Twitter Secret Key", "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['""][0-9a-z]{35,44}")
  $patternSearch.add("Typeform API Key", "tfp_[a-z0-9_\.=\-]{59}")
  $patternSearch.add("URLScan API Key", "['""][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['""]")
  $patternSearch.add("Vault Token", "[sb]\.[a-zA-Z0-9]{24}")
  $patternSearch.add("Yandex Access Token", "(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})")
  $patternSearch.add("Yandex API Key", "(AQVN[A-Za-z0-9_\-]{35,38})")
  $patternSearch.add("Yandex AWS Access Token", "(YC[a-zA-Z0-9_\-]{38})")
  $patternSearch.add("Web3 API Key", "(web3[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.?[A-Za-z0-9_.+/=\-]*)['""]")
  $patternSearch.add("Zendesk Secret Key", "([a-z0-9]{40})")
  $patternSearch.add("Generic API Key", "((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

if ($webAuth) {
  $patternSearch.add("Authorization Basic", "basic [a-zA-Z0-9_:\.=\-]+")
  $patternSearch.add("Authorization Bearer", "bearer [a-zA-Z0-9_\.=\-]+")
  $patternSearch.add("Alibaba Access Key ID", "(LTAI)[a-z0-9]{20}")
  $patternSearch.add("Alibaba Secret Key", "(alibaba[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{30})['""]")
  $patternSearch.add("Asana Client ID", "((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9]{16})['""])|((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""])")
  $patternSearch.add("AWS Client ID", "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
  $patternSearch.add("AWS MWS Key", "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
  $patternSearch.add("AWS Secret Key", "aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
  $patternSearch.add("AWS AppSync GraphQL Key", "da2-[a-z0-9]{26}")
  $patternSearch.add("Basic Auth Credentials", "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
  $patternSearch.add("Beamer Client Secret", "(beamer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""](b_[a-z0-9=_\-]{44})['""]")
  $patternSearch.add("Cloudinary Basic Auth", "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
  $patternSearch.add("Facebook Client ID", "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9]{13,17}")
  $patternSearch.add("Facebook Oauth", "[fF][aA][cC][eE][bB][oO][oO][kK].*['|""][0-9a-f]{32}['|""]")
  $patternSearch.add("Facebook Secret Key", "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9a-f]{32}")
  $patternSearch.add("Jenkins Creds", "<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
  $patternSearch.add("Generic Secret", "[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
  $patternSearch.add("Basic Auth", "//(.+):(.+)@")
  $patternSearch.add("PHP Passwords", "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
  $patternSearch.add("Config Secrets (Passwd / Credentials)", "passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
  $patternSearch.add("Generiac API tokens search", "(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

if($DeepScan){$ScanExcel = $true}

$patternSearch.add("IPs", "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
$Drives = Get-PSDrive | Where-Object { $_.Root -like "*:\" }
$targetExtensions = @("*.xml", "*.txt", "*.conf", "*.config", "*.cfg", "*.ini", ".y*ml", "*.log", "*.bak", "*.xls", "*.xlsx", "*.xlsm")


######################## SCRIPT START ########################
$reconTimer = [system.diagnostics.stopwatch]::StartNew()

if ($DeepScan) {
  Write-Host "**Deep Scan Enabled - Extended pattern matching active. Expect increased false positives.**"
}

Write-Host -BackgroundColor DarkBlue -ForegroundColor White "NOTICE: ADAPT RECON - Windows Reconnaissance Framework"
Write-Host -BackgroundColor DarkBlue -ForegroundColor White "This tool is intended for authorized security assessments, CTF challenges, and lab environments only."
Write-Host -BackgroundColor DarkBlue -ForegroundColor White "Ensure you have proper authorization before running on any system."
Write-Host ""

Write-Host -ForegroundColor red    "RED: Potential security issue or misconfiguration detected"
Write-Host -ForegroundColor green  "GREEN: Security control enabled or properly configured"
Write-Host -ForegroundColor cyan   "CYAN: Active user accounts"
Write-Host -ForegroundColor Gray   "GRAY: Disabled or inactive items"
Write-Host -ForegroundColor yellow "YELLOW: Reference links and resources"
Write-Host -ForegroundColor Blue   "BLUE: Section headers"
Write-Host ""


######################## SYSTEM INFORMATION ########################

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host "====================================|| SYSTEM OVERVIEW ||===================================="
"Curated system information. For complete details, run: Get-ComputerInfo"

systeminfo.exe


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| INSTALLED HOTFIXES"
Write-Host "=| Kernel exploit research: https://github.com/rasta-mouse/Watson" -ForegroundColor Yellow
$Hotfix = Get-HotFix | Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue | Select-Object HotfixID, Description, InstalledBy, InstalledOn
$Hotfix | Format-Table -AutoSize


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| UPDATE HISTORY"

$session = (New-Object -ComObject 'Microsoft.Update.Session')
$history = $session.QueryHistory("", 0, 1000) | Select-Object ResultCode, Date, Title

$HotfixUnique = @()
$HotFixReturnNum = @()

for ($i = 0; $i -lt $history.Count; $i++) {
  $check = Get-PatchIdentifier -title $history[$i].Title
  if ($HotfixUnique -like $check) {
  }
  else {
    $HotfixUnique += $check
    $HotFixReturnNum += $i
  }
}
$FinalHotfixList = @()

$hotfixreturnNum | ForEach-Object {
  $HotFixItem = $history[$_]
  $Result = $HotFixItem.ResultCode
  switch ($Result) {
    1 { $Result = "Missing/Superseded" }
    2 { $Result = "Succeeded" }
    3 { $Result = "Succeeded With Errors" }
    4 { $Result = "Failed" }
    5 { $Result = "Canceled" }
  }
  $FinalHotfixList += New-Object -TypeName PSObject -Property ([Ordered]@{
    Result = $Result
    Date   = $HotFixItem.Date
    Title  = $HotFixItem.Title
  })
}
$FinalHotfixList | Format-Table -AutoSize


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Storage Information"
Add-Type -AssemblyName System.Management

$diskSearcher = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")
$systemDrives = $diskSearcher.Get()

foreach ($drive in $systemDrives) {
  $driveLetter = $drive.DeviceID
  $driveLabel = $drive.VolumeName
  $driveSize = [math]::Round($drive.Size / 1GB, 2)
  $driveFreeSpace = [math]::Round($drive.FreeSpace / 1GB, 2)

  Write-Output "Drive: $driveLetter"
  Write-Output "Label: $driveLabel"
  Write-Output "Size: $driveSize GB"
  Write-Output "Free Space: $driveFreeSpace GB"
  Write-Output ""
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Security Software Detection"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Account Policy"
net accounts

######################## REGISTRY CHECKS ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| REGISTRY SECURITY CHECKS"


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Audit Configuration"
if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
  Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
}
else {
  Write-Host "No audit logging configured via registry."
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Event Forwarding Configuration"
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
  Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
}
else {
  Write-Host "Event forwarding not configured."
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| LAPS Detection"
if (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') { Write-Host "LAPS detected: C:\Program Files\LAPS\CSE\" -ForegroundColor Green }
elseif (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll' ) { Write-Host "LAPS detected: C:\Program Files (x86)\LAPS\CSE\" -ForegroundColor Green }
else { Write-Host "LAPS not installed" }
if ((Get-ItemProperty HKLM:\Software\Policies\Microsoft Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { Write-Host "LAPS enabled via registry" -ForegroundColor Green }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| WDigest Configuration"
$WDigest = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential
switch ($WDigest) {
  0 { Write-Host "WDigest disabled - credentials not cached in plaintext" }
  1 { Write-Host "WDigest ENABLED - plaintext credentials may be in LSASS" -ForegroundColor red }
  Default { Write-Host "UseLogonCredential registry key not found" }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| LSA Protection Status"
$RunAsPPL = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
$RunAsPPLBoot = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPLBoot
switch ($RunAsPPL) {
  2 { Write-Host "LSA Protection: Enabled (no UEFI lock)" }
  1 { Write-Host "LSA Protection: Enabled with UEFI lock" }
  0 { Write-Host "LSA Protection: DISABLED" -ForegroundColor red }
  Default { "LSA Protection registry keys not found" }
}
if ($RunAsPPLBoot) { Write-Host "RunAsPPLBoot: $RunAsPPLBoot" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Credential Guard Status"
$LsaCfgFlags = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags
switch ($LsaCfgFlags) {
  2 { Write-Host "Credential Guard: Enabled (no UEFI lock)" }
  1 { Write-Host "Credential Guard: Enabled with UEFI lock" }
  0 { Write-Host "Credential Guard: DISABLED" -ForegroundColor red }
  Default { "Credential Guard registry key not found" }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Cached Logon Count"
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
  (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT").CACHEDLOGONSCOUNT
  Write-Host "Cached credentials stored at: HKLM\SECURITY\Cache (SYSTEM access required)"
}

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Winlogon Credential Check"

(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| RDCMan Configuration"

if (Test-Path "$env:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") {
  Write-Host "RDCMan settings found: $($env:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ForegroundColor Red
}
else { Write-Host "No RDCMan configuration found." }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| RDP Connection History"

Write-Host "HK_Users"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
  if (Test-Path "registry::HKEY_USERS\$HKUSID\Software\Microsoft\Terminal Server Client\Default") {
    Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_USERS\$HKUSID\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"
  }
  else { Write-Host "Not found for $($_.Name)" }
}

Write-Host "HKCU"
if (Test-Path "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default") {
  Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"
}
else { Write-Host "No RDP history in HKCU" }

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PuTTY Saved Sessions"

if (Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions) {
  Get-ChildItem HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions | ForEach-Object {
    $RegKeyName = Split-Path $_.Name -Leaf
    Write-Host "Key: $RegKeyName"
    @("HostName", "PortNumber", "UserName", "PublicKeyFile", "PortForwardings", "ConnectionSharing", "ProxyUsername", "ProxyPassword") | ForEach-Object {
      Write-Host "$_ :"
      Write-Host "$((Get-ItemProperty  HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\$RegKeyName).$_)"
    }
  }
}
else { Write-Host "No PuTTY sessions found" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SSH Key Discovery"
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Reference:"
Write-Host "https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/" -ForegroundColor Yellow
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PuTTY Known Hosts"
if (Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys) {
  Write-Host "$((Get-Item -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)"
}
else { Write-Host "No PuTTY SSH keys found" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| OpenSSH Agent Keys"
if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) { Write-Host "OpenSSH keys detected. Extraction tool: https://github.com/ropnop/windows_sshagent_extract" -ForegroundColor Yellow }
else { Write-Host "No OpenSSH Agent keys found." }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| VNC Password Check"
if (Test-Path "HKCU:\Software\ORL\WinVNC3\Password") { Write-Host "WinVNC3 password at HKCU:\Software\ORL\WinVNC3\Password" }else { Write-Host "No WinVNC found." }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SNMP Configuration"
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP") { Write-Host "SNMP configured at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" }else { Write-Host "No SNMP configuration found." }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| TightVNC Check"
if (Test-Path "HKCU:\Software\TightVNC\Server") { Write-Host "TightVNC at HKCU:\Software\TightVNC\Server" }else { Write-Host "No TightVNC found." }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| UAC Configuration"
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 1) {
  Write-Host "UAC is enabled (EnableLUA = 1)"
}
else { Write-Host "UAC appears disabled" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Run Dialog History (WIN+R)"

Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
  $property = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
  $HKUSID | ForEach-Object {
    if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
      Write-Host -ForegroundColor Blue "=========|| HKU Run History"
      foreach ($p in $property) {
        Write-Host "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).getValue($p))"
      }
    }
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| HKCU Run History"
$property = (Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
foreach ($p in $property) {
  Write-Host "$((Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).getValue($p))"
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| AlwaysInstallElevated Check"


Write-Host "Checking Windows Installer policy..."
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) {
  Write-Host "HKLM AlwaysInstallElevated = 1 - VULNERABLE" -ForegroundColor red
}

if ((Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) {
  Write-Host "HKCU AlwaysInstallElevated = 1 - VULNERABLE" -ForegroundColor red
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PowerShell Versions"

(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine).PowerShellVersion | ForEach-Object {
  Write-Host "PowerShell $_ available"
}
(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine).PowerShellVersion | ForEach-Object {
  Write-Host  "PowerShell $_ available"
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PowerShell Transcription Settings"

if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PowerShell Module Logging"
if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PowerShell Script Block Logging"

if ( Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| WSUS Configuration"
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) {
  Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
}
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer" -ErrorAction SilentlyContinue).UseWUServer) {
  (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer").UseWUServer
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Internet Settings"

$property = (Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach ($p in $property) {
  Write-Host "$p - $((Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).getValue($p))"
}

$property = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach ($p in $property) {
  Write-Host "$p - $((Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).getValue($p))"
}


######################## PROCESS ENUMERATION ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| RUNNING PROCESSES"


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Process Binary Permission Check"
Get-Process | Select-Object Path -Unique | ForEach-Object { Test-PathPermissions -Target $_.path }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SYSTEM Processes"
Start-Process tasklist -ArgumentList '/v /fi "username eq system"' -Wait -NoNewWindow


######################## SERVICES ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SERVICE BINARY PERMISSIONS"
Write-Host "Checking service executable permissions..."
$UniqueServices = @{}
Get-WmiObject Win32_Service | Where-Object { $_.PathName -like '*.exe*' } | ForEach-Object {
  $Path = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
  $UniqueServices[$Path] = $_.Name
}
foreach ( $h in ($UniqueServices | Select-Object -Unique).GetEnumerator()) {
  Test-PathPermissions -Target $h.Name -ServiceName $h.Value
}


######################## UNQUOTED SERVICE PATH CHECK ############
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| UNQUOTED SERVICE PATH CHECK"

Find-UnquotedServicePaths


######################## REGISTRY SERVICE CONFIGURATION CHECK ###
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SERVICE REGISTRY PERMISSIONS"
Write-Host "Scanning service registry keys..."

Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object {
  $target = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:")
  Test-PathPermissions -Target $target
}


######################## SCHEDULED TASKS ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SCHEDULED TASK ANALYSIS"


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Task Folder Access Check"
if (Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue) {
  Write-Host "Direct access to task definitions available"
  Get-ChildItem "c:\windows\system32\tasks"
}
else {
  Write-Host "Limited access - enumerating via API"
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
    $Actions = $_.Actions.Execute
    if ($Actions -ne $null) {
      foreach ($a in $actions) {
        if ($a -like "%windir%*") { $a = $a.replace("%windir%", $Env:windir) }
        elseif ($a -like "%SystemRoot%*") { $a = $a.replace("%SystemRoot%", $Env:windir) }
        elseif ($a -like "%localappdata%*") { $a = $a.replace("%localappdata%", "$env:UserProfile\appdata\local") }
        elseif ($a -like "%appdata%*") { $a = $a.replace("%localappdata%", $env:Appdata) }
        $a = $a.Replace('"', '')
        Test-PathPermissions -Target $a
        Write-Host "`n"
        Write-Host "TaskName: $($_.TaskName)"
        Write-Host "-------------"
        New-Object -TypeName PSObject -Property ([Ordered]@{
          LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
          NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
          Status     = $_.State
          Command    = $_.Actions.execute
          Arguments  = $_.Actions.Arguments
        }) | Write-Host
      }
    }
  }
}


######################## STARTUP APPLICATIONS #########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| STARTUP APPLICATION CHECK"
"Checking for modifiable startup binaries..."

@("C:\Documents and Settings\All Users\Start Menu\Programs\Startup",
  "C:\Documents and Settings\$env:Username\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
  if (Test-Path $_) {
    Test-PathPermissions $_
    Get-ChildItem -Recurse -Force -Path $_ | ForEach-Object {
      $SubItem = $_.FullName
      if (Test-Path $SubItem) {
        Test-PathPermissions -Target $SubItem
      }
    }
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| STARTUP REGISTRY ENTRIES"

@("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
  "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
  "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
  $ROPath = $_
  (Get-Item $_) | ForEach-Object {
    $ROProperty = $_.property
    $ROProperty | ForEach-Object {
      Test-PathPermissions ((Get-ItemProperty -Path $ROPath).$_ -split '(?<=\.exe\b)')[0].Trim('"')
    }
  }
}


######################## INSTALLED APPLICATIONS ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SOFTWARE INVENTORY"
Write-Host "Enumerating installed applications..."

Get-SoftwareInventory

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| WSL/BASH DETECTION"
Get-ChildItem C:\Windows\WinSxS\ -Filter "amd64_microsoft-windows-lxss-bash*" | ForEach-Object {
  Write-Host $((Get-ChildItem $_.FullName -Recurse -Filter "*bash.exe*").FullName)
}
@("bash.exe", "wsl.exe") | ForEach-Object { Write-Host $((Get-ChildItem C:\Windows\System32\ -Filter $_).FullName) }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SCCM CLIENT CHECK"
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * -ErrorAction SilentlyContinue | Select-Object Name, SoftwareVersion
if ($result) { $result }
elseif (Test-Path 'C:\Windows\CCM\SCClient.exe') { Write-Host "SCCM Client: C:\Windows\CCM\SCClient.exe" -ForegroundColor Cyan }
else { Write-Host "SCCM not detected." }


######################## NETWORK INFORMATION ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| NETWORK RECONNAISSANCE"

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| HOSTS FILE"

Write-Host "Contents of etc\hosts:"
Get-Content "c:\windows\system32\drivers\etc\hosts"

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| IP CONFIGURATION"

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Full IP Configuration"
Start-Process ipconfig.exe -ArgumentList "/all" -Wait -NoNewWindow


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| DNS Cache"
ipconfig /displaydns | Select-String "Record" | ForEach-Object { Write-Host $('{0}' -f $_) }

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| NETWORK CONNECTIONS"

Start-Process NETSTAT.EXE -ArgumentList "-ano" -Wait -NoNewWindow


######################## ACTIVE DIRECTORY / IDENTITY CHECKS ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| DOMAIN/IDENTITY ANALYSIS"

$domainContext = Get-ADContext
if (-not $domainContext) {
  Write-Host "System appears to be standalone or AD context unavailable." -ForegroundColor DarkGray
}
else {
  $ntlmStatus = Get-NtlmConfig
  if ($ntlmStatus) {
    $recvValue = if ($ntlmStatus.RestrictReceiving -ne $null) { [int]$ntlmStatus.RestrictReceiving } else { -1 }
    $sendValue = if ($ntlmStatus.RestrictSending -ne $null) { [int]$ntlmStatus.RestrictSending } else { -1 }
    $lmValue = if ($ntlmStatus.LmCompatibility -ne $null) { [int]$ntlmStatus.LmCompatibility } else { -1 }
    $ntlmMsg = "Receiving:{0} Sending:{1} LMCompat:{2}" -f $recvValue, $sendValue, $lmValue
    if ($recvValue -ge 1 -or $sendValue -ge 1 -or $lmValue -ge 5) {
      Write-Host "[!] NTLM restrictions active ($ntlmMsg)" -ForegroundColor Yellow
    }
    else {
      Write-Host "[i] NTLM policy: $ntlmMsg"
    }
  }

  $timeSkew = Get-KerberosTimeOffset -DomainContext $domainContext
  if ($timeSkew) {
    $offsetAbs = [math]::Abs($timeSkew.OffsetSeconds)
    $timeMsg = "Offset vs {0}: {1:N3}s" -f $timeSkew.Source, $timeSkew.OffsetSeconds
    if ($offsetAbs -gt 5) {
      Write-Host "[!] Kerberos time skew detected - $timeMsg" -ForegroundColor Yellow
    }
    else {
      Write-Host "[i] Time sync OK - $timeMsg"
    }
  }

  $dnsFindings = @(Find-WeakDnsZonePermissions -DomainContext $domainContext)
  if ($dnsFindings.Count -gt 0) {
    Write-Host "[!] Weak DNS zone permissions detected (dynamic DNS hijack risk)" -ForegroundColor Yellow
    $dnsFindings | Format-Table Zone,Partition,Principal,Rights -AutoSize | Out-String | Write-Host
  }
  else {
    Write-Host "[i] No obvious weak DNS ACLs found."
  }

  $spnFindings = @(Find-PrivilegedSpnAccounts -DomainContext $domainContext)
  if ($spnFindings.Count -gt 0) {
    Write-Host "[!] High-value SPN accounts (Kerberoast targets):" -ForegroundColor Yellow
    $spnFindings | Format-Table User,Groups -AutoSize | Out-String | Write-Host
  }
  else {
    Write-Host "[i] No privileged SPN accounts found via LDAP."
  }

  $gmsaReport = @(Get-GmsaPasswordReaders -DomainContext $domainContext)
  if ($gmsaReport.Count -gt 0) {
    $weakGmsa = $gmsaReport | Where-Object { $_.WeakPrincipals -ne "" }
    if ($weakGmsa) {
      Write-Host "[!] gMSA passwords readable by low-priv groups:" -ForegroundColor Yellow
      $weakGmsa | Select-Object Account, WeakPrincipals | Format-Table -AutoSize | Out-String | Write-Host
    }
    else {
      Write-Host "[i] gMSA accounts found:"
      $gmsaReport | Select-Object Account, Allowed | Sort-Object Account | Select-Object -First 5 | Format-Table -Wrap | Out-String | Write-Host
    }
  }
  else {
    Write-Host "[i] No gMSA objects found."
  }

  $adcsInfo = Get-CertificateMappingConfig
  if ($adcsInfo.MappingValue -ne $null) {
    $hex = ('0x{0:X}' -f [int]$adcsInfo.MappingValue)
    if ($adcsInfo.UpnMapping) {
      Write-Host ("[!] Schannel UPN mapping enabled (CertificateMappingMethods={0}) - ESC10 risk" -f $hex) -ForegroundColor Yellow
    }
    else {
      Write-Host ("[i] Schannel CertificateMappingMethods={0}" -f $hex)
    }
    if ($adcsInfo.ServiceState) {
      Write-Host ("[i] AD CS service: {0}" -f $adcsInfo.ServiceState)
    }
  }
  else {
    Write-Host "[i] Schannel certificate mapping not readable." -ForegroundColor DarkGray
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| ARP TABLE"

Start-Process arp -ArgumentList "-A" -Wait -NoNewWindow

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| ROUTING TABLE"

Start-Process route -ArgumentList "print" -Wait -NoNewWindow

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| NETWORK ADAPTERS"

Get-NetAdapter | ForEach-Object {
  Write-Host "----------"
  Write-Host $_.Name
  Write-Host $_.InterfaceDescription
  Write-Host $_.ifIndex
  Write-Host $_.Status
  Write-Host $_.MacAddress
  Write-Host "----------"
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| WIFI CREDENTIALS"

((netsh.exe wlan show profiles) -match '\s{2,}:\s').replace("    All User Profile     : ", "") | ForEach-Object {
  netsh wlan show profile name="$_" key=clear
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| FIREWALL RULES"
Write-Host -ForegroundColor Blue "=========|| Full listing: netsh advfirewall firewall show rule dir=in name=all"

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SMB SHARE ANALYSIS"
Write-Host "Checking SMB share permissions..."

Get-SmbShare | Get-SmbShareAccess | ForEach-Object {
  $SMBShareObject = $_
  whoami.exe /groups /fo csv | select-object -skip 2 | ConvertFrom-Csv -Header 'group name' | Select-Object -ExpandProperty 'group name' | ForEach-Object {
    if ($SMBShareObject.AccountName -like $_ -and ($SMBShareObject.AccessRight -like "Full" -or "Change") -and $SMBShareObject.AccessControlType -like "Allow" ) {
      Write-Host -ForegroundColor red "$($SMBShareObject.AccountName) has $($SMBShareObject.AccessRight) to $($SMBShareObject.Name)"
    }
  }
}


######################## USER ENUMERATION ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| USER & GROUP ENUMERATION"
Write-Host "Enumerating local groups and members..."

Get-LocalGroup | ForEach-Object {
  "`n Group: $($_.Name) `n"
  if(Get-LocalGroupMember -name $_.Name){
    (Get-LocalGroupMember -name $_.Name).Name
  }
  else{
    "     {EMPTY GROUP}"
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| USER PROFILE ACCESS CHECK"
Get-ChildItem C:\Users\* | ForEach-Object {
  if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor red "Readable: $($_.FullName)"
  }
}

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| CURRENT USER CONTEXT"
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Privilege tokens of interest: SeImpersonate, SeAssignPrimaryToken, SeTcb, SeBackup, SeRestore, SeCreateToken, SeLoadDriver, SeTakeOwnership, SeDebug"
Start-Process whoami.exe -ArgumentList "/all" -Wait -NoNewWindow


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| CLOUD CREDENTIAL CHECK"
$Users = (Get-ChildItem C:\Users).Name
$CCreds = @(".aws\credentials",
  "AppData\Roaming\gcloud\credentials.db",
  "AppData\Roaming\gcloud\legacy_credentials",
  "AppData\Roaming\gcloud\access_tokens.db",
  ".azure\accessTokens.json",
  ".azure\azureProfile.json")
foreach ($u in $users) {
  $CCreds | ForEach-Object {
    if (Test-Path "c:\Users\$u\$_") { Write-Host "$_ found!" -ForegroundColor Red }
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| IIS AppCmd Check"
if (Test-Path ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
  Write-Host "$Env:SystemRoot\System32\inetsrv\appcmd.exe detected" -ForegroundColor Red
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| OpenVPN Credential Extraction"

$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs" -ErrorAction SilentlyContinue
if ($Keys) {
  Add-Type -AssemblyName System.Security
  $items = $keys | ForEach-Object { Get-ItemProperty $_.PsPath }
  foreach ($item in $items) {
    $encryptedbytes = $item.'auth-data'
    $entropy = $item.'entropy'
    $entropy = $entropy[0..(($entropy.Length) - 2)]

    $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $encryptedBytes,
      $entropy,
      [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

    Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| PowerShell History (Credential Search)"

Write-Host "=|| Console History"
Write-Host "=|| Full history: Get-Content (Get-PSReadlineOption).HistorySavePath"
Write-Host $(Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String pa)

Write-Host "=|| PSReadline History"
Write-Host "=|| Full history: Get-Content $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
Write-Host $(Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-String pa)


Write-Host "=|| Default Transcript Location"
if (Test-Path $env:SystemDrive\transcripts\) { "Transcripts found at $($env:SystemDrive)\transcripts\" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| ENVIRONMENT VARIABLES"
Write-Host "PATH hijacking opportunities:"

Get-ChildItem env: | Format-Table -Wrap


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Sticky Notes Database"
if (Test-Path "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite") {
  Write-Host "Sticky Notes database found - may contain plaintext credentials"
  Write-Host "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite"
}

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Windows Credential Manager"
cmdkey.exe /list


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| DPAPI Master Keys"
Write-Host "Master key locations for DPAPI credential decryption:"

$appdataRoaming = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\"
$appdataLocal = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\"
if ( Test-Path "$appdataRoaming\Protect\") {
  Write-Host "found: $appdataRoaming\Protect\"
  Get-ChildItem -Path "$appdataRoaming\Protect\" -Force | ForEach-Object {
    Write-Host $_.FullName
  }
}
if ( Test-Path "$appdataLocal\Protect\") {
  Write-Host "found: $appdataLocal\Protect\"
  Get-ChildItem -Path "$appdataLocal\Protect\" -Force | ForEach-Object {
    Write-Host $_.FullName
  }
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| DPAPI Credential Blobs"

if ( Test-Path "$appdataRoaming\Credentials\") {
  Get-ChildItem -Path "$appdataRoaming\Credentials\" -Force
}
if ( Test-Path "$appdataLocal\Credentials\") {
  Get-ChildItem -Path "$appdataLocal\Credentials\" -Force
}


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Active Logon Sessions"
try { quser }catch { Write-Host "'quser' not available" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Remote Sessions"
try { qwinsta } catch { Write-Host "'qwinsta' not available" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Kerberos Tickets"
try { klist } catch { Write-Host "No Kerberos tickets or insufficient privileges" }


Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Clipboard Contents"
Get-ClipboardContent

######################## FILE CREDENTIAL SEARCH ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| UNATTENDED INSTALL FILES"
@("C:\Windows\sysprep\sysprep.xml",
  "C:\Windows\sysprep\sysprep.inf",
  "C:\Windows\sysprep.inf",
  "C:\Windows\Panther\Unattended.xml",
  "C:\Windows\Panther\Unattend.xml",
  "C:\Windows\Panther\Unattend\Unattend.xml",
  "C:\Windows\Panther\Unattend\Unattended.xml",
  "C:\Windows\System32\Sysprep\unattend.xml",
  "C:\Windows\System32\Sysprep\unattended.xml",
  "C:\unattend.txt",
  "C:\unattend.inf") | ForEach-Object {
  if (Test-Path $_) {
    Write-Host "$_ found."
  }
}


######################## GROUP POLICY CHECKS ########################
Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| SAM/SYSTEM BACKUP FILES"

@(
  "$Env:windir\repair\SAM",
  "$Env:windir\System32\config\RegBack\SAM",
  "$Env:windir\System32\config\SAM",
  "$Env:windir\repair\system",
  "$Env:windir\System32\config\SYSTEM",
  "$Env:windir\System32\config\RegBack\system") | ForEach-Object {
  if (Test-Path $_ -ErrorAction SilentlyContinue) {
    Write-Host "$_ accessible!" -ForegroundColor red
  }
}

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| GROUP POLICY PREFERENCES"

$GroupPolicy = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")
if (Test-Path "$env:SystemDrive\Microsoft\Group Policy\history") {
  Get-ChildItem -Recurse -Force "$env:SystemDrive\Microsoft\Group Policy\history" -Include @GroupPolicy
}

if (Test-Path "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" ) {
  Get-ChildItem -Recurse -Force "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
}

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| TIP: Recycle bin credential recovery tools available at nirsoft.net"

######################## DEEP FILE SEARCH ########################

Write-Host ""
if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| CREDENTIAL PATTERN SEARCH"

if ($ShowTime) { Show-ElapsedTime }
Write-Host -ForegroundColor Blue "=========|| Scanning drives for sensitive patterns in: $targetExtensions"
Write-Host -ForegroundColor Blue "=========|| This may take considerable time..."

try {
  New-Object -ComObject Excel.Application | Out-Null
  $ReadExcel = $true
}
catch {
  $ReadExcel = $false
  if($ScanExcel) {
    Write-Host -ForegroundColor Yellow "Excel COM not available - will flag Excel files for manual review."
  }
}
$Drives.Root | ForEach-Object {
  $Drive = $_
  Get-ChildItem $Drive -Recurse -Include $targetExtensions -ErrorAction SilentlyContinue -Force | ForEach-Object {
    $path = $_
    if ($Path.FullName | select-string "(?i).*lang.*"){
    }
    if($Path.FullName | Select-String "(?i).:\\.*\\.*Pass.*"){
      write-host -ForegroundColor Blue "$($path.FullName) contains 'pass' in path"
    }
    if($Path.FullName | Select-String ".:\\.*\\.*user.*" ){
      Write-Host -ForegroundColor Blue "$($path.FullName) contains 'user' in path"
    }
    elseif ($Path.FullName | Select-String ".*\.xls",".*\.xlsm",".*\.xlsx") {
      if ($ReadExcel -and $ScanExcel) {
        Search-ExcelFile -Source $Path.FullName -SearchText "user"
        Search-ExcelFile -Source $Path.FullName -SearchText "pass"
      }
    }
    else {
      if ($path.Length -gt 0) {
      }
      if ($path.FullName | Select-String "(?i).*SiteList\.xml") {
        Write-Host "McAfee SiteList.xml found: $($_.FullName)"
        Write-Host "Decryption tool: https://github.com/funoverip/mcafee-sitelist-pwd-decryption" -ForegroundColor Yellow
      }
      $patternSearch.keys | ForEach-Object {
        $passwordFound = Get-Content $path.FullName -ErrorAction SilentlyContinue -Force | Select-String $patternSearch[$_] -Context 1, 1
        if ($passwordFound) {
          Write-Host "Match: $_" -ForegroundColor Yellow
          Write-Host $Path.FullName
          Write-Host -ForegroundColor Blue "Pattern: $_"
          Write-Host $passwordFound -ForegroundColor Red
        }
      }
    }
  }
}

######################## REGISTRY CREDENTIAL SEARCH ########################

Write-Host -ForegroundColor Blue "=========|| REGISTRY CREDENTIAL SEARCH"
Write-Host "Scanning registry for credential patterns..."
$regPath = @("registry::\HKEY_CURRENT_USER\", "registry::\HKEY_LOCAL_MACHINE\")
foreach ($r in $regPath) {
(Get-ChildItem -Path $r -Recurse -Force -ErrorAction SilentlyContinue) | ForEach-Object {
    $property = $_.property
    $Name = $_.Name
    $property | ForEach-Object {
      $Prop = $_
      $patternSearch.keys | ForEach-Object {
        $value = $patternSearch[$_]
        if ($Prop | Where-Object { $_ -like $value }) {
          Write-Host "Potential match: $Name\$Prop"
          Write-Host "Pattern: $_" -ForegroundColor Red
        }
        $Prop | ForEach-Object {
          $propValue = (Get-ItemProperty "registry::$Name").$_
          if ($propValue | Where-Object { $_ -like $Value }) {
            Write-Host "Potential match: $name\$_ $propValue"
          }
        }
      }
    }
  }
  if ($ShowTime) { Show-ElapsedTime }
  Write-Host "Completed: $r"
}

Write-Host ""
Write-Host "====================================|| SCAN COMPLETE ||===================================="
if ($ShowTime) { Show-ElapsedTime }
