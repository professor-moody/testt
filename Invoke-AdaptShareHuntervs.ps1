function Invoke-AdaptShareHunter {
<#
.SYNOPSIS
Snaffler-like share hunting tool with parallel execution, DFS discovery, and content analysis.

.DESCRIPTION
Discovers and searches file shares across a domain for sensitive content including credentials,
private keys, configuration files, and references to service accounts.

.PARAMETER ComputerName
Specific computers to scan. If not provided, queries AD for all computers.

.PARAMETER SharePath
Direct UNC paths to scan, skipping computer/share discovery.

.PARAMETER DfsOnly
Only discover shares via DFS namespaces (stealthier, faster).

.PARAMETER DfsNamespacePath
Specific DFS namespace paths to enumerate.

.PARAMETER FindFiles
Enable file discovery and analysis (not just share enumeration).

.PARAMETER SearchContent
Search inside files for sensitive patterns.

.PARAMETER SearchServiceAccounts
Query AD for service accounts and search for references to them in files.

.PARAMETER CheckCertificates
Parse certificate files to check for private keys.

.PARAMETER MinTriage
Minimum severity level to report: Black (4), Red (3), Yellow (2), Green (1), All (0).

.PARAMETER InterestLevel
Alternative severity filter 0-3 (0=all, 1=skip green, 2=skip yellow, 3=black only).

.PARAMETER ShareThreads
Number of threads for share discovery. Default 20.

.PARAMETER TreeThreads
Number of threads for directory walking. Default 10.

.PARAMETER FileThreads
Number of threads for file scanning. Default 20.

.PARAMETER MaxFileSize
Maximum file size in bytes to search content. Default 500KB.

.PARAMETER ExcludedShares
Shares to skip. Default: C$, ADMIN$, print$, IPC$.

.PARAMETER OutputFile
Path to output file.

.PARAMETER OutputFormat
Output format: Plain, JSON, TSV. Default Plain.

.PARAMETER SnaffleDir
Directory to copy interesting files to.

.PARAMETER NoPing
Skip port 445 check before scanning.

.EXAMPLE
Invoke-AdaptShareHunter -FindFiles -SearchContent

.EXAMPLE  
Invoke-AdaptShareHunter -DfsOnly -FindFiles -SearchContent -SearchServiceAccounts

.EXAMPLE
Invoke-AdaptShareHunter -SharePath "\\server\share" -FindFiles -SearchContent -OutputFormat JSON
#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String[]]$ComputerName,
        
        [String]$Domain,
        [String]$Server,
        [String[]]$SharePath,
        [Switch]$DfsOnly,
        [String[]]$DfsNamespacePath,
        [Switch]$FindFiles,
        [Switch]$SearchContent,
        [Switch]$SearchServiceAccounts,
        [Switch]$CheckCertificates,
        
        [ValidateSet('Black', 'Red', 'Yellow', 'Green', 'All')]
        [String]$MinTriage = 'Yellow',
        
        [ValidateRange(0, 3)]
        [Int]$InterestLevel = -1,
        
        [Int]$ShareThreads = 20,
        [Int]$TreeThreads = 10,
        [Int]$FileThreads = 20,
        [Int]$MaxFileSize = 500000,
        [Int]$MaxFileSizeSnaffle = 10000000,
        [Int]$ContentContext = 50,
        
        [String[]]$ExcludedShares = @('C$', 'ADMIN$', 'print$', 'IPC$'),
        
        [String]$OutputFile,
        [ValidateSet('Plain', 'JSON', 'TSV')]
        [String]$OutputFormat = 'Plain',
        [String]$SnaffleDir,
        
        [Switch]$NoPing,
        [Int]$PingTimeout = 100,
        [Int]$Delay = 0,
        [Double]$Jitter = 0.3
    )

    BEGIN {
        #region Configuration
        
        # Convert InterestLevel to MinTriage if specified
        if ($InterestLevel -ge 0) {
            $MinTriage = switch ($InterestLevel) {
                0 { 'All' }
                1 { 'Yellow' }
                2 { 'Red' }
                3 { 'Black' }
            }
        }
        
        $TriageLevels = @{ 'Black' = 4; 'Red' = 3; 'Yellow' = 2; 'Green' = 1; 'All' = 0 }
        $MinTriageLevel = $TriageLevels[$MinTriage]
        
        # Use HashSet for O(1) lookups
        $Script:SkipExtensions = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('.exe', '.dll', '.sys', '.msi', '.msp', '.msu', '.cab', '.cat', '.ocx', '.cpl', 
          '.scr', '.drv', '.efi', '.fon', '.ttf', '.otf', '.woff', '.woff2', '.eot', 
          '.bmp', '.gif', '.ico', '.jpg', '.jpeg', '.png', '.svg', '.tif', '.tiff', 
          '.webp', '.psd', '.ai', '.eps', '.mp3', '.mp4', '.wav', '.wma', '.wmv', 
          '.avi', '.mkv', '.mov', '.flv', '.swf', '.zip', '.rar', '.7z', '.gz', '.tar', 
          '.iso', '.img', '.vdi', '.vhd', '.lock', '.tmp', '.temp', '.cache', '.css', 
          '.less', '.scss', '.map', '.nupkg', '.snupkg', '.whl', '.pyc', '.pyo',
          '.class', '.jar', '.war', '.ear') | ForEach-Object { $null = $Script:SkipExtensions.Add($_) }

        $Script:SkipPaths = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('Windows', 'Program Files', 'Program Files (x86)', 'ProgramData\Microsoft',
          'AppData\Local\Microsoft', 'node_modules', 'vendor', 'packages', '.git', 
          '.svn', '__pycache__', 'site-packages', 'Temp', 'tmp', 'cache', 'Cache',
          'WinSxS', 'assembly', 'servicing', 'Installer', '$Recycle.Bin',
          'System Volume Information', 'Recovery', 'PerfLogs') | ForEach-Object { 
            $null = $Script:SkipPaths.Add($_) 
        }

        # File classifications
        $Script:BlackExtensions = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('.kdbx', '.kdb', '.ppk', '.vmdk', '.vhdx', '.ova', '.ovf', '.psafe3', '.kwallet',
          '.tblk', '.ovpn', '.pfx', '.p12', '.pem', '.key', '.asc', '.gpg', '.mdf', '.sdf',
          '.sqldump', '.bak', '.dmp', '.pcap', '.cap', '.jks', '.keystore', '.crt', '.cer',
          '.der', '.p7b', '.p7c', '.sst', '.csr') | ForEach-Object { 
            $null = $Script:BlackExtensions.Add($_) 
        }

        $Script:RedExtensions = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('.rdp', '.rdg', '.pbk', '.vnc', '.ica', '.cscfg', '.publishsettings', '.azure',
          '.aws', '.terraform', '.tfstate', '.tfvars') | ForEach-Object { 
            $null = $Script:RedExtensions.Add($_) 
        }

        $Script:YellowExtensions = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('.config', '.conf', '.cfg', '.ini', '.inf', '.cnf', '.yaml', '.yml', '.json',
          '.xml', '.properties', '.env', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs',
          '.js', '.py', '.sh', '.sql', '.htaccess', '.htpasswd', '.log', '.txt') | ForEach-Object { 
            $null = $Script:YellowExtensions.Add($_) 
        }

        $Script:BlackFilenames = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'NTDS.DIT', 'NTDS', 'shadow',
          'passwd', 'SAM', 'SYSTEM', 'SECURITY', 'pwd.db', '.netrc', '.pgpass', '.my.cnf',
          'credentials', 'credentials.xml', 'recentservers.xml', 'sftp-config.json',
          'mobaxterm.ini', 'confCons.xml', 'ConsoleHost_history.txt', 'known_hosts',
          'authorized_keys', '.bash_history', '.zsh_history', 'KeePass.config.xml',
          'ProtectedUserKey.bin', 'master.key', 'encryption.key', '.git-credentials',
          'filezilla.xml', 'sitemanager.xml', 'winscp.ini', 'ultravnc.ini',
          'VNC.ini', '.docker', 'dockercfg', '.dockerconfigjson') | ForEach-Object { 
            $null = $Script:BlackFilenames.Add($_) 
        }

        $Script:RedFilenames = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        @('web.config', 'app.config', 'applicationHost.config', 'machine.config',
          'connections.config', 'secrets.json', 'appsettings.json', 
          'appsettings.Development.json', 'appsettings.Production.json', 'database.yml',
          'settings.py', 'wp-config.php', 'configuration.php', 'LocalSettings.php',
          'config.php', '.htpasswd', '.env', '.env.local', '.env.production',
          '.env.development', 'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile',
          'Vagrantfile', 'ansible.cfg', 'inventory', 'vault.yml', 'Jenkins.xml',
          'hudson.util.Secret', 'terraform.tfstate', 'terraform.tfvars', 'unattend.xml',
          'sysprep.xml', 'sysprep.inf', 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml',
          'DataSources.xml', 'Printers.xml', 'Drives.xml', 'SiteList.xml', 'sites.xml',
          'bootstrap.ini', 'CustomSettings.ini', 'variables.xml', 'policy.xml') | ForEach-Object { 
            $null = $Script:RedFilenames.Add($_) 
        }

        $Script:YellowNamePatterns = @(
            'passw', 'secret', 'creds', 'credential', 'login', 'logon', 'token', 'apikey',
            'api_key', 'api-key', 'auth', 'private', 'vpn', 'ftp', 'ssh', 'rdp', 'admin',
            'backup', 'dump', 'export', 'database', 'db_', '_db', 'mysql', 'mssql', 'oracle',
            'postgres', 'mongo', 'redis', 'elastic', 'key', 'cert', 'ssl', 'tls', 'pki',
            'handover', 'onboard', 'as-built', 'asbuilt', 'network', 'diagram', 'topology',
            'inventory', 'asset', 'cmdb', 'install', 'setup', 'license', 'serial', 'accounts',
            'users', 'employee', 'personal', 'confidential', 'sensitive', 'restricted',
            'budget', 'salary', 'payroll', 'banking', 'wallet', 'bitcoin', 'crypto', 'seed',
            'mnemonic', 'recovery', 'ntds', 'sam_', 'lsass', 'mimikatz', 'procdump'
        )

        # Content search patterns - expanded
        $Script:ContentPatterns = @{
            'Black' = @(
                '(?i)-----BEGIN\s+(RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
                '(?i)aws_access_key_id\s*[=:]\s*[A-Z0-9]{20}',
                '(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}',
                'AKIA[0-9A-Z]{16}',
                '(?i)connectionstring[^=]*=\s*[''"][^''"]*password[^''"]*[''"]',
                '(?i)(password|passwd|pwd)\s*[=:]\s*[''"][^''"]{4,}[''"]',
                '(?i)DefaultPassword\s*[=:]\s*[''"]?.+',
                '(?i)validationKey\s*=\s*"[A-Fa-f0-9]{64,}"',
                '(?i)decryptionKey\s*=\s*"[A-Fa-f0-9]{48,}"',
                '(?i)cpassword\s*=\s*"[A-Za-z0-9/+=]+"',
                '(?i)ConvertTo-SecureString\s+[''"][^''"]+[''"]',
                '(?i)PSCredential\s*\(\s*[''"][^''"]+[''"]\s*,',
                '(?i)net\s+use\s+[^\r\n]+\s+/user:[^\s]+\s+[^\s/]+',
                '(?i)runas\s+/savecred',
                '(?i)schtasks[^\r\n]+/ru\s+[^\s]+\s+/rp\s+[^\s]+'
            )
            'Red' = @(
                '(?i)(api[_-]?key|apikey)\s*[=:]\s*[''"][^''"]{10,}[''"]',
                '(?i)(secret[_-]?key|secretkey)\s*[=:]\s*[''"][^''"]{10,}[''"]',
                '(?i)(auth[_-]?token|authtoken|access[_-]?token)\s*[=:]\s*[''"][^''"]{10,}[''"]',
                '(?i)bearer\s+[a-zA-Z0-9_\-\.=]+',
                '(?i)Basic\s+[A-Za-z0-9+/=]{20,}',
                '(?i)(client[_-]?secret|clientsecret)\s*[=:]\s*[''"][^'']+[''"]',
                '(?i)GITHUB[_-]?(TOKEN|PAT)\s*[=:]\s*[''"]?[A-Za-z0-9_]+',
                '(?i)ghp_[A-Za-z0-9]{36}',
                '(?i)gho_[A-Za-z0-9]{36}',
                '(?i)glpat-[A-Za-z0-9\-]{20}',
                '(?i)sk-[A-Za-z0-9]{32,}',
                '(?i)xox[baprs]-[0-9]{10,}-[A-Za-z0-9]+',
                '(?i)(jdbc|mysql|postgresql|sqlserver|oracle)://[^\s<>"]+:[^\s<>"]+@',
                '(?i)Data\s+Source\s*=.*Password\s*=',
                '(?i)Server\s*=.*Password\s*=',
                '(?i)mongodb(\+srv)?://[^\s<>"]+:[^\s<>"]+@',
                '(?i)New-Object\s+System\.Net\.NetworkCredential\s*\([^)]+\)',
                '(?i)\[System\.Text\.Encoding\]::\w+\.GetString\s*\(\s*\[Convert\]::FromBase64',
                '(?i)SecureString.*ConvertFrom',
                '(?i)OSDComputerName|OSDDomainOUName|TaskSequenceID'
            )
            'Yellow' = @(
                '(?i)password\s*[=:]\s*[^\s,;}{]+',
                '(?i)passwd\s*[=:]\s*[^\s,;}{]+',
                '(?i)pwd\s*[=:]\s*[^\s,;}{]+',
                '(?i)credentials?\s*[=:]\s*[^\s,;}{]+',
                '(?i)secret\s*[=:]\s*[^\s,;}{]+',
                '(?i)(user|username|login|uid)\s*[=:]\s*[^\s,;}{]+',
                '(?i)smtp[^\r\n]*password',
                '(?i)ftp[^\r\n]*password',
                '(?i)connectionString\s*[=:]',
                '(?i)dsquery|dsget|csvde|ldifde'
            )
        }

        # Service account patterns to search for
        $Script:ServiceAccountPatterns = @(
            'sql', 'svc', 'service', 'backup', 'ccm', 'scom', 'opsmgr', 'adm', 'adcs',
            'MSOL', 'adsync', 'thycotic', 'secretserver', 'cyberark', 'configmgr',
            'sccm', 'wsus', 'exchange', 'sharepoint', 'iis', 'app_', '_app', 'web_',
            '_web', 'batch', 'task', 'sched', 'agent', 'daemon', 'system', 'local'
        )

        # Scanned SYSVOL/NETLOGON tracker to avoid duplicates
        $Script:ScannedSysvolPaths = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )

        # Common share names for fallback
        $Script:CommonShares = @(
            'SYSVOL', 'NETLOGON', 'Users', 'Shared', 'Public', 'Data', 'Share', 'Shares',
            'Common', 'Software', 'Apps', 'Applications', 'Backup', 'Backups', 'IT', 'HR',
            'Finance', 'Legal', 'Dev', 'Development', 'Scripts', 'Tools', 'Home', 'homes',
            'Profiles', 'Department', 'Projects', 'Archive', 'files', 'fileshare', 'Transfer',
            'FTP', 'Upload', 'Downloads', 'Scans', 'Media', 'Resources', 'Web', 'WWW',
            'intranet', 'D$', 'E$', 'F$'
        )

        # Results collection (thread-safe)
        $Script:Results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
        $Script:ServiceAccounts = @()
        
        #endregion

        #region Helper Functions
        
        function Write-Status {
            Param([String]$Message, [String]$Level = 'Info')
            $ts = Get-Date -Format "HH:mm:ss"
            $color = switch ($Level) {
                'Error' { 'Red' }
                'Warning' { 'Yellow' }
                'Success' { 'Green' }
                'Info' { 'Cyan' }
                default { 'White' }
            }
            Write-Host "[$ts] $Message" -ForegroundColor $color
        }

        function Test-PortFast {
            Param([String]$Computer, [Int]$Port = 445, [Int]$Timeout = 100)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($Computer, $Port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne($Timeout, $false)
                if ($wait) {
                    try { $tcp.EndConnect($connect) } catch {}
                    $tcp.Close()
                    return $true
                }
                $tcp.Close()
                return $false
            }
            catch { return $false }
        }

        function Get-DomainSearcher {
            Param([String]$SearchBase, [String]$Server, [Int]$PageSize = 1000)
            try {
                $searcher = New-Object DirectoryServices.DirectorySearcher
                if ($Server) {
                    $path = "LDAP://$Server"
                    if ($SearchBase) { $path += "/$SearchBase" }
                    $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($path)
                }
                $searcher.PageSize = $PageSize
                return $searcher
            }
            catch { return $null }
        }

        function Get-DomainComputers {
            Param([String]$Domain, [String]$Server)
            Write-Status "Querying AD for computers..."
            $searcher = Get-DomainSearcher -Server $Server
            if (-not $searcher) { return @() }
            
            $searcher.Filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            $searcher.PropertiesToLoad.AddRange(@('dnshostname', 'name'))
            
            try {
                $results = $searcher.FindAll()
                $computers = @()
                foreach ($r in $results) {
                    $dns = $r.Properties['dnshostname']
                    if ($dns -and $dns[0]) { $computers += $dns[0] }
                    else { 
                        $name = $r.Properties['name']
                        if ($name -and $name[0]) { $computers += $name[0] }
                    }
                }
                Write-Status "Found $($computers.Count) computers" -Level Success
                return $computers
            }
            catch {
                Write-Status "LDAP query failed: $_" -Level Error
                return @()
            }
        }

        function Get-DfsNamespaces {
            Param([String]$Domain, [String]$Server)
            Write-Status "Discovering DFS namespaces..."
            $namespaces = @()
            
            # Query AD for DFS namespace objects
            $searcher = Get-DomainSearcher -Server $Server
            if (-not $searcher) { return @() }
            
            # Domain-based DFS
            $searcher.Filter = "(objectClass=fTDfs)"
            $searcher.PropertiesToLoad.Add('name')
            
            try {
                $results = $searcher.FindAll()
                foreach ($r in $results) {
                    $name = $r.Properties['name']
                    if ($name -and $name[0]) {
                        $nsPath = "\\$Domain\$($name[0])"
                        $namespaces += $nsPath
                    }
                }
            }
            catch {}
            
            # Also check common DFS root names
            $commonDfsRoots = @('DFS', 'DFSRoot', 'Files', 'Shares', 'Data', 'Public', 'Corp', 'Corporate')
            foreach ($root in $commonDfsRoots) {
                $testPath = "\\$Domain\$root"
                try {
                    if (Test-Path $testPath -ErrorAction SilentlyContinue) {
                        if ($namespaces -notcontains $testPath) {
                            $namespaces += $testPath
                        }
                    }
                }
                catch {}
            }
            
            Write-Status "Found $($namespaces.Count) DFS namespaces" -Level Success
            return $namespaces
        }

        function Get-DfsLinks {
            Param([String]$NamespacePath)
            $links = @()
            try {
                $items = Get-ChildItem -Path $NamespacePath -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    if ($item.PSIsContainer) {
                        $links += $item.FullName
                    }
                }
            }
            catch {}
            return $links
        }

        function Get-ServiceAccountsFromAD {
            Param([String]$Server)
            Write-Status "Discovering service accounts from AD..."
            $accounts = @()
            $searcher = Get-DomainSearcher -Server $Server
            if (-not $searcher) { return @() }
            
            # Find user accounts with SPNs (service accounts)
            $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
            $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'servicePrincipalName'))
            
            try {
                $results = $searcher.FindAll()
                foreach ($r in $results) {
                    $sam = $r.Properties['samaccountname']
                    if ($sam -and $sam[0]) {
                        $accounts += $sam[0]
                    }
                }
            }
            catch {}
            
            # Also find accounts matching service account patterns
            foreach ($pattern in $Script:ServiceAccountPatterns) {
                $searcher.Filter = "(&(objectCategory=user)(sAMAccountName=*$pattern*))"
                try {
                    $results = $searcher.FindAll()
                    foreach ($r in $results) {
                        $sam = $r.Properties['samaccountname']
                        if ($sam -and $sam[0] -and $accounts -notcontains $sam[0]) {
                            $accounts += $sam[0]
                        }
                    }
                }
                catch {}
            }
            
            Write-Status "Found $($accounts.Count) service accounts" -Level Success
            return $accounts
        }

        function Get-SharesWMI {
            Param([String]$Computer)
            $shares = @()
            try {
                $wmiShares = Get-WmiObject -Class Win32_Share -ComputerName $Computer -ErrorAction Stop
                foreach ($s in $wmiShares) {
                    if ($s.Type -eq 0 -or $s.Type -eq 2147483648) {
                        $shares += [PSCustomObject]@{
                            Name = $s.Name
                            Path = "\\$Computer\$($s.Name)"
                            Type = if ($s.Type -eq 2147483648) { 'Admin' } else { 'Disk' }
                            Remark = $s.Description
                        }
                    }
                }
            }
            catch {
                # Fallback to probing common shares
                foreach ($shareName in $Script:CommonShares) {
                    $unc = "\\$Computer\$shareName"
                    try {
                        if (Test-Path $unc -ErrorAction SilentlyContinue) {
                            $shares += [PSCustomObject]@{
                                Name = $shareName
                                Path = $unc
                                Type = if ($shareName -match '\$$') { 'Admin' } else { 'Disk' }
                                Remark = $null
                            }
                        }
                    }
                    catch {}
                }
            }
            return $shares
        }

        function Test-CertificateHasPrivateKey {
            Param([String]$FilePath)
            try {
                $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
                
                if ($ext -eq '.pfx' -or $ext -eq '.p12') {
                    # PFX/P12 files contain private keys by definition
                    return $true
                }
                elseif ($ext -eq '.pem' -or $ext -eq '.key') {
                    $content = Get-Content $FilePath -Raw -ErrorAction Stop
                    if ($content -match 'PRIVATE KEY') {
                        return $true
                    }
                }
                elseif ($ext -eq '.der' -or $ext -eq '.cer' -or $ext -eq '.crt') {
                    # Try to load as X509 and check for private key
                    try {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($FilePath)
                        return $cert.HasPrivateKey
                    }
                    catch {}
                }
                return $false
            }
            catch { return $false }
        }

        function Get-FileTriage {
            Param([String]$FileName, [String]$Extension)
            
            if ($Script:BlackExtensions.Contains($Extension)) { return 'Black' }
            if ($Script:BlackFilenames.Contains($FileName)) { return 'Black' }
            
            if ($Script:RedExtensions.Contains($Extension)) { return 'Red' }
            if ($Script:RedFilenames.Contains($FileName)) { return 'Red' }
            
            $nameLower = $FileName.ToLower()
            foreach ($pattern in $Script:YellowNamePatterns) {
                if ($nameLower.Contains($pattern)) { return 'Yellow' }
            }
            
            if ($Script:YellowExtensions.Contains($Extension)) { return 'Green' }
            
            return $null
        }

        function Search-FileContent {
            Param(
                [String]$FilePath,
                [Int]$MaxSize,
                [Int]$Context,
                [String[]]$ServiceAccounts
            )
            
            $findings = @()
            try {
                $fileInfo = Get-Item $FilePath -ErrorAction Stop
                if ($fileInfo.Length -gt $MaxSize) { return $findings }
                
                $content = Get-Content $FilePath -Raw -ErrorAction Stop
                if (-not $content) { return $findings }
                
                # Search standard patterns
                foreach ($level in @('Black', 'Red', 'Yellow')) {
                    foreach ($pattern in $Script:ContentPatterns[$level]) {
                        try {
                            $matches = [regex]::Matches($content, $pattern, 'IgnoreCase')
                            foreach ($m in $matches) {
                                $start = [Math]::Max(0, $m.Index - $Context)
                                $len = [Math]::Min($content.Length - $start, $m.Length + ($Context * 2))
                                $snippet = $content.Substring($start, $len) -replace '[\r\n]+', ' '
                                
                                $findings += [PSCustomObject]@{
                                    Triage = $level
                                    Match = $m.Value
                                    Context = $snippet.Trim()
                                    Rule = 'ContentPattern'
                                }
                            }
                        }
                        catch {}
                    }
                }
                
                # Search for service account references
                if ($ServiceAccounts -and $ServiceAccounts.Count -gt 0) {
                    foreach ($acct in $ServiceAccounts) {
                        if ($content -match [regex]::Escape($acct)) {
                            $findings += [PSCustomObject]@{
                                Triage = 'Red'
                                Match = $acct
                                Context = "Service account reference found"
                                Rule = 'ServiceAccount'
                            }
                        }
                    }
                }
            }
            catch {}
            return $findings
        }

        function Add-Finding {
            Param(
                [String]$Path,
                [String]$Triage,
                [Int64]$Size,
                [DateTime]$Modified,
                [String]$Match,
                [String]$Context,
                [String]$Rule
            )
            
            $finding = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Triage = $Triage
                Path = $Path
                Size = $Size
                Modified = $Modified
                Match = $Match
                Context = $Context
                Rule = $Rule
            }
            
            $Script:Results.Add($finding)
            
            # Output immediately
            $color = switch ($Triage) {
                'Black' { 'Magenta' }
                'Red' { 'Red' }
                'Yellow' { 'Yellow' }
                'Green' { 'Green' }
                default { 'White' }
            }
            
            $ts = Get-Date -Format "HH:mm:ss"
            $line = "[$ts] [$Triage] $Path"
            if ($Match) { $line += " | $Match" }
            
            Write-Host $line -ForegroundColor $color
            
            # Write to file if specified
            if ($OutputFile) {
                switch ($OutputFormat) {
                    'JSON' {
                        $finding | ConvertTo-Json -Compress | Out-File $OutputFile -Append -Encoding UTF8
                    }
                    'TSV' {
                        "$($finding.Timestamp)`t$Triage`t$Path`t$Match" | Out-File $OutputFile -Append -Encoding UTF8
                    }
                    default {
                        $line | Out-File $OutputFile -Append -Encoding UTF8
                    }
                }
            }
            
            # Snaffle file if requested
            if ($SnaffleDir -and $Size -le $MaxFileSizeSnaffle) {
                try {
                    $destPath = Join-Path $SnaffleDir ($Path -replace '^\\\\', '' -replace '\\', '_')
                    Copy-Item $Path $destPath -ErrorAction SilentlyContinue
                }
                catch {}
            }
        }

        function Test-ShouldSkipPath {
            Param([String]$Path)
            foreach ($skip in $Script:SkipPaths) {
                if ($Path -like "*\$skip\*" -or $Path -like "*\$skip") {
                    return $true
                }
            }
            return $false
        }

        function Test-IsSysvolOrNetlogon {
            Param([String]$Path)
            return ($Path -match '\\SYSVOL\\?' -or $Path -match '\\NETLOGON\\?')
        }

        #endregion

        $AllTargetPaths = @()
    }

    PROCESS {
        if ($SharePath) {
            $AllTargetPaths += $SharePath
        }
        elseif ($ComputerName) {
            foreach ($c in $ComputerName) {
                $AllTargetPaths += [PSCustomObject]@{ Type = 'Computer'; Value = $c }
            }
        }
    }

    END {
        $startTime = Get-Date
        Write-Status "Adapt ShareHunter v2 starting..."
        
        # Get domain info
        if (-not $Domain) {
            try {
                $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            }
            catch {
                $Domain = $env:USERDNSDOMAIN
            }
        }
        Write-Status "Target domain: $Domain"

        # Discover service accounts if requested
        if ($SearchServiceAccounts) {
            $Script:ServiceAccounts = Get-ServiceAccountsFromAD -Server $Server
        }

        # Build target list
        if ($AllTargetPaths.Count -eq 0) {
            if ($DfsOnly -or $DfsNamespacePath) {
                # DFS-only mode
                if ($DfsNamespacePath) {
                    $namespaces = $DfsNamespacePath
                }
                else {
                    $namespaces = Get-DfsNamespaces -Domain $Domain -Server $Server
                }
                
                foreach ($ns in $namespaces) {
                    $links = Get-DfsLinks -NamespacePath $ns
                    $AllTargetPaths += $links
                    if ($links.Count -eq 0) {
                        $AllTargetPaths += $ns
                    }
                }
                Write-Status "DFS discovery found $($AllTargetPaths.Count) paths"
            }
            else {
                # Full computer enumeration
                $computers = Get-DomainComputers -Domain $Domain -Server $Server
                foreach ($c in $computers) {
                    $AllTargetPaths += [PSCustomObject]@{ Type = 'Computer'; Value = $c }
                }
            }
        }

        # Phase 1: Share Discovery with Runspaces
        Write-Status "Phase 1: Share Discovery ($ShareThreads threads)..."
        
        $shareRunspacePool = [runspacefactory]::CreateRunspacePool(1, $ShareThreads)
        $shareRunspacePool.Open()
        $shareJobs = @()
        
        $shareScriptBlock = {
            Param($Computer, $ExcludedShares, $CommonShares, $NoPing, $PingTimeout)
            
            # Port check function
            function Test-Port {
                Param([String]$C, [Int]$P = 445, [Int]$T = 100)
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $conn = $tcp.BeginConnect($C, $P, $null, $null)
                    $wait = $conn.AsyncWaitHandle.WaitOne($T, $false)
                    if ($wait) { try { $tcp.EndConnect($conn) } catch {} }
                    $tcp.Close()
                    return $wait
                }
                catch { return $false }
            }
            
            $results = @()
            
            if (-not $NoPing) {
                if (-not (Test-Port -C $Computer -P 445 -T $PingTimeout)) {
                    return $results
                }
            }
            
            # Try WMI first
            try {
                $wmiShares = Get-WmiObject -Class Win32_Share -ComputerName $Computer -ErrorAction Stop
                foreach ($s in $wmiShares) {
                    if (($s.Type -eq 0 -or $s.Type -eq 2147483648) -and 
                        $ExcludedShares -notcontains $s.Name) {
                        $results += "\\$Computer\$($s.Name)"
                    }
                }
            }
            catch {
                # Fallback to probing
                foreach ($shareName in $CommonShares) {
                    if ($ExcludedShares -notcontains $shareName) {
                        $unc = "\\$Computer\$shareName"
                        try {
                            if (Test-Path $unc -ErrorAction SilentlyContinue) {
                                $results += $unc
                            }
                        }
                        catch {}
                    }
                }
            }
            
            return $results
        }

        $discoveredShares = [System.Collections.Concurrent.ConcurrentBag[String]]::new()
        
        foreach ($target in $AllTargetPaths) {
            if ($target -is [PSCustomObject] -and $target.Type -eq 'Computer') {
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $shareRunspacePool
                $null = $ps.AddScript($shareScriptBlock).AddArgument($target.Value).AddArgument($ExcludedShares).AddArgument($Script:CommonShares).AddArgument($NoPing).AddArgument($PingTimeout)
                
                $shareJobs += [PSCustomObject]@{
                    PowerShell = $ps
                    Handle = $ps.BeginInvoke()
                    Computer = $target.Value
                }
            }
            elseif ($target -is [String]) {
                $discoveredShares.Add($target)
            }
        }

        # Collect share discovery results
        foreach ($job in $shareJobs) {
            try {
                $result = $job.PowerShell.EndInvoke($job.Handle)
                foreach ($share in $result) {
                    $discoveredShares.Add($share)
                    Write-Host "[+] Found: $share" -ForegroundColor Green
                }
            }
            catch {}
            finally {
                $job.PowerShell.Dispose()
            }
        }
        
        $shareRunspacePool.Close()
        $shareRunspacePool.Dispose()

        Write-Status "Discovered $($discoveredShares.Count) accessible shares" -Level Success

        # Deduplicate SYSVOL/NETLOGON
        $finalShares = @()
        foreach ($share in $discoveredShares) {
            if (Test-IsSysvolOrNetlogon -Path $share) {
                $normalized = $share -replace '\\\\[^\\]+\\', "\\$Domain\"
                if (-not $Script:ScannedSysvolPaths.Contains($normalized)) {
                    $null = $Script:ScannedSysvolPaths.Add($normalized)
                    $finalShares += $share
                }
            }
            else {
                $finalShares += $share
            }
        }
        
        Write-Status "After deduplication: $($finalShares.Count) shares to scan"

        if (-not $FindFiles) {
            Write-Status "Share enumeration complete. Use -FindFiles to scan for sensitive files."
            return
        }

        # Phase 2: File Discovery and Analysis with Runspaces
        Write-Status "Phase 2: File Discovery and Analysis ($FileThreads threads)..."

        $fileRunspacePool = [runspacefactory]::CreateRunspacePool(1, $FileThreads)
        $fileRunspacePool.Open()
        $fileJobs = @()

        $fileScriptBlock = {
            Param(
                $SharePath, $SkipExtensions, $SkipPaths, $BlackExtensions, $RedExtensions,
                $YellowExtensions, $BlackFilenames, $RedFilenames, $YellowNamePatterns,
                $SearchContent, $CheckCertificates, $MaxFileSize, $ContentContext,
                $ContentPatterns, $ServiceAccounts, $MinTriageLevel, $TriageLevels
            )
            
            $findings = @()
            
            function Test-Skip {
                Param([String]$P)
                foreach ($s in $SkipPaths) {
                    if ($P -like "*\$s\*" -or $P -like "*\$s") { return $true }
                }
                return $false
            }
            
            function Get-Triage {
                Param([String]$Name, [String]$Ext)
                if ($BlackExtensions.Contains($Ext)) { return 'Black' }
                if ($BlackFilenames.Contains($Name)) { return 'Black' }
                if ($RedExtensions.Contains($Ext)) { return 'Red' }
                if ($RedFilenames.Contains($Name)) { return 'Red' }
                $nl = $Name.ToLower()
                foreach ($p in $YellowNamePatterns) {
                    if ($nl.Contains($p)) { return 'Yellow' }
                }
                if ($YellowExtensions.Contains($Ext)) { return 'Green' }
                return $null
            }
            
            try {
                Get-ChildItem -Path $SharePath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $file = $_
                    $path = $file.FullName
                    $ext = $file.Extension.ToLower()
                    
                    # Skip checks
                    if ($SkipExtensions.Contains($ext)) { return }
                    if (Test-Skip -P $path) { return }
                    
                    $triage = Get-Triage -Name $file.Name -Ext $ext
                    
                    # Certificate check
                    if ($CheckCertificates -and $triage -eq 'Black' -and 
                        @('.pfx', '.p12', '.pem', '.key', '.der', '.cer', '.crt') -contains $ext) {
                        # Simplified cert check
                        if ($ext -eq '.pfx' -or $ext -eq '.p12') {
                            # Always has private key
                        }
                        elseif ($ext -eq '.pem' -or $ext -eq '.key') {
                            try {
                                $c = Get-Content $path -Raw -ErrorAction Stop
                                if ($c -notmatch 'PRIVATE KEY') {
                                    $triage = 'Yellow'  # Downgrade if no private key
                                }
                            }
                            catch { $triage = 'Yellow' }
                        }
                        else {
                            $triage = 'Yellow'  # Public certs only
                        }
                    }
                    
                    # Report file-level finding
                    if ($triage -and $TriageLevels[$triage] -ge $MinTriageLevel) {
                        $findings += [PSCustomObject]@{
                            Path = $path
                            Triage = $triage
                            Size = $file.Length
                            Modified = $file.LastWriteTime
                            Match = $null
                            Context = $null
                            Rule = 'FileMatch'
                        }
                    }
                    
                    # Content search
                    if ($SearchContent -and $file.Length -le $MaxFileSize) {
                        $searchableExt = @('.config', '.conf', '.cfg', '.ini', '.yaml', '.yml',
                            '.json', '.xml', '.properties', '.env', '.ps1', '.psm1', '.bat',
                            '.cmd', '.vbs', '.js', '.py', '.sh', '.sql', '.txt', '.log')
                        
                        if ($searchableExt -contains $ext) {
                            try {
                                $content = Get-Content $path -Raw -ErrorAction Stop
                                if ($content) {
                                    foreach ($level in @('Black', 'Red', 'Yellow')) {
                                        foreach ($pattern in $ContentPatterns[$level]) {
                                            try {
                                                $matches = [regex]::Matches($content, $pattern, 'IgnoreCase')
                                                foreach ($m in $matches) {
                                                    if ($TriageLevels[$level] -ge $MinTriageLevel) {
                                                        $start = [Math]::Max(0, $m.Index - $ContentContext)
                                                        $len = [Math]::Min($content.Length - $start, $m.Length + ($ContentContext * 2))
                                                        $snippet = $content.Substring($start, $len) -replace '[\r\n]+', ' '
                                                        
                                                        $findings += [PSCustomObject]@{
                                                            Path = $path
                                                            Triage = $level
                                                            Size = $file.Length
                                                            Modified = $file.LastWriteTime
                                                            Match = $m.Value.Substring(0, [Math]::Min(100, $m.Value.Length))
                                                            Context = $snippet.Trim().Substring(0, [Math]::Min(200, $snippet.Length))
                                                            Rule = 'ContentMatch'
                                                        }
                                                    }
                                                }
                                            }
                                            catch {}
                                        }
                                    }
                                    
                                    # Service account search
                                    if ($ServiceAccounts) {
                                        foreach ($acct in $ServiceAccounts) {
                                            if ($content -match [regex]::Escape($acct)) {
                                                $findings += [PSCustomObject]@{
                                                    Path = $path
                                                    Triage = 'Red'
                                                    Size = $file.Length
                                                    Modified = $file.LastWriteTime
                                                    Match = $acct
                                                    Context = "Service account reference"
                                                    Rule = 'ServiceAccount'
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            catch {}
                        }
                    }
                }
            }
            catch {}
            
            return $findings
        }

        foreach ($share in $finalShares) {
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $fileRunspacePool
            $null = $ps.AddScript($fileScriptBlock)
            $null = $ps.AddArgument($share)
            $null = $ps.AddArgument($Script:SkipExtensions)
            $null = $ps.AddArgument($Script:SkipPaths)
            $null = $ps.AddArgument($Script:BlackExtensions)
            $null = $ps.AddArgument($Script:RedExtensions)
            $null = $ps.AddArgument($Script:YellowExtensions)
            $null = $ps.AddArgument($Script:BlackFilenames)
            $null = $ps.AddArgument($Script:RedFilenames)
            $null = $ps.AddArgument($Script:YellowNamePatterns)
            $null = $ps.AddArgument($SearchContent.IsPresent)
            $null = $ps.AddArgument($CheckCertificates.IsPresent)
            $null = $ps.AddArgument($MaxFileSize)
            $null = $ps.AddArgument($ContentContext)
            $null = $ps.AddArgument($Script:ContentPatterns)
            $null = $ps.AddArgument($Script:ServiceAccounts)
            $null = $ps.AddArgument($MinTriageLevel)
            $null = $ps.AddArgument($TriageLevels)
            
            $fileJobs += [PSCustomObject]@{
                PowerShell = $ps
                Handle = $ps.BeginInvoke()
                Share = $share
            }
        }

        # Progress monitoring
        $completed = 0
        $total = $fileJobs.Count
        
        while ($fileJobs | Where-Object { -not $_.Handle.IsCompleted }) {
            $nowCompleted = ($fileJobs | Where-Object { $_.Handle.IsCompleted }).Count
            if ($nowCompleted -ne $completed) {
                $completed = $nowCompleted
                Write-Progress -Activity "Scanning shares" -Status "$completed / $total complete" -PercentComplete (($completed / $total) * 100)
            }
            Start-Sleep -Milliseconds 500
        }
        
        Write-Progress -Activity "Scanning shares" -Completed

        # Collect results
        foreach ($job in $fileJobs) {
            try {
                $results = $job.PowerShell.EndInvoke($job.Handle)
                foreach ($finding in $results) {
                    Add-Finding -Path $finding.Path -Triage $finding.Triage -Size $finding.Size `
                        -Modified $finding.Modified -Match $finding.Match -Context $finding.Context `
                        -Rule $finding.Rule
                }
            }
            catch {}
            finally {
                $job.PowerShell.Dispose()
            }
        }

        $fileRunspacePool.Close()
        $fileRunspacePool.Dispose()

        # Summary
        $elapsed = (Get-Date) - $startTime
        Write-Status "Scan complete in $([Math]::Round($elapsed.TotalMinutes, 1)) minutes" -Level Success
        
        $black = ($Script:Results | Where-Object { $_.Triage -eq 'Black' }).Count
        $red = ($Script:Results | Where-Object { $_.Triage -eq 'Red' }).Count
        $yellow = ($Script:Results | Where-Object { $_.Triage -eq 'Yellow' }).Count
        $green = ($Script:Results | Where-Object { $_.Triage -eq 'Green' }).Count
        
        Write-Host ""
        Write-Host "Results Summary:" -ForegroundColor Cyan
        Write-Host "  Black (Critical): $black" -ForegroundColor Magenta
        Write-Host "  Red (High):       $red" -ForegroundColor Red  
        Write-Host "  Yellow (Medium):  $yellow" -ForegroundColor Yellow
        Write-Host "  Green (Low):      $green" -ForegroundColor Green
        Write-Host "  Total:            $($Script:Results.Count)" -ForegroundColor White
        
        if ($OutputFile) {
            Write-Status "Results written to: $OutputFile"
        }
    }
}
