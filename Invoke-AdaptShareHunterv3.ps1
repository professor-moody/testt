function Invoke-AdaptShareHunter {
<#
.SYNOPSIS
ADAPT ShareHunter v3 - Snaffler-inspired share hunting with DFS discovery and content analysis.

.DESCRIPTION
Discovers and searches file shares across AD environments for sensitive content including credentials,
private keys, configuration files, and service account references. Uses LDAP-only discovery for stealth.

.PARAMETER ComputerName
Specific computers to scan. If not provided, queries AD for all computers.

.PARAMETER SharePath
Direct UNC paths to scan, skipping computer/share discovery.

.PARAMETER DfsOnly
Only discover shares via DFS namespaces (stealthier, faster).

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

.PARAMETER ShareThreads
Number of threads for share discovery. Default 20.

.PARAMETER FileThreads
Number of threads for file scanning. Default 20.

.PARAMETER MaxFileSize
Maximum file size in bytes to search content. Default 500KB.

.PARAMETER NoWMI
Skip WMI for share discovery (OPSEC - uses SMB probing only).

.PARAMETER Stealth
Stealth mode preset: DfsOnly, NoWMI, 5 threads, 500ms delay.

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

.PARAMETER Server
Domain controller to query.

.PARAMETER Credential
Alternate credentials for LDAP queries.

.PARAMETER Version
DFS version to enumerate: All, V1, V2. Default All.

.EXAMPLE
Invoke-AdaptShareHunter -FindFiles -SearchContent

.EXAMPLE
Invoke-AdaptShareHunter -DfsOnly -FindFiles -SearchContent -SearchServiceAccounts

.EXAMPLE
Invoke-AdaptShareHunter -Stealth -FindFiles -SearchContent

.EXAMPLE
Invoke-AdaptShareHunter -SharePath "\\server\share" -FindFiles -SearchContent -OutputFormat JSON
#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String[]]$ComputerName,

        [String]$Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]$Server,
        [String[]]$SharePath,
        [Switch]$DfsOnly,
        [Switch]$FindFiles,
        [Switch]$SearchContent,
        [Switch]$SearchServiceAccounts,
        [Switch]$CheckCertificates,
        [Switch]$NoWMI,
        [Switch]$Stealth,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]$Version = 'All',

        [ValidateSet('Black', 'Red', 'Yellow', 'Green', 'All')]
        [String]$MinTriage = 'Yellow',

        [Int]$ShareThreads = 20,
        [Int]$FileThreads = 20,
        [Int]$MaxFileSize = 500000,
        [Int]$MaxFileSizeSnaffle = 10000000,
        [Int]$ContentContext = 50,
        [Int]$Delay = 0,

        [String[]]$ExcludedShares = @('C$', 'ADMIN$', 'print$', 'IPC$'),

        [String]$OutputFile,
        [ValidateSet('Plain', 'JSON', 'TSV')]
        [String]$OutputFormat = 'Plain',
        [String]$SnaffleDir,

        [Switch]$NoPing,
        [Int]$PingTimeout = 100,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        #region Stealth Mode
        if ($Stealth) {
            $DfsOnly = $true
            $NoWMI = $true
            $ShareThreads = 5
            $FileThreads = 5
            $Delay = 500
            Write-Host "[*] Stealth mode enabled: DfsOnly, NoWMI, 5 threads, 500ms delay" -ForegroundColor Yellow
        }
        #endregion

        #region Configuration
        $TriageLevels = @{ 'Black' = 4; 'Red' = 3; 'Yellow' = 2; 'Green' = 1; 'All' = 0 }
        $MinTriageLevel = $TriageLevels[$MinTriage]

        # HashSets for O(1) lookups - Snaffler-aligned skip lists
        $Script:SkipExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        @('.exe', '.dll', '.sys', '.msi', '.msp', '.msu', '.cab', '.cat', '.ocx', '.cpl',
          '.scr', '.drv', '.efi', '.fon', '.ttf', '.otf', '.woff', '.woff2', '.eot',
          '.bmp', '.gif', '.ico', '.jpg', '.jpeg', '.png', '.svg', '.tif', '.tiff',
          '.webp', '.psd', '.ai', '.eps', '.jfi', '.jfif', '.jif', '.jpe', '.xcf',
          '.mp3', '.mp4', '.wav', '.wma', '.wmv', '.avi', '.mkv', '.mov', '.flv', '.swf',
          '.zip', '.rar', '.7z', '.gz', '.tar', '.iso', '.img', '.vdi', '.vhd',
          '.lock', '.tmp', '.temp', '.cache', '.css', '.less', '.scss', '.map',
          '.nupkg', '.snupkg', '.whl', '.pyc', '.pyo', '.class', '.jar', '.war', '.ear',
          '.admx', '.adml', '.xsd', '.nse', '.xsl') | ForEach-Object { $null = $Script:SkipExtensions.Add($_) }

        # Snaffler-aligned path skip patterns
        $Script:SkipPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        @('winsxs', 'syswow64', 'system32', 'systemapps', 'Windows\servicing', 'servicing',
          'Microsoft.NET\Framework', 'Windows\immersivecontrolpanel', 'Windows\diagnostics',
          'Windows\debug', 'locale', 'localization', 'AppData\Local\Microsoft',
          'AppData\Roaming\Microsoft\Windows', 'AppData\Roaming\Microsoft\Teams',
          'chocolatey\helpers', 'sources\sxs', 'wsuscontent', 'servicing\LCU',
          'puppet\share\doc', 'lib\ruby', 'lib\site-packages', 'usr\share\doc',
          'node_modules', 'vendor\bundle', 'vendor\cache', 'doc\openssl',
          'Anaconda3\Lib\test', 'WindowsPowerShell\Modules', 'Reference Assemblies\Microsoft',
          'dotnet\sdk', 'dotnet\shared', 'Windows\assembly', 'ProgramData\Microsoft',
          '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs',
          '.git', '.svn', '__pycache__', 'site-packages', 'Temp', 'tmp', 'Cache') | ForEach-Object {
            $null = $Script:SkipPaths.Add($_)
        }

        #region File Classifications - Snaffler-aligned

        # BLACK - Critical finds (password managers, private keys, credential stores)
        $Script:BlackExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        @('.kdbx', '.kdb', '.psafe3', '.kwallet', '.keychain', '.agilekeychain', '.cred',
          '.ppk', '.pem', '.key', '.pfx', '.p12', '.jks', '.keystore',
          '.vmdk', '.vhdx', '.ova', '.ovf', '.pcap', '.cap',
          '.mdf', '.sdf', '.sqldump', '.dmp') | ForEach-Object {
            $null = $Script:BlackExtensions.Add($_)
        }

        $Script:BlackFilenames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        @('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa.pub', 'authorized_keys', 'known_hosts',
          'NTDS.DIT', 'NTDS', 'SAM', 'SYSTEM', 'SECURITY', 'shadow', 'passwd',
          'pwd.db', '.netrc', '.pgpass', '.my.cnf', 'credentials', 'credentials.xml',
          'recentservers.xml', 'sftp-config.json', 'mobaxterm.ini', 'mobaxterm backup.zip',
          'confCons.xml', 'ConsoleHost_history.txt', 'Visual Studio Code Host_history.txt',
          '.bash_history', '.zsh_history', '.sh_history', 'KeePass.config.xml',
          'ProtectedUserKey.bin', 'master.key', 'encryption.key', '.git-credentials',
          'filezilla.xml', 'sitemanager.xml', 'winscp.ini', 'ultravnc.ini',
          '.docker', 'dockercfg', '.dockerconfigjson', 'config.json',
          'otr.private_key', 'key3.db', 'key4.db', 'Login Data', 'logins.json') | ForEach-Object {
            $null = $Script:BlackFilenames.Add($_)
        }

        # RED - High value (config files with creds, password lists, remote access)
        $Script:RedExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        @('.rdp', '.rdg', '.rtsz', '.rtsx', '.ovpn', '.tvopt', '.sdtid',
          '.pbk', '.vnc', '.ica', '.cscfg', '.publishsettings',
          '.azure', '.aws', '.terraform', '.tfstate', '.tfvars', '.bak') | ForEach-Object {
            $null = $Script:RedExtensions.Add($_)
        }

        $Script:RedFilenames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
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
          'bootstrap.ini', 'CustomSettings.ini', 'variables.xml', 'policy.xml',
          'passwords.txt', 'pass.txt', 'accounts.txt', 'secrets.txt',
          'passwords.doc', 'passwords.docx', 'passwords.xls', 'passwords.xlsx',
          'pass.doc', 'pass.docx', 'pass.xls', 'pass.xlsx',
          'accounts.doc', 'accounts.docx', 'accounts.xls', 'accounts.xlsx',
          'secrets.doc', 'secrets.docx', 'secrets.xls', 'secrets.xlsx',
          'BitlockerLAPSPasswords.csv', 'Favorites.plist', 'proxy.config',
          'keystore', 'keyring', '.gitconfig', '.dockercfg') | ForEach-Object {
            $null = $Script:RedFilenames.Add($_)
        }

        # YELLOW - Interesting by extension (config files, scripts)
        $Script:YellowExtensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        @('.config', '.conf', '.cfg', '.ini', '.inf', '.cnf', '.yaml', '.yml', '.json',
          '.xml', '.properties', '.env', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs',
          '.js', '.py', '.sh', '.sql', '.htaccess', '.htpasswd', '.log', '.txt',
          '.key', '.keypair', '.crt', '.cer', '.der', '.p7b', '.asc', '.gpg') | ForEach-Object {
            $null = $Script:YellowExtensions.Add($_)
        }

        # Partial filename patterns for Yellow triage
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
        #endregion

        #region Content Patterns - Snaffler-aligned
        $Script:ContentPatterns = @{
            'Black' = @(
                '-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----',
                '(?i)aws_access_key_id\s*[=:]\s*[A-Z0-9]{20}',
                '(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}',
                '(\s|''|"|^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|''|"|$)',
                '(?i)connectionstring.{1,200}passw',
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
                '(?i)passw?o?r?d\s*=\s*[''"][^''"]....',
                '(?i)api[Kk]ey\s*=\s*[''"][^''"]....',
                '(?i)passw?o?r?d?>\s*[^\s<]+\s*<',
                '(?i)[\s]+-passw?o?r?d?',
                '(?i)[_\-\.]oauth\s*[=:]\s*[''"][^''"]....',
                '(?i)client_secret\s*[=:]\s*',
                '(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
                'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                '(?i)(api[_-]?key|apikey)\s*[=:]\s*[''"][^''"]{10,}[''"]',
                '(?i)(secret[_-]?key|secretkey)\s*[=:]\s*[''"][^''"]{10,}[''"]',
                '(?i)(auth[_-]?token|authtoken|access[_-]?token)\s*[=:]\s*[''"][^''"]{10,}[''"]',
                '(?i)bearer\s+[a-zA-Z0-9_\-\.=]+',
                '(?i)Basic\s+[A-Za-z0-9+/=]{20,}',
                '(?i)ghp_[A-Za-z0-9]{36}',
                '(?i)gho_[A-Za-z0-9]{36}',
                '(?i)glpat-[A-Za-z0-9\-]{20}',
                '(?i)sk-[A-Za-z0-9]{32,}',
                '(?i)(jdbc|mysql|postgresql|sqlserver|oracle)://[^\s<>"]+:[^\s<>"]+@',
                '(?i)Data\s+Source\s*=.*Password\s*=',
                '(?i)mongodb(\+srv)?://[^\s<>"]+:[^\s<>"]+@',
                '(?i)\[Net\.NetworkCredential\]::new\(',
                '(?i)-SecureString',
                '(?i)-AsPlainText',
                'password 51:b'
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
                '(?i)connectionString\s*[=:]'
            )
        }
        #endregion

        #region Common shares for SMB probing (reduced list for OPSEC)
        $Script:CommonShares = @(
            'SYSVOL', 'NETLOGON', 'Users', 'Shared', 'Public', 'Data', 'Share', 'Shares',
            'Common', 'Software', 'Backup', 'Backups', 'IT', 'HR', 'Finance', 'Scripts',
            'Tools', 'Home', 'homes', 'Profiles', 'Projects', 'Archive', 'files',
            'D$', 'E$', 'F$',
            'SCCMContentLib$', 'SCCMContentLibC$', 'SCCMContentLibD$', 'SCCMContentLibE$',
            'SCCMContent0', 'SMS_DP$', 'SMS_CPSC$', 'SMS_Site', 'SMS_OCM_DATACACHE',
            'SMSPKGC$', 'SMSPKGD$', 'SMSPKGE$', 'SMSPKG$', 'SMSSIG$',
            'REMINST', 'WsusContent', 'UpdateServicesPackages'
        )
        #endregion

        # Results collection (thread-safe)
        $Script:Results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
        $Script:ServiceAccounts = @()
        $Script:ScannedSysvolPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

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

        #region Domain Searcher - PowerView style
        function Get-DomainSearcher {
            Param(
                [String]$Domain,
                [String]$SearchBase,
                [String]$Server,
                [Int]$ResultPageSize = 200,
                [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
            )

            $TargetDomain = $null
            $BindServer = $null

            if ($Domain) {
                $TargetDomain = $Domain
                if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                    if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '')) {
                        $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$ENV:USERDNSDOMAIN"
                    }
                }
            }
            elseif ($Credential -ne [Management.Automation.PSCredential]::Empty) {
                try {
                    $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                        'Domain', $Credential.GetNetworkCredential().Domain,
                        $Credential.UserName, $Credential.GetNetworkCredential().Password)
                    $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                    $BindServer = ($DomainObject.PdcRoleOwner).Name
                    $TargetDomain = $DomainObject.Name
                } catch {}
            }
            elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $TargetDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '')) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
                }
            }
            else {
                try {
                    $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                    $BindServer = ($DomainObject.PdcRoleOwner).Name
                    $TargetDomain = $DomainObject.Name
                } catch {}
            }

            if ($Server) { $BindServer = $Server }

            $SearchString = 'LDAP://'
            if ($BindServer -and ($BindServer.Trim() -ne '')) {
                $SearchString += $BindServer
                if ($TargetDomain) { $SearchString += '/' }
            }

            if ($SearchBase) {
                if ($SearchBase -match '^LDAP://') {
                    $SearchString = $SearchBase
                } else {
                    $SearchString += $SearchBase
                }
            }
            else {
                if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                    $SearchString += "DC=$($TargetDomain.Replace('.', ',DC='))"
                }
            }

            try {
                if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
                    $DomainObject = New-Object DirectoryServices.DirectoryEntry(
                        $SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
                }
                else {
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
                }
                $Searcher.PageSize = $ResultPageSize
                $Searcher.CacheResults = $False
                $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
                return $Searcher
            }
            catch { return $null }
        }
        #endregion

        #region DFS Discovery - PowerView style with PKT parsing
        function Parse-DfsPkt {
            Param([Byte[]]$Pkt)

            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            $object_list = @()

            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]

                $target_list = @()

                switch -wildcard ($blob_name) {
                    "\domainroot*" {
                        # Parse DFS target list
                        $dfs_targetlist_blob_size_start = 52 + ([bitconverter]::ToUInt16($blob_data[18..19],0)) + ([bitconverter]::ToUInt16($blob_data[20..21],0))

                        try {
                            $comment_size = [bitconverter]::ToUInt16($blob_data[34..35],0)
                            $dfs_targetlist_blob_size_start = 52 + $comment_size + ([bitconverter]::ToUInt16($blob_data[18..19],0)) + ([bitconverter]::ToUInt16($blob_data[20..21],0))
                            $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                            $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                            $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                            $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                            $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]

                            $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[0..3],0)
                            $t_offset = 4

                            for($j=1; $j -le $target_count; $j++){
                                $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$t_offset..($t_offset+3)],0)

                                $server_name_size_start = $t_offset + 16
                                $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..($server_name_size_start+1)],0)
                                $server_name_start = $server_name_size_start + 2
                                $server_name_end = $server_name_start + $server_name_size - 1
                                $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                                $share_name_size_start = $server_name_end + 1
                                $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..($share_name_size_start+1)],0)
                                $share_name_start = $share_name_size_start + 2
                                $share_name_end = $share_name_start + $share_name_size - 1
                                $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                                $target_list += "\\$server_name\$share_name"
                                $t_offset = $share_name_end + 1
                            }
                        } catch {}
                    }
                }

                $offset = $blob_data_end + 1
                if ($target_list.Count -gt 0) {
                    $object_list += [PSCustomObject]@{
                        Name = $blob_name
                        TargetList = $target_list
                    }
                }
            }

            return $object_list
        }

        function Get-DomainDFSShareV1 {
            Param(
                [String]$Domain,
                [String]$Server,
                [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
            )

            $SearcherArgs = @{}
            if ($Domain) { $SearcherArgs['Domain'] = $Domain }
            if ($Server) { $SearcherArgs['Server'] = $Server }
            if ($Credential -ne [Management.Automation.PSCredential]::Empty) { $SearcherArgs['Credential'] = $Credential }

            $DFSsearcher = Get-DomainSearcher @SearcherArgs
            if (-not $DFSsearcher) { return @() }

            $DFSshares = @()
            $DFSsearcher.Filter = '(&(objectClass=fTDfs))'

            try {
                $Results = $DFSSearcher.FindAll()
                foreach ($Result in $Results) {
                    $Properties = $Result.Properties
                    $Name = $Properties.name[0]

                    # Get remote server names directly
                    $RemoteNames = $Properties.remoteservername
                    if ($RemoteNames) {
                        foreach ($rn in $RemoteNames) {
                            try {
                                if ($rn.Contains('\')) {
                                    $DFSshares += [PSCustomObject]@{
                                        Name = $Name
                                        RemoteServerName = $rn.split('\')[2]
                                        Path = $rn
                                    }
                                }
                            } catch {}
                        }
                    }

                    # Parse PKT blob for additional targets
                    $Pkt = $Properties.pkt
                    if ($Pkt -and $Pkt[0]) {
                        $parsed = Parse-DfsPkt -Pkt $Pkt[0]
                        foreach ($p in $parsed) {
                            foreach ($target in $p.TargetList) {
                                if ($target -and $target -ne 'null') {
                                    $serverName = $target.Split('\')[2]
                                    $DFSshares += [PSCustomObject]@{
                                        Name = $Name
                                        RemoteServerName = $serverName
                                        Path = $target
                                    }
                                }
                            }
                        }
                    }
                }
                if ($Results) { try { $Results.Dispose() } catch {} }
                $DFSSearcher.Dispose()
            }
            catch {
                Write-Verbose "[Get-DomainDFSShareV1] Error: $_"
            }

            return ($DFSshares | Sort-Object -Unique -Property Path)
        }

        function Get-DomainDFSShareV2 {
            Param(
                [String]$Domain,
                [String]$Server,
                [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
            )

            $SearcherArgs = @{}
            if ($Domain) { $SearcherArgs['Domain'] = $Domain }
            if ($Server) { $SearcherArgs['Server'] = $Server }
            if ($Credential -ne [Management.Automation.PSCredential]::Empty) { $SearcherArgs['Credential'] = $Credential }

            $DFSsearcher = Get-DomainSearcher @SearcherArgs
            if (-not $DFSsearcher) { return @() }

            $DFSshares = @()
            $DFSsearcher.Filter = '(&(objectClass=msDFS-Linkv2))'
            $null = $DFSSearcher.PropertiesToLoad.AddRange(@('msdfs-linkpathv2', 'msDFS-TargetListv2'))

            try {
                $Results = $DFSSearcher.FindAll()
                foreach ($Result in $Results) {
                    $Properties = $Result.Properties
                    $target_list = $Properties.'msdfs-targetlistv2'

                    if ($target_list -and $target_list[0]) {
                        try {
                            $xmlData = $target_list[0]
                            $xml = [xml][System.Text.Encoding]::Unicode.GetString($xmlData[2..($xmlData.Length-1)])

                            foreach ($target in $xml.targets.ChildNodes) {
                                $targetPath = $target.InnerText
                                if ($targetPath -and $targetPath.Contains('\')) {
                                    $DFSroot = $targetPath.split('\')[3]
                                    $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                    $serverName = $targetPath.split('\')[2]

                                    $DFSshares += [PSCustomObject]@{
                                        Name = "$DFSroot$ShareName"
                                        RemoteServerName = $serverName
                                        Path = $targetPath
                                    }
                                }
                            }
                        } catch {}
                    }
                }
                if ($Results) { try { $Results.Dispose() } catch {} }
                $DFSSearcher.Dispose()
            }
            catch {
                Write-Verbose "[Get-DomainDFSShareV2] Error: $_"
            }

            return ($DFSshares | Sort-Object -Unique -Property Path)
        }

        function Get-DomainDFSShare {
            Param(
                [String]$Domain,
                [String]$Server,
                [String]$Version = 'All',
                [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSshares = @()
            $SearcherArgs = @{}
            if ($Domain) { $SearcherArgs['Domain'] = $Domain }
            if ($Server) { $SearcherArgs['Server'] = $Server }
            if ($Credential -ne [Management.Automation.PSCredential]::Empty) { $SearcherArgs['Credential'] = $Credential }

            if ($Version -match 'all|1|v1') {
                $DFSshares += Get-DomainDFSShareV1 @SearcherArgs
            }
            if ($Version -match 'all|2|v2') {
                $DFSshares += Get-DomainDFSShareV2 @SearcherArgs
            }

            return ($DFSshares | Sort-Object -Property Path -Unique)
        }
        #endregion

        #region AD Queries
        function Get-DomainComputers {
            Param(
                [String]$Domain,
                [String]$Server,
                [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
            )

            Write-Status "Querying AD for computers..."
            $SearcherArgs = @{}
            if ($Domain) { $SearcherArgs['Domain'] = $Domain }
            if ($Server) { $SearcherArgs['Server'] = $Server }
            if ($Credential -ne [Management.Automation.PSCredential]::Empty) { $SearcherArgs['Credential'] = $Credential }

            $searcher = Get-DomainSearcher @SearcherArgs
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

        function Get-ServiceAccountsFromAD {
            Param(
                [String]$Server,
                [Management.Automation.PSCredential]$Credential = [Management.Automation.PSCredential]::Empty
            )

            Write-Status "Discovering service accounts from AD..."
            $accounts = @()

            $SearcherArgs = @{}
            if ($Server) { $SearcherArgs['Server'] = $Server }
            if ($Credential -ne [Management.Automation.PSCredential]::Empty) { $SearcherArgs['Credential'] = $Credential }

            $searcher = Get-DomainSearcher @SearcherArgs
            if (-not $searcher) { return @() }

            # Find accounts with SPNs
            $searcher.Filter = "(&(objectCategory=user)(servicePrincipalName=*))"
            $searcher.PropertiesToLoad.AddRange(@('sAMAccountName'))

            try {
                $results = $searcher.FindAll()
                foreach ($r in $results) {
                    $sam = $r.Properties['samaccountname']
                    if ($sam -and $sam[0]) { $accounts += $sam[0] }
                }
            } catch {}

            # Also find accounts matching service patterns
            $servicePatterns = @('svc_', '_svc', 'sql', 'backup', 'admin', 'service')
            foreach ($pattern in $servicePatterns) {
                $searcher.Filter = "(&(objectCategory=user)(sAMAccountName=*$pattern*))"
                try {
                    $results = $searcher.FindAll()
                    foreach ($r in $results) {
                        $sam = $r.Properties['samaccountname']
                        if ($sam -and $sam[0] -and $accounts -notcontains $sam[0]) {
                            $accounts += $sam[0]
                        }
                    }
                } catch {}
            }

            Write-Status "Found $($accounts.Count) service accounts" -Level Success
            return $accounts
        }
        #endregion

        #region File Analysis
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

            if ($OutputFile) {
                switch ($OutputFormat) {
                    'JSON' { $finding | ConvertTo-Json -Compress | Out-File $OutputFile -Append -Encoding UTF8 }
                    'TSV' { "$($finding.Timestamp)`t$Triage`t$Path`t$Match" | Out-File $OutputFile -Append -Encoding UTF8 }
                    default { $line | Out-File $OutputFile -Append -Encoding UTF8 }
                }
            }

            if ($SnaffleDir -and $Size -le $MaxFileSizeSnaffle) {
                try {
                    $destPath = Join-Path $SnaffleDir ($Path -replace '^\\\\', '' -replace '\\', '_')
                    Copy-Item $Path $destPath -ErrorAction SilentlyContinue
                } catch {}
            }
        }

        function Test-ShouldSkipPath {
            Param([String]$Path)
            foreach ($skip in $Script:SkipPaths) {
                if ($Path -like "*\$skip\*" -or $Path -like "*\$skip") { return $true }
            }
            return $false
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
        Write-Host ""
        Write-Host "    _    ____    _    ____ _____   ____  _   _    _    ____  _____ " -ForegroundColor Cyan
        Write-Host "   / \  |  _ \  / \  |  _ \_   _| / ___|| | | |  / \  |  _ \| ____|" -ForegroundColor Cyan
        Write-Host "  / _ \ | | | |/ _ \ | |_) || |   \___ \| |_| | / _ \ | |_) |  _|  " -ForegroundColor Cyan
        Write-Host " / ___ \| |_| / ___ \|  __/ | |    ___) |  _  |/ ___ \|  _ <| |___ " -ForegroundColor Cyan
        Write-Host "/_/   \_\____/_/   \_\_|    |_|   |____/|_| |_/_/   \_\_| \_\_____|" -ForegroundColor Cyan
        Write-Host "                    HUNTER v3                                      " -ForegroundColor Yellow
        Write-Host ""

        # Get domain info
        if (-not $Domain) {
            try { $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name }
            catch { $Domain = $env:USERDNSDOMAIN }
        }
        Write-Status "Target domain: $Domain"

        # Setup credential args
        $CredArgs = @{}
        if ($Server) { $CredArgs['Server'] = $Server }
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) { $CredArgs['Credential'] = $Credential }

        # Discover service accounts if requested
        if ($SearchServiceAccounts) {
            $Script:ServiceAccounts = Get-ServiceAccountsFromAD @CredArgs
        }

        # Build target list
        if ($AllTargetPaths.Count -eq 0) {
            if ($DfsOnly) {
                # DFS-only mode - LDAP queries only, no WMI
                Write-Status "DFS discovery mode (LDAP only)..."
                $dfsShares = Get-DomainDFSShare -Domain $Domain -Version $Version @CredArgs

                foreach ($share in $dfsShares) {
                    if ($share.Path) {
                        $AllTargetPaths += $share.Path
                    }
                }
                Write-Status "DFS discovery found $($AllTargetPaths.Count) share paths" -Level Success
            }
            else {
                # Full computer enumeration
                $computers = Get-DomainComputers -Domain $Domain @CredArgs
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
            Param($Computer, $ExcludedShares, $CommonShares, $NoPing, $PingTimeout, $NoWMI)

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

            # WMI share enumeration (if allowed)
            if (-not $NoWMI) {
                try {
                    $wmiShares = Get-WmiObject -Class Win32_Share -ComputerName $Computer -ErrorAction Stop
                    foreach ($s in $wmiShares) {
                        if (($s.Type -eq 0 -or $s.Type -eq 2147483648) -and $ExcludedShares -notcontains $s.Name) {
                            $results += "\\$Computer\$($s.Name)"
                        }
                    }
                    return $results
                }
                catch {}
            }

            # SMB probing fallback (always used if NoWMI)
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

            return $results
        }

        $discoveredShares = [System.Collections.Concurrent.ConcurrentBag[String]]::new()

        foreach ($target in $AllTargetPaths) {
            if ($target -is [PSCustomObject] -and $target.Type -eq 'Computer') {
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $shareRunspacePool
                $null = $ps.AddScript($shareScriptBlock)
                $null = $ps.AddArgument($target.Value)
                $null = $ps.AddArgument($ExcludedShares)
                $null = $ps.AddArgument($Script:CommonShares)
                $null = $ps.AddArgument($NoPing.IsPresent)
                $null = $ps.AddArgument($PingTimeout)
                $null = $ps.AddArgument($NoWMI.IsPresent)

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

            if ($Delay -gt 0) {
                Start-Sleep -Milliseconds $Delay
            }
        }

        $shareRunspacePool.Close()
        $shareRunspacePool.Dispose()

        Write-Status "Discovered $($discoveredShares.Count) accessible shares" -Level Success

        # Deduplicate SYSVOL/NETLOGON
        $finalShares = @()
        foreach ($share in $discoveredShares) {
            if ($share -match '\\SYSVOL\\?' -or $share -match '\\NETLOGON\\?') {
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

        # Phase 2: File Discovery with Runspaces
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

                    if ($SkipExtensions.Contains($ext)) { return }
                    if (Test-Skip -P $path) { return }

                    $triage = Get-Triage -Name $file.Name -Ext $ext

                    # Certificate private key check
                    if ($CheckCertificates -and $triage -eq 'Black' -and
                        @('.pfx', '.p12', '.pem', '.key') -contains $ext) {
                        if ($ext -eq '.pem' -or $ext -eq '.key') {
                            try {
                                $c = Get-Content $path -Raw -ErrorAction Stop
                                if ($c -notmatch 'PRIVATE KEY') {
                                    $triage = 'Yellow'
                                }
                            }
                            catch { $triage = 'Yellow' }
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
