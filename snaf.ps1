function Invoke-AdaptShareHunter {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String[]]$ComputerName,
        
        [String]$Domain,
        
        [String]$Server,
        
        [String[]]$SharePath,
        
        [Switch]$CheckAccess,
        
        [Switch]$FindFiles,
        
        [ValidateSet('Black', 'Red', 'Yellow', 'Green', 'All')]
        [String]$MinTriage = 'Yellow',
        
        [Switch]$SearchContent,
        
        [Int]$MaxFileSize = 500000,
        
        [Int]$ContentContext = 50,
        
        [Int]$Threads = 10,
        
        [Int]$Delay = 0,
        
        [Double]$Jitter = 0.3,
        
        [String]$OutputFile,
        
        [Switch]$NoPing
    )

    BEGIN {
        $TriageLevels = @{ 'Black' = 4; 'Red' = 3; 'Yellow' = 2; 'Green' = 1; 'All' = 0 }
        $MinTriageLevel = $TriageLevels[$MinTriage]
        
        $BlackExtensions = @('.kdbx', '.kdb', '.ppk', '.vmdk', '.vhdx', '.ova', '.ovf', '.psafe3', '.kwallet', '.tblk', '.ovpn', '.pfx', '.p12', '.pem', '.key', '.asc', '.gpg', '.mdf', '.sdf', '.sqldump', '.bak', '.dmp', '.pcap', '.cap')
        
        $RedExtensions = @('.rdp', '.rdg', '.pbk', '.vnc', '.ica', '.cscfg', '.publishsettings', '.azure', '.aws')
        
        $YellowExtensions = @('.config', '.conf', '.cfg', '.ini', '.inf', '.cnf', '.yaml', '.yml', '.json', '.xml', '.properties', '.env', '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.js', '.py', '.sh', '.sql', '.htaccess', '.htpasswd')
        
        $BlackFilenames = @('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'NTDS.DIT', 'NTDS', 'shadow', 'passwd', 'SAM', 'SYSTEM', 'SECURITY', 'pwd.db', '.netrc', '.pgpass', '.my.cnf', 'credentials', 'credentials.xml', 'recentservers.xml', 'sftp-config.json', 'mobaxterm.ini', 'confCons.xml', 'ConsoleHost_history.txt')
        
        $RedFilenames = @('web.config', 'app.config', 'applicationHost.config', 'machine.config', 'connections.config', 'secrets.json', 'appsettings.json', 'database.yml', 'settings.py', 'wp-config.php', 'configuration.php', 'LocalSettings.php', 'config.php', '.htpasswd', '.env', '.env.local', '.env.production', 'docker-compose.yml', 'Dockerfile', 'Vagrantfile', 'ansible.cfg', 'inventory', 'vault.yml', 'Jenkins.xml', 'hudson.util.Secret', 'master.key', 'credentials.xml', 'terraform.tfstate', 'terraform.tfvars')
        
        $YellowNamePatterns = @('passw', 'secret', 'creds', 'credential', 'login', 'logon', 'token', 'apikey', 'api_key', 'api-key', 'auth', 'private', 'vpn', 'ftp', 'ssh', 'rdp', 'admin', 'backup', 'dump', 'export', 'database', 'db_', '_db', 'mysql', 'mssql', 'oracle', 'postgres', 'mongo', 'redis', 'elastic', 'key', 'cert', 'ssl', 'tls', 'pki', 'handover', 'onboard', 'as-built', 'asbuilt', 'network', 'diagram', 'topology', 'inventory', 'asset', 'cmdb')
        
        $SkipExtensions = @('.exe', '.dll', '.sys', '.msi', '.msp', '.msu', '.cab', '.cat', '.ocx', '.cpl', '.scr', '.drv', '.efi', '.fon', '.ttf', '.otf', '.woff', '.woff2', '.eot', '.bmp', '.gif', '.ico', '.jpg', '.jpeg', '.png', '.svg', '.tif', '.tiff', '.webp', '.psd', '.ai', '.eps', '.mp3', '.mp4', '.wav', '.wma', '.wmv', '.avi', '.mkv', '.mov', '.flv', '.swf', '.zip', '.rar', '.7z', '.gz', '.tar', '.iso', '.img', '.vdi', '.vhd', '.lock', '.log', '.tmp', '.temp', '.cache', '.css', '.less', '.scss', '.map')
        
        $SkipPaths = @('Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', 'node_modules', 'vendor', 'packages', '.git', '.svn', '__pycache__', 'site-packages', 'Temp', 'tmp', 'cache', 'Cache', 'logs', 'Logs')
        
        $ContentPatterns = @{
            'Black' = @(
                '(?i)PRIVATE\s+KEY',
                '(?i)BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE',
                '(?i)aws_access_key_id\s*[=:]\s*[A-Z0-9]{20}',
                '(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}',
                'AKIA[0-9A-Z]{16}',
                '(?i)connectionstring\s*[=:].*password',
                '(?i)(password|passwd|pwd)\s*[=:]\s*["''][^"'']{4,}["'']',
                '(?i)DefaultPassword\s*[=:]\s*.+',
                '(?i)validationKey\s*=\s*"[A-F0-9]+"',
                '(?i)decryptionKey\s*=\s*"[A-F0-9]+"'
            )
            'Red' = @(
                '(?i)(api[_-]?key|apikey)\s*[=:]\s*["''][^"'']{10,}["'']',
                '(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["''][^"'']{10,}["'']',
                '(?i)(auth[_-]?token|authtoken)\s*[=:]\s*["''][^"'']{10,}["'']',
                '(?i)bearer\s+[a-zA-Z0-9_\-\.]+',
                '(?i)Basic\s+[A-Za-z0-9+/=]{20,}',
                '(?i)(client[_-]?secret|clientsecret)\s*[=:]\s*["''][^"'']+["'']',
                '(?i)GITHUB[_-]?TOKEN\s*[=:]\s*["'']?[A-Za-z0-9_]+',
                '(?i)ghp_[A-Za-z0-9]{36}',
                '(?i)sk-[A-Za-z0-9]{48}',
                '(?i)xox[baprs]-[0-9]{10,}-[A-Za-z0-9]+'
            )
            'Yellow' = @(
                '(?i)password\s*[=:]\s*\S+',
                '(?i)passwd\s*[=:]\s*\S+',
                '(?i)pwd\s*[=:]\s*\S+',
                '(?i)credentials?\s*[=:]\s*\S+',
                '(?i)secret\s*[=:]\s*\S+',
                '(?i)token\s*[=:]\s*\S+'
            )
        }
        
        $ShareNames = @('C$', 'ADMIN$', 'IPC$', 'D$', 'E$', 'SYSVOL', 'NETLOGON', 'print$', 'Users', 'Shared', 'Public', 'Data', 'Share', 'Shares', 'Common', 'Software', 'Apps', 'Applications', 'Install', 'Installs', 'Backup', 'Backups', 'IT', 'HR', 'Finance', 'Legal', 'Dev', 'Development', 'Staging', 'Production', 'Scripts', 'Tools', 'Utilities', 'Home', 'homes', 'Profiles', 'Department', 'Projects', 'Archive', 'Archives', 'Logs', 'temp', 'Temp', 'Media', 'Resources', 'Assets', 'Content', 'Web', 'WWW', 'intranet', 'files', 'fileshare', 'Transfer', 'FTP', 'Upload', 'Downloads', 'Scans')

        function Get-AdaptDomainComputerInternal {
            Param([String]$Domain, [String]$Server)
            try {
                $Searcher = New-Object DirectoryServices.DirectorySearcher
                if ($Server) {
                    $Searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server")
                }
                $Searcher.Filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $Searcher.PageSize = 1000
                $Searcher.PropertiesToLoad.AddRange(@('dnshostname', 'name'))
                $Results = $Searcher.FindAll()
                foreach ($Result in $Results) {
                    $dns = $Result.Properties['dnshostname']
                    if ($dns) { $dns[0] } else { $Result.Properties['name'][0] }
                }
            }
            catch {
                Write-Warning "LDAP query failed: $_"
            }
        }

        function Test-AdaptPortInternal {
            Param([String]$ComputerName, [Int]$Port = 445, [Int]$Timeout = 100)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
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

        function Get-AdaptShareListInternal {
            Param([String]$ComputerName)
            $FoundShares = @()
            foreach ($ShareName in $ShareNames) {
                $UNC = "\\$ComputerName\$ShareName"
                try {
                    if (Test-Path -Path $UNC -ErrorAction SilentlyContinue) {
                        $FoundShares += $ShareName
                    }
                }
                catch {}
            }
            return $FoundShares
        }

        function Get-FileTriageInternal {
            Param([String]$FilePath, [String]$FileName, [String]$Extension)
            
            $ExtLower = $Extension.ToLower()
            $NameLower = $FileName.ToLower()
            
            if ($BlackExtensions -contains $ExtLower) { return 'Black' }
            if ($BlackFilenames -contains $NameLower) { return 'Black' }
            
            if ($RedExtensions -contains $ExtLower) { return 'Red' }
            if ($RedFilenames -contains $NameLower) { return 'Red' }
            
            foreach ($Pattern in $YellowNamePatterns) {
                if ($NameLower -match $Pattern) { return 'Yellow' }
            }
            
            if ($YellowExtensions -contains $ExtLower) { return 'Green' }
            
            return $null
        }

        function Search-FileContentInternal {
            Param([String]$FilePath, [Int]$MaxSize, [Int]$Context)
            
            $Results = @()
            try {
                $FileInfo = Get-Item -Path $FilePath -ErrorAction Stop
                if ($FileInfo.Length -gt $MaxSize) { return $Results }
                
                $Content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
                if (-not $Content) { return $Results }
                
                foreach ($Level in @('Black', 'Red', 'Yellow')) {
                    foreach ($Pattern in $ContentPatterns[$Level]) {
                        $RegMatches = [regex]::Matches($Content, $Pattern)
                        foreach ($RegMatch in $RegMatches) {
                            $Start = [Math]::Max(0, $RegMatch.Index - $Context)
                            $Length = [Math]::Min($Content.Length - $Start, $RegMatch.Length + ($Context * 2))
                            $Snippet = $Content.Substring($Start, $Length) -replace '[\r\n]+', ' '
                            $Results += [PSCustomObject]@{
                                Triage = $Level
                                Pattern = $Pattern
                                Match = $RegMatch.Value
                                Context = $Snippet.Trim()
                            }
                        }
                    }
                }
            }
            catch {}
            return $Results
        }

        function Write-FindingInternal {
            Param($Finding, [String]$OutFile)
            
            $Color = switch ($Finding.Triage) {
                'Black' { 'Magenta' }
                'Red' { 'Red' }
                'Yellow' { 'Yellow' }
                'Green' { 'Green' }
                default { 'White' }
            }
            
            $Timestamp = Get-Date -Format "HH:mm:ss"
            $Line = "[$Timestamp] [$($Finding.Triage)] $($Finding.Path)"
            if ($Finding.Match) { 
                $Line = $Line + " | " + $Finding.Match 
            }
            if ($Finding.Context) { 
                $CtxLen = [Math]::Min(100, $Finding.Context.Length)
                $Line = $Line + " | " + $Finding.Context.Substring(0, $CtxLen) + "..."
            }
            
            Write-Host $Line -ForegroundColor $Color
            
            if ($OutFile) {
                $Line | Out-File -FilePath $OutFile -Append -Encoding UTF8
            }
        }

        $AllComputers = @()
    }

    PROCESS {
        if ($SharePath) {
            foreach ($Path in $SharePath) {
                $AllComputers += [PSCustomObject]@{ Type = 'Path'; Value = $Path }
            }
        }
        elseif ($ComputerName) {
            foreach ($Computer in $ComputerName) {
                $AllComputers += [PSCustomObject]@{ Type = 'Computer'; Value = $Computer }
            }
        }
    }

    END {
        if ($AllComputers.Count -eq 0 -and -not $SharePath) {
            Write-Host "[*] Querying AD for computers..." -ForegroundColor Cyan
            $Computers = Get-AdaptDomainComputerInternal -Domain $Domain -Server $Server
            foreach ($Computer in $Computers) {
                $AllComputers += [PSCustomObject]@{ Type = 'Computer'; Value = $Computer }
            }
            Write-Host "[*] Found $($AllComputers.Count) computers" -ForegroundColor Cyan
        }

        $ProcessedShares = @()
        
        foreach ($Target in $AllComputers) {
            if ($Target.Type -eq 'Path') {
                $ProcessedShares += $Target.Value
            }
            else {
                $Computer = $Target.Value
                
                if (-not $NoPing) {
                    if (-not (Test-AdaptPortInternal -ComputerName $Computer -Port 445 -Timeout 100)) {
                        Write-Verbose "[-] $Computer - Port 445 closed"
                        continue
                    }
                }
                
                Write-Verbose "[*] Enumerating shares on $Computer"
                $Shares = Get-AdaptShareListInternal -ComputerName $Computer
                
                foreach ($Share in $Shares) {
                    $UNC = "\\$Computer\$Share"
                    
                    if ($CheckAccess) {
                        try {
                            $null = Get-ChildItem -Path $UNC -ErrorAction Stop | Select-Object -First 1
                            Write-Host "[+] Readable: $UNC" -ForegroundColor Green
                            $ProcessedShares += $UNC
                        }
                        catch {
                            Write-Verbose "[-] Access denied: $UNC"
                        }
                    }
                    else {
                        $ProcessedShares += $UNC
                        Write-Host "[+] Found: $UNC" -ForegroundColor Green
                    }
                }
                
                if ($Delay -gt 0) {
                    $JitterDelay = $Delay + (Get-Random -Minimum (-$Delay * $Jitter) -Maximum ($Delay * $Jitter))
                    Start-Sleep -Milliseconds ([Math]::Max(0, $JitterDelay * 1000))
                }
            }
        }

        if ($FindFiles -and $ProcessedShares.Count -gt 0) {
            Write-Host "" -ForegroundColor Cyan
            Write-Host "[*] Searching for interesting files in $($ProcessedShares.Count) shares..." -ForegroundColor Cyan
            
            foreach ($ShareUNC in $ProcessedShares) {
                Write-Verbose "[*] Scanning: $ShareUNC"
                
                try {
                    Get-ChildItem -Path $ShareUNC -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                        $File = $_
                        $FilePath = $File.FullName
                        
                        $Skip = $false
                        foreach ($SkipExt in $SkipExtensions) {
                            if ($File.Extension -eq $SkipExt) { $Skip = $true; break }
                        }
                        foreach ($SkipP in $SkipPaths) {
                            if ($FilePath -like "*\$SkipP\*") { $Skip = $true; break }
                        }
                        if ($Skip) { return }
                        
                        $Triage = Get-FileTriageInternal -FilePath $FilePath -FileName $File.Name -Extension $File.Extension
                        
                        if ($Triage) {
                            $TriageLevel = $TriageLevels[$Triage]
                            if ($TriageLevel -ge $MinTriageLevel) {
                                $Finding = [PSCustomObject]@{
                                    Triage = $Triage
                                    Path = $FilePath
                                    Size = $File.Length
                                    Modified = $File.LastWriteTime
                                    Match = $null
                                    Context = $null
                                }
                                Write-FindingInternal -Finding $Finding -OutFile $OutputFile
                            }
                        }
                        
                        if ($SearchContent) {
                            $ExtLower = $File.Extension.ToLower()
                            if ($YellowExtensions -contains $ExtLower -or $RedExtensions -contains $ExtLower) {
                                $ContentResults = Search-FileContentInternal -FilePath $FilePath -MaxSize $MaxFileSize -Context $ContentContext
                                foreach ($Result in $ContentResults) {
                                    $TriageLevel = $TriageLevels[$Result.Triage]
                                    if ($TriageLevel -ge $MinTriageLevel) {
                                        $Finding = [PSCustomObject]@{
                                            Triage = $Result.Triage
                                            Path = $FilePath
                                            Size = $File.Length
                                            Modified = $File.LastWriteTime
                                            Match = $Result.Match
                                            Context = $Result.Context
                                        }
                                        Write-FindingInternal -Finding $Finding -OutFile $OutputFile
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[-] Error scanning ${ShareUNC}: $_"
                }
            }
        }

        if (-not $FindFiles) {
            Write-Host "" -ForegroundColor Cyan
            Write-Host "[*] Found $($ProcessedShares.Count) accessible shares:" -ForegroundColor Cyan
            foreach ($s in $ProcessedShares) {
                Write-Host "    $s" -ForegroundColor White
            }
        }
    }
}
