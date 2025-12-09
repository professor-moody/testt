function Get-AdaptWMIRegProxy {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'List' = $True
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $Computer
                    'ErrorAction' = 'Stop'
                }
                if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }
                $RegProvider = Get-WmiObject @WmiArguments
                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
                $HKCU = 2147483649
                $ProxyServer = $RegProvider.GetStringValue($HKCU, $Key, 'ProxyServer').sValue
                $AutoConfigURL = $RegProvider.GetStringValue($HKCU, $Key, 'AutoConfigURL').sValue
                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        Write-Warning "[Get-AdaptWMIRegProxy] Error connecting to AutoConfigURL : $AutoConfigURL"
                    }
                }
                if ($ProxyServer -or $AutoConfigUrl) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'ComputerName' $Computer
                    $Out | Add-Member Noteproperty 'ProxyServer' $ProxyServer
                    $Out | Add-Member Noteproperty 'AutoConfigURL' $AutoConfigURL
                    $Out | Add-Member Noteproperty 'Wpad' $Wpad
                    $Out
                }
                else {
                    Write-Warning "[Get-AdaptWMIRegProxy] No proxy settings found for $ComputerName"
                }
            }
            catch {
                Write-Warning "[Get-AdaptWMIRegProxy] Error enumerating proxy settings for $ComputerName : $_"
            }
        }
    }
}
