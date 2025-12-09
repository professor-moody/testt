function Get-AdaptWMIProcess {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'ComputerName' = $ComputerName
                    'Class' = 'Win32_process'
                }
                if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty 'ComputerName' $Computer
                    $Process | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $Process | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $Process | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $Process | Add-Member Noteproperty 'User' $Owner.User
                    $Process
                }
            }
            catch {
                Write-Verbose "[Get-AdaptWMIProcess] Error enumerating remote processes on '$Computer', access likely denied: $_"
            }
        }
    }
}
