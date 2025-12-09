function Find-AdaptProcessDLLHijack {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),
        [Switch]
        $ExcludeWindows,
        [Switch]
        $ExcludeProgramFiles,
        [Switch]
        $ExcludeOwned
    )
    BEGIN {
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }
    PROCESS {
        ForEach ($ProcessName in $Name) {
            $TargetProcess = Get-Process -Name $ProcessName
            if ($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($Null -ne $TargetProcess.Path)) {
                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent
                    $LoadedModules = $TargetProcess.Modules
                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]
                    ForEach ($Module in $LoadedModules){
                        $ModulePath = "$BasePath\$($Module.ModuleName)"
                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {
                            $Exclude = $False
                            if ($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }
                            if ($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }
                            if ($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }
                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}
