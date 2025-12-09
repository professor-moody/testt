function Convert-ADName {
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $Identity,
        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $OutputType,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $NameTypes = @{
            'DN'                =   1
            'Canonical'         =   2
            'NT4'               =   3
            'Display'           =   4
            'DomainSimple'      =   5
            'EnterpriseSimple'  =   6
            'GUID'              =   7
            'Unknown'           =   8
            'UPN'               =   9
            'CanonicalEx'       =   10
            'SPN'               =   11
            'SID'               =   12
        }
        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Null
            $Output = $Object.GetType().InvokeMember($Method, 'InvokeMethod', $NULL, $Object, $Parameters)
            Write-Output $Output
        }
        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, 'GetProperty', $NULL, $Object, $NULL)
        }
        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, 'SetProperty', $NULL, $Object, $Parameters)
        }
        if ($PSBoundParameters['Server']) {
            $ADSInitType = 2
            $InitName = $Server
        }
        elseif ($PSBoundParameters['Domain']) {
            $ADSInitType = 1
            $InitName = $Domain
        }
        elseif ($PSBoundParameters['Credential']) {
            $Cred = $Credential.GetNetworkCredential()
            $ADSInitType = 1
            $InitName = $Cred.Domain
        }
        else {
            $ADSInitType = 3
            $InitName = $Null
        }
    }
    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($TargetIdentity -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $ADSOutputType = $NameTypes['DomainSimple']
                }
                else {
                    $ADSOutputType = $NameTypes['NT4']
                }
            }
            else {
                $ADSOutputType = $NameTypes[$OutputType]
            }
            $Translate = New-Object -ComObject NameTranslate
            if ($PSBoundParameters['Credential']) {
                try {
                    $Cred = $Credential.GetNetworkCredential()
                    Invoke-Method $Translate 'InitEx' (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $Null = Invoke-Method $Translate 'Init' (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' : $_"
                }
            }
            Set-Property $Translate 'ChaseReferral' (0x60)
            try {
                $Null = Invoke-Method $Translate 'Set' (8, $TargetIdentity)
                Invoke-Method $Translate 'Get' ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}

function Get-PrincipalContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    try {
        if ($PSBoundParameters['Domain'] -or ($Identity -match '.+\\.+')) {
            if ($Identity -match '.+\\.+') {
                $ConvertedIdentity = $Identity | Convert-ADName -OutputType Canonical
                if ($ConvertedIdentity) {
                    $ConnectTarget = $ConvertedIdentity.SubString(0, $ConvertedIdentity.IndexOf('/'))
                    $ObjectIdentity = $Identity.Split('\')[1]
                    Write-Verbose "[Get-PrincipalContext] Binding to domain '$ConnectTarget'"
                }
            }
            else {
                $ObjectIdentity = $Identity
                Write-Verbose "[Get-PrincipalContext] Binding to domain '$Domain'"
                $ConnectTarget = $Domain
            }
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget)
            }
        }
        else {
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $DomainName = Get-AdaptDomain | Select-Object -ExpandProperty Name
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $ObjectIdentity = $Identity
        }
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'Context' $Context
        $Out | Add-Member Noteproperty 'Identity' $ObjectIdentity
        $Out
    }
    catch {
        Write-Warning "[Get-PrincipalContext] Error creating binding for object ('$Identity') context : $_"
    }
}

function Get-AdaptDomain {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[Get-AdaptDomain] Using alternate credentials for Get-AdaptDomain'
            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-AdaptDomain] Extracted domain '$TargetDomain' from -Credential"
            }
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-AdaptDomain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-AdaptDomain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-AdaptDomain] Error retrieving the current domain: $_"
            }
        }
    }
}

function Remove-AdaptDomainGroupMember {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters['Domain']) { $ContextArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Credential']) { $ContextArguments['Credential'] = $Credential }
        $GroupContext = Get-PrincipalContext @ContextArguments
        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning "[Remove-AdaptDomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }
    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match '.+\\.+') {
                    $ContextArguments['Identity'] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose "[Remove-AdaptDomainGroupMember] Removing member '$Member' from group '$Identity'"
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Remove($Member)
                $Group.Save()
            }
        }
    }
}
