function Get-AdaptGPODelegation {
    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',
        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200
    )
    $Exclusions = @('SYSTEM','Domain Admins','Enterprise Admins')
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $Filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = "Subtree"
        $listGPO = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
        if ($ACL -ne $null){
            $GpoACL = New-Object psobject
            $GpoACL | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}
