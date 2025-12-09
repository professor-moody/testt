function Get-AdaptServiceDetail {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )
    PROCESS {
        ForEach($IndividualService in $Name) {
            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            if ($TargetService) {
                Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                    try {
                        $_
                    }
                    catch {
                        Write-Verbose "Error: $_"
                    }
                }
            }
        }
    }
}
