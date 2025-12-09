function Find-AdaptInterestingFile {
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = '.\',

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeFolders,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess
    )

    BEGIN {
        $SearcherArguments = @{
            'Recurse' = $True
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $Include
        }
        if ($PSBoundParameters['OfficeDocs']) {
            $SearcherArguments['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($PSBoundParameters['FreshEXEs']) {
            $LastAccessTime = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearcherArguments['Include'] = @('*.exe')
        }
        $SearcherArguments['Force'] = -not $PSBoundParameters['ExcludeHidden']

        function Test-Write {
            [CmdletBinding()]Param([String]$Path)
            try {
                $Filetest = [IO.File]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                $False
            }
        }
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            $SearcherArguments['Path'] = $TargetPath
            Get-ChildItem @SearcherArguments | ForEach-Object {
                $Continue = $True
                if ($PSBoundParameters['ExcludeFolders'] -and ($_.PSIsContainer)) {
                    $Continue = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters['LastWriteTime'] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters['CreationTime'] -and ($_.CreationTime -lt $CreationTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters['CheckWriteAccess'] -and (-not (Test-Write -Path $_.FullName))) {
                    $Continue = $False
                }
                if ($Continue) {
                    $FileParams = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $FoundFile = New-Object -TypeName PSObject -Property $FileParams
                    $FoundFile
                }
            }
        }
    }
}
