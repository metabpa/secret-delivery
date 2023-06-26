<#
.SYNOPSIS
Returns credentials stored in the SDE database.

.DESCRIPTION
Returns credentials stored in the SDE database.

.PARAMETER Thumbprint
A thumbprint to match. Exact match only!

.PARAMETER Name
A display name to filter on. Exact match only!

.INPUTS
None.

.OUTPUTS
A collection of PSCustomObject objects representing the credentials. 

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function Get-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$IncludePayload
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return $false
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT * FROM CREDS WHERE (1=1)"
        if (-not [string]::IsNullOrEmpty($Thumbprint)) {
            $q += " AND (CertThumbprint='$($Thumbprint)')"
        }
        if (-not [string]::IsNullOrEmpty($Name)) {
            $q += " AND (CredName='$($Name -replace "'","''")')"
        }
        
        Write-Verbose $q
        $sqlCmd.CommandText = $q
        $sqlRdr = $sqlCmd.ExecuteReader()
        while ($sqlRdr.Read()) {
            [PSCustomObject]@{
                'ID' = $sqlRdr['CredID']
                'Thumbprint' = $sqlRdr['CertThumbprint']
                'Name' = $sqlRdr['CredName']
                'AddedOn' = $sqlRdr['CredAddedOn']
                'AddedBy' = $sqlRdr['CredAddedBy']
                'UpdatedOn' = $sqlRdr['CredUpdatedOn']
                'UpdatedBy' = $sqlRdr['CredUpdatedBy']
                'Payload' = if ($IncludePayload) { $sqlRdr['CredData'] }
            }
        }
        $sqlrdr.Close()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    } else {
        return $null
    }
}