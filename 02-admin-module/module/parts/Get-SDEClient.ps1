<#
.SYNOPSIS
Returns client restrictions stored in the SDE database.

.DESCRIPTION
Returns client restrictions stored in the SDE database.

.PARAMETER Thumbprint
One or more thumbprints to match. Exact match only!

.PARAMETER Name
One or more credential names to filter on. Exact match only!

.PARAMETER IPAddress
One or more IP addresses to filter on. Exact match only!

.INPUTS
None.

.OUTPUTS
A collection of PSCustomObject objects representing the client restrictions.

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function Get-SDEClient {
    [CmdletBinding(DefaultParameterSetName='All')]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='Thumbprint')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint,
        [Parameter(Mandatory=$true,ParameterSetName='IPAddress')]
        [ValidateScript({$ipa = ($_ -as [ipaddress]); if ($null -ne $ipa) { ($ipa.IPAddressToString -ieq $_) } else { $false }})]
        [string[]]$IPAddress
    )
    $q = "SELECT * FROM CLIENTS"
    switch ($PSCmdlet.ParameterSetName) {
        'All' { $q += " ORDER BY CredName" }
        'Name' { $q += " WHERE CredName IN ('$(($Name | ForEach-Object {$_ -replace "'","''"}) -join "','")') ORDER BY CredName" }
        'Thumbprint' { $q += " WHERE CertThumbprint IN ('$($Thumbprint -join "','")') ORDER BY CertThumbprint" }
        'IPAddress' { $q += " WHERE SourceIP IN ('$($IPAddress -join "','")') ORDER BY SourceIP" }
    }
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $sqlCmd = $sqlConn.CreateCommand()
        Write-Verbose $q
        $sqlCmd.CommandText = $q
        $rdr = $sqlCmd.ExecuteReader()
        while ($rdr.Read()) {
            [PSCustomObject]@{
                'CredentialName' = $rdr['CredName']
                'Thumbprint' = $rdr['CertThumbprint']
                'IPAddress' = $rdr['SourceIP']
            }
        }
        $rdr.Close()
        $rdr.Dispose()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}