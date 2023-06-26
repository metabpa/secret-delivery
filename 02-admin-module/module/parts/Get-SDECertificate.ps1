<#
.SYNOPSIS
Returns certificates stored in the SDE database.

.DESCRIPTION
Returns certificates stored in the SDE database.

.PARAMETER Thumbprint
A thumbprint to match. Exact match only!

.PARAMETER DisplayName
A display name to filter on. Exact match only!

.PARAMETER Raw
If this switch is specified, raw X509Certificate2 objects are returned.

.PARAMETER Status
If contains 'managed', only managed certificates, i.e. those imported or confirmed by an admin, are returned.
If contains 'unmanaged', only unmanaged certificates, i.e. uploaded by the client (not implemented in the API yet) are returned.
If contains 'valid', only certificates that are neither revoked nor expired are returned.
If contains 'revoked', only revoked certificates are returned.
If contains 'expired', only expired certificates are returned.
If this parameter is omitted, all certificated matching the rest of the criteria are returned.

.INPUTS
None.

.OUTPUTS
One of two:
- a collection of PSCustomObject objects representing the certificates. These objects contain domain-specific information like DisplayName, IsManaged and IsRevoked.
- a collection of X509Certificate2 objects (if -Raw was specified).

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function Get-SDECertificate {
    [CmdletBinding(DefaultParameterSetName='Thumbprint')]
    Param(
        [Parameter(Mandatory=$false,ParameterSetName='Thumbprint')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,ParameterSetName='DisplayName')]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [switch]$Raw,
        [Parameter(Mandatory=$false)]
        [ValidateSet('managed','unmanaged','revoked','expired','valid')]
        [string[]]$Status
    )
    if (($Status -contains 'managed') -and ($Status -contains 'unmanaged')) {
        Write-Warning 'No certificate entry can be managed and unmanaged!'
        retrun $null
    }
    if (($Status -contains 'revoked') -and ($Status -contains 'valid')) {
        Write-Warning 'No certificate entry can be revoked and valid!'
        retrun $null
    }
    if (($Status -contains 'expired') -and ($Status -contains 'valid')) {
        Write-Warning 'No certificate entry can be expired and valid!'
        retrun $null
    }
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
        $q = "SELECT * FROM CERTS WHERE (1=1)"
        if (-not [string]::IsNullOrEmpty($Thumbprint)) {
            $q += " AND (CertThumbprint='$($Thumbprint)')"
        } elseif (-not [string]::IsNullOrEmpty($DisplayName)) {
            $q += " AND (CertName='$($DisplayName)')"
        }
        if ($Status -contains 'managed') {
            $q += " AND (CertIsManaged=1)"
        } elseif ($Status -contains 'unmanaged') {
            $q += " AND (CertIsManaged=0)"
        }
        if ($Status -contains 'revoked') {
            $q += " AND (CertIsRevoked=1)"
        } 
        if ($Status -contains 'expired') {
            $q += " AND (CertNotAfter < '$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')')"
        }
        if ($Status -contains 'valid') {
            $q += " AND (CertIsRevoked=0) AND (CertNotAfter > '$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')')"
        }
        Write-Verbose $q
        $sqlCmd.CommandText = $q
        $sqlRdr = $sqlCmd.ExecuteReader()
        while ($sqlRdr.Read()) {
            if ($Raw) {
                $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                try {
                    $tmpCert.Import([byte[]][char[]]($sqlRdr['CertData']))
                    $tmpCert
                } catch {
                    Write-Warning "Error importing certificate [$($sqlRdr['CertThumbprint'])]: $($_.Exception.Message)"
                }
            } else {
                [PSCustomObject]@{
                    'Thumbprint' = $sqlRdr['CertThumbprint']
                    'DisplayName' = $sqlRdr['CertName']
                    'Subject' = $sqlRdr['CertSubject']
                    'Issuer' = $sqlRdr['CertIssuer']
                    'NotBefore' = $sqlRdr['CertNotBefore']
                    'NotAfter' = $sqlRdr['CertNotAfter']
                    'IsManaged' = ($sqlRdr['CertIsManaged'] -eq 1)
                    'IsRevoked' = ($sqlRdr['CertIsManaged'] -eq 1)
                    'AddedOn' = $sqlRdr['CertAddedOn']
                    'AddedBy' = $sqlRdr['CertAddedBy']
                }
            }
        }
        $sqlrdr.Close()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}