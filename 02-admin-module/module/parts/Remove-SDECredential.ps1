<#
.SYNOPSIS
Deletes a credential stored in the SDE database.

.DESCRIPTION
Deletes a credential stored in the SDE database. Client restrictions linked to this credential are also deleted.

.PARAMETER Name
Name of the credential to remove. Exact match only!

.PARAMETER Thumbprint
One or multiple thumbprints to match. Exact match only!
If no thumbprint is specifed, all encrypted records for the credential name are deleted.

.INPUTS
None.

.OUTPUTS
True or False, depending on the success of the removal operation.

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function Remove-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint
    )
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection
    $sqlConn.ConnectionString = $script:moduleConfig.SQLConnectionString
    try {
        $sqlConn.Open()
    } catch {
        Write-Warning $_.Exception.Message
        return
    }
    if ($sqlConn.State -eq 'Open') {
        $res = $true
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
        $sqlCmd.CommandText = $q
        $nameCount = $sqlCmd.ExecuteScalar()
        if ($nameCount -eq 0) {
            Write-Host "Credential [$($Name)] not found in the database. Use New-SDECredential to insert new credential."
            Write-AuditLog -EventType RemoveCred -EventSubject "Credential [$($Name)] not found in the database"
        } else {
            if (-not $PSBoundParameters.ContainsKey('Thumbprint')) {
                Write-Verbose 'Determining thumbprints this credential is stored for'
                $Thumbprint = @()
                $q = "Select CertThumbprint FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
                $sqlCmd.CommandText = $q
                $rdr = $sqlCmd.ExecuteReader()
                while ($rdr.Read()) {
                    Write-Verbose "Adding $($rdr['CertThumbprint'])"
                    $Thumbprint += $rdr['CertThumbprint']
                }
                $rdr.Close()
                $rdr.Dispose()
            }
            foreach ($tp in $Thumbprint) {
                $q = "DELETE FROM CREDS WHERE CredName='$($Name -replace "'","''")' AND CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $nDelCred = $sqlCmd.ExecuteNonQuery()
                $q = "DELETE FROM CLIENTS WHERE CredName='$($Name -replace "'","''")' AND CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $nDelCli = $sqlCmd.ExecuteNonQuery()
                Write-AuditLog -EventType RemoveCred -EventSubject "Credential [$($Name)] removed for certificate [$($tp)]. $nDelCred credential entries and $nDelCli client restrictions were removed."
            }
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    } else {
        $res = $false
    }
    return $res
}