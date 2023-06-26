<#
.SYNOPSIS
Deletes certificates stored in the SDE database.

.DESCRIPTION
Deletes certificates stored in the SDE database. Credentials encrypted by the deleted certificates and client restrictions linked to these credentials are also deleted.

.PARAMETER Thumbprint
A thumbprint to match. Exact match only!

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
function Remove-SDECertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint
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
        $res = $true
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT CertId FROM CERTS  WHERE CertThumbprint='$($Thumbprint)'"
        $sqlCmd.CommandText = $q
        $cid = $sqlCmd.ExecuteScalar()
        if ($cid -gt 0) {
            Write-Verbose "Certificate found, delete associated entries using ID=$($cid)"
            $q = "DELETE FROM CREDS WHERE CertThumbprint='$($Thumbprint)'"
            $sqlCmd.CommandText = $q
            $nDelCred = $sqlCmd.ExecuteNonQuery()
            Write-Verbose "Removed $($nDelCred) credentials from database"
            $q = "DELETE FROM CLIENTS WHERE CertThumbprint='$($Thumbprint)'"
            $sqlCmd.CommandText = $q
            $nDelCli = $sqlCmd.ExecuteNonQuery()
            Write-Verbose "Removed $($nDelCli) client restrictions from database"
            $q = "DELETE FROM CERTS WHERE CertThumbprint='$($Thumbprint)'"
            $sqlCmd.CommandText = $q
            $nDelCert = $sqlCmd.ExecuteNonQuery()
            if ($nDelCert -gt 0) {
                Write-Verbose "Certificate removed"
                Write-AuditLog -EventType RemoveCertSuccess -EventSubject "Removed certificate [$($Thumbprint)] including $($nDelCli) client restrictions and $($nDelCred) saved credentials"
            } else {
                Write-Verbose "Certificate not removed"
                Write-AuditLog -EventType RemoveCertFailure -EventSubject "Could not remove certificate [$($Thumbprint)], $($nDelCli) client restrictions and $($nDelCred) saved credentials were removed from database"
                $res = $false
            }
        } else {
            Write-Warning 'Certificate not found in database'
            Write-AuditLog -EventType RemoveCert -EventSubject "Certificate [$($Thumbprint)] not found in database"
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    } else {
        $res = $false
    }
    return $res
}