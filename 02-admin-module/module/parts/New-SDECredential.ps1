<#
.SYNOPSIS
Creates a new credential in the SDE database.

.DESCRIPTION
Creates a new credential in the SDE database. This means, that the name used to add the credential has not yet been used.

.PARAMETER Thumbprint
One or more thumbprints of certificates to encrypt credential with. Exact match only.

.PARAMETER Name
A name for the new credential. The name will be used to build a retreival URI so ideally it should only contain letters and numbers.

.PARAMETER Credential
A PSCredential object representing the credential.

.INPUTS
None.

.OUTPUTS
True or False, depending on the success of the operation.

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function New-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory=$true)]
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
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CREDS WHERE CredName='$($Name -replace "'","''")'"
        $sqlCmd.CommandText = $q
        $nameCount = $sqlCmd.ExecuteScalar()
        if ($nameCount -gt 0) {
            Write-Warning "Credential [$($Name)] already present in the database. Use Update-SDECredential to update an existing credential."
            Write-AuditLog -EventType NewCred -EventSubject "Credential [$($Name)] already present in the database."
        } else {
            $insertQ = @()
            foreach ($tp in $Thumbprint) {
                $q = "SELECT CertData, CertSubject, CertTemplateOID FROM CERTS WHERE CertThumbprint='$($tp)'"
                $sqlCmd.CommandText = $q
                $rdr = $sqlCmd.ExecuteReader()
                if ($rdr.HasRows) {
                    $null = $rdr.Read()
                    $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $tmpCert.Import([byte[]][char[]]($rdr['certData']))
                    $payloadObject = [PSCustomObject]@{
                        'Padding' = Get-Padding
                        'UserName' = $Credential.UserName
                        'Password' = $Credential.GetNetworkCredential().Password
                        'Thumbprint' = $tp
                        'Name' = $Name
                        'Template' = $rdr['CertTemplateOID']
                        'Updated' = Get-Date
                    }
                    $payloadText = $payloadObject | ConvertTo-Json -Compress
                    $payloadMessage = Protect-CmsMessage -To $tmpCert -Content $payloadText
                    $insertQ += "INSERT INTO CREDS (CertThumbprint,CredName,CredData,CredAddedBy,CredAddedOn) VALUES ('$($tp)','$($Name -replace "'","''")','$($payloadMessage)','$($env:USERDOMAIN)\$($env:USERNAME)',CURRENT_TIMESTAMP)"
                    Write-AuditLog -EventType NewCred -EventSubject "Credential [$($Name)] encrypted for certificate [$($tp)]"
                    $rdr.Close()
                    $rdr.Dispose()
                } else {
                    Write-Warning ('Certificate with thumbprint [{0}] not present in the database. Use Add-SDECertificate to add it.' -f $tp)
                }
            }
            foreach ($q in $insertQ) {
                $sqlcmd.CommandText = $q
                try {
                    $null = $sqlCmd.ExecuteNonQuery()
                } catch {
                    Write-Warning $q
                    Write-Warning $_.Exception.Message
                }
            }
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
        return $true
    }
}