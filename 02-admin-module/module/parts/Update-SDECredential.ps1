function Update-SDECredential {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint
    )
    <#
        2DO:
        - add/remove instances
    #>
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
        if ($nameCount -eq 0) {
            Write-Host "Credential [$($Name)] not found in the database. Use New-SDECredential to insert new credential."
            Write-AuditLog -EventType UpdateCred -EventSubject "Credential [$($Name)] not found in the database"
        } else {
            $updateQ = @()
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
                    $updateQ += "UPDATE CREDS SET CredData='$($payloadMessage)',CredUpdatedBy='$($env:USERDOMAIN)\$($env:USERNAME)',CredUpdatedOn=CURRENT_TIMESTAMP WHERE CertThumbprint='$($tp)' AND CredName='$($Name -replace "'","''")'"
                    $rdr.Close()
                    $rdr.Dispose()
                    Write-AuditLog -EventType UpdateCred -EventSubject "Credential [$($Name)] updated for certificate [$($tp)]"
                } else {
                    Write-Warning ('Certificate with thumbprint [{0}] not present in the database. Use Add-SDECertificate to add it.' -f $tp)
                }
            }
            foreach ($q in $updateQ) {
                $sqlcmd.CommandText = $q
                $null = $sqlCmd.ExecuteNonQuery()
            }
        }

        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
        return $true
    }
}