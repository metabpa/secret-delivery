<#
.SYNOPSIS
Imports a certificate into SDE database.

.DESCRIPTION
Imports a certificate into the SDE database. The certificate can be one of the following:
- Path: a path to a .cer, .crt or .pem file
- Thumbprint: a cert from the personal store of the invoking user.
- Certificate: An object convertable to X509Certificate2
These three are mutually exclusive.

.PARAMETER Path
A path to a .cer, .crt or .pem file.

.PARAMETER Thumbprint
A certificate from the personal store of the invoking user.

.PARAMETER Certificate
A certificate object.

.PARAMETER IgnoreEKU
Without this switch, only certificates having a Document Encryption EKU (1.3.6.1.4.1.311.80.1) will be imported.
This switch allows you to override this behaviour.

.PARAMETER DisplayName
An optional display name for the certificate in the SDE database. If omitted, the SAH-1 thumbprint will be used.

.INPUTS
None.

.OUTPUTS
True or False, according to the success of the operation.

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.3.1
Build: 2023-06-20
#>
function Add-SDECertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,ParameterSetName='File')]
        [string]$Path,
        [Parameter(Mandatory=$true,ParameterSetName='Store')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$true,ParameterSetName='X509')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$false,ParameterSetName='File')]
        [Parameter(Mandatory=$false,ParameterSetName='Store')]
        [Parameter(Mandatory=$false,ParameterSetName='X509')]
        [switch]$IgnoreEKU,
        [Parameter(Mandatory=$false,ParameterSetName='File')]
        [Parameter(Mandatory=$false,ParameterSetName='Store')]
        [Parameter(Mandatory=$false,ParameterSetName='X509')]
        [string]$DisplayName
    )
    $cert2add = $null
    switch ($PSCmdlet.ParameterSetName) {
        'File' {
            if (Test-Path -Path $Path -PathType Leaf) {
                $tmpCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                try {
                    $null = $tmpCert.Import($Path)
                    $cert2add = $tmpCert
                } catch {
                    Write-Warning ('Error importing {0} into X509 Certificate: {1}' -f $Path, $_.Exception.Message)
                }
            }
        }
        'Store' {
            try {
                $tmpCert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -EA Stop
            } catch {
                $tmpCert = $null
            }
            if ($null -eq $tmpCert) {
                try {
                    $tmpCert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -EA Stop
                } catch {}
            }
            if ($null -ne $tmpCert) {
                $cert2add = $tmpCert
            }
        }
        'X509' {
            $cert2add = $Certificate
        }
    }
    if ($null -eq $cert2add) {
        return $false
        Write-AuditLog -EventType AddCertFailure -EventSubject "Certificate could not be found ($($PSCmdlet.ParameterSetName))"
    }
    if (-not $IgnoreEKU) {
        if ($cert2add.EnhancedKeyUsageList.ObjectID -notcontains '1.3.6.1.4.1.311.80.1') {
            Write-AuditLog -EventType AddCertFailure -EventSubject "Certificate does not have Document Encryption EKU ($($cert2add.Thumbprint))"
            return $false
        }
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
        $res = $true
        $sqlCmd = $sqlConn.CreateCommand()
        $q = "SELECT COUNT(*) FROM CERTS WHERE CertThumbprint='$($cert2add.Thumbprint)'"
        $sqlCmd.CommandText = $q
        $existingCount = $sqlCmd.ExecuteScalar()
        if ($existingCount -gt 0) {
            Write-Host 'Certificate already present in the database'
            Write-AuditLog -EventType AddCertFailure -EventSubject "Certificate already present in the database ($($cert2add.Thumbprint))"
        } else {
            if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $cert2add.Thumbprint }
            $certData = [Convert]::ToBase64String($cert2add.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert), [Base64FormattingOptions]::InsertLineBreaks)
            $certData = "-----BEGIN CERTIFICATE-----`r`n$($certData)`r`n-----END CERTIFICATE-----"
            $certTemplate = Get-TemplateInfo -Certificate $cert2add
            if ($null -eq $certTemplate) {
                $tName = ''
                $tOID = ''
            }else {
                $tName = $certTemplate.TemplateName -replace "'","''"
                $tOID = $certTemplate.TemplateOID
            }
            $q = "INSERT INTO CERTS (CertName,CertThumbprint,CertSubject,CertIssuer,CertData,CertNotAfter,CertNotBefore,CertTemplateName,CertTemplateOID,CertIsManaged,CertAddedBy,CertAddedOn) VALUES ('$($DisplayName)','$($cert2add.Thumbprint)','$($cert2add.Subject)','$($cert2add.Issuer)','$($certData)','$(Get-Date $cert2add.NotAfter -Format "yyyy-MM-ddTHH:mm:ss")','$(Get-Date $cert2add.NotBefore -Format "yyyy-MM-ddTHH:mm:ss")','$($tName)','$($tOID)',1,'$($env:USERDOMAIN)\$($env:USERNAME)',CURRENT_TIMESTAMP)"
            $sqlcmd.CommandText = $q
            $null = $sqlCmd.ExecuteNonQuery()
            Write-AuditLog -EventType AddCertSuccess -EventSubject "Certificate [$($cert2add.Thumbprint)] added successfully from ($($PSCmdlet.ParameterSetName)): Subject=$($cert2add.Subject), Issuer=$($cert2add.Issuer)"
        }

        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
        return $true
    }
}