<#
    SDE Admin Module
    https://github.com/metabpa/secret-delivery
#>
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

<#
.SYNOPSIS
Adds a client restriction record to the SDE database.

.DESCRIPTION
Adds a client restriction record to the SDE database.

.PARAMETER Thumbprint
One or more thumbprints to match. Exact match only!

.PARAMETER Name
One or more credential names to filter on. Exact match only!

.PARAMETER IPAddress
One or more IP addresses to filter on. Exact match only!

.PARAMETER Description
An optional description you can add to a client restriction records.

.INPUTS
None.

.OUTPUTS
None.

.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function Add-SDEClient {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$Thumbprint,
        [Parameter(Mandatory=$true)]
        [ValidateScript({$ipa = ($_ -as [ipaddress]); if ($null -ne $ipa) { ($ipa.IPAddressToString -ieq $_) } else { $false }})]
        [string[]]$IPAddress,
        [Parameter(Mandatory=$false)]
        [string]$Description
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
        $exNames = @()
        $sqlCmd.CommandText = "SELECT CredName FROM CREDS WHERE CredName IN ('$($Name -join "','")')"
        $rdr = $sqlCmd.ExecuteReader()
        while ($rdr.Read()) {
            $exNames += $rdr['CredName']
        }
        $rdr.Close()
        Write-Verbose "Determined $($exNames.Count) Names to process: $($exNames -join ', ')"
        foreach ($cn in $exNames) {
            Write-Verbose "Processing $cn"
            $exTP = @()
            $sqlCmd.CommandText = "SELECT CertThumbprint FROM CREDS WHERE CredName='$($cn -replace "'","''")'"
            $rdr = $sqlCmd.ExecuteReader()
            while ($rdr.Read()) {
                if ($Thumbprint.Count -eq 0) {
                    $exTP += $rdr['CertThumbprint']
                } else {
                    if ($Thumbprint -icontains $rdr['CertThumbprint']) {
                        $exTP += $rdr['CertThumbprint']
                    }
                }
            }
            $rdr.Close()
            foreach ($tp in $exTP) {
                $sqlCmd.CommandText = "SELECT COUNT(*) FROM CREDS WHERE (CredName='$($cn -replace "'","''")') AND (CertThumbprint='$($tp)')"
                $nCred = $sqlCmd.ExecuteScalar()
                if ($nCred -gt 0) {
                    foreach ($ip in $IPAddress) {
                        $sqlcmd.CommandText = "IF NOT EXISTS (SELECT * FROM CLIENTS WHERE (CredName='$($cn -replace "'","''")') AND (CertThumbprint='$($tp)') AND (SourceIP='$($ip)')) INSERT INTO CLIENTS (CredName,CertThumbprint,SourceIP,Description) VALUES ('$($cn -replace "'","''")','$($tp)','$($ip)','$($Description)')"
                        $nins = $sqlCmd.ExecuteNonQuery()
                        if ($nins -gt 0) {
                            Write-AuditLog -EventType AddClient -EventSubject "Added client restriction to $($ip) for [$($cn)] with certificate $($tp)"
                        }
                    }
                } else {
                    Write-Verbose "No credential item for [$($cn)] with certificate $($tp)"
                }
            }
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}

<#
.SYNOPSIS
Exports a HTML report of the SDE database inventory.

.DESCRIPTION
Exports a HTML report of the SDE database inventory. Will be replaced later by the Management Portal.

.PARAMETER Path
A path to a folder where the inventory report will be placed. If omitted, the Documents folder of the invoking user is used.

.INPUTS
None.

.OUTPUTS


.LINK
https://metabpa.org/projects/sde/admin-module/

.NOTES
Version 
Build: 
#>
function Export-SDEInventory {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Path
    )
    Write-Warning "THIS IS NOT IMPLEMENTED YET"
}

function Get-Padding {
    [CmdletBinding()]
    Param()
    $padLen = Get-Random -Minimum 10 -Maximum 100
    $padChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789^!°"§$%&/()=?\{}[],;.:-_<>|'
    $res = '';
    for ($i = 0;$i -lt $padLen; $i++) {
        $res += $padChars.Substring((Get-Random -Minimum 0 -Maximum ($padChars.Length)),1)
    }
    return $res
}

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

function Get-TemplateInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $tplData = $Certificate.Extensions.Where({$_.Oid.Value -eq '1.3.6.1.4.1.311.21.7'})
    if ($tplData.Count -gt 0) { 
        $tplText = $tplData.Format($true)
        if ($tplText -match 'Template\=(?<tplinfo>.*)\W') {
            $tplName = $Matches['tplinfo']
            if ($tplName -match '(?<name>.+)\((?<oid>[\d\.]+)\)') {
                return [PSCustomObject]@{
                            'TemplateName' = $Matches['name']
                            'TemplateOID' = $matches['oid']
                        }
            }
        }
    } else {
        return $null
    }
}

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

function Remove-SDEClient {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [ValidateScript({$ipa = ($_ -as [ipaddress]); if ($null -ne $ipa) { ($ipa.IPAddressToString -ieq $_) } else { $false }})]
        [string]$IPAddress
    )
    if ([string]::IsNullOrWhiteSpace($Name) -and [string]::IsNullOrWhiteSpace($Thumbprint) -and [string]::IsNullOrWhiteSpace($IPAddress)) { return }
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
        $clauses = @()
        if (-not [string]::IsNullOrWhiteSpace($Name)) { $clauses += "(CredName='$($Name -replace "'","''")')" }
        if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) { $clauses += "(CertThumbprint='$($Thumbprint)')" }
        if (-not [string]::IsNullOrWhiteSpace($IPAddress)) { $clauses += "(SourceIP='$($IPAddress)')" }
        $sqlCmd.CommandText = "DELETE FROM CLIENTS WHERE $($clauses -join " AND ")"
        $nDel = $sqlCmd.ExecuteNonQuery()
        if ($nDel -gt 0) {
            Write-AuditLog -EventType RemoveClient -EventSubject "Removed $nDel entries for $($clauses -join " AND ")"
        }
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}

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

<#
.SYNOPSIS
Sets the database connection in a global variable and saves it in a configuration file.

.DESCRIPTION
Sets the database connection in a global variable and saves it in a configuration file.
The database connection is verified prior to saving.

.PARAMETER SQLServer
Name or FQDN of the SQL server hosting the SDE database.

.PARAMETER SQLInstance
Instance name, if a named instance is being used. Should not be used together with -Port.

.PARAMETER SQLPort
Port number, if not the default port 1433 uis being used and/or SQL browser service is not available. Should not be used together with -Instance.

.PARAMETER SQLDatabase
Database name. If the database exists and the permissions allow it, the SDE table structure will be created regardless of any other tables being already present in the database.

.PARAMETER SQLCredential
If present, the specified name and password will be used as a SQL credential for connecting to the SQL server.
In this case the connection string will not be saved in the config file.

.INPUTS
None.

.OUTPUTS
$true or $false.

.LINK
https://github.com/metabpa/secret-delivery/tree/main/02-admin-module

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
function Set-SDEDatabase {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$SQLServer,
        [Parameter(Mandatory=$false)]
        [string]$SQLInstance,
        [Parameter(Mandatory=$false)]
        [int]$SQLPort,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$SQLDatabase,
        [Parameter(Mandatory=$false)]
        [PSCredential]$SQLCredential
    )
    if ([string]::IsNullOrWhiteSpace($SQLServer)) {
        Write-Warning 'SQLServer cannot be empty!'
        return
    }
    if ([string]::IsNullOrWhiteSpace($SQLDatabase)) {
        Write-Warning 'SQLDatabase cannot be empty!'
        return
    }
    if (($null -ne ($SQLPort -as [int])) -and ($SQLPort -gt 0) ) {
        $instancePart = (',{0}' -f $SQLPort)
    } elseif (-not [string]::IsNullOrWhiteSpace($SQLInstance)) {
        $instancePart = ('\{0}' -f $SQLInstance.Trim())
    } else {
        $instancePart = ''
    }
    if ($null -eq $SQLCredential) {
        $authPart = 'Trusted_Connection=True'
    } else {
        $authPart = ('User ID={0}; Password={1}' -f $SQLCredential.UserName, $SQLCredential.GetNetworkCredential().Password)
    }
    $connStrDB = ('Server={0}{1}; {2}; Database={3};' -f $SQLServer, $instancePart, $authPart, $SQLDatabase.Trim())
    $dbConn = New-Object System.Data.SqlClient.SqlConnection
    $dbConn.ConnectionString = $connStrDB
    try {
        $dbConn.Open()
    } catch {}
    if ($dbConn.State -eq 'Open') {
        if (Test-Path -Path $script:moduleConfigFile -PathType Leaf) {
            $script:moduleConfig = (Get-Content -Path $script:moduleConfigFile | ConvertFrom-Json)
            $script:moduleConfig.SQLConnectionString = $connStrDB
        } else {
            $script:moduleConfig = [PSCustomObject]@{
                'SQLConnectionString' = $connStrDB
            }
        }
        $dbConn.Close()
        if ($null -eq $SQLCredential) {
            Write-Host "Saving configuration to $($script:moduleConfigFile)"
            $script:moduleConfig | ConvertTo-Json | Set-Content -Path $script:moduleConfigFile -Force
        } else {
            Write-Warning "Password will not be saved in the config file because explicit credentials have been specified."
        }
    } else {
        Write-Warning "Could not open SQL connection to $connStrDB"
    }
}

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

function Write-AuditLog {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$EventType,
        [Parameter(Mandatory=$true)]
        [string]$EventSubject
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
        $q = "INSERT INTO AUDITLOG (EventTimeStamp,EventIdentity,EventType,EventSubject) VALUES (CURRENT_TIMESTAMP,'$($env:USERNAME)@$($env:COMPUTERNAME)','$($EventType -replace "'","''")','$($EventSubject -replace "'","''")')"
        $sqlCmd.CommandText = $q
        $null = $sqlCmd.ExecuteNonQuery()
        $sqlCmd.Dispose()
        $sqlConn.Close()
        $sqlConn.Dispose()
    }
}

#region footer
$script:moduleConfigFile = Join-Path -Path ([Environment]::GetFolderPath('UserProfile')) -ChildPath '.SDEAdmin.config'
if (Test-Path -Path $script:moduleConfigFile -PathType Leaf) {
    $script:moduleConfig = (Get-Content -Path $script:moduleConfigFile | ConvertFrom-Json)
} else {
    Write-Warning 'Module configuration not found. Use Set-SDEDatabase to create it.'
    $script:moduleConfig = $null
}
#endregion
Export-ModuleMember -Function @('Set-SDEDatabase','Export-SDEInventory','Add-SDECertificate','Get-SDECertificate','Remove-SDECertificate','Get-SDECredential','New-SDECredential','Update-SDECredential','Remove-SDECredential','Get-SDEClient','Add-SDEClient','Remove-SDEClient')
