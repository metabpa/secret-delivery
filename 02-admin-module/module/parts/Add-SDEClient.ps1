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