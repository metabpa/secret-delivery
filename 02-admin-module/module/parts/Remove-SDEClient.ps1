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