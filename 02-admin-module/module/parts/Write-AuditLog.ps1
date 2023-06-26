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