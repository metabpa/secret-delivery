<#
.SYNOPSIS
Creates the SDE database and structure.

.DESCRIPTION
Creates the SDE database and structure. Can also create the login for the webservice and grant it appropriate permissions to read cred and cert data and write audit log.

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

.PARAMETER AddSQLCredential
If specified, this script will add a SQL user to the server and grant this user the required permissions for use with the webservice.

.INPUTS
None.

.OUTPUTS
Connection string for use with the webservice.

.LINK
https://metabpa.org/projects/sde/database/

.NOTES
Version 0.4.0
Build: 2023-06-24
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$SQLServer,
    [Parameter(Mandatory=$false)]
    [string]$SQLInstance,
    [Parameter(Mandatory=$false)]
    [int]$SQLPort,
    [Parameter(Mandatory=$false)]
    [string]$SQLDatabase,
    [Parameter(Mandatory=$false)]
    [PSCredential]$SQLCredential,
    [Parameter(Mandatory=$false)]
    [PSCredential]$AddSQLCredential
)
if ([string]::IsNullOrWhiteSpace($SQLServer)) {
    Write-Warning 'SQLServer cannot be empty!'
    break
}
if ([string]::IsNullOrWhiteSpace($SQLDatabase)) {
    Write-Warning 'SQLDatabase cannot be empty!'
    break
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
$connStrServer = ('Server={0}{1}; {2};' -f $SQLServer, $instancePart, $authPart)
$connStrDB = ('Server={0}{1}; {2}; Database={3};' -f $SQLServer, $instancePart, $authPart, $SQLDatabase.Trim())
$dbConn = New-Object System.Data.SqlClient.SqlConnection

# check if DB exists and create
$ok = $true
$dbConn.ConnectionString = $connStrServer
try {
    $dbConn.Open()
    $dbCmd = $dbConn.CreateCommand()
    $q = "IF NOT EXISTS (SELECT name FROM master.sys.databases WHERE name='$SQLDatabase') CREATE DATABASE $SQLDatabase"
    $dbCmd.CommandText = $q
    $null = $dbcmd.ExecuteNonQuery()
} catch {
    Write-Warning $q
    Write-Warning $_.Exception.Message
    $ok = $false
}
$dbCmd.Dispose()
$dbConn.Close()
if (-not $ok) { exit }

# create DB structure
$dbConn.ConnectionString = $connStrDB
try {
    $dbConn.Open()
} catch {
    Write-Warning $_.Exception.Message
    exit
}
$dbCmd = $dbConn.CreateCommand()
$qs = @(
    "CREATE TABLE CERTS (CertID bigint IDENTITY(1,1), CertName varchar(255), CertThumbprint varchar(40), CertSubject varchar(255), CertIssuer varchar(255), CertData varchar(max), CertNotBefore datetime, CertNotAfter datetime, CertTemplateName varchar(255), CertTemplateOID varchar(255), CertIsManaged tinyint DEFAULT 0, CertIsRevoked tinyint DEFAULT 0, CertAddedBy varchar(255), CertAddedOn datetime)"
    "CREATE TABLE CREDS (CredID bigint IDENTITY(1,1), CertThumbprint varchar(40), CredName varchar(255), CredData varchar(max), CredAddedBy varchar(255), CredAddedOn datetime, CredUpdatedBy varchar(255), CredUpdatedOn datetime)"
    "CREATE INDEX IDX_CRED_Thumbprint ON CREDS (CertThumbprint)"
    "CREATE TABLE CLIENTS (CredName varchar(255), CertThumbprint varchar(40), SourceIP varchar(45), Description varchar(255))"
    "CREATE INDEX IDX_CLIENT_Thumbprint ON CLIENTS (CertThumbprint)"
    "CREATE TABLE AUDITLOG (EventID bigint IDENTITY(1,1), EventTimestamp datetime, EventType varchar(255), EventIdentity varchar(255), EventSubject varchar(255))"
)
if ($null -ne $AddSQLCredential) {
    $qs += "IF NOT EXISTS (SELECT loginname FROM master.dbo.syslogins WHERE name = '$($AddSQLCredential.UserName)') CREATE LOGIN [$($AddSQLCredential.UserName)] WITH PASSWORD='$($AddSQLCredential.GetNetworkCredential().Password)', DEFAULT_DATABASE = [$($SQLDatabase)], CHECK_EXPIRATION = OFF, CHECK_POLICY = OFF"
    $qs += "CREATE USER [$($AddSQLCredential.UserName)] FROM LOGIN [$($AddSQLCredential.UserName)]" 
    $qs += "EXEC sp_addrolemember 'db_datareader', '$($AddSQLCredential.UserName)'"
    $qs += "GRANT INSERT ON dbo.AUDITLOG TO [$($AddSQLCredential.UserName)]"
}
$ok = $true
foreach ($q in $qs) {
    $dbCmd.CommandText = $q
    try {
        $null = $dbcmd.ExecuteNonQuery()
    } catch {
        Write-Warning $q
        Write-Warning $_.Exception.Message
        $ok = $true
    }
}

$dbCmd.Dispose()
$dbConn.Close()
if (-not $ok) {
    Write-Host "There were some error creating the database structure. Please double-check these and rerung the script."
}
if (($null -ne ($SQLPort -as [int])) -and ($SQLPort -gt 0) ) {
    $instancePart = (',{0}' -f $SQLPort)
} elseif (-not [string]::IsNullOrWhiteSpace($SQLInstance)) {
    $instancePart = ('\{0}' -f $SQLInstance.Trim())
} else {
    $instancePart = ''
}
if ($null -eq $AddSQLCredential) {
    $authPart = 'Trusted_Connection=True'
} else {
    $authPart = ('User ID={0}; Password={1}' -f $AddSQLCredential.UserName, $AddSQLCredential.GetNetworkCredential().Password)
}
$connStrDB = ('Server={0}{1}; {2}; Database={3};' -f $SQLServer, $instancePart, $authPart, $SQLDatabase.Trim())
Write-Host 'Connection string for use in the webservice configuration:'
Write-Host $connStrDB