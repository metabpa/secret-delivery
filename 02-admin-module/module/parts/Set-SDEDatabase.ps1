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