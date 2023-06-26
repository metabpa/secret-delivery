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