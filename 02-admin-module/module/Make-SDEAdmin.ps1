$thisModuleVersion = '0.4.0.0'
$thisModuleName = 'SDEAdmin'
$functionsToExport = @(
    'Set-SDEDatabase'
    'Export-SDEInventory'
    'Add-SDECertificate'
    'Get-SDECertificate'
    'Remove-SDECertificate'
    'Get-SDECredential'
    'New-SDECredential'
    'Update-SDECredential'
    'Remove-SDECredential'
    'Get-SDEClient'
    'Add-SDEClient'
    'Remove-SDEClient'
)

$manifest = @{
    ModuleVersion = $thisModuleVersion
    GUID = 'fc39e1a6-0a5d-4c57-95fa-b4104db99da7'
    Author = 'Evgenij Smirnov'
    CompanyName = 'metaBPA.org'
    Copyright = '2023 metaBPA.org'
    Description = 'Manages certificates and credentials in the SDE database.'
	HelpInfoURI = 'https://github.com/metabpa/secret-delivery/tree/main/02-admin-module'
    ProjectURI = 'https://metabpa.org/projects/sde/'
    IconURI = 'https://metabpa.org/wp-content/uploads/2019/11/cropped-metaBPA-192x192.png'
    PowerShellVersion = '5.0'
    Path = "$PSScriptRoot\$($thisModuleName)\$($thisModuleName).psd1"
    RootModule = "$($thisModuleName).psm1"
    NestedModules = @()
    FunctionsToExport = $functionsToExport
    CmdletsToExport = @()
    VariablesToExport = @()
    DefaultCommandPrefix = ''
    PrivateData = @{
        'CompanyFolder' = 'metaBPA.org'
        'ModuleFolder' = 'SDEAdmin'
    }
}

New-ModuleManifest @manifest

$partsPath = Join-Path -Path $PSScriptRoot -ChildPath 'parts'
$lines = @(Get-Content -Path (Join-Path -Path $partsPath -ChildPath '_header.ps1'))

$files = Get-ChildItem -Path $partsPath -Exclude "_*.*"
foreach ($file in $files) {
    Write-Host "Adding content of $($file.FullName)"
    $lines += Get-Content -Path $file.FullName
    $lines += ""
}

$lines += Get-Content -Path (Join-Path -Path $partsPath -ChildPath '_footer.ps1')
$lines += "Export-ModuleMember -Function @('$($functionsToExport -join "','")')"
$lines | Set-Content "$PSScriptRoot\$($thisModuleName)\$($thisModuleName).psm1" -Force