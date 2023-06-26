#region footer
$script:moduleConfigFile = Join-Path -Path ([Environment]::GetFolderPath('UserProfile')) -ChildPath '.SDEAdmin.config'
if (Test-Path -Path $script:moduleConfigFile -PathType Leaf) {
    $script:moduleConfig = (Get-Content -Path $script:moduleConfigFile | ConvertFrom-Json)
} else {
    Write-Warning 'Module configuration not found. Use Set-SDEDatabase to create it.'
    $script:moduleConfig = $null
}
#endregion