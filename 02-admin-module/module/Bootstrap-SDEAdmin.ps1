$partsPath = Join-Path -Path $PSScriptRoot -ChildPath 'parts'
. (Join-Path -Path $partsPath -ChildPath '_header.ps1')

$files = Get-ChildItem -Path $partsPath -Exclude "_*.*"
foreach ($file in $files) {
    Write-Host $file.FullName
    . $file.FullName
}

. (Join-Path -Path $partsPath -ChildPath '_footer.ps1')