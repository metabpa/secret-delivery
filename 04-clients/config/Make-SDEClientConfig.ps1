[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$APIServerAddress,
    [Parameter(Mandatory=$false)]
    [int]$APIServerPort,
    [Parameter(Mandatory=$false)]
    [bool]$DoNotUseSSL,
    [Parameter(Mandatory=$false)]
    [bool]$TrustAllCertificates,
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    try {
        $realPath = Resolve-Path -Path $OutputPath -EA Stop
        if (-not (Test-Path -Path $realPath -PathType Container)) {
            Write-Warning "Path $($realPath) not found or not a folder!"
            exit
        }
    } catch {
        Write-Warning $_.Exception.Message
        exit
    }
} else {
    $realPath = [Environment]::GetFolderPath('MyDocuments')
}
$configData = @{
    'APIServerAddress' = $null
    'APIServerPort' = 0
    'DoNotUseSSL' = $DoNotUseSSL
    'TrustAllCertificates' = $TrustAllCertificates
}
if (-not [string]::IsNullOrWhiteSpace($APIServerAddress)) {
    $configData['APIServerAddress'] = $APIServerAddress
    if (0 -lt $APIServerPort) {
        $configData['APIServerPort'] = $APIServerPort
    } else {
        if ($DoNotUseSSL) {
            $configData['APIServerPort'] = 80
        } else {
            $configData['APIServerPort'] = 443
        }
    }
}
$configObject = [PSCustomObject]$configData
$configFile = Join-Path -Path $realPath -ChildPath '.sdeconfig'
try {
    $configObject | ConvertTo-Json | Set-Content -Path $configFile -Force -EA Stop
} catch {
    Write-Warning $_.Exception.Message
}
$mReg = @('Windows Registry Editor Version 5.00','','[HKEY_LOCAL_MACHINE\SOFTWARE\SecretDeliveryEngine]')
$uReg = @('Windows Registry Editor Version 5.00','','[HKEY_CURRENT_USER\SOFTWARE\SecretDeliveryEngine]')
$zReg = @()
if (-not [string]::IsNullOrWhiteSpace($configObject.APIServerAddress)) {
    $zReg += ('"APIServerAddress"="{0}"' -f $configObject.APIServerAddress)
    $zReg += ('"APIServerPort"=dword:{0,8:X8}' -f $configObject.APIServerPort)
} else {
    $zReg += '"APIServerAddress"=""'
    $zReg += '"APIServerPort"=dword:00000000'
}
if ($configObject.DoNotUseSSL) {
    $zReg += '"DoNotUseSSL"=dword:00000001'
} else {
    $zReg += '"DoNotUseSSL"=dword:00000000'
}
if ($configObject.TrustAllCertificates) {
    $zReg += '"TrustAllCertificates"=dword:00000001'
} else {
    $zReg += '"TrustAllCertificates"=dword:00000000'
}
$mRegFile = Join-Path -Path $realPath -ChildPath 'sde-machine.reg'
$uRegFile = Join-Path -Path $realPath -ChildPath 'sde-user.reg'
($mreg + $zReg) | Set-Content -Path $mRegFile -Force
($ureg + $zReg) | Set-Content -Path $uRegFile -Force