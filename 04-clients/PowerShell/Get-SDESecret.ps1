<#
    This function will only work on Windows because:
    - Resolve-DNSName
    - registry access
#>
function Get-SDESecret {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string]$APIServerAddress,
        [Parameter(Mandatory=$false)]
        [int]$APIServerPort,
        [Parameter(Mandatory=$false)]
        [bool]$DoNotUseSSL,
        [Parameter(Mandatory=$false)]
        [bool]$TrustAllCertificates
    )
    #region identifying certificates
    if ([Environment]::UserInteractive) {
        $certStore = 'CurrentUser'
    } else {
        $certStore = 'LocalMachine'
    }
    if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
        try {
            $DECerts = @(Get-Item -Path "cert:\$($certStore)\My\$($Thumbprint)" -EA Stop)
        } catch {
            Write-Warning "Certificate with thumbprin $($Thumbprint) not found"
            $DECerts = @()
        }
        $DECerts = $DECerts.Where({$_.HasPrivateKey -and ($_.EnhancedKeyUsageList.ObjectID -contains '1.3.6.1.4.1.311.80.1')})
    } else {
        $DECerts = @(Get-ChildItem -Path "cert:\$($certStore)\My" | Where-Object {$_.HasPrivateKey -and ($_.EnhancedKeyUsageList.ObjectID -contains '1.3.6.1.4.1.311.80.1')})
    }
    if ($DECerts.Count -eq 0) {
        Write-Warning "No approprate decryption certificates found in store"
        return
    } else {
        Write-Verbose "$($DECerts.Count) approprate decryption certificate(s) found in store"
    }
    #endregion
    #region reading configuration
    $configObject = [PSCustomObject]@{
        'APIServerAddress' = $null
        'APIServerPort' = 0
        'DoNotUseSSL' = $false
        'TrustAllCertificates' = $false
    }
    # local config file
    $configPath = Join-Path -Path $env:USERPROFILE -ChildPath '.sdeconfig'
    if (Test-Path -Path $configPath -PathType Leaf) {
        try {
            $fileObject = Get-Content -Path $configPath -EA Stop | ConvertFrom-Json -EA Stop
        } catch {
            Write-Warning $_.Exception.Message
            $fileObject = $null
        }
    }
    if ($null -ne $fileObject) {
        if ($null -ne $fileObject.APIServerAddress) { $configObject.APIServerAddress = $fileObject.APIServerAddress }
        if (0 -lt $fileObject.APIServerPort) { $configObject.APIServerPort = $fileObject.APIServerPort }
        $configObject.DoNotUseSSL = $fileObject.DoNotUseSSL -as [bool]
        $configObject.TrustAllCertificates = $fileObject.TrustAllCertificates -as [bool]
    }
    # user registry
    if (Test-Path -Path "HKCU:\SOFTWARE\SecretDeliveryEngine") {
        $rk = Get-Item -Path "HKCU:\SOFTWARE\SecretDeliveryEngine"
        if ($null -ne $rk.GetValue('APIServerAddress')) { $configObject.APIServerAddress = $rk.GetValue('APIServerAddress').ToString() }
        if (0 -ne ($rk.GetValue('APIServerPort') -as [int])) { $configObject.APIServerPort = ($rk.GetValue('APIServerPort') -as [int]) }
        if ($null -ne $rk.GetValue('DoNotUseSSL')) { $configObject.DoNotUseSSL = (($rk.GetValue('DoNotUseSSL') -as [int]) -eq 1) }
        if ($null -ne $rk.GetValue('TrustAllCertificates')) { $configObject.TrustAllCertificates = (($rk.GetValue('TrustAllCertificates') -as [int]) -eq 1) }
    }
    # machine registry
    if (Test-Path -Path "HKLM:\SOFTWARE\SecretDeliveryEngine") {
        $rk = Get-Item -Path "HKLM:\SOFTWARE\SecretDeliveryEngine"
        if ($null -ne $rk.GetValue('APIServerAddress')) { $configObject.APIServerAddress = $rk.GetValue('APIServerAddress').ToString() }
        if (0 -ne ($rk.GetValue('APIServerPort') -as [int])) { $configObject.APIServerPort = ($rk.GetValue('APIServerPort') -as [int]) }
        if ($null -ne $rk.GetValue('DoNotUseSSL')) { $configObject.DoNotUseSSL = (($rk.GetValue('DoNotUseSSL') -as [int]) -eq 1) }
        if ($null -ne $rk.GetValue('TrustAllCertificates')) { $configObject.TrustAllCertificates = (($rk.GetValue('TrustAllCertificates') -as [int]) -eq 1) }
    }
    # user policy
    if (Test-Path -Path "HKCU:\SOFTWARE\Policies\SecretDeliveryEngine") {
        $rk = Get-Item -Path "HKCU:\SOFTWARE\Policies\SecretDeliveryEngine"
        if ($null -ne $rk.GetValue('APIServerAddress')) { $configObject.APIServerAddress = $rk.GetValue('APIServerAddress').ToString() }
        if (0 -ne ($rk.GetValue('APIServerPort') -as [int])) { $configObject.APIServerPort = ($rk.GetValue('APIServerPort') -as [int]) }
        if ($null -ne $rk.GetValue('DoNotUseSSL')) { $configObject.DoNotUseSSL = (($rk.GetValue('DoNotUseSSL') -as [int]) -eq 1) }
        if ($null -ne $rk.GetValue('TrustAllCertificates')) { $configObject.TrustAllCertificates = (($rk.GetValue('TrustAllCertificates') -as [int]) -eq 1) }
    }
    # machine policy
    if (Test-Path -Path "HKLM:\SOFTWARE\Policies\SecretDeliveryEngine") {
        $rk = Get-Item -Path "HKLM:\SOFTWARE\Policies\SecretDeliveryEngine"
        if ($null -ne $rk.GetValue('APIServerAddress')) { $configObject.APIServerAddress = $rk.GetValue('APIServerAddress').ToString() }
        if (0 -ne ($rk.GetValue('APIServerPort') -as [int])) { $configObject.APIServerPort = ($rk.GetValue('APIServerPort') -as [int]) }
        if ($null -ne $rk.GetValue('DoNotUseSSL')) { $configObject.DoNotUseSSL = (($rk.GetValue('DoNotUseSSL') -as [int]) -eq 1) }
        if ($null -ne $rk.GetValue('TrustAllCertificates')) { $configObject.TrustAllCertificates = (($rk.GetValue('TrustAllCertificates') -as [int]) -eq 1) }
    }
    # parameter values
    if (-not [string]::IsNullOrWhiteSpace($APIServerAddress)) {
        $configObject.APIServerAddress = $APIServerAddress
        if (0 -lt $APIServerPort) {
            $configObject.APIServerPort = $APIServerPort
        }
    }
    if ($PSBoundParameters.ContainsKey('DoNotUseSSL')) { $configObject.DoNotUseSSL = $DoNotUseSSL }
    if ($PSBoundParameters.ContainsKey('TrustAllCertificates')) { $configObject.TrustAllCertificates = $TrustAllCertificates }
    #endregion
    #region resolving API from DNS if not found in config
    $apihost = $null
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    if ([string]::IsNullOrWhiteSpace($configObject.APIServerAddress)) {
        try {
            $srvObject = Resolve-DnsName -Type SRV -Name "_secretdelivery._tcp.$($domain)" -EA Stop
        } catch {
            $srvObject = $null
        }
        if ($null -ne $srvObject) {
            $configObject.APIServerAddress = $srvObject.NameTarget
            $configObject.APIServerPort = $srvObject.Port
            if ($configObject.APIServerPort -eq 443) {
                $configObject.DoNotUseSSL = $false
            } elseif ($configObject.APIServerPort -eq 80) {
                $configObject.DoNotUseSSL = $true
            }
            Write-Verbose "Determined host from SRV: $($configObject.APIServerAddress):$($configObject.APIServerPort)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($configObject.APIServerAddress)) {
        try {
            $srvObject = Resolve-DnsName -Type CNAME -Name "secretdelivery.$($domain)" -EA Stop
        } catch {
            $srvObject = $null
        }
        if ($null -ne $srvObject) {
            $configObject.APIServerAddress = $srvObject.NameHost
            Write-Verbose "Determined host from CNAME: $($configObject.APIServerAddress)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($configObject.APIServerAddress)) {
        try {
            $srvObject = Resolve-DnsName -Type A -Name "secretdelivery.$($domain)" -EA Stop
        } catch {
            $srvObject = $null
        }
        if ($null -ne $srvObject) {
            $configObject.APIServerAddress = "secretdelivery.$($domain)"
            Write-Verbose "Determined host from A: $($configObject.APIServerAddress)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($configObject.APIServerAddress)) {
        Write-Warning "Could not find the SDE API server by any method!"
        return
    }
    if (0 -eq $configObject.APIServerPort) {
        if ((Test-NetConnection -ComputerName $configObject.APIServerAddress -Port 443).TcpTestSucceeded) {
            $configObject.APIServerPort = 443
            $configObject.DoNotUseSSL = $false
        } elseif ((Test-NetConnection -ComputerName $configObject.APIServerAddress -Port 80).TcpTestSucceeded) {
            $configObject.APIServerPort = 80
            $configObject.DoNotUseSSL = $true
        } else {
            Write-Warning "API port was not specified and both 443 and 80 failed!"
            return
        }
    }
    if ($configObject.DoNotUseSSL) {
        $uriPrefix = 'http'
    } else {
        $uriPrefix = 'https'
    }
    
    $credObject = $null
    $credData = $null
    foreach ($cert in $DECerts) {
        $uri = "$($uriPrefix)://$($configObject.APIServerAddress):$($configObject.APIServerPort)/api/$($cert.Thumbprint)/$([System.URI]::EscapeDataString($Name))"
        try {
            $apires = Invoke-RestMethod -Method Get -Uri $uri -EA Stop
        } catch {
            $apires = $null
        }
        if (-not [string]::IsNullOrWhiteSpace($apires)) { 
            try {
                $credObject = Unprotect-CmsMessage -To $cert -Content $apires
                if ($null -ne $credObject) { 
                    try {
                        $credData = $credObject | ConvertFrom-Json -EA Stop
                    } catch {
                        Write-Warning $_.Exception.Message
                        $credData = $null    
                    }
                }
            } catch {
                Write-Warning $_.Exception.Message
                $credObject = $null
            } 
        }
    }
    if ($null -ne $credData) {
        $secPwd = $credData.Password | ConvertTo-SecureString -AsPlainText -Force
        return (New-Object System.Management.Automation.PSCredential($credData.UserName, $secPwd))
    }
        
}
Get-SDESecret -Name vSphereAdmin -Verbose