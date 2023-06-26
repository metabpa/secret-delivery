function Get-TemplateInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $tplData = $Certificate.Extensions.Where({$_.Oid.Value -eq '1.3.6.1.4.1.311.21.7'})
    if ($tplData.Count -gt 0) { 
        $tplText = $tplData.Format($true)
        if ($tplText -match 'Template\=(?<tplinfo>.*)\W') {
            $tplName = $Matches['tplinfo']
            if ($tplName -match '(?<name>.+)\((?<oid>[\d\.]+)\)') {
                return [PSCustomObject]@{
                            'TemplateName' = $Matches['name']
                            'TemplateOID' = $matches['oid']
                        }
            }
        }
    } else {
        return $null
    }
}