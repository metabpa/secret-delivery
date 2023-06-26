function Get-Padding {
    [CmdletBinding()]
    Param()
    $padLen = Get-Random -Minimum 10 -Maximum 100
    $padChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789^!°"§$%&/()=?\{}[],;.:-_<>|'
    $res = '';
    for ($i = 0;$i -lt $padLen; $i++) {
        $res += $padChars.Substring((Get-Random -Minimum 0 -Maximum ($padChars.Length)),1)
    }
    return $res
}