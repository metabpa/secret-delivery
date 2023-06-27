# SDE Clients

Various client components for retrieving secrets.

All client technologies share one common workflow:

1. Identify what certificate(s) will be used for the encryption:
    - if there is a certificate configured, check if it's present, including private key access, and build a list of that one certificate.
    - if no certificate is configured, build a list of certificates (correct EKU + private key access) that will be tried.
2. Look up the API:
    - if a hostname and port have been configured (.sdeconfig file in %userprofile% --> user registry --> machine registry --> user policy --> machine policy --> explicit parameter value) test connectivity to that hostname:port.
    - if no hostname has been configured, try to resolve the SRV record for _secretdelivery.tcp.(domain) and test connectivity if resolution was successfull.
    - if SRV record cannot be resolved, try to resolve CNAME secretdelivery.(domain) and test connectivity on port 443, followed by a test on port 80, if 443 does not succeed.
    - if CNAME record cannot be resolved, try to resolve A secretdelivery.(domain) and test connectivity on port 443, followed by a test on port 80, if 443 does not succeed.
3. Build the list of API call URIs and run a GET against them:      
https://{hostname from previous step}/api/{cert-thumbprint}/{secret-name}
4. If one blob has been returned, decrypt it.
5. If more than one blob is returned, decrypt them and return the credential with the latest update timestamp.

Both the config file and registry import files for User and Machine can be built using the Make-SDEClientConfig.ps1 script in the config folder of this repo.

## Client technologies
Following client technologies are available or in development:

1. [PowerShell](/powershell/readme.md) A collection of functions for different platforms.
2. [.NET](/dotnet/readme.md) A .NET component for retrieving secrets from SDE.
3. [SecretManagement](/secret-management/readme.md) A SecretManagement plugin for SDE.

## Registry settings (Windows only)
The following registry settings allow rolling out the API server location (keys are listed in order of their application):

```
HKEY_CURRENT_USER\SOFTWARE\SecretDeliveryEngine\Client
HKEY_CURRENT_USER\SOFTWARE\Policies\SecretDeliveryEngine\Client
HKEY_LOCAL_MACHINE\SOFTWARE\SecretDeliveryEngine\Client
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\SecretDeliveryEngine\Client

APIServerAddress REG_SZ
APIServerPort REG_DWORD
DoNotUseSSL REG_DWORD
TrustAllCertificates REG_DWORD
```
