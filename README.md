# SDE: A Secret Delivery Engine

The idea behind SDE is to simplify the secure delivery of secrets to a variety of consumers using asymmetric cryptography. The concept was demonstrated by Evgenij Smirnov at the PSConfEU 2023 in Prague. SDE works aroud having to provide a vault-unlocking 'master secret' to the consumer by utilizing the secret(s) consumers already hold, namely the private keys of certificates. If these certificates are obtained from an Enterprise PKI via autoenrollment, this constitutes a zero-touch deployment of secrets.

## A credential in SDE

Since SDE was born out of PowerShell, the objective of SDE is to provide a secret consumer with a data structure that translates to a PSCredential object. That is why we always talk about a 'credential' rather than a 'secret' in SDE. If the secret to be delivered is not a credential in the literal sense, just omit the username or, better still, provide some random string in lieu of the username to increase thr entropy.

However, SDE does not make use of the SecureString-based password storage of PowerShell in the backend but stores a CMS-encrypted JSON structure containing the following fields:

- Username
- Password in cleartext
- a random piece of text (salt) to offer further protection from brute-forcing the encryption
- internal name of the secret (by which the secret is obtained from SDE) to provide consistency checking capability
- SHA-1 thumbprint of the certificate used for encrypting the secret (this, again, only helps provide a cross-checking ability)
- OID of the certificate template (if the certificate has been issued by an Enterprise PKI)
- date stamp of last update of the secret in the SDE database

After obtaining and decrypting the blob, it is the consumer's obligation to protect the cleartext as strongly as possible. Ideally, a PowerShell based consumer will convert the JSON structure to a PSCredential object and then destroy the vsriable holding the JSON data, invoking Garbage Collection at the end.

## Credential lifecycle in SDE

Within SDE, the credential flow is as follows:

1. Consumer obtains or generates a certificate having a Document Encryption EKU. Ideally, the certificate will have *only* this EKU.
2. The public part of the certificate and its thumbprint get stored in the SDE database. In case of PKI-signed certificates this can be done by the ADCS interop, otherwise the consumer has to provide the certificate to the SDE administrator who then imports it into the SDE database.
3. The SDE administrator retrieves a credential from the vault where it is stored and updates the SDE database with the credential, specifying the newly imported certificate as a new target.
4. The SDE administrator can also provide client restrictions, specifying a list of IP addresses the credential can be retrieved from.
5. The consumer contacts the SDE API, specifying the SHA-1 thumbprint of the certificate they will use for decryption and the internal name of the credential in the SDE database.
6. If an encrypted JSON for the combination of certificate, name and IP (if specified) exists in the database, the API will deliver the CMS-encrypted message to the consumer.
7. The consumer uses the certificate's private key to decrypt the message and has now received the credential in plaintext!

## Components of the solution

The SDE consists of the following components:

1. [Central data store](/01-database/readme.md). This is a SQL database holding registered certificates and encrypted credentials as well as IP restrictions and the audit log.
2. [Admin module](/02-admin-module/readme.md). A PowerShell module that stores certificates and encrypted credential blobs in the SQL database.
3. [API](/03-api/readme.md). An authentication-free API for requesting encrypted credentials from the database.
4. [Clients](/04-clients/readme.md). Components allowing a consumer to locate the API and retrieve a credential.
    - PowerShell function
    - PowerShell module
    - PowerShell SecretManagement plug-in
    - C# class library
5. [ADCS Interop](/05-adcs-interop/readme.md). A component facilitating automatic import of certificates from a Windows CA:
    - restricted by EKU or template(s)
    - flagging on revocation

## The future

- An API variant enforcing Kerberos authentication, thus allowing an additional level of protection before delivering an encrypted credential. Specifically, we could require that certificates used for decryption are stored in AD of the user account retrieving the blob from the API.
- Web-based administration for the SDE. This should not run in the same binding context as the API, and ideally not on the same machine.