# Secret Delivery Engine Database


## Database structure

### Table [CERTS]

Holds the certificates used for secret encryption.

| Column | Type | Description |
|---|---|---|
| CertID | bigint IDENTITY(1,1) | Internal ID of the certificate. |
| CertName | varchar(255) | A name identifying the certificate in the database. If not specified upon upload, the common name from the certificate will be used. |
| CertThumbprint | varchar(40) | SHA-1 thumbprint of the certificate in uppercase. |
| CertSubject | varchar(255) | Subject of the certificate. |
| CertIssuer | varchar(255) | Issuer of the certificate (subject of the CA certificate). |
| CertData | varchar(max) | Certificate in base64 encoded form. |
| CertNotBefore | datetime | Begin of certifiacte's validity period.  |
| CertNotAfter | datetime | End of certifiacte's validity period. |
| CertTemplateName | varchar(255) | If issued by a Windows Enterprise CA, the name of the template used in request. |
| CertTemplateOID | varchar(255) | If issued by a Windows Enterprise CA, the OID of the template used in request. |
| CertIsManaged | tinyint | 0: Certificate was uploaded by a client (default).<br />1: Certificate was added or verified by an administrator.  |
| CertIsRevoked | tinyint | 0: Certificate is not revoked (default).<br />1:Certificate is revoked by the VA. |
| CertAddedBy | varchar(255) | User name that added the certificate to the database. Alternatively: "API" or "CAInterop". |
| CertAddedOn | datetime | When the certificate was added. |

### Table [CREDS]

Holds the encrypted credential objects.

| Column | Type | Description |
|---|---|---|
| CredID | bigint IDENTITY(1,1) |  |
| CertThumbprint | varchar(40) |  |
| CredName | varchar(255) |  |
| CredData | varchar(max) |  |
| CredAddedBy | varchar(255) |  |
| CredAddedOn | datetime |  |
| CredUpdatedBy | varchar(255) |  |
| CredUpdatedOn | datetime |  |

### Table [CLIENTS]

Holds the IP address restrictions for certain credential entries. If no restricting entry is found, any client can retrieve the encrypted object.

| Column | Type | Description |
|---|---|---|
| CredName | varchar(255) |  |
| CertThumbprint | varchar(40) |  |
| SourceIP | varchar(45) |  |
| Description |varchar(255) |  |

### Table [AUDITLOG]

Holds the audit log of the SDE backend.

| Column | Type | Description |
|---|---|---|
| EventID | bigint IDENTITY(1,1) |  |
| EventTimestamp | datetime |  |
| EventType | varchar(255) |  |
| EventIdentity varchar(255) |  |
| EventSubject | varchar(255) |  |

## Required permissions

The admin module needs SELECT, INSERT, UPDATE and DELETE on all tables except [AUDITLOG] as well as SELECT and INSERT on [AUDITLOG].

The API (AppPool identioty or explicit SQL login) needs SELECT on all tables except [AUDITLOG] as well es INSERT on [AUDITLOG].
