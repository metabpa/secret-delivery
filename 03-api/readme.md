# SDE Web API

Provides a convenient way for retrieving the encrypted credentials from the database.

The Web API supports only one method:

GET https://(server)/api/(THUMBPRINT)/(Credential Name)

If the requested credential, encrypted by the requested certificate, is found in the database and client restrictions, if any, are satisfied, then the complete CMS message, including header and footer, is returned. Otherwise, a NULL string is returned.

## Obtaining the API

SOURCE CODE WILL BE PUBLISHED SHORTLY

## Installaiton

A MORE HUMAN-FRIENDLY INSTALLER WILL BE PROVIDED SHORTLY.
AT THE MOMENT, MANUAL INSTALLATION IS THE ONLY OPTION:

- Install IIS features
- Create a new site or use the Default Web Site
- Download and unzip [SDE-web-api.zip](/SDE-web-api.zip)
- Copy the publish package into the site root folder
- Edit web.config and replace the development SQL connection string with your own. If using Windows Authentication with SQL, the AppPool identity must have the database permissions outlined in [Central Store](/../01-database/readme.md)