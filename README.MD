# Tenant Builder Script #

## About ##
This PowerShell script leverages the Azure, AzureAD and Graph capabilities to build out an Azure Active Directory Tenant suitable for demonstrating various Identity capabilities.

As time allows I will look to refactor to use 100% Graph to reduce the number of dependencies.

The script will build out the following based on the supplied Organisation description in JSON format:

1. Active Directory Users
- Manager & Department Information
- Random Password
- Licence allocation
2. Dynamic Groups
- Each Manager has a dynamic group create created called "<Manager Name> Directs" this targets all Users tagged with that Manager
3. Security Groups
4. Azure Custom Roles and assignments of Security Groups
5. Azure Applications
- Custom roles
- Service Principal
6. Entitlement Management Catalogs
- Security Groups
- Applications (& Roles)
- SharePoint (pending - cannot get to work)
7. Entitlmement Access Packages
8. Privilidge Identity Management for Azure resources and assignment

## Dependencies ##
1. Azure Active Directory PowerShell V2 2.0-preview
2. Az PowerShell 4.2.0

## Usage ##
1. Review organisation.json file and ammend as neccessary
2. Execute tenantbuilder.ps1

## Logs ##
The script will append to objects.csv the type and object id of each object it creates.  Over time tenantsweeper.ps1 will be able to use this log to clear any created items.
