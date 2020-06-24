# Tenant Builder Script #

## This script has been developed for use against MSDN subscriptions and assumes Global Administrator permissions ##

## About ##
This PowerShell script leverages the Azure, AzureAD and Graph capabilities to build out an Azure Active Directory Tenant suitable for demonstrating various Identity capabilities.  As part of the script an application called _Tenant Builder PowerShell Script_ is created which is required for Graph interactions.

The script will build out the following based on the supplied Organisation description in JSON format:

1. User and Group configuration based on the definition for [Department](https://github.com/ianalderman/tenantbuilder/blob/master/docs/departments.md)
2. Security Groups and Role assignment based on the [Groups](https://github.com/ianalderman/tenantbuilder/blob/master/docs/groups.md) section
3. Azure Custom Roles and assignments of Security Groups as per [CustomRoles](https://github.com/ianalderman/tenantbuilder/blob/master/docs/customRoles.md)
4. Azure Applications and their roles as per [Applications](https://github.com/ianalderman/tenantbuilder/blob/master/docs/applications.md)
5. Entitlement Management catalogs and access packages as per [Entitlements](https://github.com/ianalderman/tenantbuilder/blob/master/docs/entitlements.md)
6. Privilidge Identity Management for Azure resources and assignment as per [PIM](https://github.com/ianalderman/tenantbuilder/blob/master/docs/pim.md)
7. Administrative Units as per [AUs](https://github.com/ianalderman/tenantbuilder/blob/master/docs/administrativeUnits.md)


## Dependencies ##
1. Azure Active Directory PowerShell V2 2.0-preview
2. Az PowerShell 4.2.0

**_Note these will be installed if not present_**

## Usage ##
1. Review organisation.json file and ammend as neccessary - as a minimum you MUST change the "upnSuffix" value to a valid one in your organisation 
2. Execute the script

### Script switches ###
The script supports the following switches:
1. ````ProcessAll```` must be supplied with the value ````$true````, this will process all sections of the supplied JSON file.  Example:
````.\tenantBuilder.ps1 -ProcessAll $true````

2. ````ProcessOnly```` this allows processing of specific sections of the JSON file.  See _Available Process Options_ for valid values.  Note you can supply multiple options as a comma seperated list.  Examples:
````.\tenantBuilder.ps1 -ProcessOnly "AdministrativeUnits"````
````.\tenantBuilder.ps1 -ProcessOnly "AdministrativeUnits,Groups"````

3. ````OrganisationFile```` allows specifying an alternative JSON file for processing
4. ````loglevel```` determines the detail logged.  Level *1* outputs only warnings and errors, *2* includes information level events whilst *3* includes debug.

#### Available Process Options ####
- Departments
- Applications
- CustomRoles
- Groups
- Entitlements
- PIM
- AdministrativeUnits

## Logs ##
The script will append to objects.csv the type and object id of each object it creates.  Over time tenantsweeper.ps1 will be able to use this log to clear any created items.

A log of all activity will be kept in log.txt

## Known Issues ##
1. If executing from the Integrated Shell in VS Code the logon window will appear behind VS Code
2. SharePoint sites will not add to access packages / catalogs
3. This requires a native cloud domain (non-federated)
4. The script expects Global Administrator rights (or at least has only been tested with this!)
