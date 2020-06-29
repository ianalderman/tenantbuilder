# Organisation #
## About ##
The Organisation is the top level object that is used to define the objects built out by the script.

#### User Object  ###

````
{
    "upnSuffix": "@egunicorn.co.uk",
    "Department": [],
    "Application": [],
    "CustomRoles": [],
    "groups":[],
    "AdministrativeUnit"[],
    "PIM": {},
    "EntitlementManagement":{}
````
Property | Required | Description
-------- | -------- | -----------
upnSuffix | Yes | Defines the suffix applied to all [Users](https://github.com/ianalderman/tenantbuilder/blob/master/docs/departments.md) created as part of the script
Department | No | Defines any [Department](https://github.com/ianalderman/tenantbuilder/blob/master/docs/departments.md) objects to create
Application | No | Defines any [Applications](https://github.com/ianalderman/tenantbuilder/blob/master/docs/applications.md) to provision
