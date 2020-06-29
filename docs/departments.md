# Departments #

## About ##
The Departments functionality is responsible for configuring users and groups associated with an Organisation's structure.

### Departments ###
Each department will automatically have the following groups created (but not populated):
- <Department Name> Members
- <Department Name> Owners

A Department will have a Leadership Team and one or more Product Teams.  When processing the Leadership section the script will look for the ````IsManager```` property defined for a user, where this is ````true```` a _dynamic group_ called *<Manager Name> Directs* will be created.  This group will contain any user objects which have the manager set to this user.

### Product Teams ###
Product Teams are simply a team name and a list of team members

## Users ##

When creating users for both the ````Leadership```` and ````ProductTeam````sections the script will create a user with the following properties set:
- Given Name
- Surname
- Display Name
- Department - set to the _Department Name_ for _Leadership_ members or the _Product Team Name_ for Product Team Members
- Title
- Manager (if set)
- Usage Location (defaults to GB if not supplied)
- Licence (defaults to DEVELOPERPACK_E5 if not supplied)
- Random password (shared across all users for the script run)

## Licences ##
The script can assign licences to users as part of provisioning which is required for certain functionality.  There are two ways to assign licences:

In the JSON section for Department add a ````LicenceSKU```` entry e.g.:

````
"Department": [
        {
        "Name": "Digital",
        "LicenceSKU": "DEVELOPER_E5"
        ...
````

Alternatively against an individual team member you can add a ````LicenceSKU```` entry e.g,:
````
{
    "GivenName": "Arnold",
    "Surname": "Potts",
    "Title": "Engineer",
    "ManagedBy": "mateo.garcia",
    "LicenceSKU": "AAD_PREMIUM_P2"
}
````

This allows you to have a default licence for the whole department which you can override on a per user basis, or only apply licences to certain users.  In order to identify the available SKUs in your subscription you can run the command:

````Get-AzureADSubscribedSKU````

This will list the available licence SKUs.  Note it is the _SkuPartNumber_ column you require for the JSON file.

## Technical Detail ##

### Objects Created ###
- Azure Active Directory User
- Azure Active Directory Group
- Azure Active Directory Dynamic Group

### JSON Template ###

#### Department Object ###
````
"Department": [
    {
    "Name": "Digital",
    "Leadership": [],
    "ProductTeam": []
]
````

Property | Required | Description
-------- | -------- | -----------
Name    |   Yes | Name of the department
LicenceSKU | No | Default Licence SKU to apply to the Leadership and Product Users
Leadership | No | One ore more *User objects* definining the Leadership team for the departments, it is expected that Managers are defined here
Product Team | No | One or more *User objects* defining the users that form each Product Team

#### User Object  ###

````
{
    "GivenName": "Arnold",
    "Surname": "Potts",
    "Title": "Engineer",
    "ManagedBy": "mateo.garcia",
    "LicenceSKU": "DEVELOPERPACK_E5"
}
````
Property | Required | Description
-------- | -------- | -----------
GivenName | Yes | First name of the user, e.g., Arnold
Surname | Yes | Surname of the user, e.g., Pots
Title | No | Job Title for the user
ManagedBy | No | Who manages this user, in the format givenname.surname (the Organisation UPN suffix is appended automatically)
IsManager | No  | Boolean determines if this user is configured as a manager
LicenceSKU | No | Licence SKU, e.g., to assign to this user

