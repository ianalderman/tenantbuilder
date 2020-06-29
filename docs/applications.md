# Applications #

## About ##
The Applications functionality configures custom applications in Azure Active Directory.  

Each Application will have the following configured:
- Name
- Application URL
- Reply URL
- Supplied Application Roles

### JSON template ###

#### Application Object ####
````
"Application": [
        {
            "Name": "Jaguar Team App",
            "URI": "jag.egunicorn.co.uk",
            "ReplyURI": "https://jag.egunicorn.co.uk/reply",
            "Role": [
                {
                    "Name": "User role",
                    "Description": "This role is for general application users"
                },
                {
                    "Name": "Admin role",
                    "Description": "This role is for application administration"
                }
            ]
        }
    ]
````

Property | Required | Description
-------- | -------- | -----------
Name    |   Yes | Name of the Application Unit
URI | Yes | URI for the application
ReplyURI | No | ReplyURI for the application, will default to ````https://localhost:1234````
Role | No | One or more roles to configure for the app *N.B.* Entitlement Management needs a role to assign to so if an app to be used with that define a role here

##### Role Object #####

````
"Role": [
    {
        "Name": "User role",
        "Description": "This role is for general application users"
    }
]
````

Property | Required | Description
-------- | -------- | -----------
Name    |   Yes | Name of the role
Description | Yes | Description for the role



