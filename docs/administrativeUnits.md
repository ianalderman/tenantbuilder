# Administrative Units #

## About ##
The Administrative Units (AU) functionality builds out 1 or more Administrative Units within the Directory.  The script will

- Assign Users to an AU
- Assign Groups to an AU
- Assign 1 or more deletegated roles for the AU

### JSON Template ###

#### Administrative Unit Object ###
````
"AdministrativeUnit": [
        {
            "Name": "Jaguar",
            "Description": "Administrative unit for devolving Jaguar User administration",
            "Users": ["an.li@egunicorn.co.uk"],
            "Groups": ["Digital Team Members"],
            "Roles": [
                {
                    "Role": "User Account Administrator",
                    "Users": [
                        "anvi.rao@egunicorn.co.uk"
                    ]
                }
            ]
        }
    ]
````

Property | Required | Description
-------- | -------- | -----------
Name    |   Yes | Name of the Administrative Unit
Description | Yes | Description for the Administrative Unit
Users | No | List of user UPNs to be assigned as members of the AU
Groups | No | List of Groups to be assigned as members of the AU
Roles | No | One or more supported roles to assign for delegated management of the AU

##### Role Object #####

````
{
    "Role": "User Account Administrator",
        "Users": [
            "anvi.rao@egunicorn.co.uk"
        ]
}
````

Property | Required | Description
-------- | -------- | -----------
Role | Yes | Name of the role to delegate
Users | Yes | List of user UPNs to be assigned to the role