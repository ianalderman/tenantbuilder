# Entitlements #

## About ##

The following objects are deployed as part of the Entitlement Management functionality:
- Catalogs
- Group and Application resources assigned to catalog (SharePoint is pending)
- Access Packages
- Access Package policies

### JSON Template ###

#### EntitlementManagement Object ####
````
"EntitlementManagement": {
        "Catalogues": [],
        "AccessPackagePolicies": [],
        "AccessPackages": []
    }
````

Property | Required | Description
-------- | -------- | -----------
Catalogues | Yes | One or more Entitlement Management catalogs to deploy as part of the script
AccessPackagePolicies | No | One or more Access Package Policies to deploy
AccessPackages | No | One or more Access Packages to deploy

##### Catalogues Object #####
Catalogues can be re-used across access packages, *N.B.* An access package is a collection of resources within a catalogue - so they must be defined in the catalog first before they can be packaged and published via an access package

````
"Catalogues": [
            {
                "Name": "Jaguar",
                "Description": "This catalogue contains resources that are used by the Jaguar Team",
                "ExternallyAvailable": false,
                "Groups": [],
                "Applications": [],
                "Sites":[]
            }
        ]
````

Property | Required | Description
-------- | -------- | -----------
Name | Yes | The name of this catalogue
Description | Yes | Description for the catalogue
ExternallyAvailable | Yes | Will this catalogue be available for guest users
Groups | No | List of Groups to publish via the catalog
Applications | No | List of Applications (and role) to publish via the catalog
Sites | No | List of SharePoint sites to publish via the catalog *_These currently don't publish_*

##### AccessPackagePolicies Object #####
Access Package Policies can be re-used across access packages, they determine how an access package can be consumed.

````
"AccessPackagePolicies": [
            {
                "displayName": "direct",
                "description": "direct assignments by administrator",
                "accessReviewSettings": null,
                "requestorSettings": {
                  "scopeType": "NoSubjects",
                  "acceptRequests": true,
                  "allowedRequestors": []
                },
                "requestApprovalSettings": {
                  "isApprovalRequired": false,
                  "isApprovalRequiredForExtension": false,
                  "isRequestorJustificationRequired": false,
                  "approvalMode": "NoApproval",
                  "approvalStages": []
                }
              }
````

Property | Required | Description
-------- | -------- | -----------
displayName | Yes | The name of this Access Package Policy
description | Yes | Description of the access package policy
