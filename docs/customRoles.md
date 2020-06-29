# Custom Roles #

## About ##
The Custom Roles functionality deploys Azure Custom roles and assigns them to the subscription that the user is logged in to.

### JSON Template ###

#### customRoles Object ####

````
"CustomRoles": [
        {
            "Name": "Virtual Machine Operator",
            "Description": "Can monitor and restart virtual machines.",
            "Actions": [
                "Microsoft.Storage/*/read",
                "Microsoft.Network/*/read",
                "Microsoft.Compute/*/read",
                "Microsoft.Compute/virtualMachines/start/action",
                "Microsoft.Compute/virtualMachines/restart/action",
                "Microsoft.Authorization/*/read",
                "Microsoft.ResourceHealth/availabilityStatuses/read",
                "Microsoft.Resources/subscriptions/resourceGroups/read",
                "Microsoft.Insights/alertRules/*",
                "Microsoft.Insights/diagnosticSettings/*",
                "Microsoft.Support/*"
            ],
            "NotActions": [],
            "DataActions": [],
            "NotDataActions": [],
            "AssignableScopes": [
              "/subscriptions/{SubscriptionId}"
            ] 
        }
    ]
````

Property | Required | Description
-------- | -------- | -----------
Name    |   Yes | Name of the Custom role
Description | Yes | Description for the Custom Role
Actions | Yes | List of actions that the role can perform
NotActions | No | List of actions the user is prevented from doing
DataActions | No | One or more supported actions at the data layer (not managamenet plane)
NotDataActions | No | One or more supported actions at the data layer to deny (not managamenet plane)
AssignableScopes | Yes | Currently read-only.  The SubscriptionId will be replaced at run time with the logged in subscription Id