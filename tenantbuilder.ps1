
#TODO B2B
#TO FIX SHAREPOINT SITES!
#TODO Conditional Access Policies
#TODO Add JSON as script parameter
#TODO Add flags as parameter default run all unless flags list which to run
#TODO Add Breakglass accounts with alerts for logons
#TODO for all items check if exist if then get ids and carry on rather than erroring and failing to pass info
#TODO Check reponse codes to make sure they are 200s
#TODO Add Licence SKU to JSON

#Cload App Security integration for alerts
#$DebugPreference = "Continue"

#Import-Module -Name AzureADPreview
#Import-Module -Name Az
#Import-Module -Name Microsoft.graph

$processDepartments = $true
$processApplications = $false
$processCustomRoles = $false
$processGroups = $false
$processEntitlements = $false
$processPIM = $false

$OutputLogFile = ".\objects.csv"
$JSONToLoad = ".\test.json"
$UserLicenceSKU = "DEVELOPERPACK_E5"
$NewUserPassword = ([System.Web.Security.Membership]::GeneratePassword(12,2))

function initOutputFile() {
    #ToDo need to think about asking people if they want re-initilise this file.  Decided to just keep appending for now so we can clear up across runs.
    Add-Content -Path $OutputLogFile -Value "ObjectType,ObjectId,Name"
}

function addOutEntry($ObjectType, $ObjectId, $Name) {
    $outEntry = "$($ObjectType),$($ObjectId),$($Name)"
    Add-Content -Path $OutputLogFile -Value $outEntry 
}

function addNewUser($User) {
    
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
    $PasswordProfile.EnforceChangePasswordPolicy = $true
    $PasswordProfile.Password = $NewUserPassword

    $UserDisplayName = $User.GivenName + " " + $User.Surname
    $mailNickName = $User.GivenName.ToLower() + $User.Surname.ToLower()
    $upn = $User.GivenName.ToLower() + "." + $User.Surname.ToLower() + $organisation.upnSuffix
    $User | add-member -Name "UPN" -value $upn -MemberType NoteProperty

    $UserGUID = New-AzureAdUser -AccountEnabled $true -userPrincipalName $User.UPN -Department $User.Department -DisplayName $UserDisplayName -GivenName $User.GivenName -Surname $User.Surname -JobTitle $User.Title -MailNickname $mailNickName -PasswordProfile $PasswordProfile -UsageLocation "GB"
    #SkuPartNumber DEVELOPERPACK_E5
    #$UserGUID = New-GUID
    $User | add-member -Name "GUID" -value $UserGUID.ObjectId -MemberType NoteProperty
    addOutEntry -ObjectType "user" -ObjectId $User.GUID -Name $UserDisplayName

    if ($User.ManagedBy -ne "") {
        Write-Host "Setting Manager for" $UserDisplayName " UserGUID:" $User.GUID " manager guid:" $User.ManagerGUID
        Set-AzureADUserManager -ObjectId $User.GUID -RefObjectId $User.ManagerGUID
        #write-host "ManagerGUID:" + $User.ManagerGUID
    }
    
    if ($User.IsManager) {
        #Each Manager gets a dynamic group that contains their direct reports
        $MembershipRule = "Direct Reports for ""$($User.GUID)"""
        $RuleDisplayName = "$($UserDisplayName) Directs"
        $RuleDescription = "Direct Reports for $($UserDisplayName)"

        $DirectsGroup = New-AzureADMSGroup -DisplayName $RuleDisplayName -Description $RuleDescription -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule $MembershipRule -MembershipRuleProcessingState "On"
        addOutEntry -ObjectType "group" -ObjectId $DirectsGroup.Id -Name $RuleDisplayName
    }

    # Create the objects we'll need to add and remove licenses
    $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses

    # Find the SkuID of the license we want to add
    $license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value $UserLicenceSKU -EQ).SkuID

    # Set the Office license as the license we want to add in the $licenses object
    $licenses.AddLicenses = $license

    # Call the Set-AzureADUserLicense cmdlet to set the license.
    Set-AzureADUserLicense -ObjectId $User.UPN -AssignedLicenses $licenses

}

function removeUser($UserObjectId) {
    Write-Debug -Message "Removing User ObjectId: $($UserObjectId)"
    Remove-AzureADUser -ObjectId $UserObjectId
}

function loadGroups() {
    Foreach($group in $organisation.groups) {
        $grp = New-AzureADMSGroup -DisplayName $group.name -Description $group.description -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
        addOutEntry -ObjectType "group" -objectId $grp.Id -Name $group.name

        ForEach($role in $group.AssignRoles) {
            #$roleDef = Get-AzRoleDefinition -Name $role
           
            $retryCount = 1
            

            do {
                try {
                    $roleAssignment = New-AzRoleAssignment -ObjectId $grp.Id -RoleDefinitionName $role -ErrorAction Stop
                    $roleAssigned = $true
                }
                catch {
                    "Failed to assign group retrying in 10 seconds ($retryCount of 5)"
                    Start-Sleep -s 10
                    $retryCount ++
                }            
            }   until ($retryCount -gt 5 -or $roleAssigned)
           
            if ($retryCount -gt 5) {
                Write-host "Unable to assign $($grp.Name) to role $($role)"
            }
        }

        ForEach($member in $group.members) {
            $user = Get-AzureADUser -ObjectId $member
            $addMember = Add-AzureADGroupMember -ObjectId $grp.Id -RefObjectId $user.ObjectId
        }
    }
}

function removeGroup($GroupObjectId) {
    Write-Debug -Message "Removing Group ObjectId: $($GroupObjectId)"
    Remove-AzureADGroup -ObjectId $GroupObjectId
}

function getManagerGUID($UserObj) {

    if ($UserObj.ManagedBy -ne "") {
        $UserMgrUPN = $UserObj.ManagedBy + $organisation.upnSuffix
        $MgrObject = $Leadership | Where-Object {$_.upn -eq $UserMgrUPN}
        write-host "getManagerGUID Mgr:" $MgrObject "; GUID:" $MgrObject.GUID
        return $MgrObject.GUID
    } else {
        return ""
    }
}

function loadCustomRoles() {
    Write-Host "Processing Roles..."
    ForEach($role in $organisation.CustomRoles) {
        $customRole = Get-AzRoleDefinition -Name "Virtual Machine Contributor"
        $customRole.Id = $null
        $customRole.Name = $role.Name
        $customRole.Description = $role.Description
        $customRole.Actions.RemoveRange(0,$customRole.Actions.Count)

        ForEach($action in $role.Actions) {
            $customRole.Actions.Add($action)
        }

        $customRole.NotActions.RemoveRange(0,$customRole.NotActions.Count)
        ForEach($notAction in $role.NotActions) {
            $customRole.NotActions.Add($notAction)
        }

        $customRole.DataActions.RemoveRange(0,$customRole.DataActions.Count)
        ForEach($dataAction in $role.DataActions) {
            $customRole.DataActions.Add($dataAction)
        }

        $customRole.NotDataActions.RemoveRange(0,$customRole.NotDataActions.Count)
        ForEach($notDataAction in $role.NotDataActions) {
            $customRole.NotDataActions.Add($notDataAction)
        }

        $customRole.AssignableScopes.Clear()

        ForEach($scope in $role.AssignableScopes) {
            $assignmentScope = $scope.Replace("{SubscriptionId}",$SubscriptionId)
            $customRole.AssignableScopes.Add($assignmentScope)
        }

        $newRole = New-AzRoleDefinition -Role $customRole
        addOutEntry -ObjectType "role" -ObjectId $newRole.Id -Name ""
    }
}

function removeCustomRole($roleId) {
    Write-Debug -Message "Removing Custom Role Id: $($roleId)"
    Remove-AzRoleDefinition -Id $roleId
}

#https://stackoverflow.com/questions/54316815/unable-to-add-roles-via-powershell-to-azure-app-registration
# Create an application role of given name and description
Function CreateAppRole([string] $Name, [string] $Description)
{
    $appRole = New-Object Microsoft.Open.AzureAD.Model.AppRole
    $appRole.AllowedMemberTypes = New-Object System.Collections.Generic.List[string]
    $appRole.AllowedMemberTypes.Add("User");
    $appRole.DisplayName = $Name
    $appRole.Id = New-Guid
    $appRole.IsEnabled = $true
    $appRole.Description = $Description
    $appRole.Value = $Name;
    return $appRole
}

function loadApp() {
    Write-Host "Processing Applications"

    ForEach($App in $organisation.Application) {
        $ReplyURI = "https://localhost:1234"

        $appRegistration = New-AzureADApplication -DisplayName $App.Name -IdentifierUris $App.URI -ReplyUrls @($ReplyURI)
        $eaApp = Get-AzureADApplication -ObjectId $appRegistration.ObjectId
        addOutEntry -ObjectType "app" -ObjectId $appRegistration.ObjectId -Name $appRegistration.DisplayName

        #Add a SPN to make it the application an Enterprise Application so we can assign to access package
        $spnDisplayName = $app.DisplayName + " SPN"
        $spn = New-AzureADServicePrincipal -AppId $eaApp.AppId
        addOutEntry -ObjectType"spn" -ObjectId $spn.ObjectId -Name $spnDisplayName
        #write-host "*** SPN Created for App $($app.DisplayName):" $spn
        #Loop through and create the roles
        ForEach($role in $App.Role) {
            $role.Name = $role.Name.Replace(" ", "")
            $newRole = CreateAppRole -Name $role.Name -Description $role.Description
            $eaApp.AppRoles.Add($newRole)
        }

        #Apply the roles to the application
        Set-AzureADApplication -ObjectId $eaApp.ObjectId -AppRoles $eaApp.AppRoles

        
    }
}

function removeApp($AppObjectId) {
    Write-Debug -Message "Removing Application ObjectId: $($AppObjectId)"
    Remove-AzureADApplication -ObjectId $AppObjectId
}

function processDepartment() {
    Write-Host "Processing Departments"
    ForEach ($Department in $organisation.Department){
        #Each Department gets an "Owner" & "Members" security group
        $DepartmentDisplayName = $Department.Name + " Team Owners"
        $OwnerGroup = New-AzureADGroup -DisplayName $DepartmentDisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $DepartmentDisplayName.Replace(" ","-")
        $Department | add-member -Name "OwnerGroupGUID" -value $OwnerGroup  -MemberType NoteProperty
        addOutEntry -ObjectType "group" -ObjectId $OwnerGroup.ObjectId -Name $DepartmentDisplayName

        $DepartmentDisplayName = $Department.Name + " Team Members"
        $MemberGroup = New-AzureADGroup -DisplayName $DepartmentDisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $DepartmentDisplayName.Replace(" ","-")
        $Department | add-member -Name "MemberGroupGUID" -value $MemberGroup  -MemberType NoteProperty
        addOutEntry -ObjectType "group" -ObjectId $OwnerGroup.ObjectId -Name $DepartmentDisplayName

        $Leadership = $Department.Leadership

        ForEach ($User in $Leadership){
            $User | add-member -Name "Department" -value $Department.Name -MemberType NoteProperty
            
            if ($User.ManagedBy -ne "") {
                $User.ManagedBy
                $mgrupn = $User.ManagedBy + $organisation.upnSuffix
                $Mgr = $Leadership | Where-Object {$_.upn -eq $mgrupn}
                $User | add-member -Name "ManagerGUID" -value $Mgr.GUID -MemberType NoteProperty
            }

            addNewUser($User)
        }

        $Products = $Department.ProductTeam

        ForEach ($Product in $Products) {
            $Members = $Product.Members

            ForEach($Member in $Members) {
                $MgrGUID = getManagerGUID($Member)
                $Member | add-member -Name "Department" -value $Product.Name -MemberType NoteProperty
                $Member | add-member -Name "ManagerGUID" -value $MgrGUID -MemberType NoteProperty 
                addNewUser($Member)
            }
        }
    }
}

function loadEntitlementManagement() {
    #Need to create catalogue and assign items to it
    #Create packages in catalogues consuming assigned resources
    write-host "Processing Entitlemenet Management"

    $EntitlementManagement = $organisation.EntitlementManagement
    
    #TODO AccessCatalog App
    #TODO AccessCatalog SharePoint
    #TODO AccessPackage
    #Ensure the signed in user has PIM rights (listed as required)

    $PIMRoleAdmins = Get-AzureADDirectoryRoleMember -ObjectId "083a4064-745c-4d9a-a523-228602931e47"
    $pimRoleAdminRef = $PIMRoleAdmins | Where-Object {$_.UserPrincipalName -eq $accountId}

    if (-not $pimRoleAdminRef) {
        $SignedInUser = Get-AzADUser -UserPrincipalName $accountId
        Add-AzureADDirectoryRoleMember -ObjectId 083a4064-745c-4d9a-a523-228602931e47  -RefObjectId $SignedInUser.Id
    }

    loadEntitlementManagementCatalogues -Catalogues $EntitlementManagement.Catalogues
    loadEntitlementManagementAccessPackages -AccessPackages $EntitlementManagement.AccessPackages

    #$catalogs = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body "" -Method "GET" | ConvertFrom-Json
    #$accessPackagePolicies = $organisation.AccessPackagePolicies | ConvertFrom-Json

    Write-Host "catalogs:" $catalogs
    

}

function loadEntitlementManagementCatalogues($Catalogues) {
    ForEach ($catalogue in $Catalogues) {
        #Create the catalogue
            $body = @{
                displayName = $catalogue.Name
                description = $catalogue.Description
                isExternallyVisible = $catalogue.ExternallyAvailable
            } | ConvertTo-JSON
    
            $catalog = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body $body -Method "POST"
    
            addOutEntry -ObjectType "catalogue" -ObjectId $catalog.Id -Name $catalog.Name
    
            #$groupsToAdd = $catalog.Groups
            ForEach ($group in $catalogue.groups) {
                Write-Host "Processing Groups"
                $grp = Get-AzureADGroup -SearchString "$($group)"
                
                if ($grp) {
                    $grpBody = @{
                        catalogId = $catalog.Id
                        requestType = "AdminAdd"
                        justification = ""
                        accessPackageResource = @{
                            displayName = $grp.DisplayName
                            description = $grp.Description
                            url = "https://account.activedirectory.windowsazure.com/r?tenantId=$($tenantId)#/manageMembership?objectType=Group&objectId=$($grp.ObjectId)"
                            resourceType = "Group"
                            originId = $grp.ObjectId
                            originSystem = "AadGroup"
                        }
                    } | ConvertTo-Json
        
                    $catalogGroup = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageResourceRequests" -Body $grpBody -Method "POST"
                } else {
                    Write-Warning "Unable to add Entitlement Management Catalog Group Resource as group not found.  Group: " $group
                }
            }
            
            ForEach ($app in $catalogue.Applications) {
                Write-Host "Processing App $($app)"
                $app = $app.Replace("'", "''")
                $appRegistration = Get-AzureADApplication -Filter "DisplayName eq '$($app)'"
                $appSPN = Get-AzureADServicePrincipal -SearchString "$($app)"
                #Write-Host "*** App SPN: $($appSPN) ***"
                #$app
                $appBody = @{
                    catalogId = $catalog.Id
                    requestType = "AdminAdd"
                    justification = ""
                    accessPackageResource = @{
                        displayName = $app
                        url = "https://myapps.microsoft.com/$($tenantDetail.DisplayName).onmicrosoft.com/signin.$($app)/$($appRegistration.AppId)"
                        description = "AppId: $($appRegistration.AppId)"
                        resourceType = "Application"
                        originId = $appSPN.ObjectId
                        originSystem = "AadApplication"
                    }
                } | ConvertTo-Json
                #$appBody
                $catalogapp = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageResourceRequests" -Body $appBody -Method "POST"
            }
    
            ForEach ($site in $catalogue.Sites) {
                Write-Host "Processing Sites"
                $siteBody = @{
                    catalogId = $catalog.Id
                    requestType = "AdminAdd"
                    justification = ""
                    accessPackageResource = @{
                        displayName = $site.Name
                        description = $site.Url
                        resourceType = "SharePoint Online Site"
                        url = $site.Url
                        originId = $site.Url
                        originSystem = "SharePointOnline"
                    }
                } | ConvertTo-Json
                #$appBody
                #CANNOT GOT THIS TO WORK!!
                #$catalogSite = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageResourceRequests" -Body $siteBody -Method "POST"
            }
        }
}

function removeEntitlementManagementCatalogues($catalogObjectId) {

}

function loadEntitlementManagementAccessPackages($AccessPackages) {
    ForEach($accessPkg in $AccessPackages) {
        #Need to first create access package
        #Then add a scope request to entry in the catalogue https://docs.microsoft.com/en-us/graph/api/accesspackage-post-accesspackageresourcerolescopes?view=graph-rest-beta&tabs=http
        $catalogs = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body "" -Method "GET" | ConvertFrom-Json
        $catalogs = $catalogs.value 
        $catalogs = $catalogs | Where-Object {$_.displayName -eq "$($accessPkg.Catalogue)"}

        $pkgBody = @{
            catalogId = "$($catalogs.Id)"
            displayName = "$($accessPkg.Name)"
            description = "$($accessPkg.description)"
        } | ConvertTo-Json

        $accessPkgResponse = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages" -Body $pkgBody -Method "POST"

        #for fuller policy example look here https://docs.microsoft.com/en-us/graph/api/accesspackageassignmentpolicy-post?view=graph-rest-beta&tabs=http

        #Add in the id of the newly created package
        $accessPkg | Add-Member -MemberType NoteProperty -Name "id" -Value $accessPkgResponse.id        
        #Get a list of resources in the catalog
        $catalogResources = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($catalogs.Id)/accessPackageResources" -Body "" -Method "GET" | ConvertFrom-Json
        $catalogResources = $catalogResources.value

        Foreach($pkgGroup in $accessPkg.Groups) {
            $groupRole = buildAccessPackageRole -packageName $pkgGroup.Name -packageRole $pkgGroup.Role -resourceType "AadGroup" -catalogId $catalogs.Id -catalogResourcesList $catalogResources
            $addGroupResponse = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackages/$($accessPkgResponse.id)/accessPackageResourceRoleScopes" -Body $groupRole -Method "POST"
        }

        Foreach($pkgApp in $accessPkg.Applications) {
            $appRole = buildAccessPackageRole -packageName $pkgApp.Name -packageRole $pkgApp.Role -resourceType "AadApplication" -catalogId $catalogs.Id -catalogResourcesList $catalogResources
            $addAppResponse = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackages/$($accessPkgResponse.id)/accessPackageResourceRoleScopes" -Body $appRole -Method "POST"
            #Write-Host "aadAppResponse: " $addAppResponse
        }

        loadAccessEntitlementManagementAccessPackagePolicies -AccessPackage $accessPkg
    }
}

function removeAccessPackage($AccessPackageObjectId) {

}

function buildAccessPackageRole($packageName, $packageRole, $resourceType, $catalogId, $catalogResourcesList) {
    #write-host "Package Name: $($packageName), Package Role: $($packageRole), Resource Type: $($resourceType), Cat Id: $($catalogId), Cat Res: $($catalogResourcesList)"
    $catalogEntry = $catalogResourcesList | Where-Object {$_.DisplayName -eq "$($packageName)" -and $_.originSystem -eq "$($resourceType)"}

    $resourceRole = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($catalogId)/accessPackageResourceRoles?`$filter=(originSystem+eq+%27$($resourceType)%27+and+accessPackageResource/id+eq+%27$($catalogEntry.Id)%27)&`$expand=accessPackageResource" -body "" -Method "GET" | ConvertFrom-JSON
    $resourceRole = $resourceRole.value

    #When loading the roles Graph strips the spaces so remove the spaces from the role name to locate it
    $packagerole = $packageRole.Replace(" ","")
    $resourceRoleToAdd = $resourceRole | Where-Object {$_.DisplayName -eq "$($packageRole)"}

    $apr = @{
        accessPackageResourceRole = @{
            originId = $resourceRoleToAdd.originId
            displayName = $resourceRoleToAdd.displayName
            originSystem = $resourceRoleToAdd.originSystem
            accessPackageResource = @{
                id = $catalogEntry.Id
                resourceType = $catalogEntry.resourceType
                originId = $catalogEntry.originId
                originSystem = $catalogEntry.originSystem
            }
        }
        accessPackageResourceScope = @{
            originId = $catalogEntry.originId
            originSystem = $catalogEntry.originSystem
        }
    } | ConvertTo-Json

    return $apr
}

function loadAccessEntitlementManagementAccessPackagePolicies($accessPackage) {
    Write-Host "Processing Access Policies for Package: " $accessPackage
    #Load the access package policy into an object to work on
    $accessPackagePolicy = $organisation.entitlementmanagement.accesspackagepolicies | Where-Object {$_.displayName -eq "$($accessPackage.PolicyName)"}
    Write-Host "Loaded Policy Def:" $accessPackagePolicy
    #Add in the id of the newly created package
    $accessPackagePolicy | Add-Member -MemberType NoteProperty -Name "accessPackageId" -Value $accessPackage.id

    #Populate the GUIDs for the groups and users listed in the policy
    if ($accessPackagePolicy.requestorSettings.allowedRequestors) {
        $accessPackagePolicy.requestorSettings.allowedRequestors = markupoDataEntries -Object $accessPackagePolicy.requestorSettings.allowedRequestors
    }
    
    Foreach($stage in $accessPackagePolicy.requestApprovalSettings.approvalStages) {
        if ($stage.primaryApprovers) {
            write-host "*** Primary Approvers ***" $stasge.primaryApprovers
            $stage.primaryApprovers = markupoDataEntries -Object $stage.primaryApprovers
        }
        
        if ($stage.escalationApprovers) {
            $stage.escalationApprovers = markupoDataEntries -Object $stage.escalationApprovers
        }
    }

    if ($accessPackagePolicy.accessReviewSettings.reviewers) {
        $accessPackagePolicy.accessReviewSettings.reviewers = markupoDataEntries -Object $accessPackagePolicy.accessReviewSettings.reviewers
    }

    #Access Review dates must start today or later check and update
    if ($accessPackagePolicy.accessReviewSettings) {
        $startDate = [DateTime]$accessPackagePolicy.accessReviewSettings.startDateTime
        $today = Get-Date

        if ($startDate -lt $today) {
            $accessPackagePolicy.accessReviewSettings.startDateTime = $today.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            Write-Warning "Access Review Start Date for package $($accessPackage.DisplayName) had illegal start date (less than today), this has been defaulted to today's date"
        }
    }
    
    $accessPackagePolicy = $accessPackagePolicy | ConvertTo-Json -Depth 100
    
    $response = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies" -Body $accessPackagePolicy -Method "POST"
}
function markupoDataEntries($Object) {
    ForEach ($entry in $Object) {
        switch ($entry.'@odata.type') {
            "#microsoft.graph.groupMembers" {
                $grp =  Get-AzureADGroup -SearchString "$($entry.description)"
                $entry.id = $grp.ObjectId  
            }
            "#microsoft.graph.singleUser" {
                $usr = Get-AzureADUser -SearchString "$($entry.description)"
                $entry.id = $usr.ObjectId
                $entry.description = $user.DisplayName
            }
            default {
                Write-host "Unknown odata.type" $entry.'@odata.type'
            }
        }
    }
    return , $Object
}

function invokeGraphAPI($Call, $Body, $Method) {
    $accessToken = Get-AzCachedAccessToken
    
    $url = "https://graph.microsoft.com/$($Call)"
    #Write-Host "Url: " $url
    #Write-Host "Body: " $body

    if ($Method -eq "GET") {
        $graphResponse = Invoke-WebRequest -UseBasicParsing -Headers  @{Authorization = $accessToken} -Uri $url -Method GET
    } else {
        $graphResponse = Invoke-RestMethod -Headers @{Authorization = $accessToken} -Uri $url -Body $body -Method POST -ContentType "application/json"
    }
    return $graphResponse
}

function loadPIM() {
    #Need to onboard subscription first - check if it is, if not enable it
    #Need to configure roles - this looks like a lot of settings put a profile in the JSON to rinse and repeat?
    #TODO PIM SETTINGS
    #TODO PIM Alllow multiple users / groups to a single assignment
    #TODO PIM Notifictaions

    #https://docs.microsoft.com/en-us/graph/api/governanceresource-register?view=graph-rest-beta

    # Policy https://docs.microsoft.com/en-us/powershell/module/azuread/set-azureadmsprivilegedrolesetting?view=azureadps-2.0-preview

    #Ensure the signed in user has PIM rights
    $SignedInUser = Get-AzADUser -UserPrincipalName $accountId

    $pimRoleAdmins = Get-AzureADDirectoryRoleMember -ObjectId "083a4064-745c-4d9a-a523-228602931e47"
    $pimRoleAdminRef = $pimRoleAdmins | Where-Object {$_.UserPrincipalName -eq $accountId}

    if (-not $pimRoleAdminRef) {
        Add-AzureADDirectoryRoleMember -ObjectId 083a4064-745c-4d9a-a523-228602931e47  -RefObjectId $SignedInUser.Id
    }

    $PIM = $organisation.PIM
    if ($PIM.Enrol) {
        $body = @{
            externalId = "/subscriptions/$($SubscriptionId)"
        } | ConvertTo-JSON
        invokeGraphAPI -Call "beta/privilegedAccess/azureResources/resources/register" -Body $body -Method "POST"
    }

    #Get all the Subscriptions enrolled in PIM
    $PIMSubscriptions = ListResources

    #UserMemberSettings
    #RuleIdentifier    Setting
    #--------------    -------
    #ExpirationRule    {"maximumGrantPeriod":"08:00:00","maximumGrantPeriodInMinutes":480,"permanentAssignment":false}
    #MfaRule           {"mfaRequired":false}
    #JustificationRule {"required":true}
    #ApprovalRule      {"enabled":false,"isCriteriaSupported":false,"approvers":null,"businessFlowId":null,"hasNotificationPolicy":false}
    #TicketingRule     {"ticketingRequired":false}
    #AcrsRule          {"acrsRequired":false,"acrs":null}    #This is the Conditional Access Rule $policyString= '{"ruleIdentifier":"AcrsRule","setting":"{\"acrsRequired\":true,\"acrs\":\"'+$policyTag+'\"}"}' see https://www.powershellgallery.com/packages/AzSK/4.3.0/Content/Framework%5CCore%5CPIM%5CPIMScript.ps1

    ForEach($Subscription in $PIMSubscriptions) {
        #Get the roles for the subscription
        $roles = ListRoles($Subscription.ResourceId)
        ForEach($role in $PIM.Roles) {
            $PIMRole = $roles | Where-Object {$_.RoleName -eq $role.Name}

            if ($PIMRole -is [array]) {
                #This happened in testing where role was created / re-created multiple times...
                $PIMRole = $PIMRole | Sort-Object -Property id -Descending
                $PIMRole = $PIMRole[0]
            }
            
            ForEach($assignment in $role.Assignments) {
                $groupToAdd = get-azureadmsgroup -Filter "DisplayName eq '$($assignment.GroupToAdd)'"

                if ($groupToAdd -eq $null) {
                    Write-Host "Failed to find Group: " $assignment.GroupToAdd
                    break
                }

                #Write-Host "Assingment: " $assignment
                $body = @{
                    assignmentState = $assignment.Type
                    type = "AdminAdd"
                    reason = "Assigned through Tenant Builder PowerShell Script"
                    roleDefinitionId = "$($PIMRole.RoleDefinitionId)"
                    resourceId = "$($Subscription.ResourceId)"
                    subjectId = "$($groupToAdd.Id)"
                    schedule = @{
                        startDateTime =[Datetime]::ParseExact($assignment.startDateutc, "yyyy-MM-dd",$null).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        endDateTime = [Datetime]::ParseExact($assignment.endDateutc, "yyyy-MM-dd",$null).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        type = "once"
                    }
                } | ConvertTo-JSON
    
                $reponse = invokeGraphAPI -Call "beta/privilegedAccess/azureResources/roleAssignmentRequests" -Body $body -Method "POST"

                
            }   
        }
    }
}
function ListResources(){
    #http://www.anujchaudhary.com/2018/02/powershell-sample-for-privileged
    Write-Host "Loading PIM Subscribed Resources"
    $url = "beta/privilegedAccess/azureResources/resources?`$filter=(type+eq+'subscription')"

    $response = invokeGraphAPI -Call $url  -Body "" -Method "GET"

    $resources = ConvertFrom-Json $response.Content
    $i = 0
    $obj = @()
    foreach ($resource in $resources.value)
    {
        $item = New-Object psobject -Property @{
        id = ++$i
        ResourceId =  $resource.id
        ResourceName =  $resource.DisplayName
        Type =  $resource.type
        ExternalId =  $resource.externalId
    }
    $obj = $obj + $item
}

return $obj
}

function ListRoles($resourceId){
    #http://www.anujchaudhary.com/2018/02/powershell-sample-for-privileged.html
    Write-Host "Loading Roles for Subscription"
    $url = "beta/privilegedAccess/azureResources/resources/" + $resourceId + "/roleDefinitions?&`$orderby=displayName"
    #Write-Host $url

    #$response = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method Get
    $response = invokeGraphAPI -Call $url  -Body "" -Method "GET"
    $roles = ConvertFrom-Json $response.Content
    $i = 0
    $obj = @()
    foreach ($role in $roles.value)
    {
        $item = New-Object psobject -Property @{
        id = ++$i
        RoleDefinitionId =  $role.id
        RoleName =  $role.DisplayName
    }
    $obj = $obj + $item
    }

    return $obj
}

function Get-AzCachedAccessToken(){

    
    $clientId = $tenantBuilerAppId

    $redirectUri = "https://localhost"

    $authorityUri = "https://login.microsoftonline.com/$($tenantId)/oauth2/v2.0/authorize"

    $ApiEndpointUri = "https://graph.microsoft.com"

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authorityUri

    $promptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    $authParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $promptBehaviour
    $authResult = $authContext.AcquireTokenAsync($ApiEndpointUri,  $clientId, $redirectUri,  $authParam).GetAwaiter().GetResult()

    return $authResult.CreateAuthorizationHeader()
}

function createTenantBuilderApp() {
    #Check if app exists and return AppId if so
    $existingApp = Get-AzureADApplication -Filter "DisplayName eq 'Tenant Builder PowerShell Script'"

    if ($existingApp) {
        return $existingApp.AppId
    }

    Write-Host "Tenant Builder App not found.  The script will create an app called Tenant Builder PowerShell Scipt, this is required for interacting with Graph.  You will be prompted to consent to the required permissions.  This is a one-time activity."
    #Create new Public Client App (required for this flow)
    $tenantBuilderApp = New-AzureADApplication -DisplayName "Tenant Builder PowerShell Script" -ReplyUrls @("https://localhost") -PublicClient $true
    
    $appAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    #Microsoft.Graph/User.Read Delegated
    $UserRead = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "e1fe6dd8-ba31-4d61-89e7-88639da4683d","Scope" 
    #Microsoft.Graph/EntitlementManagement.ReadWrite.All Delegated
    $EntitlementManagementReadWriteAll = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ae7a573d-81d7-432b-ad44-4ed5c9d89038","Scope"
    #PriviledgedAccess.ReadWrite.AzureAD
    $PriviledgedAccessReadWriteAzureAD = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "3c3c74f5-cdaa-4a97-b7e0-4e788bfcfb37","Scope"
    #PriviledgedAccess.ReadWrite.AzureADGroup
    $PriviledgedAccessReadWriteAzureADGroup = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "32531c59-1f32-461f-b8df-6f8a3b89f73b","Scope"
    #PriviledgedAccess.ReadWrite.AzureResources
    $PriviledgedAccessReadWriteAzureResources = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "a84a9652-ffd3-496e-a991-22ba5529156a","Scope"
    #Sites.FullControl.All
    $SitesFullControlAll = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "5a54b8b3-347c-476d-8f8e-42d5c7424d29","Scope"
    
    $appAccess.ResourceAccess = $UserRead,$EntitlementManagementReadWriteAll,$PriviledgedAccessReadWriteAzureAD,$PriviledgedAccessReadWriteAzureADGroup,$PriviledgedAccessReadWriteAzureResources,$SitesFullControlAll
    $appAccess.ResourceAppId = "00000003-0000-0000-c000-000000000000" #Microsoft Graph API
    
    Set-AzureADApplication -ObjectId $tenantBuilderApp.ObjectId -RequiredResourceAccess $appAccess
    
    addOutEntry -ObjectType "app" -ObjectId $tenantBuilderApp.ObjectId -Name $DepartmentDisplayName

    #In my testing the consent frequently failed with app not found, pausing seems to fix this *sigh*
    Write-Host "Sleeping for 30s for app registration to complete"
    Start-Sleep -s 30

    $proc = Start-Process -FilePath  "https://login.microsoftonline.com/$($tenantId)/oauth2/authorize?client_id=$($tenantBuilderApp.AppId)&response_type=code&redirect_uri=https%3A%2F%2Flocalhost%2Fmyapp%2F&response_mode=query&resource=&state=12345&prompt=admin_consent"

    #Wait for Admin consent to be granted so that the Graph related stuff can work
    read-host "Please consent to application and press ENTER to continue..."
    return $tenantBuilderApp.AppId
}

#*** Globals and commands ***

#Connect to Azure to enable AZ cmdlets and set up globals
Connect-AzAccount
#Set up some globals
$currentAzureContext = Get-AzContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
$SubscriptionId = $currentAzureContext.Subscription.Id


#Connect to AzureAD to enable the AzureAD Cmdlets
Connect-AzureAD -TenantId $tenantId -AccountId $accountId
$tenantDetail = Get-AzureADTenantDetail
#Connect to Graph to enable the Graph Cmdlets
#Connect-Graph

write-host "Connected to Tenant"

#Load the JSON Tenant definition
$organisation = Get-Content -Raw -Path $JSONToLoad | ConvertFrom-Json

#In order to play with the Graph we need an application as the PowerShell well known Id cannot perform some operations
$tenantBuilerAppId = createTenantBuilderApp

Write-Host "Loaded JSON:" $JSONToLoad

#Initialise what is in effect the state file
initOutputFile

if ($processDepartments) {
    processDepartment
}

if ($processApplications) {
    loadApp
}

if ($processCustomRoles) {
    loadCustomRoles
}

if ($processGroups) {
    loadGroups
}

if ($processEntitlements) {
    loadEntitlementManagement
}

if ($processPIM) {
    loadPIM
}

Write-Host "Password for new users not this is not stored: $($NewUserPassword)"
#Uncomment the line below to get the access token for use with Postman
#Get-AzCachedAccessToken

$DebugPreference = "SilentlyContinue"
