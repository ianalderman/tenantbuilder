
#TODO B2B
#TODO Conditional Access Policies
$DebugPreference = "Continue"

#Import-Module -Name AzureADPreview
#Import-Module -Name Az
#Import-Module -Name Microsoft.graph

$processDepartments = $false
$processApplications = $false
$processCustomRoles = $false
$processGroups = $false
$processEntitlements = $true
$processPIM = $false

$OutputLogFile = ".\objects.csv"
$JSONToLoad = ".\test.json"
$UserLicenceSKU = "DEVELOPERPACK_E5"


function initOutputFile() {
    Set-Content -Path $OutputLogFile -Value "ObjectType,ObjectId,Name"
}

function addOutEntry($ObjectType, $ObjectId, $Name) {
    $outEntry = "$($ObjectType),$($ObjectId),$($Name)"
    Add-Content -Path $OutputLogFile -Value $outEntry 
}

function addNewUser($User) {
    
    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
    $PasswordProfile.EnforceChangePasswordPolicy = $true
    $PasswordProfile.Password = "WelcomeToTheNumber1Team!"

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
        write-host "ManagerGUID:" + $User.ManagerGUID
    }
    
    if ($User.IsManager) {
        #Each Manager gets a dynamic group that contains their direct reports
        $MembershipRule = "Direct Reports for ""$($User.GUID)"""
        $RuleDisplayName = "$($UserDisplayName) Directs"
        $RuleDescription = "Direct Reports for $($UserDisplayName)"

        $DirectsGroup = New-AzureADMSGroup -DisplayName $RuleDisplayName -Description $RuleDescription -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule $MembershipRule -MembershipRuleProcessingState "On"
        $DirectsGroup
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
        $eaApp= Get-AzureADApplication -ObjectId $appRegistration.ObjectId
        addOutEntry -ObjectType "app" -ObjectId $appRegistration.ObjectId -Name $appRegistration.DisplayName

        ForEach($role in $App.Role) {
            $role.Name = $role.Name.Replace(" ", "")
            $newRole = CreateAppRole -Name $role.Name -Description $role.Description
            $eaApp.AppRoles.Add($newRole)
        }

        #Apply the roles to the application
        Set-AzureADApplication -ObjectId $eaApp.ObjectId -AppRoles $eaApp.AppRoles

        #Add a SPN to make it the application an Enterprise Application so we can assign to access package
        $spnDisplayName = $app.DisplayName + " SPN"
        $spn = New-AzureADServicePrincipal -AppId $eaApp.AppId
        addOutEntry -ObjectType"spn" -ObjectId $spn.ObjectId -Name $spnDisplayName
    }
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
    ForEach ($catalogue in $EntitlementManagement.Catalogues) {
    #Create the catalogue
        $body = @{
            displayName = $catalogue.Name
            description = $catalogue.Description
            isExternallyVisible = $catalogue.ExternallyAvailable
        } | ConvertTo-JSON

        $catalog = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body $body -Method "POST"

        addOutEntry -ObjectType "catalogue" -ObjectId $catalog.ObjectId -Name $catalog.Name

        #$groupsToAdd = $catalog.Groups
        ForEach ($group in $catalogue.groups) {
            Write-Host "Processing Groups"
            $grp = Get-AzureADGroup -SearchString $group

            $grpBody = @{
                catalogId = $catalog.Id
                requestType = "AdminAdd"
                justification = ""
                accessPackageResource = @{
                    displayName = $grp.DisplayName
                    description = $grp.Description
                    resourceType = "Group"
                    originId = $grp.ObjectId
                    originSystem = "AadGroup"
                }
            } | ConvertTo-Json

            $catalogGroup = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageResourceRequests" -Body $grpBody -Method "POST"
        }
        
        ForEach ($app in $catalogue.Applications) {
            Write-Host "Processing Apps"
            $app = $app.Replace("'", "''")
            $appRegistration = Get-AzureADApplication -Filter "DisplayName eq '$($app)'"
            #$app
            $appBody = @{
                catalogId = $catalog.Id
                requestType = "AdminAdd"
                justification = ""
                accessPackageResource = @{
                    displayName = $app
                    description = "AppId: $($appRegistration.AppId)"
                    resourceType = "Application"
                    originId = $appRegistration.ObjectId
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
            $catalogSite = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageResourceRequests" -Body $siteBody -Method "POST"
        }
    }

    $catalogs = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body "" -Method "GET" | ConvertFrom-Json

    Write-Host "catalogs:" $catalogs
    ForEach($accessPkg in $EntitlementManagement.AccessPackages) {
        #Need to first create access package
        #Then add a scope request to entry in the catalogue https://docs.microsoft.com/en-us/graph/api/accesspackage-post-accesspackageresourcerolescopes?view=graph-rest-beta&tabs=http
        $catalog = $catalogs | Where-Object ($_.DisplayName -eq $accessPkg.Catalogue)

        $pkgBody = @{
            catalogId = "$($catalog.Id)"
            displayName = "$($accessPkg.Name)"
            description = "$($accessPkg.description)"
        }

        $accessPkgResponse = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages" -Body $pkgBody -Method "POST"

        Foreach($pkgGroup in $accessPkg.Groups) {

            $pgb = @{
                
            }
        }
    }

}

function invokeGraphAPI($Call, $Body, $Method) {
    $accessToken = Get-AzCachedAccessToken
    
    $url = "https://graph.microsoft.com/$($Call)"
    Write-Host "Url: " $url
    Write-Host "Body: " $body

    if ($Method -eq "GET") {
        $graphResponse = Invoke-WebRequest -UseBasicParsing -Headers  @{Authorization = $accessToken} -Uri $url -Method Get
    } else {
        $graphResponse = Invoke-RestMethod -Headers @{Authorization = $accessToken} -Uri $url -Body $body -Method $Method -ContentType "application/json"
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
    #TODO Clean this up check and if not then add
    $SignedInUser = Get-AzADUser -UserPrincipalName $accountId
    Add-AzureADDirectoryRoleMember -ObjectId 083a4064-745c-4d9a-a523-228602931e47  -RefObjectId $SignedInUser.Id

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
            Write-Host "PIM Role: " $PIMRole
            #$url = $serviceRoot + "roleAssignmentRequests"
            # Update end time
            #$ts = New-TimeSpan -Days 30
            ForEach($assignment in $role.Assignments) {
                $groupToAdd = get-azureadmsgroup -Filter "DisplayName eq '$($assignment.GroupToAdd)'"

                if ($groupToAdd -eq $null) {
                    Write-Host "Failed to find Group: " $assignment.GroupToAdd
                    break
                }

                Write-Host "Assingment: " $assignment
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

                #[Datetime]::ParseExact($startDate, "yyyy-mm-dd",$null).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    
                $reponse = invokeGraphAPI -Call "beta/privilegedAccess/azureResources/roleAssignmentRequests" -Body $body -Method "POST"

                #$postParams = '{"assignmentState":"Eligible","type":"AdminAdd","reason":"Assign","roleDefinitionId":"' + $roleDefinitionId + '","resourceId":"' + $resourceId + '","subjectId":"' + $subjectId + '","schedule":{"startDateTime":"' + (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + '","endDateTime":"' + ((Get-Date) + $ts).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + '","type":"Once"}}'
                #write-Host $postParams
    
                #try
                #{
                    #$response = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method Post -ContentType "application/json" -Body $postParams
                    #Write-Host "Assignment request queued successfully ..." -ForegroundColor Green
                    #$recursive = $false
                #} catch {
                #    $stream = $_.Exception.Response.GetResponseStream()
                #    $stream.Position = 0;
                #    $streamReader = New-Object System.IO.StreamReader($stream)
                #    $err = $streamReader.ReadToEnd()
                #    $streamReader.Close()
                #    $stream.Close()
    
                #    if($mfaDone -eq $false -and $err.Contains("MfaRule"))
                #    {
                #        Write-Host "Prompting the user for mfa ..." -ForegroundColor Green
                #        AcquireToken $global:clientID $global:redirectUri $global:resourceAppIdURI $global:authority $true
                #        Activate $true
                #    }
                #    else
                #    {
                #        Write-Host $err -ForegroundColor Red
                #    }
                #}
            }   
        }
    }
}
function ListResources(){
    #http://www.anujchaudhary.com/2018/02/powershell-sample-for-privileged
    Write-Host "Loading PIM Subscribed Resources"
    $url = "beta/privilegedAccess/azureResources/resources?`$filter=(type+eq+'subscription')"

    #$response = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method Get

    #$response = Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url -Method Get
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
    Write-Host $url

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

function createTenatBuilderApp() {
    #Check if app exists and return AppId if so
    $existingApp = Get-AzureADApplication -Filter "DisplayName eq 'Tenant Builder PowerShell Script'"

    if ($existingApp) {
        return $existingApp.AppId
    }

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
    $PriviledgedAccessReadWriteAzureAResources = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "a84a9652-ffd3-496e-a991-22ba5529156a","Scope"
    
    $appAccess.ResourceAccess = $UserRead,$EntitlementManagementReadWriteAll,$PriviledgedAccessReadWriteAzureAD,$PriviledgedAccessReadWriteAzureADGroup,$PriviledgedAccessReadWriteAzureAResources
    $appAccess.ResourceAppId = "00000003-0000-0000-c000-000000000000" #Microsoft Graph API

    Set-AzureADApplication -ObjectId $tenantBuilderApp.ObjectId -RequiredResourceAccess $appAcces
    
    addOutEntry -ObjectType "app" -ObjectId $tenantBuilderApp.ObjectId -Name $DepartmentDisplayName
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

#Connect to Graph to enable the Graph Cmdlets
#Connect-Graph

write-host "Connected to Tenant"

#Load the JSON Tenant definition
$organisation = Get-Content -Raw -Path $JSONToLoad | ConvertFrom-Json

#In order to play with the Graph we need an application as the PowerShell well known Id cannot perform some operations
$tenantBuilerAppId = createTenatBuilderApp

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


if ($processEntitlements) {
    loadEntitlementManagement
}

if ($processGroups) {
    loadGroups
}

if ($processPIM) {
    loadPIM
}

#ListResources#

#ListRoles("209b9ca1-4809-4907-a4a6-f2cec5a24459")


Get-AzCachedAccessToken

$DebugPreference = "SilentlyContinue"

#$context = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
#$token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $dexResourceUrl).AccessToken


#$headers = @{
#	Accept = "application/json"
#	Authorization = "Bearer $token"
#	Host = $dexResourceHost
#}

#https://docs.microsoft.com/en-us/powershell/module/az.resources/invoke-azresourceaction?view=azps-4.1.0 
#Invoke-azResourceAction
#Invoke-RestMethod -Method Post -Uri "$dexResourceUrl/v1/rest/mgmt" -Body (ConvertTo-Json $createTableRequestBody) -ContentType "application/json" -Headers $headers >$null


#$TigerOwners = New-AzureADGroup -DisplayName "Tiger Team Owners" -MailEnabled $false -SecurityEnabled $true
#$TigerMembers = New-AzureADGroup -DisplayName "Tiger Team Members" -MailEnabled $false -SecurityEnabled $true
#$JaguarOwners = New-AzureADGroup -DisplayName "Jaguar Team Owners" -MailEnabled $false -SecurityEnabled $true
#$JaguarMembers = New-AzureADGroup -DisplayName "Jaguar Team Members" -MailEnabled $false -SecurityEnabled $true

#$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
#$PasswordProfile.Password = "WelcomeToTheNumber1Team!"



#$data.Where({$_.FirstName -eq 'Kevin'})
#$data | Where-Object {$_.FirstName -eq 'Kevin'}

#az ad user create --display-name "Anvi Rao" --password "WelcomeToTheNumber1Team!" --user-principal-name "mateo.garcia@egunicorn.co.uk" -PasswordProfile $PasswordProfile -AccountEnabled $true 
                  