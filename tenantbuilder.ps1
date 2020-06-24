[CmdletBinding()]
param(
    [bool]$ProcessAll=$false,
    [string]$ProcessOnly="",
    [string]$OrganisationFile=".\organisation.json",
    [int]$logLevel=2
)

$processDepartments = $false
$processApplications = $false
$processCustomRoles = $false
$processGroups = $false
$processEntitlements = $false
$processPIM = $false
$processBearer = $false
$processAdministrativeUnits = $false
$bUsersCreated = $false

if ($ProcessAll) {
    $processDepartments = $true
    $processApplications = $true
    $processCustomRoles = $true
    $processGroups = $true
    $processEntitlements = $true
    $processPIM = $true
    $processAdministrativeUnits = $true
} else {
    if ($ProcessOnly -eq "") {
        Write-Host "You must supply either ProcessAll=true or a comma seperated list of areas to process - Departments, Applications, CustomRoles, Groups, Entitlements, PIM,AdministrativeUnits"
        Exit
    } else {
        $processThese = $ProcessOnly.Split(",")
        foreach($processThis in $processThese) {
            switch ($processThis) {
                "Departments" { $processDepartments = $true; break }
                "Applications" { $processApplications = $true; break }
                "CustomRoles" { $processCustomRoles = $true; break }
                "Groups" { $processGroups = $true; break }
                "Entitlements" { $processEntitlements = $true; break }
                "PIM" { $processPIM = $true; break }
                "AdministrativeUnits" { $processAdministrativeUnits = $true; break }
                "Bearer" {$processBearer = $true; break}
                Default {}
            }
        }
    }
}

if ($logLevel -gt 1) {
    $InformationPreference = "Continue"
} else {
    $InformationPreference = "SilentlyContinue"
}

if ($logLevel -gt 2) {
    $DebugPreference = "Continue"
} else {
    $DebugPreference = "SilentlyContinue"
}

#TO FIX SHAREPOINT SITES!
#TODO Conditional Access Policies
#TODO Add JSON as script parameter
#TODO Add Breakglass accounts with alerts for logons
#TODO for all items check if exist if then get ids and carry on rather than erroring and failing to pass info
#TODO Check reponse codes to make sure they are 200s
#TODO External users https://docs.microsoft.com/en-us/graph/api/resources/invitation?view=graph-rest-beta, https://docs.microsoft.com/en-us/azure/active-directory/b2b/code-samples?view=azureadps-2.0#powershell-example
#TODO Administrative units - use Powershell.  Include ability to have scoped roles and define admin
#TODO Terms of use?
#Cload App Security integration for alerts
#$DebugPreference = "Continue"

function initOutputFile() {
    #ToDo need to think about asking people if they want re-initilise this file.  Decided to just keep appending for now so we can clear up across runs.
    Add-Content -Path $OutputObjectFile -Value "ObjectType,ObjectId,Name"
}

function addOutEntry($ObjectType, $ObjectId, $Name) {
    $outEntry = "$($ObjectType),$($ObjectId),$($Name)"
    Add-Content -Path $OutputObjectFile -Value $outEntry 
}

function log($message, $level) {
    $message = (Get-Date).ToString() + ": " + $message

    switch($level) {
        "debug" {
            Write-Debug -Message $message
            if ($logLevel -gt 2) {
                Add-Content -Path $outputLogFile -Value $message
            }
            break
        }
        "info" {
            Write-Information -Message $message
            $message = "info: " + $message
            if ($logLevel -gt 1) {
                Add-Content -Path $outputLogFile -Value $message
            }
            break
        }
        "warn" {
            Write-Warning -Message $message
            $message = "warn: " + $message
            Add-Content -Path $outputLogFile -Value $message
            break
        }
        "error" {
            Write-Error -Message $message
            $message = "error: " + $message
            Add-Content -Path $outputLogFile -Value $message
            break
        }
        default {
            break
        }
    }
}

function addNewUser($User) {
    
    try {
        if ($User.GivenName -and $User.Surname) {
            log -message "Modeling AD User for $($User.GivenName) $($User.Surname)" -level "debug"
        }
        else {
            throw "User records must have a GivenName and Surname configured"
        }

        $UserDisplayName = $User.GivenName + " " + $User.Surname
        

        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        $PasswordProfile.EnforceChangePasswordPolicy = $true
        $PasswordProfile.Password = $NewUserPassword

        $mailNickName = $User.GivenName.ToLower() + $User.Surname.ToLower()
        $upn = $User.GivenName.ToLower() + "." + $User.Surname.ToLower() + $organisation.upnSuffix
        $User | add-member -Name "UPN" -value $upn -MemberType NoteProperty

        if (!$User.UsageLocation) {
            $User | add-member -Name "UsageLocation" -value "GB" -MemberType NoteProperty
        }

        if (!$User.LicenceSKU) {
            $User | add-member -Name "LicenceSKU" -value "DEVELOPERPACK_E5" -MemberType NoteProperty
        }

        $UserGUID = ""

        $existingUser = Get-AzureADUser -SearchString $User.UPN

        if ($existingUser) {
            log -message "UPN $($User.UPN) already exists in directory, user skipped - no changes have been made for this user object.  N.B. Manager & licence information may still change" -level "Warn"
            $UserGUID = $existingUser
            $User | add-member -Name "GUID" -Value $UserGUID.ObjectId -Type NoteProperty
            #$User = $existingUser
        } else {
            $UserGUID = New-AzureAdUser -AccountEnabled $true -userPrincipalName $User.UPN -Department $User.Department -DisplayName $UserDisplayName -GivenName $User.GivenName -Surname $User.Surname -JobTitle $User.Title -MailNickname $mailNickName -PasswordProfile $PasswordProfile -UsageLocation $User.UsageLocation
            log -message "Created AD User for $($UserDisplayName)" -level "debug"
            $User | add-member -Name "GUID" -Value $UserGUID.ObjectId -Type NoteProperty
            $bUsersCreated = $true
        }
        

        #SkuPartNumber DEVELOPERPACK_E5
        #$UserGUID = New-GUID

        addOutEntry -ObjectType "user" -ObjectId $User.GUID -Name $UserDisplayName

        if ($User.ManagedBy -ne "") {
            if (!$User.ManagerGUID) {
                $ManagerGUID = getManagerGUID($User)
                if (!$ManagerGUID) {
                    $User | Add-Member -Name "ManagerGUID" -Value $ManagerGUID -MemberType NoteProperty -Force
                } else {
                    Throw "Unable to identify manager GUID for $($UserDisplayName) manager: $($User.ManagedBy)"
                }
            }
            
            #write-host "User: $($User)"
            log -Message "Setting Manager for $($UserDisplayName)  UserGUID:$($UserGUID.GUID) manager guid:$($User.ManagerGUID)" -level "Info"
            $SetMgr = Set-AzureADUserManager -ObjectId $User.GUID -RefObjectId $User.ManagerGUID
            log -Message "Manager set $($UserDisplayName)  UserGUID:$($User.GUID) manager guid:$($User.ManagerGUID)" -level "Debug"
            #write-host "ManagerGUID:" + $User.ManagerGUID
        }
        
        if ($User.IsManager) {
            #Each Manager gets a dynamic group that contains their direct reports
            $MembershipRule = "Direct Reports for ""$($User.GUID)"""
            $RuleDisplayName = "$($UserDisplayName) Directs"
            $RuleDescription = "Direct Reports for $($UserDisplayName)"

            $existingGroup = get-azureadmsgroup -SearchString $RuleDisplayName

            if ($existingGroup) {
                log -message "Directs Group $($RuleDisplayName) already exists in directory, group skipped - no changes have been made for this object" -level "Warn"
            } else {
                $DirectsGroup = New-AzureADMSGroup -DisplayName $RuleDisplayName -Description $RuleDescription -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule $MembershipRule -MembershipRuleProcessingState "On"
                addOutEntry -ObjectType "group" -ObjectId $DirectsGroup.Id -Name $RuleDisplayName
                log -message "Direct Reports Group for $($UserDisplayName) created" -level "info"
            }
            
        }

        # Create the objects we'll need to add and remove licenses
        $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
        $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses

        if (!$User.LicenceSKU) {
            $User | add-member -Name "LicenceSKU" -value $UserLicenceSKU -MemberType NoteProperty
        
        }
        # Find the SkuID of the license we want to add

        $license.SkuId = (Get-AzureADSubscribedSku | Where-Object {$_.SkuPartNumber -eq $User.LicenceSKU}).SkuID
        if (!$license.SkuId) {
            Throw "Unable to locate licence SKU: $($User.LicenceSKU) - is it valid?"
        }
        # Set the Office license as the license we want to add in the $licenses object
        $licenses.AddLicenses = $license

        # Call the Set-AzureADUserLicense cmdlet to set the license.
        $licenceAssignment = Set-AzureADUserLicense -ObjectId $User.UPN -AssignedLicenses $licenses
        log -message "User $($UserDisplayName) processed" -level "info"
    } catch {
        $message = "Unable to add user $($UserDisplayName) to AD.  Exception: $_"
        log -message $message -level "error"
        exit
    }
}

function loadGroups() {
    Foreach($group in $organisation.groups) {
        try {

            if (!$group.Name -or $group.Name -eq "" -or $group.description -eq "" -or !$group.description) {
                try {
                    $group | add-member -Name "Name" -value "NOT SET" -MemberType NoteProperty
                } catch {}
                log -message "Group name & Description must be set" -level "Error"
                Throw "Group name & Description must be set"
            }

            $existingGroup = Get-AzureADGroup -SearchString "$($group.name)"

            if ($existingGroup) {
                log -message "Group $($group.name) already exists, skipping" -level "Warn"
            } else {
                $grp = New-AzureADMSGroup -DisplayName $group.name -Description $group.description -MailEnabled $False -MailNickName "group" -SecurityEnabled $True
                addOutEntry -ObjectType "group" -objectId $grp.Id -Name $group.name
                log -message "Group $($group.name) created" -level "Info"
 
                ForEach($role in $group.AssignRoles) {
                    #$roleDef = Get-AzRoleDefinition -Name $role
                
                    $retryCount = 1
                    do {
                        try {
                            $roleAssignment = New-AzRoleAssignment -ObjectId $grp.Id -RoleDefinitionName $role -ErrorAction Stop
                            $roleAssigned = $true
                            log -message "Group $($grp.name) assigned to role $($role)" -level "Info"
                        }
                        catch {
                            log -message "Failed to assign group $($grp.name) to $($role) retrying in 10 seconds ($retryCount of 5)" -level "Warn"
                            Start-Sleep -s 10
                            $retryCount ++
                        }            
                    }   until ($retryCount -gt 5 -or $roleAssigned)
                
                    if ($retryCount -gt 5) {
                        log -message "Unable to assign $($grp.Name) to role $($role)" -level "Error"
                    }
                }

                ForEach($member in $group.members) {
                    $user = Get-AzureADUser -ObjectId $member
                    if ($user) {
                        $addMember = Add-AzureADGroupMember -ObjectId $grp.Id -RefObjectId $user.ObjectId
                    } else {
                        log -message "User $($member) not found in the directory unable to add to $($grp.name)" -level "Error"
                    }
                }
            }
        } catch {
            $message = "Unable to add group $($group.Name) to AD.  Exception: $_"
            log -message $message -level "error"
            exit
        }
        
    }
}

function getManagerGUID($UserObj) {

    if ($UserObj.ManagedBy -ne "") {
        $UserMgrUPN = $UserObj.ManagedBy + $organisation.upnSuffix
        $MgrObject = $Leadership | Where-Object {$_.upn -eq $UserMgrUPN}
        return $MgrObject.GUID
    } else {
        return ""
    }
}

function loadCustomRoles() {
    Write-Host "Processing Roles..."
    ForEach($role in $organisation.CustomRoles) {
        try {
            if (!$role.Name) {
                $role | Add-Member -Name "Name" -value "NOT SET" -MemberType NoteProperty
                Throw "Custom Role Name is required"
            }

            if (!$role.Actions) {
                Throw "Actions are required for Custom Role creation"
            }
            write-host $role.Name
            $roleExists = Get-AzRoleDefinition -Name $role.Name
            
            if ($roleExists) {
                Write-Host "RoleExists Value" $roleExists.Name " id: " $roleExists.Id
                log -message "Role $($Role.Name) already exists, skipping role" -level "Warn"
            } else {
                #Load a known Role to provide us the skeleton to change
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
                log -message "Finished processing Role $($Role.Name)" -level "Info"
                }
                
        } catch {
            $message = "Unable to add Custom Role $($role.Name) to AD.  Exception: $_"
        log -message $message -level "error"
        exit
        }
        
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
        try {
            if (!$App.Name) {
                #Set the name property as we ref it in the catch
                $App | add-member -Name "Name" -value "NOT SET" -MemberType NoteProperty
                Throw "Application name is required."
            }

            if (!$App.URI) {
                Throw "Application URI is required."
            }

            if (!$App.ReplyURI) {
                $App | add-member -Name "ReplyURI" -value "https://localhost:1234" -MemberType NoteProperty
            }
            
            $checkForExistingApp = Get-AzureAdApplication -SearchString $App.Name

            if ($checkForExistingApp) {
                log -message "Application $($App.Name) already exists, skipping creation" -level "Warn"
            } 
            else {
                $appRegistration = New-AzureADApplication -DisplayName $App.Name -IdentifierUris $App.URI -ReplyUrls @($App.ReplyURI)
                $eaApp = Get-AzureADApplication -ObjectId $appRegistration.ObjectId
                addOutEntry -ObjectType "app" -ObjectId $appRegistration.ObjectId -Name $appRegistration.DisplayName
                log -message "Application $($App.Name) registered" -level "Info"
        
                #Add a SPN  so we can assign to access package
                $spnDisplayName = $app.DisplayName + " SPN"
                $spn = New-AzureADServicePrincipal -AppId $eaApp.AppId
                addOutEntry -ObjectType "spn" -ObjectId $spn.ObjectId -Name $spnDisplayName
                log -message "Application SPN $($spnDisplayName) created" -level "Info"

                #Loop through and create the roles
                ForEach($role in $App.Role) {
                    $role.Name = $role.Name.Replace(" ", "")
                    $newRole = CreateAppRole -Name $role.Name -Description $role.Description
                    $eaApp.AppRoles.Add($newRole)
                }
    
                #Apply the roles to the application
                Set-AzureADApplication -ObjectId $eaApp.ObjectId -AppRoles $eaApp.AppRoles
                log -message "Application Roles created" -level "Info"
            }
        } catch {
            $message = "Unable to add application $($App.Name).  Exception: $_"
            log -message $message -level "error"
            exit
        }
    }
        
}

function removeApp($AppObjectId) {
    Write-Debug -Message "Removing Application ObjectId: $($AppObjectId)"
    Remove-AzureADApplication -ObjectId $AppObjectId
}

function processDepartment() {
    Write-Host "Processing Departments"
    try {
        ForEach ($Department in $organisation.Department){
            #Each Department gets an "Owner" & "Members" security group
            #*** Should this be removed and if you want them you just define them in the groups? ***
            $DepartmentDisplayName = $Department.Name + " Team Owners"
            $existingDepartmentOwnerGroup = get-azureadmsgroup -SearchString $DepartmentDisplayName

            if ($existingDepartmentOwnerGroup) {
                log -message "Group $($DepartmentDisplayName) already exists, skipping" -level "Warn"
                $Department | add-member -Name "OwnerGroupGUID" -value $OwnerGroup.ObjectId  -MemberType NoteProperty
            } else {
                $OwnerGroup = New-AzureADGroup -DisplayName $DepartmentDisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $DepartmentDisplayName.Replace(" ","-")
                log -message "Added AD Group $($DepartmentDisplayName)" -level "Info"
                $Department | add-member -Name "OwnerGroupGUID" -value $OwnerGroup.ObjectId -MemberType NoteProperty
                addOutEntry -ObjectType "group" -ObjectId $OwnerGroup.ObjectId -Name $DepartmentDisplayName
            }
            
    
            $DepartmentDisplayName = $Department.Name + " Team Members"
            $existingDepartmentMembersGroup = get-azureadmsgroup -SearchString $DepartmentDisplayName
            if ($existingDepartmentOwnerGroup) {
                log -message "Group $($DepartmentDisplayName) already exists, skipping" -level "Warn"
                $Department | add-member -Name "MemberGroupGUID" -value $MemberGroup.ObjectId  -MemberType NoteProperty
            } else {
                $MemberGroup = New-AzureADGroup -DisplayName $DepartmentDisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $DepartmentDisplayName.Replace(" ","-")
                log -message "Added AD Group $($DepartmentDisplayName)" -level "Info"
                $Department | add-member -Name "MemberGroupGUID" -value $MemberGroup.ObjectId  -MemberType NoteProperty
                addOutEntry -ObjectType "group" -ObjectId $MemberGroup.ObjectId -Name $DepartmentDisplayName
            }
            
    
            $Leadership = $Department.Leadership
    
            ForEach ($User in $Leadership){
                $User | add-member -Name "Department" -value $Department.Name -MemberType NoteProperty
                
                if ($User.ManagedBy -ne "") {
                    #$User.ManagedBy
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
    } catch {
        $message = "Unable to add user $($UserDisplayName) to AD.  Exception: $_"
        log -message $message -level "error"
        exit
    }
    
}

function loadEntitlementManagement() {
    #Need to create catalogue and assign items to it
    #Create packages in catalogues consuming assigned resources
    log -message "Processing Entitlemenet Management" -level "Info"

    $EntitlementManagement = $organisation.EntitlementManagement
    
    #TODO AccessCatalog SharePoint
    #Ensure the signed in user has PIM rights (listed as required)
    try {
        $PIMRoleAdmins = Get-AzureADDirectoryRoleMember -ObjectId "083a4064-745c-4d9a-a523-228602931e47"
        $pimRoleAdminRef = $PIMRoleAdmins | Where-Object {$_.UserPrincipalName -eq $accountId}

        if (-not $pimRoleAdminRef) {
            $SignedInUser = Get-AzADUser -UserPrincipalName $accountId
            Add-AzureADDirectoryRoleMember -ObjectId 083a4064-745c-4d9a-a523-228602931e47  -RefObjectId $SignedInUser.Id
            log -message "Logged in user $($accountId) has been added to PIM Administrators" -level "Warn"
        }

        loadEntitlementManagementCatalogues -Catalogues $EntitlementManagement.Catalogues
        loadEntitlementManagementAccessPackages -AccessPackages $EntitlementManagement.AccessPackages

        log -message "Finished processing Entitlement Management" -level "Info"
    } catch {
        $message = "Error processing entitlement management.  Exception: $_"
        log -message $message -level "error"
        exit
    }
}

function loadEntitlementManagementCatalogues($Catalogues) {
    log -message "Processing Catalogs" -level "Info"
    try { 
        $existingCatlogs = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Method "GET" | ConvertFrom-JSON
    
        if (!$existingCatlogs) {
            Throw "Unable to get catalog list."
        }

        $existingCatlogs = $existingCatlogs.value

        ForEach ($catalogue in $Catalogues) {
            if ($catalogue.name -eq "" -or !$catalogue.name) {
                Throw "Catalogue name must be set"
            }

            if (!$catalogue.Description) {
                $catalogue |  Add-Member -MemberType NoteProperty -Name "Description" -Value ""
            }

            $catalog = $existingCatlogs | Where-Object {$_.displayName -eq $catalogue.Name}

            if ($catalog) {
                log -message "Catalog $($catalogue.Name) already exists.  Catalog creation will be skipped.  Resources and packages will still be processed." -level "Warn"
                $catalog = $catalog
            }
            else {
                #Need to go around the houses to check if a boolean exists when using the not logic :)
                if (![bool]($catalogue.PSobject.Properties.name -match "ExternallyAvailable")) {
                    $catalogue |  Add-Member -MemberType NoteProperty -Name "ExternallyAvailable" -Value $false
                }

                #Create the catalogue
                $body = @{
                    displayName = $catalogue.Name
                    description = $catalogue.Description
                    isExternallyVisible = $catalogue.ExternallyAvailable
                } | ConvertTo-JSON
        
                $catalog = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body $body -Method "POST"
                
                log -message "Created catlog $($catalogue.name)" -level "Info"
                addOutEntry -ObjectType "catalogue" -ObjectId $catalog.Id -Name $catalog.Name
            }

            $catalogResources =  invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($catalog.Id)/accessPackageResources" -Method "GET" | ConvertFrom-JSON

            $catalogResources = $catalogResources.Value

            #$groupsToAdd = $catalog.Groups
            ForEach ($group in $catalogue.groups) {

                if ($catalogResources) {
                    $existingGroupResource = $catalogResources | Where-Object {$_.displayName -eq $group.DisplayName}
                    if ($existingGroupResource) {
                        log -message "Group resource $($group.DisplayName) already exists in $($catalog.DisplayName)" -level "Warn"
                        $skipGroup = $true
                    }
                } else {
                    if (!$skipGroup) {
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
                            log -message "Unable to find group $($group) in AD to add to catalogue" -level "Error"
                        }
                    }
                }
            }
            
            ForEach ($app in $catalogue.Applications) {
                if ($catalogResources) {
                    $existingAppResource = $catalogResources | Where-Object {$_.displayName -eq $app}
                    if ($existingAppResource) {
                        log -message "App resource $($app) already exists in $($catalog.DisplayName)" -level "Warn"
                        $skipApp = $true
                    }
                } else {
                    if (!$skipApp) {
                        $app = $app.Replace("'", "''")

                        $appRegistration = Get-AzureADApplication -Filter "DisplayName eq '$($app)'"
        
                        $appSPN = Get-AzureADServicePrincipal -SearchString "$($app)"
        
                        if (!$appSPN -or !$appRegistration) {
                            throw "Unable to find application $($app) to add to catalogue"
                        }
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
                        $catalogapp = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageResourceRequests" -Body $appBody -Method "POST"
                    }
                }
            }
    
            ForEach ($site in $catalogue.Sites) {
                if (!$site.Name -or !$site.Url) {
                    Throw "SharePoint sites require name and Url"
                }

                if ($site.Name -eq "" -or $site.Url -eq "") {
                    Throw "SharePoint sites require name and Url"
                }

                if ($catalogResources) {
                    $existingSiteResource = $catalogResources | Where-Object {$_.displayName -eq $site.Name}
                    if ($existingSiteResource) {
                        log -message "Site resource $($app) already exists in $($catalog.DisplayName)" -level "Warn"
                        $skipSite = $true
                    }
                } else {
                    if (!$skipSite) {
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
        }
    } catch {
        $message = "Unable to complete Entitlement Catalogues.  Exception: $_"
        log -message $message -level "error"
        exit
    }
}

function loadEntitlementManagementAccessPackages($AccessPackages) {

    $catalogs = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body "" -Method "GET" | ConvertFrom-Json

    if (!$catalogs) {
        Throw "Unable to read catalog information"
    }

    $catalogs = $catalogs.value 

    $AccessPackages = $AccessPackages

    $existingAccessPackages = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages" -body "" -method "GET" | ConvertFrom-JSON
    #write-host "Existing packages: $($existingAccessPackages)"
    #write-host "pgs val: $($existingAccessPackages.value)"
    #write-host "val:$($existingAccessPackages.value)"

    #foreach($x in $existingAccessPackages.value) {
    #    write-host $x
    #}

    $existingAccessPackages = $existingAccessPackages.value

    ForEach($accessPkg in $AccessPackages) {
        #Need to first create access package
        #Then add a scope request to entry in the catalogue https://docs.microsoft.com/en-us/graph/api/accesspackage-post-accesspackageresourcerolescopes?view=graph-rest-beta&tabs=http
       
        if (!$accessPkg.Name -or !$accessPkg.Catalogue -or !$accessPkg.Description) {
            Throw "Acesss Package must have Catalogue, Name and Description supplied"
        }

        if ($accessPkg.Name -eq "" -or $accessPkg.Catalogue -eq "" -or $accessPkg.Description -eq "") {
            Throw "Acesss Package must have Catalogue, Name and Description supplied"
        }

        $catalog = $catalogs | Where-Object {$_.displayName -eq "$($accessPkg.Catalogue)"}

        if (!$catalog) {
            Throw "Unable to locate $($accessPkg.Catalogue)"
        }

        $pkgBody = @{
            catalogId = "$($catalog.Id)"
            displayName = "$($accessPkg.Name)"
            description = "$($accessPkg.description)"
        } | ConvertTo-Json

        $bSkipAccessPackage = $false

        if ($existingAccessPackages) {
            $existingPackage = $existingAccessPackages | Where-Object {$_.displayName -eq $accessPkg.Name -and $_.catalogId -eq $catalog.Id}

            if ($existingPackage) {
                log -message "Access package $($accessPkg.Name) already exists in catalog $($catalog.DisplayName), skipping" -level "Warn"
                $bSkipAccessPackage = $true
            }
        }   
        
        if (!$bSkipAccessPackage) {
            $accessPkgResponse = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages" -Body $pkgBody -Method "POST"
            log -message "Access Package $($accessPkg.Name) added to catalog $($catalog.DisplayName)" -level "Info"
            addOutEntry -ObjectType "accesspackage" -objectId $accessPkgResponse.id -Name $accessPkg.Name
            #for fuller policy example look here https://docs.microsoft.com/en-us/graph/api/accesspackageassignmentpolicy-post?view=graph-rest-beta&tabs=http

            #Add in the id of the newly created package
            $accessPkg | Add-Member -MemberType NoteProperty -Name "id" -Value $accessPkgResponse.id        
            #Get a list of resources in the catalog
            $catalogResources = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($catalog.Id)/accessPackageResources" -Body "" -Method "GET" | ConvertFrom-Json

            if (!$catalogResources) {
                Throw "No resources found for catalog $($Catalog.Name)"
            }

            $catalogResources = $catalogResources.value

            Foreach($pkgGroup in $accessPkg.Groups) {
                if (!$pkgGroup.Name -or !$pkgGroup.Role) {
                    Throw "Access Pakcage Groups must have Name and Role supplied"
                }

                if ($pkgGroup.Name -eq "" -or $pkgGroup.Role -eq "") {
                    Throw "Access Pakcage Groups must have Name and Role supplied"
                }

                $groupRole = buildAccessPackageRole -packageName $pkgGroup.Name -packageRole $pkgGroup.Role -resourceType "AadGroup" -catalogId $catalog.Id -catalogResourcesList $catalogResources
                $addGroupResponse = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackages/$($accessPkgResponse.id)/accessPackageResourceRoleScopes" -Body $groupRole -Method "POST"
                log -message "Group: $($pkgGroup.Name) added to Access Package $($accessPkg.Name) for catalog $($catalog.DisplayName)" -level "Info"
            }

            Foreach($pkgApp in $accessPkg.Applications) {
                if (!$pkgApp.Name -or !$pkgApp.Role) {
                    Throw "Access Pakcage Applications must have Name and Role supplied"
                }

                if ($pkgApp.Name -eq "" -or $pkgApp.Role -eq "") {
                    Throw "Access Pakcage Applications must have Name and Role supplied"
                }

                $appRole = buildAccessPackageRole -packageName $pkgApp.Name -packageRole $pkgApp.Role -resourceType "AadApplication" -catalogId $catalog.Id -catalogResourcesList $catalogResources
                $addAppResponse = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackages/$($accessPkgResponse.id)/accessPackageResourceRoleScopes" -Body $appRole -Method "POST"
                log -message "Application: $($pkgApp.Name) added to Access Package $($accessPkg.Name) for catalog $($catalog.DisplayName)" -level "Info"
                #Write-Host "aadAppResponse: " $addAppResponse
            }

            loadAccessEntitlementManagementAccessPackagePolicies -AccessPackage $accessPkg
        }
    }
}


function buildAccessPackageRole($packageName, $packageRole, $resourceType, $catalogId, $catalogResourcesList) {
    #write-host "Package Name: $($packageName), Package Role: $($packageRole), Resource Type: $($resourceType), Cat Id: $($catalogId), Cat Res: $($catalogResourcesList)"
    Try {

    
        if ($packageName -eq "" -or $packageRole -eq "" -or $resourceType -eq "" -or $catalogId -eq "") {
            Throw "buildAcessPackageRole requires valid PackageName, Role, Type, CatalogId and Catalog Resource List"
        }

        if (!$packageName -or !$packageRole -or !$resourceType -or !$catalogId) {
            Throw "buildAcessPackageRole requires valid PackageName, Role, Type, CatalogId and Catalog Resource List"
        }

        if ($catalogResourcesList.DisplayName -eq "" -or $catalogResourcesList.originSystem -eq "") {
            Throw "Catalog Resouurces requires Display Name and Origin System to be configured."
        }

        if (!$catalogResourcesList.DisplayName -or !$catalogResourcesList.originSystem) {
            Throw "Catalog Resouurces requires Display Name and Origin System to be configured."
        }


        $catalogEntry = $catalogResourcesList | Where-Object {$_.DisplayName -eq "$($packageName)" -and $_.originSystem -eq "$($resourceType)"}

        if (!$catalogEntry) {
            Throw "Unable to locate requested AccessPackage $($packageName)"
        }

        $resourceRole = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($catalogId)/accessPackageResourceRoles?`$filter=(originSystem+eq+%27$($resourceType)%27+and+accessPackageResource/id+eq+%27$($catalogEntry.Id)%27)&`$expand=accessPackageResource" -body "" -Method "GET" | ConvertFrom-JSON

        if (!$resourceRole) {
            Throw "Unable to load requested Resource Roles for $($packageName)"
        }

        $resourceRole = $resourceRole.value

        #When loading the roles Graph strips the spaces so remove the spaces from the role name to locate it
        $packagerole = $packageRole.Replace(" ","")
        $resourceRoleToAdd = $resourceRole | Where-Object {$_.DisplayName -eq "$($packageRole)"}

        if (!$resourceRoleToAdd) {
            Throw "Unable to locate requested role - $($packageRole)"
        }

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
    } catch {
        $message = "Unable to build access package role.  Exception: $_"
        log -message $message -level "error"
        exit
    }
}

function loadAccessEntitlementManagementAccessPackagePolicies($accessPackage) {
    try {
        if (!$accessPackage -or !$accessPackage.PolicyName) {
            Throw "Valid Access Package Object required"
        }

        
        log -message "Processing Access Policies for Package: $($accessPackage.Name)" -level "Info"
        #Load the access package policy into an object to work on
        $accessPackagePolicy = $organisation.entitlementmanagement.accesspackagepolicies | Where-Object {$_.displayName -eq "$($accessPackage.PolicyName)"}
        
        #Add in the id of the newly created package
        $accessPackagePolicy | Add-Member -MemberType NoteProperty -Name "accessPackageId" -Value $accessPackage.id

        #Populate the GUIDs for the groups and users listed in the policy
        if ($accessPackagePolicy.requestorSettings.allowedRequestors) {
            $accessPackagePolicy.requestorSettings.allowedRequestors = markupoDataEntries -Object $accessPackagePolicy.requestorSettings.allowedRequestors
        }
        
        Foreach($stage in $accessPackagePolicy.requestApprovalSettings.approvalStages) {
            if ($stage.primaryApprovers) {
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
                log -message "Access Review Start Date for package $($accessPackage.DisplayName) had illegal start date (less than today), this has been defaulted to today's date" -level "Warn"
            }
        }
        
        $accessPackagePolicy = $accessPackagePolicy | ConvertTo-Json -Depth 100
        
        $response = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies" -Body $accessPackagePolicy -Method "POST"
        log -message "Added access policy $($accessPackage.PolicyName) to access package $($accessPackage.name)" -level "Info"
    }
    catch {
        $message = "Unable to load access package policies.  Exception: $_"
        log -message $message -level "error"
        exit
    }
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

    try {
        #Ensure the signed in user has PIM rights
        $SignedInUser = Get-AzADUser -UserPrincipalName $accountId

        if (!$organisation.PIM) {
            Throw "No PIM Cofiguration found."
        }
        if (!$SignedInUser) {
            Throw "Unable to retrieve signed in user details"
        }

        $pimRoleAdmins = Get-AzureADDirectoryRoleMember -ObjectId "083a4064-745c-4d9a-a523-228602931e47"
        if (!$pimRoleAdmins) {
            Throw "Unable to load PIM Admin Role Members"
        }
        $pimRoleAdminRef = $pimRoleAdmins | Where-Object {$_.UserPrincipalName -eq $accountId}

        if (-not $pimRoleAdminRef) {
            Add-AzureADDirectoryRoleMember -ObjectId 083a4064-745c-4d9a-a523-228602931e47  -RefObjectId $SignedInUser.Id
            log -message "Added signed in user to PIM Adim Role" -level "Warn"
        }

        
       
        $PIM = $organisation.PIM
        #Get all the Subscriptions enrolled in PIM
        $PIMSubscriptions = ListResources
        $thisSubscription = $PIMSubscriptions | Where-Object {$_.ExternalId -eq "/subscriptions/$($SubscriptionId)"}
        
        if (!$thisSubscription) {     
                if ($PIM.Enrol) {
                    try {
                        $body = @{
                            externalId = "/subscriptions/$($SubscriptionId)"
                        } | ConvertTo-JSON
                        invokeGraphAPI -Call "beta/privilegedAccess/azureResources/resources/register" -Body $body -Method "POST"
                        log -message "Registered subscription $($SubscriptionId) in PIM, pausing for 60 seconds to give discovery a chance.  Note you may need encounter errors and need to run again later if discovery has not completed in time." -level "Info"
                        Start-Sleep -seconds 60
                    }
                    catch {
                        Throw "Unable to register subscription $($SubscriptionId) with PIM"
                    }
                } else {
                    Throw "Subscription is not enrolled in PIM please enrol in PIM either via Portal or via setting Enrol to true"
                }
        } else {
            log -message "Subscription $($SubscriptionId) is enrolled in PIM" -level "Info"
        }

        $PIM = $organisation.PIM
        

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
            if ($Subscription.ExternalId = $SubscriptionId) {
                
                #Get the roles for the subscription
                $roles = ListRoles($Subscription.ResourceId)
                
                if (!$roles) {
                    Throw "No roles discovered for PIM, if PIM is enabled for subscription please try again later"
                }

                ForEach($role in $PIM.Roles) {
                    if (!$role.Name -or !$role.Assignments) {
                        Throw "Role Name and Assisgments are required for PIM"
                    }

                    if ($role.Name -eq "" -or $role.Assignments.Count -eq 0) {
                        Throw "Role Name and Assignments are required for PIM"
                    }

                    $PIMRole = $roles | Where-Object {$_.RoleName -eq $role.Name}

                    if (!$PIMRole) {
                        Throw "Unable to locate $($role.Name) in discovered PIM Roles, please check role name and if PIM is enabled for subscription please try again later"
                    }

                    if ($PIMRole -is [array]) {
                        #This happened in testing where role was created / re-created multiple times...
                        $PIMRole = $PIMRole | Sort-Object -Property id -Descending
                        $PIMRole = $PIMRole[0]
                    }
                    
                    ForEach($assignment in $role.Assignments) {
                        $groupToAdd = get-azureadmsgroup -Filter "DisplayName eq '$($assignment.GroupToAdd)'"

                        if ($groupToAdd -eq $null) {
                            log -message "Failed to find Group:  $($assignment.GroupToAdd)" -level "Error"
                            exit
                        }
                        
                        $existingAssignment = invokeGraphAPI -call "beta/privilegedAccess/azureResources/roleAssignments?`$filter=(resourceId+eq+'$($Subscription.ResourceId)'+and+subjectId+eq+'$($groupToAdd.Id)')" -body "" -Method "GET" | ConvertFrom-JSON

                        $existingAssignment = $existingAssignment.value

                        if (!$existingAssignment) {
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
                            $response = invokeGraphAPI -Call "beta/privilegedAccess/azureResources/roleAssignmentRequests" -Body $body -Method "POST"  
                            log -message "Requested assignment for resourceId $($Subscription.ResourceId) and subjectId $($groupToAdd.Id)" -level "Info"
                            addOutEntry -ObjectType "pim" -ObjectId $response.id -Name ""
                        } else {
                            log -message "Requested assignment for resourceId $($Subscription.ResourceId) and subjectId $($groupToAdd.Id) already exists, skipping" -level "Warn"
                        }
                        
                    }   
                }
            } else {
                log -message "Subscription $($Subscription.ExternalId) was found enrolled in PIM but this script context is for SubscriptionId : $($SubscriptionId)" -level "Warn"
            }
        }
    }
    catch {
        $message = "Error processing PIM details.  Exception: $_"
        log -message $message -level "error"
        exit
    }
}
function ListResources(){
    #http://www.anujchaudhary.com/2018/02/powershell-sample-for-privileged
    
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

function loadAdministrativeUnits{
    log -message "Processing Administrative Units" -level "Info"
    try {
        $AUs = $organisation.AdministrativeUnit
        
        if ($AUs) {
            ForEach ($AU in $AUs) {
                if (!$AU.Name -or !$AU.Description) {
                    Throw "Name & Description required for each Administrative Unit to configure"
                }

                if ($AU.Name -eq "" -or $AU.Description -eq "") {
                    Throw "Name & Description required for each Administrative Unit to configure"
                }

                $existingAU = get-AzureADAdministrativeUnit -Filter "displayName eq '$($AU.Name)'"
                $AUObjectId = ""
                if ($existingAU) {
                    log -message "Administrative Unit $($AU.Name) already exists, skipping creation" -level "Warn"
                    $AUObjectId = $existingAU.ObjectId
                } else {
                    $NewAU = New-AzureADAdministrativeUnit -DisplayName $AU.Name -Description $AU.Description
                    addOutEntry -ObjectType "au" -ObjectId $AU.ObjectId -Name $AU.Name
                    $AUObjectId = $NewAU.ObjectId
                    log -message "Administrative Unit $($AU.Name) created" -level "Info"
                }

                #$UserMembership
                $AUMembership = Get-AzureADAdministrativeUnitMember -ObjectId $AUObjectId
                
                ForEach ($User in $AU.Users) {
                    try {
                        $UserObject = Get-AzureADUser -SearchString $User
                        if (!$UserObject) {
                            Throw "User $($User) not found"
                        }
                        try {
                            $Membership = $AUMembership | Where-Object {$_.ObjectId -eq $UserObject.ObjectId}
                        } catch {}

                        if (!$Membership) {
                            $AddMember = Add-AzureADAdministrativeUnitMember -ObjectId $AUObjectId -RefObjectId $UserObject.ObjectId
                            log -message "User $($User) added to Administrative Unit $($AU.Name)" -level "Info"
                            addOutEntry -ObjectType "AUMember" -ObjectId $AddMember.ObjectId -Name ""
                        } else {
                            log -message "User $($User) is already a member of Administrative Unit $($AU.Name), skipping" -level "Warn"
                        }
                    } catch {
                        log -message "User: $($User) not found, unable to add to Administrative Unit $($AU.Name)" -level "Warn"
                    }                   
                }

                ForEach ($Group in $AU.Groups) {
                    try {
                        $GroupObject = Get-AzureADGroup -SearchString $Group

                        if (!$GroupObject) {
                            Throw "Group $($Group) not found"
                        }
                        try {
                            $GroupMembership = $AUMembership | Where-Object {$_.ObjectId -eq $GroupObject.ObjectId}
                        } catch {}
                        
                        if (!$GroupMembership) {
                            $AddMember = Add-AzureADAdministrativeUnitMember -ObjectId $AUObjectId -RefObjectId $GroupObject.ObjectId
                            log -message "Group $($Group) added to Administrative Unit $($AU.Name)" -level "Info"
                            addOutEntry -ObjectType "AUMember" -ObjectId $AddMember.ObjectId -Name ""
                        } else {
                            log -message "Group $($Group) is already a member of Administrative Unit $($AU.Name), skipping" -level "Warn"
                        }
                    } catch {
                        log -message "Group: $($Group) not found unable to add to Administrative Unit $($AU.Name)" -level "Warn"
                    }                   
                }

                ForEach ($role in $AU.Roles) {
                    if (!$role.Role -or !$role.Users) {
                        Throw "Roles for Administrative units need a role name and users supplied"
                    }
                    
                    checkAzureADRoleEnabled($role.role)
                    $roleDef = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq $role.Role}
                    
                    $bSkip = $false
                    if (!$roleDef) {
                        log -message "Unable to find requested role: $($role.Role) for Administrative Unit: $($AU.Name), skipping" -level "Warn"
                        $bSkip = $true
                    }

                    if (!$bSkip) {
                        ForEach($User in $role.Users) {
                            $Userobject = Get-AzureADUser -SearchString $User
                            if (!$UserObject) {
                                AUObjectId
                                $RoleMember = New-Object -TypeName Microsoft.Open.AzureAD.Model.RoleMemberInfo
                                $RoleMember.ObjectId = $UserObject.ObjectID
                                $NewMembership = Add-AzureADScopedRoleMembership -ObjectId $AUObjectId -RoleObjectId $roleDef.ObjectId -RoleMemberInfo $RoleMember
                                addOutEntry -ObjectType "aurole" -ObjectId $NewMembership.AdministrativeUnitObjectId + "," + $NewMembership.RoleObjectId -Name ""
                                log -message "User $($User) added to role $(role.role) for Administrative Unit $($AU.Name)" -level "Info"
                            }
                        }
                    }
                }
            }
        } else {
            log -message "No Administrative Units found to configure" -level "Info"
        }
    } catch {
        $message = "Error processing Administrative Units details.  Exception: $_"
        log -message $message -level "error"
        exit
    }
    
}

function checkAzureADRoleEnabled($role) {
    try {
        $roleEnabled = Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq $role}

        if (!$roleEnabled) {
            $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object {$_.DisplayName -eq $role}

            if ($roleTemplate) {
                $EnabledRole = Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
                log -message "Role $($role) enabled in AD.  New Role Id: $($EnabledRole.ObjectId)" -level "Warn"
            } else {
                Throw "Unable to find a template for role $($role) is it valid?"
            }
        } else {
            log -message "Role $($role) already enbaled in AD" -level "Info"
        }
    } catch {
        $message = "Error validating $($role) is enabled.  Exception: $_"
        log -message $message -level "error"
        exit
    }
}

function Get-AzCachedAccessToken(){

    
    $clientId = $tenantBuilerAppId

    $redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"

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
    try {
        $existingApp = Get-AzureADApplication -Filter "DisplayName eq 'Tenant Builder PowerShell Script'"

        if ($existingApp) {
            log -message "Tenant Builder PowerShell Script application exists, skipping creation.  Note no changes will be made to app configuration." -level "Warn"
            log -message "Resetting keys for application - existing keys will be removed and a new one added" -level "Warn"
                $KeyIDs = Get-AzureADApplicationPasswordCredential -ObjectId $existingApp.ObjectId
                ForEach ($key in $KeyIDs) {
                    Remove-AzureADApplicationPasswordCredential -ObjectId $existingApp.ObjectId -KeyId $key.KeyId
                }
                
                $pwdCred = New-AzureADApplicationPasswordCredential -ObjectId $existingApp.ObjectId -CustomKeyIdentifier "ScriptProvisioned" -EndDate (Get-Date).AddDays(1) 
                $tenantBuilderAppSecret = $pwdCred.Value
            return $existingApp.AppId
        }
        $redirectURI = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        Write-Host "Tenant Builder App not found.  The script will create an app called Tenant Builder PowerShell Scipt, this is required for interacting with Graph.  You will be prompted to consent to the required permissions.  This is a one-time activity."
        #Create new Public Client App (required for this flow)
        #$tenantBuilderApp = New-AzureADApplication -DisplayName "Tenant Builder PowerShell Script" -ReplyUrls @("https://localhost") -PublicClient $true
        $tenantBuilderApp = New-AzureADApplication -DisplayName "Tenant Builder PowerShell Script" -ReplyUrls @($redirectURI) -PublicClient $true
        log -message "Tenant Builder App created step 1 of 4.." -level "Info"
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
        log -message "Tenant Builder App API permissions configured step 2 of 4.." -level "Info"
        addOutEntry -ObjectType "app" -ObjectId $tenantBuilderApp.ObjectId -Name $DepartmentDisplayName

        $pwdCred = New-AzureADApplicationPasswordCredential -ObjectId $tenantBuilderApp.ObjectId -CustomKeyIdentifier "ScriptProvisioned" -EndDate (Get-Date).AddDays(1) 
        $tenantBuilderAppSecret = $pwdCred.Value
        log -message "Secret assigned to application step 3 of 4." -level "Info"

        #In my testing the consent frequently failed with app not found, pausing seems to fix this *sigh*
        Write-Host "Sleeping for 30s for app registration to complete"
        Start-Sleep -s 30
        log -message "Calling grant screen, script will pause for user input to continue" -level "Info"
        #$proc = Start-Process -FilePath  "https://login.microsoftonline.com/$($tenantId)/oauth2/authorize?client_id=$($tenantBuilderApp.AppId)&response_type=code&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth%2Fnativeclient&response_mode=query&resource=&state=12345&prompt=admin_consent"
        $proc = Start-Process -FilePath  "https://login.microsoftonline.com/$($tenantId)/oauth2/authorize?client_id=$($tenantBuilderApp.AppId)&response_type=code&redirect_uri=$($redirectURI)&response_mode=query&resource=&state=12345&prompt=admin_consent"
        #Wait for Admin consent to be granted so that the Graph related stuff can work
        read-host "Please consent to application, once you have logged in and granted consent you will be redirected to a blank page you can close that. Press ENTER to continue..."
        log -message "Tenant Builder App administrator consent completed step 4 of 4.." -level "Info"
        return $tenantBuilderApp.AppId
    } catch {
        $message = "Unable to create Tenant Builder PowerShell App.  Exception: $_"
        log -message $message -level "error"
        exit
    }
    
}

#https://stackoverflow.com/questions/28740320/how-do-i-check-if-a-powershell-module-is-installed
# See https://www.powershellgallery.com/ for module and version info
Function Install-ModuleIfNotInstalled(
    [string] [Parameter(Mandatory = $true)] $moduleName,
    [string] $minimalVersion
) {
    $module = Get-Module -Name $moduleName -ListAvailable |`
        Where-Object { $null -eq $minimalVersion -or $minimalVersion -ge $_.Version } |`
        Select-Object -Last 1
    if ($null -ne $module) {
         Write-Verbose ('Module {0} (v{1}) is available.' -f $moduleName, $module.Version)
    }
    else {
        Import-Module -Name 'PowershellGet'
        $installedModule = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue
        if ($null -ne $installedModule) {
            Write-Verbose ('Module [{0}] (v {1}) is installed.' -f $moduleName, $installedModule.Version)
        }
        if ($null -eq $installedModule -or ($null -ne $minimalVersion -and $installedModule.Version -lt $minimalVersion)) {
            Write-Verbose ('Module {0} min.vers {1}: not installed; check if nuget v2.8.5.201 or later is installed.' -f $moduleName, $minimalVersion)
            #First check if package provider NuGet is installed. Incase an older version is installed the required version is installed explicitly
            if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201') {
                Write-Warning ('Module {0} min.vers {1}: Install nuget!' -f $moduleName, $minimalVersion)
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }        
            $optionalArgs = New-Object -TypeName Hashtable
            if ($null -ne $minimalVersion) {
                $optionalArgs['RequiredVersion'] = $minimalVersion
            }  
            Write-Warning ('Install module {0} (version [{1}]) within scope of the current user.' -f $moduleName, $minimalVersion)
            Install-Module -Name $moduleName @optionalArgs -Scope CurrentUser -Force -Verbose
        } 
    }
}


try {
    Write-Host "Importing modules..."
    Install-ModuleIfNotInstalled -moduleName "AzureADPreview" -minimalVersion "2.0.2.102"
    #Install-ModuleIfNotInstalled -moduleName "Az" -minimalVersion "4.2.0"
    Install-ModuleIfNotInstalled -moduleName "Az.Resources" -minimalVersion "2.1.0"
    Install-ModuleIfNotInstalled -moduleName "Az.Accounts" -minimalVersion "1.8.1"
    Write-Host "Modules loaded"
} catch {
    Throw "Unable to load required modules"
}
#Import-Module -Name AzureADPreview -MinimumVersion 2.0.2.102

#Import-Module -Name Az -MinimumVersion 4.2.0

#Import-Module -Name Microsoft.graph
Add-Type -AssemblyName System.Web

#$logLevel = 3 #1 = Warn, 2= Info 3 = Debug



$outputLogFile = ".\log.txt"
$OutputObjectFile = ".\objects.csv"
$UserLicenceSKU = "DEVELOPERPACK_E5"
$NewUserPassword = ([System.Web.Security.Membership]::GeneratePassword(12,2))
$tenantBuilderAppSecret = ""
log -message "Script Starting" -level "Info"
#Connect to Azure to enable AZ cmdlets and set up globals
Write-Host "Requesting Login to Azure"
$connectAz = Connect-AzAccount
#Set up some globals
$currentAzureContext = Get-AzContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
$SubscriptionId = $currentAzureContext.Subscription.Id


#Connect to AzureAD to enable the AzureAD Cmdlets
$connectAd = Connect-AzureAD -TenantId $tenantId -AccountId $accountId
$tenantDetail = Get-AzureADTenantDetail
#Connect to Graph to enable the Graph Cmdlets
#Connect-Graph

log -message "Connected to Tenant" -level "Info"

#Load the JSON Tenant definition
if (Test-Path -Path $OrganisationFile) {
    try {
        $organisation = Get-Content -Raw -Path $OrganisationFile | ConvertFrom-Json
        log -message "Loaded Organisation from $($OrganisationFile)" -level "Info"
    } catch {
        $message = "Unable to load JSON file $($OrganisationFile), is it valid? Exception: $_"
        log -message $message -level "error"
        exit
    }
} else {
    log -message "Orginisation file: $($OrganisationFile) not found, please supply a valid path" -level "Error"
    Exit
}
#Initialise what is in effect the state file
if (!(Test-Path -Path $OutputObjectFile)) {
    initOutputFile
}

#In order to play with the Graph we need an application as the PowerShell well known Id cannot perform some operations
$tenantBuilerAppId = createTenantBuilderApp

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

if ($processAdministrativeUnits) {
    loadAdministrativeUnits
}

if ($processBearer) {
    Get-AzCachedAccessToken
}

if ($bUsersCreated) {
    Write-Host "Password for any new users created (note this is not stored or logged): $($NewUserPassword)"
}

log -message "Script Complete" -level "Info"


$DebugPreference = "SilentlyContinue"
