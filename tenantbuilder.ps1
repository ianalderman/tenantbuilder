
$DebugPreference = "Continue"

#Import-Module -Name AzureADPreview
#Import-Module -Name Az
#Import-Module -Name Microsoft.graph

$processDepartments = $false
$processApplications = $false
$processCustomRoles = $false
$processEntitlements = $false
$createTenantBuilderApp = $true #Required for Entitlements

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
            $customRole.AssignableScopes.Add($scope)
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

        $appRegistration = New-AzureADApplication -DisplayName $App.Name -IdentifierUris $App.URI -GroupMembershipClaims "" -ReplyUrls @($ReplyURI)
        #$appRegistration = New-AzureRmADApplication -DisplayName $App.Name -IdentifierUris $App.URI
        $eaApp= Get-AzureADApplication -ObjectId $appRegistration.ObjectId
        addOutEntry -ObjectType "app" -ObjectId $appRegistration.ObjectId -Name $appRegistration.DisplayName

        ForEach($role in $App.Role) {
            $role.Name = $role.Name.Replace(" ", "")
            $newRole = CreateAppRole -Name $role.Name -Description $role.Description
            $eaApp.AppRoles.Add($newRole)
        }

        #$appRegistration
        #Apply the roles to the application
        Set-AzureADApplication -ObjectId $eaApp.ObjectId -AppRoles $eaApp.AppRoles

        #Add a SPN to make it the application an Enterprise Application so we can assign to access package
        $spnDisplayName = $app.DisplayName + " SPN"
        $spn = New-AzureADServicePrincipal -AppId $eaApp.AppId
        addOutEntry -ObjectType"spn" -ObjectId $spn.ObjectId -Name $spnDisplayName
    }

    # ObjectId for application from App Registrations in your AzureAD
    #$app = New-AzureADApplication -DisplayName "My Test App"
    
    #$appObjectId = "<Your Application Object Id>"
    #$app = Get-AzureADApplication -ObjectId $appObjectId
    #$appRoles = $app.AppRoles
    #Write-Host "App Roles before addition of new role.."
    #Write-Host $appRoles

    #$newRole = CreateAppRole -Name "MyNewApplicationRole" -Description "This is my new Application Role"
    #$app.AppRoles.Add($newRole)
    #$newRole = CreateAppRole -Name "MyNewApplicationRole2" -Description "This is another new Application Role"
    #$app.AppRoles.Add($newRole)

    #Set-AzureADApplication -ObjectId $app.ObjectId -AppRoles $app.AppRoles

    #$spnDisplayName = $app.DisplayName + " SPN"
    #$spn = New-AzureADServicePrincipal -AppId $app.AppId
    #addOutEntry("spn", $spn.ObjectId, $spnDisplayName)
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

# ----------------- Az module compatible below from https://www.codeisahighway.com/how-to-easily-and-silently-obtain-accesstoken-bearer-from-an-existing-azure-powershell-session/

function Get-AzCachedAccessToken()
{
    $ErrorActionPreference = 'Stop'
  
    if(-not (Get-Module Az.Accounts)) {
        Import-Module Az.Accounts
    }
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if(-not $azProfile.Accounts.Count) {
        Write-Error "Ensure you have logged in before calling this function."    
    }
  




    $context = Get-AzContext

    #$appId = '53316905-a6e5-46ed-b0c9-524a2379579e'
    $appId = "1950a258-227b-4e31-a9cf-717495945fc2"
    $redirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    $graphScopes = 'user.read'
    $logonEndpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0'

    $authContext = [Microsoft.Identity.Client.PublicClientApplication]::new($appId, $logonEndpoint, $null)

    $asyncResult = $authContext.AcquireTokenAsync([System.Collections.Generic.List[string]] $graphScopes)
    $token = $asyncResult.Result
    Write-host "Token: " $token
    return $token

    #$clientId = "1950a258-227b-4e31-a9cf-717495945fc2" #PowerShell well-known clientId
    #$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    #https://login.microsoftonline.com/$TenantName
    #$authorityUri = "https://login.microsoftonline.com/$context.Tenant.Id"
    #$authorityUri = "https://login.microsoftonline.com/$context.Tenant.Id/oauth2/v2.0/token"
    #$Instance = "https://login.microsoftonline.com/{0}";
    #$authority = string.Format(CultureInfo.InvariantCulture, $Instance, $context.Tenant.Id);
    #$authorityUri= "https://login.windows.net/$context.Tenant.Id"
    #$authorityUri= "$($context.Environment.ActiveDirectoryAuthority)/$context.Tenant.Id"
    #$ApiEndpointUri = "https://graph.microsoft.com"
    #*?Is client assertion the powershell clientid and the existing token?
    #*Also AcquireTokenAsync(String, String, Uri, IPlatformParameters, UserIdentifier)

    #$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authorityUri

    #$promptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    #$authParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $promptBehaviour
    #$UserId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $context.Account, 2
    #$authResult = $authContext.AcquireTokenSilentAsync($ApiEndpointUri, $clientId,$redirectUri, "Auto").GetAwaiter().GetResult()
    #$authResult = $authContext.AcquireTokenAsync($ApiEndpointUri,  $clientId, $redirectUri, $authParam, $UserId).GetAwaiter().GetResult()

    #write-host "AuthResult: " $authResult
    #write-host "Token: " $authResult.AccessToken
    #return $authResult.AccessToken
    #$currentAzureContext = Get-AzContext
    #$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    #https://github.com/Azure/azure-powershell/issues/2494
    #$context = Get-AzContext
    #$cache = $context.TokenCache
    #$cacheItem = $cache.ReadItems()

    #$token = ($cacheItem | where { $_.Resource -eq "https://graph.windows.net/" }).accessToken
    #if ($token.ExpiresOn -le [System.DateTime]::UtcNow) {
    #    $ac = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new("$($context.Environment.ActiveDirectoryAuthority)$($context.Tenant.Id)",$token)
    #    $token = $ac.AcquireTokenByRefreshToken($token.RefreshToken, "1950a258-227b-4e31-a9cf-717495945fc2", "https://graph.windows.net")
    #}

    #Write-Host "Graph token: " $token
    #return $token
    

    

    
    #https://stackoverflow.com/questions/50572810/authenticate-to-microsoft-graph-api-using-powershell

    #$authority = "https://login.microsoftonline.com/$TenantName"

    #$clientId = "00d16af4-d0c7-460a-a9dc-fd350eb4b100" 
    #$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    #$resourceAppIdURI = "https://graph.microsoft.com"
    #$authority = "https://login.microsoftonline.com/$TenantName"
    #$authority = "https://login.microsoftonline.com/$currentAzureContext.Tenant.TenantId"
    #$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    #$promptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    #$authParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $promptBehaviour
    #$authenticationTask = $authContext.AcquireTokenASync($resourceAppIdURI, $clientId,$redirectUri,$authParam)
    #$token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
    #$authenticationTask = $authContext.AcquireTokenAsync($resourceAppIdURI, "ija@egunicorn.co.uk", $token.AccessToken)
    #$authenticationTask.Wait()
    #$authenticationResult = $authenticationTask.Result
    #$authenticationResult
    #return $authenticationResult.AccessToken

    #$authority = "https://login.microsoftonline.com/$currentAzureContext.Tenant.TenantId"
    #$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    #$resourceAppIdURI = "https://graph.microsoft.com"
    #Write-Debug ("Getting access token for tenant " + $currentAzureContext.Subscription.TenantId)
    #$token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    #Write-Debug ("Access token: " + $token.AccessToken)
    #Write-Host "Getting graph token"

    #$authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, "ija@egunicorn.co.uk", $token.AccessToken).GetAwaiter().GetResult()

    #$authResult
    #return $authResult.AccessToken
}

function Get-AzBearerToken()
{
    $ErrorActionPreference = 'Stop'
    ('Bearer {0}' -f (Get-AzCachedAccessToken2))
}

function loadEntitlementManagement() {
    #Need to create catalogue and assign items to it
    #Create packages in catalogues consuming assigned resources
    write-host "Processing Entitlemenet Management"

    $EntitlementManagement = $organisation.EntitlementManagement
    
    
    ForEach ($catalog in $EntitlementManagement.Catalogues) {
    #Create the catalogue
    $body = @{
        displayName = $catalog.Name
        description = $catalog.Description
        isExternallyVisible = $catalog.ExternallyAvailable
    } | ConvertTo-JSON
    

    #$body = $body | ConvertTo-JSON

    $catalog = invokeGraphAPI -Call "beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body $body -Method "POST"
    #$catalog
    }

}

function invokeGraphAPI($Call, $Body, $Method) {
    #$accessToken = Get-AzBearerToken
    $accessToken = Get-AzCachedAccessToken2
    
    $headers = @{
	    Accept = "application/json"
        Authorization = $token
        Host = "graph.microsoft.com"
    }

    Write-Host "Headers: " $headers

    $url = "https://graph.microsoft.com/$($Call)"

    Write-Host "Url: " $url

    Write-Host "Body: " $body

    Write-Host "Token" $accessToken
    #return Invoke-RestMethod -Uri $url -Headers $headers -Method $Method -Body $body | ConvertTo-Json
   # $apiUrl = 'https://graph.microsoft.com/v1.0/groups'
    $Data = Invoke-RestMethod -Headers @{Authorization = $accessToken} -Uri $url -Body $body -Method Post -ContentType "application/json"

}

function loadPIM() {
    #Need to onboard subscription first - check if it is, if not enable it
    #Need to configure roles - this looks like a lot of settings put a profile in the JSON to rinse and repeat?
}


function Get-AzCachedAccessToken1()
{
    $ErrorActionPreference = 'Stop'
  
    if(-not (Get-Module Az.Accounts)) {
        Import-Module Az.Accounts
    }
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if(-not $azProfile.Accounts.Count) {
        Write-Error "Ensure you have logged in before calling this function."    
    }

    #$context = Get-AzContext

    #$appId = '53316905-a6e5-46ed-b0c9-524a2379579e'
    #$appId = "1950a258-227b-4e31-a9cf-717495945fc2"
    $appId = $tenantBuilerAppId
    #$redirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    $graphScopes = 'user.read'
    $logonEndpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0'

    # $authContext = [Microsoft.Identity.Client.PublicClientApplication]::new($appId, $logonEndpoint, $null)

    $asyncResult = $authContext.AcquireTokenAsync([System.Collections.Generic.List[string]] $graphScopes)
    $token = $asyncResult.Result
    Write-host "Token: " $token
    return $token
}

function Get-AzCachedAccessToken2(){
    $context = Get-AzContext
    #$clientId = "1950a258-227b-4e31-a9cf-717495945fc2" #PowerShell well-known clientId
    #$clientId = "30055d02-25ec-42d3-9525-7072854ba2fd"
    $clientId = $tenantBuilerAppId
    #$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    #$redirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    $redirectUri = "https://localhost"
    #https://login.microsoftonline.com/$TenantName
    #secret OcO!4ir@1Cj1 _nQ-L6UIJEhh3YpCo-8qkzj~QjbJ_iLZH2
    #$authorityUri = "https://login.microsoftonline.com/$($context.Tenant.Id)"
    #$authorityUri = "https://login.microsoftonline.com/common"
    $authorityUri = "https://login.microsoftonline.com/$($context.Tenant.Id)/oauth2/v2.0/authorize"
    #$tokenUri = "https://login.microsoftonline.com/$context.Tenant.Id/oauth2/v2.0/token"
    #$Instance = "https://login.microsoftonline.com/{0}";
    #$authority = string.Format(CultureInfo.InvariantCulture, $Instance, $context.Tenant.Id);
    #$authorityUri= "https://login.windows.net/$context.Tenant.Id"
    #$authorityUri= "$($context.Environment.ActiveDirectoryAuthority)/$context.Tenant.Id"
    $ApiEndpointUri = "https://graph.microsoft.com"
    #*?Is client assertion the powershell clientid and the existing token?
    #*Also AcquireTokenAsync(String, String, Uri, IPlatformParameters, UserIdentifier)
    #scopes: EntitlementManagement.ReadWrite.All
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authorityUri

    $promptBehaviour = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    $authParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $promptBehaviour
    #$clientCred = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList $clientId, "_nQ-L6UIJEhh3YpCo-8qkzj~QjbJ_iLZH2"
    #$context=Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant 72f988bf-86f1-41af-91ab-2d7cd011db47
    #$UserId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $context.Account, 2
    #$authResult = $authContext.AcquireTokenSilentAsync($ApiEndpointUri, $clientId,$redirectUri, "Auto").GetAwaiter().GetResult()
    #$authResult = $authContext.AcquireTokenAsync($ApiEndpointUri,  $clientId, $redirectUri, $authParam).GetAwaiter().GetResult()
    $authResult = $authContext.AcquireTokenAsync($ApiEndpointUri,  $clientId, $redirectUri,  $authParam).GetAwaiter().GetResult()
    write-host "AuthResultTokenType " $authResult.AccessTokenType
    write-host "UserInfo " $authResult.UserInfo
    write-host "AuthResult: " $authResult | Format-List
    #write-host "Token: " $authResult.AccessToken

    #$body = "grant_type=authorization_code&redirect_uri=$redirectUri&client_id=$clientId&client_secret=$clientSecretEncoded&code=$authCode&resource=$resource"
    #$tokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token `
    #-Method Post -ContentType "application/x-www-form-urlencoded" `
    #-Body $body `
    #do this https://www.lee-ford.co.uk/getting-started-with-microsoft-graph-with-powershell/
    #return $authResult.AccessToken
    return $authResult.CreateAuthorizationHeader()
}

function Get-AzCachedAccessToken3() {
    #$currentAzureContext = Get-AzContext
    #$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    #https://github.com/Azure/azure-powershell/issues/2494
    $context = Get-AzContext
    $cache = $context.TokenCache
    $cacheItem = $cache.ReadItems()

    $token = ($cacheItem | where { $_.Resource -eq "https://graph.windows.net/" }).accessToken
    if ($token.ExpiresOn -le [System.DateTime]::UtcNow) {
        $ac = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new("$($context.Environment.ActiveDirectoryAuthority)$($context.Tenant.Id)",$token)
        $token = $ac.AcquireTokenByRefreshToken($token.RefreshToken, "1950a258-227b-4e31-a9cf-717495945fc2", "https://graph.windows.net")
        
    }

    Write-Host "Graph token: " $token
    return $token
}

function createTenatBuilderApp() {
    #{class ResourceAccess {
    #    Id: ae7a573d-81d7-432b-ad44-4ed5c9d89038 #Microsoft.Graph/EntitlementManagement.ReadWrite.All Delegated
    #    Type: Scope
    #  }
    #  , class ResourceAccess {
    #    Id: e1fe6dd8-ba31-4d61-89e7-88639da4683d #Microsoft.Graph/User.Read Delegated
    #    Type: Scope
    #  }
    # https://stackoverflow.com/questions/42164581/how-to-configure-a-new-azure-ad-application-through-powershell

    $existingApp = Get-AzureADApplication -Filter "DisplayName eq 'Tenant Builder PowerShell Script'"

    if ($existingApp) {
        return $existingApp.AppId
    }

    $tenantBuilderApp = New-AzureADApplication -DisplayName "Tenant Builder PowerShell Script" -ReplyUrls @("https://localhost") -PublicClient $true
    $appAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $UserRead = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "e1fe6dd8-ba31-4d61-89e7-88639da4683d","Scope"
    $EntitlementManagementReadWriteAll = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ae7a573d-81d7-432b-ad44-4ed5c9d89038","Scope"
    $appAccess.ResourceAccess = $UserRead,$EntitlementManagementReadWriteAll
    $appAccess.ResourceAppId = "00000003-0000-0000-c000-000000000000" #Microsoft Graph API

    Set-AzureADApplication -ObjectId $tenantBuilderApp.ObjectId -RequiredResourceAccess $appAccess
    write-host "https://login.microsoftonline.com/$($tenantId)/adminconsent?client_id=$($tenantBuilderApp.AppId)&redirect_uri=https://localhost"
    $response = Invoke-WebRequest -Uri "https://login.microsoftonline.com/$($tenantId)/adminconsent?client_id=$($tenantBuilderApp.AppId)&redirect_uri=https://localhost"
    return $tenantBuilderApp.AppId
}
#Connect-AzureAD
#Connect-AzureRMAccount

Connect-AzAccount
$currentAzureContext = Get-AzContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
Connect-AzureAD -TenantId $tenantId -AccountId $accountId

Connect-Graph

write-host "Connected to Tenant"
$organisation = Get-Content -Raw -Path $JSONToLoad | ConvertFrom-Json
$tenantBuilerAppId = "00000"
Write-Host "Loaded JSON:" $JSONToLoad
initOutputFile

if ($createTenantBuilderApp) {
    $tenantBuilerAppId = createTenatBuilderApp
}


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

Get-AzCachedAccessToken2

#Get-AzCachedAccessToken2

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
                  