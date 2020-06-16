
$ObjectsToSweep = Import-CSV -Path .\objects.csv

#We need to delete things in a certain order
$AccessPackagesToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "accesspackage"}
$CatalogsToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "catalog"}
$GroupsToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "group"}
$UsersToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "user"}
$RolesToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "role"}

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

function invokeGraphAPI($Call, $Body, $Method) {
    $accessToken = Get-AzCachedAccessToken
    
    $url = "https://graph.microsoft.com/$($Call)"
    #Write-Host "Url: " $url
    #Write-Host "Body: " $body

    if ($Method -eq "GET", "DELETE") {
        $graphResponse = Invoke-WebRequest -UseBasicParsing -Headers  @{Authorization = $accessToken} -Uri $url -Method $Method
    } else {
        $graphResponse = Invoke-RestMethod -Headers @{Authorization = $accessToken} -Uri $url -Body $body -Method POST -ContentType "application/json"
    }
    return $graphResponse
}


ForEach ($accessPackage in $AccessPackagesToDelete) {
    #TODO Check if any assignments first
    
    DELETE "beta/identityGovernance/entitlementManagement/accessPackages/{id}
}

ForEach ($catalog in $CatalogsToDelete) {
    #Check if any access Packages...
}

function getTenantBuilderAppId() {
    $existingApp = Get-AzureADApplication -Filter "DisplayName eq 'Tenant Builder PowerShell Script'"

    if ($existingApp) {
        return $existingApp.AppId
    } else {
        Write-Host "Unable to locate Tenant Builder App"
        Exit
    }
}

#Connect to Azure to enable AZ cmdlets and set up globals
Connect-AzAccount
#Set up some globals
$currentAzureContext = Get-AzContext
$tenantId = $currentAzureContext.Tenant.Id
$accountId = $currentAzureContext.Account.Id
$SubscriptionId = $currentAzureContext.Subscription.Id
$tenantBuilerAppId = getTenantBuilderAppId()
#Connect to AzureAD to enable the AzureAD Cmdlets
Connect-AzureAD -TenantId $tenantId -AccountId $accountId

#Connect to Graph to enable the Graph Cmdlets
#Connect-Graph

write-host "Connected to Tenant"

