
$PathToSweepFile = ".\objects.csv"
$PathToLogFile = ".\tenantSweeper.txt"
$whatIfMode = $true
#We need to delete things in a certain order
$AccessPackagesToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "accesspackage"}
$CatalogsToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "catalog"}
$GroupsToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "group"}
$UsersToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "user"}
$RolesToDelete = $ObjectsToSweep | Where-Object {$_.ObjectType -eq "role"}


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
            $message = "info: " + $message
            Write-Information -Message $message
            if ($logLevel -gt 1) {
                Add-Content -Path $outputLogFile -Value $message
            }
            break
        }
        "warn" {
            $message = "warn: " + $message
            Write-Warning -Message $message
            Add-Content -Path $outputLogFile -Value $message
            break
        }
        "error" {
            $message = "error: " + $message
            Write-Error -Message $message
            Add-Content -Path $outputLogFile -Value $message
            break
        }
        default {
            break
        }
    }
}

function removeUser($UserObjectId) {
    #Write-Debug -Message "Removing User ObjectId: $($UserObjectId)"
    try {
        $usr = get-AzureADUser -ObjectId $UserObjectId
        log -message "User objectID: $($UserObjectId) will be removed" -level "Info"
        if (!$whatIfMode) {
            Remove-AzureADUser -ObjectId $UserObjectId
            log -message "User ($usr.DisplayName), objectId: $($UserObjectId) removed" -level "Warn"
        }
        return $true
    } catch {
        log -message "User objectID: $($UserObjectId) not found" -level "Info"
        return $false
    }    
}

function removeGroup($GroupObjectId) {
    try {
        $grp = get-AzureADGroup -ObjectId $GroupObjectId
        log -message "Group $($grp.displayName) objectId: $($GroupObjectId) will be removed" -level "Info"
        if (!$whatIfMode) {
            Remove-AzureADGroup -ObjectId $GroupObjectId
            log -message "Group $($grp.displayName) objectId: $($GroupObjectId) removed" -level "Warn"
        }
        return $true
    } catch {
        log -message "Group objectID: $($UserObjectId) not found" -level "Info"
        return $false
    }
    #Write-Debug -Message "Removing Group ObjectId: $($GroupObjectId)"
    
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

function deleteAccessPackage($accessPackageId) {
    try {
        $accessPackage = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages/$(accessPackageId)" -body "" -Method "GET"
        log -message "Access Package $($accessPackage.displayName) objectId: $($accessPackageId) will be removed" -level "Info"
        if (!$whatIfMode) {
            invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages/$(accessPackageId)" -body "" -Method "DELETE"
            log -message "Access Package $($accessPackage.displayName) objectId: $($accessPackageId) removed" -level "Warn"
        }
        return $true   
    } catch {
        log -message "Access Package $($accessPackageId) not found" -level "Info"
        return $false
    }
}

function deleteGraphItem($itemId, $itemType) {
    try {
        $item = invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/$($itemType)/$(itemId)" -body "" -Method "GET"
        log -message "$($itemType) $($item.displayName) objectId: $($itemId) will be removed" -level "Info"
        if (!$whatIfMode) {
            invokeGraphAPI -call "beta/identityGovernance/entitlementManagement/accessPackages/$(accessPackageId)" -body "" -Method "DELETE"
            log -message "$($itemType) $($item.displayName) objectId: $($itemId) removed" -level "Warn"
        }
        return $true   
    } catch {
        log -message "$($itemtype) $($accessPackageId) not found" -level "Info"
        return $false
    }
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
$tenantBuilerAppId = getTenantBuilderAppId
#Connect to AzureAD to enable the AzureAD Cmdlets
Connect-AzureAD -TenantId $tenantId -AccountId $accountId




#Connect to Graph to enable the Graph Cmdlets
#Connect-Graph

write-host "Connected to Tenant"

if (Test-Path -Path $PathToSweepFile) {
    try {
        $sweepObjects = Import-CSV -Path $PathToSweepFile
        log -message "Loaded sweep file from $($PathToSweepFile)" -level "Info"

        $UserObjects = @()
        $GroupObjects = @()
        $AccessPackageObjects = @()
        $CatalogObjects = @()
        $RoleObjects = @()
        $AppObjects = @()
        $PimObjects = @()
        
        ForEach ($item in $sweepObjects) {
            switch ($item.objectType) {
                "user" {$UserObjects += $item}
                "group" {$GroupObjects += $item}
                "accessPackage" {$AccessPackageObjects + $item}
                "catalog" {$CatalogObjects += $item}
                "role" {$RoleObjects += $item}
                "app" {$AppObjects += $item}
                "pim" {$PimObjects+= $item}
                default {break}
            }
        }

        ForEach ($user in $UserObjects) {
            removeUser $user.objectId
        }
    } catch {
        $message = "Unable to load sweep file $($PathToSweepFile) Exception: $_"
        log -message $message -level "error"
        exit
    }
} else {
    log -message "Sweep file: $($PathToSweepFile) not found, please supply a valid path" -level "Error"
    Exit
}

