
$DebugPreference = "Continue"
$OutputLogFile = ".\objects.csv"
$JSONToLoad = ".\test.json"

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
    addOutEntry("user", $User.GUID, $UserDisplayName)

    if ($User.ManagedBy -ne "") {
        Write-Host "Setting Manager for" $UserDisplayName " UserGUID:" $User.GUID " manager guid:" $User.ManagerGUID
        Set-AzureADUserManager -ObjectId $User.GUID -RefObjectId $User.ManagerGUID
        write-host "ManagerGUID:" + $User.ManagerGUID
    }
    
    # Create the objects we'll need to add and remove licenses
    $license = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses

    # Find the SkuID of the license we want to add - in this example we'll use the O365_BUSINESS_PREMIUM license
    $license.SkuId = (Get-AzureADSubscribedSku | Where-Object -Property SkuPartNumber -Value "DEVELOPERPACK_E5" -EQ).SkuID

    # Set the Office license as the license we want to add in the $licenses object
    $licenses.AddLicenses = $license

    # Call the Set-AzureADUserLicense cmdlet to set the license.
    Set-AzureADUserLicense -ObjectId $User.UPN -AssignedLicenses $licenses

}

function getManagerGUID($UserObj) {
    #$User | add-member -Name "Department" -value $TeamName -MemberType NoteProperty
    
    if ($UserObj.ManagedBy -ne "") {
        #$UserObj.ManagedBy
        $UserMgrUPN = $UserObj.ManagedBy + $organisation.upnSuffix
        $MgrObject = $Leadership | Where-Object {$_.upn -eq $UserMgrUPN}
        write-host "getManagerGUID Mgr:" $MgrObject "; GUID:" $MgrObject.GUID
        #$User | add-member -Name "ManagerGUID" -value $Mgr.GUID -MemberType NoteProperty
        return $MgrObject.GUID
    } else {
        return ""
    }
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
    # ObjectId for application from App Registrations in your AzureAD
    $app = New-AzureADApplication -DisplayName "My Test App"
    addOutEntry("app", $app.ObjectId, $app.DisplayName)
    #$appObjectId = "<Your Application Object Id>"
    #$app = Get-AzureADApplication -ObjectId $appObjectId
    #$appRoles = $app.AppRoles
    #Write-Host "App Roles before addition of new role.."
    #Write-Host $appRoles

    $newRole = CreateAppRole -Name "MyNewApplicationRole" -Description "This is my new Application Role"
    $app.AppRoles.Add($newRole)
    $newRole = CreateAppRole -Name "MyNewApplicationRole2" -Description "This is another new Application Role"
    $app.AppRoles.Add($newRole)

    Set-AzureADApplication -ObjectId $app.ObjectId -AppRoles $app.AppRoles

    $spnDisplayName = $app.DisplayName + " SPN"
    $spn = New-AzureADServicePrincipal -AppId $app.AppId
    addOutEntry("spn", $spn.ObjectId, $spnDisplayName)
}

function processDepartment() {
    Write-Host "Processing Departments"
    ForEach ($Department in $organisation.Department){
        #Write-Debug "Starting Department:" ($Department.Name | Out-String)
        $DepartmentDisplayName = $Department.Name + " Team Owners"
        $OwnerGroup = New-AzureADGroup -DisplayName $DepartmentDisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $DepartmentDisplayName.Replace(" ","-")
        $Department | add-member -Name "OwnerGroupGUID" -value $OwnerGroup  -MemberType NoteProperty
        addOutEntry("group", $OwnerGroup.ObjectId, $DepartmentDisplayName)

        $DepartmentDisplayName = $Department.Name + " Team Members"
        $MemberGroup = New-AzureADGroup -DisplayName $DepartmentDisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $DepartmentDisplayName.Replace(" ","-")
        $Department | add-member -Name "MemberGroupGUID" -value $MemberGroup  -MemberType NoteProperty
        addOutEntry("group", $OwnerGroup.ObjectId, $DepartmentDisplayName)

        $Leadership = $Department.Leadership

        ForEach ($User in $Leadership){
            #$UserDisplayName = $User.GivenName + " " + $User.Surname
            #$mailNickName = $User.GivenName.ToLower() + $User.Surname.ToLower()
            #$upn = $User.GivenName.ToLower() + "." + $User.Surname.ToLower() + $organisation.upnSuffix
            #$User | add-member -Name "UPN" -value $upn -MemberType NoteProperty
            $User | add-member -Name "Department" -value $Department.Name -MemberType NoteProperty
            #User.Department = $Department.Name
            
            if ($User.ManagedBy -ne "") {
                $User.ManagedBy
                $mgrupn = $User.ManagedBy + $organisation.upnSuffix
                $Mgr = $Leadership | Where-Object {$_.upn -eq $mgrupn}
                $User | add-member -Name "ManagerGUID" -value $Mgr.GUID -MemberType NoteProperty
            }

            addNewUser($User)
            #$UserGUID = New-AzureAdUser -AccountEnabled $true -Department $DepartmentDisplayName -DisplayName UserDisplayName -GivenName $User.GivenName -Surname $User.Surname -JobTitle $User.Title -MailNickname $mailNickName -PasswordProfile $PasswordProfile

            #$User | add-member -Name "GUID" -value $UserGUID -MemberType NoteProperty
            #$User
            #write-debug "User GUID" $User.guid
        }

        $Products = $Department.ProductTeam

        ForEach ($Product in $Products) {
            
            #Write-Debug "Processing Product:" $Product.Name
            $Members = $Product.Members

            ForEach($Member in $Members) {
                $MgrGUID = getManagerGUID($Member)
                $Member | add-member -Name "Department" -value $Product.Name -MemberType NoteProperty
                $Member | add-member -Name "ManagerGUID" -value $MgrGUID -MemberType NoteProperty 
                addNewUser($Member)
            }
        }
        #Write-Debug "Completed Department:" ($Department.Name | Out-String)
    }
}



Connect-AzureAD
write-host "Connected to Tenant"
$organisation = Get-Content -Raw -Path $JSONToLoad | ConvertFrom-Json
Write-Host "Loaded JSON:" $JSONToLoad
initOutputFile
#processDepartment
loadApp

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
                  