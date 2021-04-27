# Script to create and sync user accounts from local AD to Azure AD and to sync exchange setup for the new user
# Version 0.1

$runtime = $true
$creds = Get-Credential

while ($runtime) {
    #Setup Vars
    Write-Host "`n`nInitializing..." -NoNewline
    #$azureadSession = New-PSSession -ComputerName azuread
    $ex1Session = New-PSSession -ConfigurationName Microsoft.Exchange -Credential $creds -ConnectionUri http://ex1/PowerShell/
    Write-Host "Done.`n"

    $syncoptionrun = $true

    # Step 1 - Get username
    $username = Read-Host -Prompt 'Please enter username'

    # Step 2, 3, and 4 - Get F Name, L Name, Dept, and create user in AD, then assign license
    #$fname = Read-Host -Prompt 'Please enter First Name'
    #$lname = Read-Host -Prompt 'Please enter Last Name'

    #$usertype = Read-Host -Prompt 'Please enter User Type (1 = Houston Users, 2 = Field Services):'

    #$fullname = $fname + " " + $lname
    #$fullname = Read-Host -Prompt 'Please enter Full Name'
    #$email = $username + "@gie.com"
    #Write-Host "`nUsername: $username"
    #Write-Host "Full Name: $fullname `n"
    #Write-Host "E-mail: $email `n"

    # Step 3 - Create user in AD
    #New-ADUser -DisplayName:"$fullname" -EmailAddress:"$email" -GivenName:"$fname" -Name:"$fullname" -Path:"OU=Users,OU=Field Services,OU=GIE,DC=gulf,DC=local" -SamAccountName:"jameyt" -Server:"GULFDC4.gulf.local" -Surname:"Thompkins" -Type:"user" -UserPrincipalName:"jameyt@gie.com"
    #Set-ADAccountPassword -Identity:"CN=Jamey Thompkins,OU=Users,OU=Field Services,OU=GIE,DC=gulf,DC=local" -NewPassword:(ConvertTo-SecureString -AsPlainText "Th1sGuyF@wks" -Force) -Reset:$true -Server:"GULFDC4.gulf.local"
    #Enable-ADAccount -Identity:"CN=Jamey Thompkins,OU=Users,OU=Field Services,OU=GIE,DC=gulf,DC=local" -Server:"GULFDC4.gulf.local"
    #Add-ADPrincipalGroupMembership -Identity:"CN=Jamey Thompkins,OU=Users,OU=Field Services,OU=GIE,DC=gulf,DC=local" -MemberOf:"CN=MSO365-E1-NoTeams,OU=Groups,OU=Houston,OU=GIE,DC=gulf,DC=local","CN=PGE Field Services,OU=Groups,OU=Field Services,OU=GIE,DC=gulf,DC=local" -Server:"GULFDC4.gulf.local"
    #Set-ADAccountControl -AccountNotDelegated:$false -AllowReversiblePasswordEncryption:$false -CannotChangePassword:$false -DoesNotRequirePreAuth:$false -Identity:"CN=Jamey Thompkins,OU=Users,OU=Field Services,OU=GIE,DC=gulf,DC=local" -PasswordNeverExpires:$true -Server:"GULFDC4.gulf.local" -UseDESKeyOnly:$false
    #Set-ADUser -ChangePasswordAtLogon:$false -Identity:"CN=Jamey Thompkins,OU=Users,OU=Field Services,OU=GIE,DC=gulf,DC=local" -Server:"GULFDC4.gulf.local" -SmartcardLogonRequired:$false

    # Step 5 - Connect to azuread sync service and run sync - then sleep for 5 minutes
    
    while ($syncoptionrun) {
        $syncoption = Read-Host -Prompt 'Do you need to run Azure Sync? (Y|N)'

        if ($syncoption -eq "Y" -Or $syncoption -eq "y") {
            Write-Host "`n`nExecuting Sync..." -NoNewline
            Invoke-Command -ComputerName azuread -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta} -Credential $creds | Select-Object -Property * -ExcludeProperty PSComputerName,RunspaceID
            #Remove-PSSession $azureadSession
            Write-Host "Done."
            Write-Host "Waiting for sync to finish..." -NoNewline
            For ($i=300; $i -gt 1; $i–-) {  
                Write-Progress -Activity "Waiting for sync to finish..." -SecondsRemaining $i
                Start-Sleep 1
            }
            Write-Progress -Activity "Waiting" -Completed  
            Write-Host "Done."
            $syncoptionrun = $false
        } elseif ($syncoption -eq "N" -Or $syncoption -eq "n") { 
            Write-Host "Skipping Azure Sync."
            $syncoptionrun = $false
            # Wrong Input. Run it back.
       }
   }
    
    # Step 6 - Connect to EX1 and run exchange addition commands
    Write-Host "`nConnecting to EX1..." -NoNewline
    Import-PSSession $ex1Session -DisableNameChecking -AllowClobber
    Write-Host "Done."
    Write-Host "Enable Remote Mailbox..." -NoNewline
    Enable-RemoteMailbox "$username" -RemoteRoutingAddress "$username@gulfinterstate.mail.onmicrosoft.com"
    #Enable-RemoteMailbox "$fullname" -RemoteRoutingAddress "$username@gulfinterstate.mail.onmicrosoft.com"
    Write-Host "Done."
    Write-Host "Add gulfcompanies.com Alias..." -NoNewline
    Set-RemoteMailbox $username@gie.com -EmailAddresses @{Add="$username@gulfcompanies.com"}
    Write-Host "Done."

    # Step 7 - Update offline address book and exit
    Write-Host "Updating Offline Address Book..." -NoNewline
    Update-OfflineAddressBook "Default Offline Address Book"
    Write-Host "Done."
    Write-Host "Disconnecting..." -NoNewline
    Remove-PSSession $ex1Session
    Write-Host "Done."

    Write-Host "`n`nAll steps are completed."

    # Step 8 - Run again?
    $exitoption = Read-Host -Prompt 'Do you wish to exit? (Y|N)'
    if ($exitoption -eq "Y" -Or $exitoption -eq "y") {$runtime = $false}
}