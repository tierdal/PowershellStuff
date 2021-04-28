Param(
    [parameter(Mandatory=$true)]
    [string]$PROJECTNUMBER
)

$prjNum = $PROJECTNUMBER
$prjAccessGroup = 'access' + $prjNum
#$currentUser = $env:UserDomain+ '\' + $env:UserName

Write-Output "The Project number is: $prjNum"

function FixACL {
    param (
        [Parameter(Mandatory=$true)] [string] $aclRootPath
    )
    $aclRoot = Get-Acl -Path "$aclRootPath" 
    $aclFolders = Get-ChildItem -Recurse -Path $aclRootPath
    foreach ($folder in $aclFolders) {
        Write-Output "Current Folder: " $folder.FullName
        $icacls = "$folder"
        Set-ACL -Path $folder.FullName -AclObject $aclRoot
        icacls $icacls /q /c /t /reset
    }
}

Function Set-Owner {
    <# https://gallery.technet.microsoft.com/scriptcenter/Set-Owner-ff4db177
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.

        .DESCRIPTION
            Changes owner of a file or folder to another user or group.

        .PARAMETER Path
            The folder or file that will have the owner changed.

        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.

            Default value is 'Builtin\Administrators'

        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder.

        .NOTES
            Name: Set-Owner
            Author: Boe Prox
            Version History:
                 1.0 - Boe Prox
                    - Initial Version

        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt

            Description
            -----------
            Changes the owner of test.txt to Builtin\Administrators

        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt -Account 'Domain\bprox

            Description
            -----------
            Changes the owner of test.txt to Domain\bprox

        .EXAMPLE
            Set-Owner -Path C:\temp -Recurse 

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators

        .EXAMPLE
            Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\bprox'

            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Domain\bprox
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path,
        [parameter()]
        [string]$Account = 'Builtin\Administrators',
        [parameter()]
        [switch]$Recurse
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;

             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }
    Process {
        ForEach ($Item in $Path) {
            Write-Verbose "FullName: $Item"
            #The ACL objects do not like being used more than once, so re-create them on the Process block
            $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
            $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $FileOwner = New-Object System.Security.AccessControl.FileSecurity
            $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $AdminACL = New-Object System.Security.AccessControl.FileSystemAccessRule('Builtin\Administrators','FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow')
            $FileAdminAcl.AddAccessRule($AdminACL)
            $DirAdminAcl.AddAccessRule($AdminACL)
            Try {
                $Item = Get-Item -Path $Item -Force -ErrorAction Stop
                If (-NOT $Item.PSIsContainer) {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
                        Try {
                            $Item.SetAccessControl($FileOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($FileAdminAcl)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
                        Try {
                            $Item.SetAccessControl($DirOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirAdminAcl) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        Get-ChildItem $Item -Force | Set-Owner @PSBoundParameters
                    }
                }
            } Catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }
    }
    End {  
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

function Set-Permission {
    <# https://github.com/jasonjas/powershell/blob/master/Set-Permissions-ACL.ps1
        .SYNOPSIS
            Add / Remove NTFS rights to files or folders
        .DESCRIPTION
            Modifies ACLs of folders and files using Get-Acl and Set-Acl.
            Created by Jason Svatos
            Created on 3/10/2016
            Modified 3/12/2016 (Added EnableInheritance switch parameter and Action:Replace parameter)
            Modified 3/13/2016 (Added recurse and changed error catching on settting permissions)
        .EXAMPLE
            Set-Permission -Path C:\Temp -User domain\user -Permission FullControl
            This will append the FullControl permission to the folder C:\Temp for account domain\user
        .EXAMPLE
            Set-Permission -Path C:\Temp\Test -User Administrator -Permission FullControl -Action Replace
            This will replace all permissions on the folder "Test" with FullControl for the local Administrator account only
        .EXAMPLE
            Set-Permission -Path C:\Software -User domain\user -Permission ReadAndExecute -Action Remove -Recurse
            This will remove the ReadAndExecute permission for account domain\user on the folder C:\Software. 
        .EXAMPLE 
            Get-ChildItem c:\temp | Set-Permission -User domain\user -Permission ReadAndExecute -Recurse -inherit
            This will add ReadAndExecute permissions for domain\user to all files, folders, and subfolders under c:\temp.
            It will set inheritance on those folders for that account as well (Container Inherit and Object Inherit). 
        .PARAMETER Path
            Path of the file or folder to change permissions on
        .PARAMETER User
            "Domain\Username" of the account to add/remove rights for
        .PARAMETER Permissions
            Permissions to grant to the user. Separate each permission with a comma if using multiple permissions.
        .PARAMETER Action
            Add: Add permissions to the folder / file only for the specified account
            Replace: Replace the permissions that exist on the file or folder. This will remove all entries and overwrite with the permission(s) / account specified.
            **Warning! Using this can cause issues if you remove permissions for yourself, system, or admins.
            Remove: Remove the specified Permission(s) for the specified account on the folders/files
        .PARAMETER Inherit
            Set permissions to inherit to subdirectories/files
        .PARAMETER Recurse
            Apply permissions to all subfolders and files below specified directory
        .PARAMETER EnableInheritance
            Allow inheritance to work on the folder/file specified. This will re-enable inheritance on folders/files that have been changed with the "Replace" action.
            ** Overrides the "Replace" Action which removes inheritance
    #>

    [CmdletBinding(SupportsShouldProcess = $True)]
    param (
        [parameter(Mandatory=$true,
            Position=1,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Alias("FullName","Location")]
        [String[]]$Path,

        [parameter(Mandatory=$true)]
        [String]$User,

        [parameter(Mandatory=$true)]
        [ValidateSet("AppendData","ChangePermissions","CreateDirectories","CreateFiles","Delete",
            "DeleteSubdirectoriesAndFiles","ExecuteFile","FullControl","ListDirectory","Modify",
            "Read","ReadAndExecute","ReadAttributes","ReadData","ReadExtendedAttributes",
            "ReadPermissions","Synchronize","TakeOwnership","Traverse","Write","WriteAttributes",
            "WriteData","WriteExtendedAttributes")]
        [String[]]$Permissions,

        [Switch]$Recurse,

        [parameter(Mandatory=$false,
            HelpMessage="Add; Remove; or Replace permissions. Default is Add")]
        [ValidateSet("Add","Remove","Replace")]
        [string]$Action = "Add",
        
        [Switch]$Inherit,

        [Switch]$EnableInheritance
    )

    Begin {
        $ErrorActionPreference = "Stop"

        # Create function for using with -recurse parameter
        # loopes through all sub-directories and gathers file and folder names
        function Get-SubFolders($directory) {
            # Create array to put files and directories in
            # This needs to be cleared on each iteration of the function or it will return duplicate objects
            [System.Collections.ArrayList]$subItems = @()
            try {
                # Get all files in the directory
                foreach ($f in [System.IO.Directory]::GetFiles($directory))
                {
                    # add files to arrayList - out-Null as it outputs a count for each item added
                    $subItems.Add($f) | Out-Null
                }
                # Get all sub-directories in the directory
                foreach ($d in [System.IO.Directory]::GetDirectories($directory))
                {
                    # add directories to arrayList - out-Null as it outputs a count for each item added
                    $subItems.Add($d) | Out-Null
                    # re-run the function again to get all sub-directories and files
                    Get-SubFolders $d
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-Warning ("Unable to access {0}, Access Denied" -f $directory)
            }
            catch {
                # catch any errors
                Write-Warning $_.Exception.Message
            }
            return $subItems
        }

        if ($Recurse)
        { # check if recurse is used
            foreach ($p in $Path)
            { # loop through each item and get all files and directories in it
                
                Write-Verbose "Getting all sub files and sub folders (Recurse is on)."
                Write-Verbose "This may take some time for large directories / structures..."
                $Path = Get-SubFolders -directory $p
            }
        }
    }

    Process {
        foreach ($itemPath in $Path)
        {
            try {
                $location = (Get-Item $itemPath).FullName
            }
            catch {
                # Catch any errors as Get-Item $Location will throw a different type of error
                Write-Warning "Error getting full path of object, skipping $itemPath"
                continue
            }
            Write-Verbose "Checking information for $location ..."
            # Check if the path exists
            if (-not (Test-Path -Path $location))
            {
                Write-Warning "Path does not exist"
                continue
            }
            # do some checking to see if the path is a file or directory
            # needed for security permissions and how to work with them
            if ((Get-Item $location) -is [System.IO.DirectoryInfo])
            {
                # path points to a directory
                Write-Verbose "$location is a directory"
                # Set location type for directory - needed for creating correct FileSystemAccessRule
                $locationType = "d"
            }
            else
            {
                # path points to a file
                Write-Verbose "$location is a file"
                # set location type for file - needed for creating correct FileSystemAccessRule
                $locationType = "f"
            }

            # Create variables
            # -------------------
            # Set inherit flags to default to "none"
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
            # set propagation flags to be "none"
            $propagation = [System.Security.AccessControl.PropagationFlags]::None

            # Get the ACL of the files/folders that exist
            # Required if appending or reqplacing
            Write-Verbose "Getting ACL of current location."
            $currentACL = Get-Acl -Path $location
        
            if ($Inherit -and $locationType -eq "d")
            {
                # Only set if it is a directory - it will cause an error if it is set on a file
                # Set inheritance
                Write-Verbose "Setting Inheritance to enable"
                $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
            }

            try {
                # Create access rule for permissions
                # .NET Constructor: FileSystemAccessRule(String, FileSystemRights, InheritanceFlags, PropagationFlags AccessControlType)
                # See https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemaccessrule(v=vs.110).aspx
                Write-Verbose "Creating FileSystemAccessRule object"
                $fileSystemAccessRule = New-Object system.security.AccessControl.FileSystemAccessRule($User,[System.Security.AccessControl.FileSystemRights]$Permissions,$inheritance,$propagation,"Allow")
            }
            catch {
                Write-Error $_.Exception.ToString()
            }

            Write-Verbose "Setting action to $Action ACL"
            
            try {
                switch($Action)
                {
                    # Add, Remove, or Replace ACL from the current ACL on the folder/file
                    "Remove" {$currentACL.RemoveAccessRuleAll($fileSystemAccessRule); Break}
                    "Replace" {
                                # check if access/inheritance rules are protected
                                if ($currentACL.AreAccessRulesProtected)
                                {
                                    $currentACL.Access | foreach {$currentACL.PurgeAccessRules($_.IdentityReference)}
                                }
                                else {
                                    # Disable inheritance from folder / file
                                    # SetAccessRuleProtection([Disable Inheritance (BOOL)], [Preserve Inherited Permissions (BOOL)])
                                    $currentACL.SetAccessRuleProtection($true,$false)
                                }
                        
                                # Add ACE to current ACL
                                $currentACL.AddAccessRule($fileSystemAccessRule)
                                Break
                            } # end replace selection bracket
                    # Add = default to catch any unexpected entries
                    DEFAULT {$currentACL.AddAccessRule($fileSystemAccessRule); Break}
                }
            }
            catch {
                Write-Error $_.Exception.ToString()
            }

            if ($EnableInheritance)
            {
                # Set inheritance to be enabled on file / folder
                $currentACL.SetAccessRuleProtection($false,$false)
            }

            # Setting ACL on object
            Write-Verbose "Setting ACL on $location"

            try {
                # "SupportsShouldProcess = $True" affects this command
                # Can use -WhatIf or -Confirm
                Set-Acl -Path $location -AclObject $currentACL
            }
            catch [System.UnauthorizedAccessException] {
                # Permissions error on file / folder
                Write-Warning "Unable to change permissions on $location"
                continue
            }
            catch {
                Write-Error $_.Exception.ToString()
            }
            
            # Show ACL output if -Verbos parameter is used
            Write-Verbose "Displaying ACL for $location"

            # Get acl and format as list, output as string and write verbose
            Write-Verbose $(Get-Acl -Path $location | fl AccessToString | Out-String)
        }
    }

    End {
        Write-Verbose "Finished!"
    }
}

Function SetACLAgain {
    Param (
        [Parameter(Mandatory=$true)] [string] $prjNumber,
        #[Parameter(Mandatory=$true)] [string] $currentCreatingUser,
        [Parameter(Mandatory=$true)] [string] $projectAccessGroup
    )

    #$accessRuleMaster = New-Object System.Security.AccessControl.FileSystemAccessRule("GULF\AccessControlMaster","FullControl","Allow")
    #$ownerMaster = New-Object System.Security.Principal.Ntaccount("GULF\AccessControlMaster")
    #$AccessRule_Main = New-Object System.Security.AccessControl.FileSystemAccessRule("GULF\$prjAccessGroup","ReadAndExecute, Synchronize","Allow")
    #$AccessRule_MainQuality = New-Object System.Security.AccessControl.FileSystemAccessRule("GULF\gulf041","ReadAndExecute, Synchronize","Allow")
    $AccessRule_ProjectControls = "GULF\gulf034"
    $AccessRule_ProjectControlsMgMt = "GULF\mgmt034"
    $AccessRule_MaterialsManagementGroup = "GULF\gulf037"
    $AccessRule_Quality = "GULF\gulf041"
    $AccessRule_GIS = "GULF\gulf048"
    $AccessRule_Estimating = "GULF\gulf069"
    $AccessRule_ProjectServicesMgmt = "GULF\mgmt067"
    $AccessRule_ContractsMgt = "GULF\gulf075"
    $AccessRule_ProjectAdmins = "GULF\gulf032"
    $AccessRule_ProjectAdminsMgmt = "GULF\gulf032"
    $AccessRule_ProjectManagement = "GULF\gulf072"

    # Apply all Access Rules here
    Write-Output "Applying Access Rules"

    <# # root Folder
    Write-Output "1"
    $acl = Get-Acl \\nutfs\gulf_projects\$prjNum\
    $acl.SetAccessRule($accessRuleMaster)
    $acl.SetAccessRule($AccessRule_Main)
    $acl.SetAccessRule($AccessRule_MainQuality)
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($ownerMaster)
    $acl | Set-Acl \\nutfs\gulf_projects\$prjNum\

    #Write-Output "$prjNumber owner"
    #Get-ChildItem -Path "\\?\UNC\nutfs\gulf_projects\$prjNumber\" | Set-Owner -Recurse -Account "GULF\AccessControlMaster"
    
    #Write-Output "$prjNumber root"
    #Set-Permission -Path "\\?\UNC\nutfs\gulf_projects\$prjNumber\" -User "GULF\AccessControlMaster" -Permission "FullControl" -inherit
    #Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\" -User $currentCreatingUser -Permission "FullControl" -Action Remove -Recurse #>

    # Admin Folder
    Write-Output "$prjNumber admin"

    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\admin\" -User $AccessRule_ProjectAdmins -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\admin\" -User $AccessRule_ProjectAdminsMgmt -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\admin\" -User $AccessRule_ProjectManagement -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\admin\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\admin"

    # Doc Folder
    Write-Output "$prjNumber doc"

    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\doc\" -User "GULF\$prjAccessGroup" -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\doc\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\doc"

    # Procurement Folder
    Write-Output "$prjNumber procurement"
    
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\procurement\" -User $AccessRule_MaterialsManagementGroup -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\procurement\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\procurement"

    # ProjCtrl Folder
    Write-Output "$prjNumber ProjCtrl"
    
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\ProjCtrl\" -User $AccessRule_ProjectControls -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\ProjCtrl\" -User $AccessRule_ProjectControlsMgMt -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\ProjCtrl\" -User $AccessRule_ProjectServicesMgmt -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\ProjCtrl\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\ProjCtrl"

    # GIS Folder

    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\GIS\" -User $AccessRule_GIS -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\GIS\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\GIS"

    # Estimating Folder
    Write-Output "$prjNumber estimating"
    
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\estimating\" -User $AccessRule_Estimating -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\estimating\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\estimating"

    # GIS Folder
    Write-Output "$prjNumber Contracts Mgt"
    
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\Contracts Mgt\" -User $AccessRule_ContractsMgt -Permission "FullControl" -inherit
    Set-Permission -Path "\\nutfs\gulf_projects\$prjNumber\Contracts Mgt\" -User $AccessRule_Quality -Permission "FullControl" -inherit
    #FixACL "\\nutfs\gulf_projects\$prjNumber\Contracts Mgt"
}

SetACLAgain $prjNum $prjAccessGroup

Unregister-ScheduledTask -TaskName "PermFix$prjNum" -Confirm:$false

Write-Output "Done. Permissions for Project $prjNum are set."
