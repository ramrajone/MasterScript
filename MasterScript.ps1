<#

.SYNOPSIS
  Overview of script is to create Menu with sub menu then selection of action
.DESCRIPTION
  Brief description of script, based on selection this script will exectute and do it's task, then returns back to Menu selection
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
    At the moment there are not parameter set for this script
.INPUTS
  Inputs are required by user based on selection to take action on
.OUTPUTS
  Outputs at moment there are not logs created
.NOTES
  Version:        1.0
  Author:         Ramnik Sanariya
  Creation Date:  3/2/2023
  Purpose/Change: Initial script development to learn and grow on day to day task
  
.EXAMPLE
  Selection 1
  action for selection 1

#>
cls
function startOver{
Clear-Host
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx This script is used for users and Admins xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host ' ' This script will execute 1 or more action based on selections, just be careful on your selections  -ForegroundColor Yellow
$text=@"
$ver
        __  __              _                _____                            _____  _            _  _ 
       |  \/  |            | |              |  __ \                          / ____|| |          | || |
       | \  / |  __ _  ___ | |_  ___  _ __  | |__) |___ __      __ ___  _ __| (___  | |__    ___ | || |
       | |\/| | / _` |/ __|| __|/ _ \| '__| |  ___// _ \\ \ /\ / // _ \| '__|\___ \ | '_ \  / _ \| || |
       | |  | || (_| |\__ \| |_|  __/| |    | |   | (_) |\ V  V /|  __/| |   ____) || | | ||  __/| || |
       |_|  |_| \__,_||___/ \__|\___||_|    |_|    \___/  \_/\_/  \___||_|  |_____/ |_| |_| \___||_||_|
                                     _____              _         _                                                            
                                    / ____|            (_)       | |                                                           
                                   | (___    ___  _ __  _  _ __  | |_                                                          
                                    \___ \  / __|| '__|| || '_ \ | __|                                                         
                                    ____) || (__ | |   | || |_) || |_                                                          
                                   |_____/  \___||_|   |_|| .__/  \__|                                                         
                                                          | |                                                                  
                                                          |_|                                            
"@
$text
Write-Host '                           Note: This Script AS IS, please use it with caustion' -ForegroundColor Red
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Start of checking Admin mode  #######################################################
Write-Host ' '
Write-Host "Testing if the signed in user has local admin permissions..." -ForegroundColor Yellow
        $LocalAdminGroup=(whoami /groups | Select-String 'S-1-5-32-544')
        if ($LocalAdminGroup){
            Write-Host "Test passed: the signed in user has local admin permissions" -ForegroundColor Green
        }else{
            Write-Host "Test failed: the signed in user does NOT have local admin permissions" -ForegroundColor Red
#           Write-Log -Message "Test failed: the signed in user does NOT have local admin permissions" -Level ERROR
            Write-Host ''
            Write-Host "Recommended action: sign in with a user that has local admin permissions" -ForegroundColor Yellow
            Write-Host ''
            Write-Host ''
            Write-Host "Script Ended" -ForegroundColor Green
            Write-Host ''
            Write-Host ''
            #break
            }
# End of checking Admin mode #######################################################

# To see what's set to:
$CurrentExecutionPolicy = Get-ExecutionPolicy
Write-Host "Currently execution Policy is set to: " $CurrentExecutionPolicy

$CurrentLoginName=whoami
Write-Host 'You are logged in as:                 ' $CurrentLoginName -ForegroundColor Green

$CurrentComputerName = $env:COMPUTERNAME
Write-Host 'Your Current computer name:           ' $CurrentComputerName -ForegroundColor Green
MainMenu
}

function exitScript{
    Clear-Host
    Write-Host 'You Selected to Exit the Script'
    exit
    }

function ClearScreen{
        cls
        Write-Host "Please wait this may take few seconds"
        }

function MainMenu{  # Start of Main Menu
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host '            Main Menu ' -ForegroundColor Green
Write-Host ' '
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host '    0  To Exit' -ForegroundColor Yellow
$menu = @"

    1. Get Information only
    2. Setup Computer
    3. Install Application(s)
    4. Troubleshooting Tools

    Make a selection:
"@ 
$userChoice = Read-Host $menu


# Using a switch statement to perform different actions based on the selected option
switch ($userChoice){
    "0" {
        exitScript
        }       
    "1" { # Launch subMenu1 Get Information only
           
            subMenu1
            
        }
    "2" { # Launch submenu2 Setup Computer
            
            subMenu2
           
        }
    "3" { # Submenu3 Install Application(s)
            subMenu3
        }
    "4"{ # Submenu4 Troubleshooting Tools
            subMenu4
       }

    default {
    Clear-Host
    Write-Host 'Invalid selection please make selection'
    MainMenu
    }      
}
} # End of Main Menu

function subMenu1{  # Start of Sub Menu 1
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host '       Get Information only' -ForegroundColor Green
Write-Host ' '
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-host '     0  To Exit' -ForegroundColor Yellow
Write-host '     B  To Go Back' -ForegroundColor Yellow
Write-host '     S  Start Over' -ForegroundColor Yellow
$submenu1 = @"

    1. Get name of your Computer
    2. Find out whom you are logged in as
    3. Get List of Printers
    4. Get Windows Version
    5. Get Your IP address info
    6. Get List of Programs and it's Locations
    7. Find out which version of MS office 32bit or 64bit

    Make a selection:
"@
$userChoice = Read-Host -Prompt $submenu1


# Using a switch statement to perform different actions based on the selected option
switch ($userChoice){
    "0" {
        exitScript

    }
    "B" {
        Clear-Host
        MainMenu
        }     
    "S" {
        startOver
    }    
   
    "1" {
        Clear-Host
            Write-Host 'Your Computer Name is: ' -NoNewline
            HOSTNAME   
        ''
        subMenu1
        }
    "2" {
        Clear-Host
            $CurrentLoginName=whoami
            Write-Host 'You are logged in as: ' $CurrentLoginName -ForegroundColor Green
            ''
        subMenu1
            
        }
    "3" {
        Clear-Host
            Write-Host 'Your Computer have following printers installed:'
            Write-Host ' '
            Get-Printer | Format-Table
        ''
        subMenu1 
        }

    "4" { 
        Clear-Host
            'Checking please wait'
            Write-Host 'Your Windows Version is: '
            $WindowVersion=(Get-WmiObject -class Win32_OperatingSystem).Caption + '  '+ (Get-CimInstance Win32_OperatingSystem).Version 
            Write-Host $WindowVersion -ForegroundColor Green
        ''
        subMenu1
        }

    "5" { 
        Clear-Host
           'Your IP address info listed below: '
            Get-NetIPConfiguration | Format-List
            
        ''
        subMenu1 
        }

    "6"{
        Clear-host
            Write-Host 'Your Computer have following Programs installed: '
            try {
	        if ($IsLinux) {
		        & snap list
	        } else {
		        Get-AppxPackage | Format-Table -property Name,Version,Architecture,Status,InstallLocation -autoSize
                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,Publisher,DisplayVersion,InstallLocation,UninstallString  | Format-Table -AutoSize
	        sleep 1
            }
             ''
            subMenu1
            } catch {
	            "Error in line $($_.InvocationInfo.ScriptLineNumber): $($Error[0])"
	            exit 1
            }
        }
    "7"{
        ClearScreen
                Write-Host 'Checking Which version of MS office is installed'
                # To check MS office version, if it's 32bit or 64bit
                $officeCheck = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration").platform
                
                
                if($officeCheck -eq 'x64'){
                    Write-Host "Your computer have MS Office 64 bit" -ForegroundColor Green
                    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" | Select-Object Platform,ProductReleaseIds,InstallationPath | Format-List
                }
                else{
                    Write-Host "Your computer have MS Office 32 bit." -ForegroundColor Green
                    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" | Select-Object Platform,ProductReleaseIds,InstallationPath | Format-List
                }
        }
    default {
        Clear-Host
        Write-Host 'Invalid selection please make another selection'
        subMenu1
        }
}
}# End of Sub Menu 1


function subMenu2{ # Start of Sub Menu 2

Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host '              Setup Computer' -ForegroundColor Green
Write-Host ' '
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '

Write-host '     0  To Exit' -ForegroundColor Yellow
Write-host '     B  To Go Back' -ForegroundColor Yellow
Write-host '     S  Start Over' -ForegroundColor Yellow

$submenu2 = @"

    1. Rename Computer
    2. Join to Domain
    3. Add user to LocalAdmin


    Make a selection:
"@
$userChoice = Read-Host -Prompt $submenu2


# Use a switch statement to perform different actions based on the selected option
switch ($userChoice){
    "0" {
        exitScript

    }
    "B" {
        Write-Host "You selected to goback"
        Clear-Host
        MainMenu
        }
    "S" {
        startOver
        }
                  
    "1" { ClearScreen
            "Renaming Computer"
            $CurrentComputerName = $env:COMPUTERNAME
            $NewComputerName = Read-Host "Enter the new computer name:"

            Rename-Computer -NewName $NewComputerName -Restart -Force

            if ($env:COMPUTERNAME -eq $NewComputerName) {
                Write-Host "Successfully renamed the computer from $CurrentComputerName to $NewComputerName."
            } else {
                Write-Host "Failed to rename the computer."
            }
        ''
        subMenu2
        }
    "2" { ClearScreen
            'Joining compter to Domain'
            $cred = Get-Credential
            $YourDomainName = Read-Host "Enter your Domain name:"
            Add-Computer -DomainName $YourDomainName -Credential $cred
        ''
        subMenu2
            
        }
    "3" { ClearScreen
            'To Add user to Local Admin Group'
            $UserName = Read-Host "Enter username to add to Local admin Group as domain\userName"
            $LocalAdminGroup=Get-LocalGroupMember -Group 'Administrators' -Member $UserName -ErrorAction SilentlyContinue
            if ($LocalAdminGroup){
              Write-Host "$UserName is a member of the local administrator group."
              }
            else {
              Write-Host "$UserName is not a member of the local administrator group.  Adding now"
              Add-LocalGroupMember -Group 'Administrators' -Member $UserName
                }
        ''
        subMenu2
        }
     
     default {
        Clear-Host
        Write-Host 'Invalid selection please make another selection'
        subMenu2
        }
}
} # End of Sub Menu 2

function subMenu3{ # Start of Sub Menu 3
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host '              Application Install' -ForegroundColor Green
Write-Host ' '
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '

Write-host '     0  To Exit' -ForegroundColor Yellow
Write-host '     B  To Go Back' -ForegroundColor Yellow
Write-host '     S  Start Over' -ForegroundColor Yellow

$submenu3 = @"

    1. Adobe Reader
    2. Chrome browser

    Make a selection:
"@
$userChoice = Read-Host -Prompt $submenu3

switch ($userChoice){
    "0" {
        exitScript

    }
    "B" {
        Write-Host "You selected to goback"
        Clear-Host
        MainMenu
        }
    "S" {
        startOver
        }         
    "1" { ClearScreen
             'Installing Adobe Reader'
              Write-Host ""
              Write-Host ' '
              Write-Host 'Adobe Reader Installing please wait ... ' -ForegroundColor Yellow
              $url= "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/2200320322/AcroRdrDC2200320322_en_US.exe"
              $outpath =  "$env:USERPROFILE\downloads\AcroRdrDC2200320322_en_US.exe"
            Invoke-WebRequest -Uri $url -OutFile $outpath
            Start-Process $outpath
        ''
        subMenu3
        }
    "2" {ClearScreen
        Write-Host 'Please wait while Chrome browser is installing'
        try {
	        $StopWatch = [system.diagnostics.stopwatch]::startNew()

	        $Path = $env:TEMP;
	        $Installer = "chrome_installer.exe"
	        Invoke-WebRequest "http://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile $Path\$Installer
	        Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait
	        Remove-Item $Path\$Installer

	        [int]$Elapsed = $StopWatch.Elapsed.TotalSeconds
	        "Installed Google Chrome in $Elapsed sec"
	        subMenu3
        } catch {
	        "⚠️ Error in line $($_.InvocationInfo.ScriptLineNumber): $($Error[0])"
	        exit 1
        }
        ''
        subMenu3            
        }
    
    
     default {
        Clear-Host
        Write-Host 'Invalid selection please make another selection'
        subMenu3
        }
}
} # End of Sub Menu 3


function subMenu4{ # Start of Sub Menu 4
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '
Write-Host '              Troubleshooting Tools ' -ForegroundColor Green
Write-Host ' '
Write-Host xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Write-Host ' '

Write-host '     0  To Exit' -ForegroundColor Yellow
Write-host '     B  To Go Back' -ForegroundColor Yellow
Write-host '     S  Start Over' -ForegroundColor Yellow

$submenu4 = @"

    1. Close Microsoft Edge
    2. Close Google Chrome
    3. Open Task Manager
    4. Open Control Pannel
    5. Open Programs and Features
    6. Restart Print spooler to help clear jam print job
    7. Open System Properties

    Make a selection:
"@
$userChoice = Read-Host -Prompt $submenu4

switch ($userChoice){
    "0" {
        exitScript

    }
    "b" {
        Write-Host "You selected to goback"
        Clear-Host
        MainMenu
        }
    "S" {
        startOver
        }         
   
    "1" { ClearScreen
            TaskKill /im msedge.exe /f /t
            if ($lastExitCode -ne "0") {
	            Write-Host "Sorry, Microsoft Edge isn't running." -ForegroundColor Red
	            subMenu4
            }
            Write-Host ' '
            Write-Host 'Microsoft Edge is closed' -ForegroundColor Green
        ''
        subMenu4
        }
    "2" { ClearScreen
            TaskKill /im chrome.exe /f /t
            if ($lastExitCode -ne "0") {
	            Write-Host "Sorry, Google Chrome isn't running." -ForegroundColor Red
	            subMenu4
            }
            Write-Host ' '
            Write-Host 'Google Chrome is closed' -ForegroundColor Green
        ''
        subMenu4
        }
    "3" { ClearScreen
            Write-Host ' '
            Write-Host 'Opening Task Manager' -ForegroundColor Green
            taskmgr
        ''
        subMenu4
        }

    "4" { ClearScreen
            Write-Host ' '
            Write-Host 'Opening Control Pannel' -ForegroundColor Green
            control
        ''
        subMenu4
        }

    "5" { ClearScreen
            Write-Host ' '
            Write-Host 'Opening Programs and Features' -ForegroundColor Green
            control
        ''
        subMenu4
        }
     "6" { ClearScreen
            Write-Host ' '
            Write-Host 'Restarting Print spooler' -ForegroundColor Green
            Restart-Service Spooler
        ''
        subMenu4
        }
      "7"{ClearScreen
            Write-Host ' '
            Write-Host 'Opening System Properties'
            sysdm.cpl
       ''
        subMenu4
        }
         
           
     default {
        Clear-Host
        Write-Host 'Invalid selection please make selection'
        subMenu4
        }
}
} # End of Sub Menu 4


startOver
mainMenu
