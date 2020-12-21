<#
.SYNOPSIS

    The purpose of this script is to automate the BIOS Update from Commandline to be used 
    with MDT / ConfigMgr / AD / Intune
    
    ..Use this script at your own risk.. 

.DESCRIPTION

    This script will determine the model of the computer, manufacturer and operating system used then download,
    extract & install the latest bios package from the manufacturer. At present Dell are supported.
    
    Supported Platforms: Powershell x64
                         Powershell x86
                         Interactive admin cmd
                         NonInteractive system cmd
                         Intune
                         MDT
                         ConfigmMgr
                         AD - ComputerStartUp Script
                         WinPE-64 version 10.0.16299.15 with .Net and Powershell modules
    Requires:            Internet access to Dell site.
	
.NOTES

    FileName:    Invoke-BIOSUpdate.ps1

    Author:      Daniel Olsson
    Contact:     @danielolsson100
    Created:     2018-01-22
    Updated:     2018-02-14
    Creds:       To @MoDaly_IT for some of his functions that I reused from github

    Version history:

    1.0.0 - (2018-01-22) Script created
    1.0.1 - (2018-01-26) Major bugfixes regarding the BIOS update process to support BIOS Password etc
    1.0.2 - (2018-01-26) Added support for WinPE-x64, tested with psexec / Powershell in x86/AMDx64 environment.
    1.1.0 - (2018-02-14) Added support for Lenovo
    1.1.1 - (2018-02-27) Various bugfixes, Better logging, support for TSEnv
    1.1.2 - (2018-03-22) Bugfix Dell Download cab support in WinPE instead of start-bitstransfer.
    1.1.3 - (2018-11-26) Removed FileHash Lenovo because X260 BIOS has wrong filehash on Lenovo.
    1.1.4 - (2019-07-03) Added Logics for the code to be executed with IntuneManagementExtensions.
    1.1.5 - (2019-09-25) Added logics to copy the logfile to a new path due to Intune cleanup logics
    1.1.6 - (2019-09-26) Added shutdown /r /t 600 /c "Restart needed due to BIOS upgrade" if Intune Mode detected
    1.1.7 - (2019-09-26) Note that this script is custom made for Intune..
#>
