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
# // =================== BASE VARIABLES ================ //

# Set Temp & Log Location
$StartPath = (Get-Location).Path	

# Added 20190703 for Intune support.
if($StartPath -match "c:\Windows\System32"){
    #Write-Host(Get-Date) - Script StartPath match C:\Windows\system32 - Assume that it is being executed from Intune Management Extensions
    $IntuneManagementExtensions=$True
    [string]$global:TempDirectory = "C:\Windows\Temp"
    [string]$global:LogDirectory = "C:\Windows\Logs"
}
else {
    [string]$global:TempDirectory = Join-Path $($StartPath) "\Temp"
    [string]$global:LogDirectory = Join-Path $($StartPath) "\Logs"
}

# Create Temp Folder 
if ((Test-Path -Path $global:TempDirectory) -eq $false) {
	$Output=New-Item -Path $global:TempDirectory -ItemType Dir
}
# Create Logs Folder 
if ((Test-Path -Path $global:LogDirectory) -eq $false) {
	$Output=New-Item -Path $global:LogDirectory -ItemType Dir
}


# // =================== COMMON VARIABLES ================ //

# Define the BIOS Password if Customer uses a BIOS Password
# This value should $null or a string
$BIOSPassword=$null
#$BIOSPassword="1234"

$global:BitsOptions = @{
	RetryInterval    = "60"
	RetryTimeout	 = "180"
	Priority		 = "Foreground"
}

# // =================== DELL VARIABLES ================ //
	
# Define Dell Download Sources
$DellDownloadList = "https://downloads.dell.com/published/Pages/index.html"
$DellDownloadBase = "https://downloads.dell.com"
$DellDriverListURL = "https://en.community.dell.com/techcenter/enterprise-client/w/wiki/2065.dell-command-deploy-driver-packs-for-enterprise-client-os-deployment"
$DellBaseURL = "https://en.community.dell.com"
$Dell64BIOSUtil = "https://en.community.dell.com/techcenter/enterprise-client/w/wiki/12237.64-bit-bios-installation-utility"
$Dell64BIOSUtilUri="https://downloads.dell.com/FOLDER04165397M/1/Flash64W.zip"

# Define Dell Download Sources
$DellXMLCabinetSource = "https://downloads.dell.com/catalog/DriverPackCatalog.cab"
$DellCatalogSource = "https://downloads.dell.com/catalog/CatalogPC.cab"
	
# Define Dell Cabinet/XL Names and Paths
$DellCabFile = [string]($DellXMLCabinetSource | Split-Path -Leaf)
$DellCatalogFile = [string]($DellCatalogSource | Split-Path -Leaf)
$DellXMLFile = $DellCabFile.Trim(".cab")
$DellXMLFile = $DellXMLFile + ".xml"
$DellCatalogXMLFile = $DellCatalogFile.Trim(".cab") + ".xml"
	
# Define Dell Global Variables
$global:DellCatalogXML = $null
$global:DellModelXML = $null
$global:DellModelCabFiles = $null

# // =================== Lenovo VARIABLES ================ //

$LenovoBaseCatalogURL="https://download.lenovo.com/catalog/"
$LenovoBaseCatalogURLEnd="_Win10.xml"

# // =================== Functions ================ //

function global:Write-CMLogEntry {
	param (
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]
		$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]
		$FileName = "Invoke-BIOSUpgrade.log",
		[parameter(Mandatory = $false, HelpMessage = "Variable for skipping verbose output to the GUI.")]
		[ValidateNotNullOrEmpty()]
		[boolean]
		$SkipGuiLog
	)
	# Determine log file location
	$LogFilePath = Join-Path -Path $global:LogDirectory -ChildPath $FileName
		
	# Construct time stamp for log entry
	$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
		
	# Construct date for log entry
	$Date = (Get-Date -Format "MM-dd-yyyy")
		
	# Construct context for log entry
	#$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $Context = $null	
	
	# Construct final log entry
	$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Invoke-BIOSUpgrade"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
	# Add value to log file
	try {
		Add-Content -Value $LogText -LiteralPath $LogFilePath -ErrorAction Stop
        if($Severity -eq 1) {
            Write-Host $Value -ForegroundColor Gray
        }
        elseif($Severity -eq 2) {
            Write-Host $Value -ForegroundColor Yellow
        }
        elseif($Severity -eq 3) {
            Write-Host $Value -ForegroundColor Red -BackgroundColor White
        }
	}
	catch [System.Exception] {
		Write-Warning -Message "Unable to append log entry to Invoke-BIOSUpdate.log file. Error message: $($_.Exception.Message)"
	}
}

function Start-DellBiosFinder {
	param (
		[string]
		$Model
	)
		
	if ((Test-Path -Path $global:TempDirectory\$DellCatalogXMLFile) -eq $false) {
		global:Write-CMLogEntry -Value "======== Downloading Dell Driver Catalog  ========" -Severity 1
		global:Write-CMLogEntry -Value "Info: Downloading Dell driver catalog cabinet file from $DellCatalogSource" -Severity 1
		# Download Dell Model Cabinet File
		try {
			if ($global:ProxySettingsSet -eq $true) {
				Start-BitsTransfer -Source $DellCatalogSource -Destination $global:TempDirectory @global:BitsProxyOptions
			}
			else {
                #Start-BitsTransfer -Source $DellCatalogSource -Destination $global:TempDirectory @global:BitsOptions
                Invoke-WebRequest -Uri $DellCatalogSource -OutFile ($global:TempDirectory+"\CatalogPC.cab")
			}
		}
		catch {
			global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
		}
			
		# Expand Cabinet File
		global:Write-CMLogEntry -Value "Info: Expanding Dell driver pack cabinet file: $DellCatalogFile" -Severity 1
		Expand "$global:TempDirectory\$DellCatalogFile" -F:* "$global:TempDirectory\$DellCatalogXMLFile" | Out-Null
	}
		
	if ($global:DellCatalogXML -eq $null) {
		# Read XML File
		global:Write-CMLogEntry -Value "Info: Reading driver pack XML file - $global:TempDirectory\$DellCatalogXMLFile" -Severity 1
		[xml]$global:DellCatalogXML = Get-Content -Path $global:TempDirectory\$DellCatalogXMLFile
			
		# Set XML Object
		$global:DellCatalogXML.GetType().FullName
	}		
		
	# Cater for multiple bios version matches and select the most recent
	$DellBIOSFile = $global:DellCatalogXML.Manifest.SoftwareComponent | Where-Object {
		($_.name.display."#cdata-section" -match "BIOS") -and ($_.name.display."#cdata-section" -match "$model")
	} | Sort-Object ReleaseDate
	# Cater for multi model updates
	if ($DellBIOSFile -eq $null) {
		$global:DellCatalogXML.Manifest.SoftwareComponent | Where-Object {
			($_.name.display."#cdata-section" -match "BIOS") -and ($_.name.display."#cdata-section" -like "*$(($model).Split(' ')[1])*")
		} | Sort-Object ReleaseDate | Select-Object -First 1
	}
	if (($DellBIOSFile -eq $null) -or (($DellBIOSFile).Count -gt 1)) {
		# Attempt to find BIOS link		
		if ($Model -match "AIO") {
			$DellBIOSFile = $DellBIOSFile | Where-Object {
				$_.SupportedSystems.Brand.Model.Display.'#cdata-section' -match "AIO"
			} | Sort-Object ReleaseDate | Select-Object -First 1
		}
		else {
			$DellBIOSFile = $DellBIOSFile | Where-Object {
				$_.SupportedSystems.Brand.Model.Display.'#cdata-section' -eq "$($Model.Split(' ')[1])"
			} | Sort-Object ReleaseDate | Select-Object -First 1
		}
	}
	elseif ($DellBIOSFile -eq $null) {
		# Attempt to find BIOS link via Dell model number (V-Pro / Non-V-Pro Condition)
		$DellBIOSFile = $global:DellCatalogXML.Manifest.SoftwareComponent | Where-Object {
			($_.name.display."#cdata-section" -match "BIOS") -and ($_.name.display."#cdata-section" -match "$($model.Split("-")[0])")
		} | Sort-Object ReleaseDate | Select-Object -First 1
	}
		
	global:Write-CMLogEntry -Value "Info: Found BIOS URL $($DellBIOSFile.Path)" -Severity 1
	# Return BIOS file values
	Return $DellBIOSFile
}

function Get-DellBIOSFile {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True)][string]$Uri,
        [Parameter(Mandatory=$True)][string]$SavePath,
        [Parameter(Mandatory=$True)][string]$HashMD5
    )
    global:Write-CMLogEntry -Value "Info: Downloading BIOS from: $Uri" -Severity 1  
    Invoke-WebRequest -Uri $Uri -OutFile $SavePath
    $DownloadedFileHashMD5=Get-FileHash -Path $SavePath -Algorithm MD5 | Select -ExpandProperty Hash
    
    # Compare FileHash and retry if hash is invalid
    if($DownloadedFileHashMD5 -notmatch $HashMD5){
        global:Write-CMLogEntry -Value "Error: Incorrect filehash for file: $SavePath HashMD5: $DownloadedFileHashMD5" -Severity 2
        
    }
    elseif($DownloadedFileHashMD5 -match $HashMD5){
        global:Write-CMLogEntry -Value "Info: Correct filehash for file: $SavePath" -Severity 1
    }
}

function Get-DellIsBIOSUpgradeNeeded{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True)][String]$NewBIOSVersion
    ) 

    $SMBIOSBIOSVersion=Get-WmiObject -Class win32_bios | Select -ExpandProperty SMBIOSBIOSVersion
    if($SMBIOSBIOSVersion -match "A"){
        $CustSMBIOSBIOSVersion=[version]($SMBIOSBIOSVersion).Replace("A","0.")
    }
    elseif ($SMBIOSBIOSVersion -match "."){
        $CustSMBIOSBIOSVersion=[Version]$SMBIOSBIOSVersion
    }
    
    if($NewBIOSVersion -match "A"){
        $CustNewBIOSVersion=[version]($NewBIOSVersion).Replace("A","0.")
    }
    elseif($NewBIOSVersion -match "."){
        $CustNewBIOSVersion=[Version]$NewBIOSVersion
    }

    # Upgrade BIOS if needed
    if($CustNewBIOSVersion -gt $CustSMBIOSBIOSVersion){
        return $true
    }
    else{
        return $false
    }
}

function Get-BitlockerProtectionStatus_C {
<#
 
.SYNOPSIS
Get-CustBitlockerProtectionStatus_C is used to determine if a computers C Drive is encrypted with bitlocker or not
 
.DESCRIPTION
Get-CustBitlockerProtectionStatus_C is used to determine if a computers C Drive is encrypted with bitlocker or not 
#>
    $BitlockerProtectionStatus_C=Get-BitLockerVolume -MountPoint c: | Select -ExpandProperty ProtectionStatus
    if($BitlockerProtectionStatus_C -eq "Off"){
        return $false
    }
    elseif($BitlockerProtectionStatus_C -eq "On"){
        return $true
    }
    else {
        return $null
    }
}

function Get-IsLaptop {
<#
 
.SYNOPSIS
Get-CustIsLaptop is used to determine if a computer is a laptop of desktop.
 
.DESCRIPTION
Get-CustIsLaptop is used to determine a computer's hardware type of whether or not the
computer is a laptop or a desktop.
 
#>
    $hardwaretype = Get-WmiObject -Class Win32_ComputerSystem -Property PCSystemType
    if ($hardwaretype.PCSystemType -ne "2"){
        return $false
    }
    else{
        return $true
    }
}

function Get-IsLaptopACConnected {
<#
 
.SYNOPSIS
Get-CustIsLaptopACConnected is used to determine if a Laptop is AC connected or not
 
.DESCRIPTION
Get-CustIsLaptopACConnected is used to determine if a Laptop is AC connected or not
 
#>

    $BatteryStatus=Get-WmiObject -class Win32_battery | select -ExpandProperty BatteryStatus
    if($BatteryStatus -eq 2){
        return $true
    }
    else{
        return $false
    }
}

function Get-BatteryChargeLevel {
    $BatteryChangeLevel=[INT](Get-WmiObject -class Win32_battery | Select -ExpandProperty EstimatedChargeRemaining | Select -First 1)
    return $BatteryChangeLevel
}

function Get-IsOSWinPE {
    if(Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WinPE" -ErrorAction SilentlyContinue){
        return $true
    }
    else{
        return $false
    }
}

function Get-DellFlash64WUtil {
    global:Write-CMLogEntry -Value "Info: Downloading Flash64W Util from: $Dell64BIOSUtilUri" -Severity 1 
    Invoke-WebRequest -Uri $Dell64BIOSUtilUri -OutFile ($global:TempDirectory+'\Flash64W.zip')
    global:Write-CMLogEntry -Value "Info: Unzipping Dell Flash64W.exe" -Severity 1
    Add-Type -AssemblyName "system.io.compression.filesystem"
	[io.compression.zipfile]::ExtractToDirectory("$($global:TempDirectory+'\Flash64W.zip')", "$($global:TempDirectory)")
}

function Start-DellBIOSUpgrade {
    # Upgrade BIOS if needed
    global:Write-CMLogEntry -Value "Info: BIOS Upgrade is needed, Current BIOS:$CurrentBIOSVersion New BIOS:$NewBIOSVersion" -Severity 1
        
    # Upgrade BIOS only if the laptop have external AC connected
    if(Get-IsLaptop -eq $true){
        
        if(Get-IsLaptopACConnected -eq $True) {
            global:Write-CMLogEntry -Value "Info: Laptop is connected to external AC" -Severity 1
            
            $BatteryChargeLevel=Get-BatteryChargeLevel
            if($BatteryChargeLevel -gt 10){
                global:Write-CMLogEntry -Value "Info: Laptop battery charge level OK" -Severity 1
            }
            else {
                global:Write-CMLogEntry -Value "Info: Laptop battery change level is not OK, BIOS upgrade not possible, terminating script" -Severity 3; exit 1
            }
        }
        else {
            global:Write-CMLogEntry -Value "Error: Laptop is NOT connected to external AC, BIOS upgrade not possible, terminating script" -Severity 3; exit 1
        }
    }
    else{
        global:Write-CMLogEntry -Value "Info: This is not an laptop, skipping battery check" -Severity 1
    }
    # Suspend Bitlocker on C-Drive if needed, should not be required in WinPE
    $IsOSWinPE=Get-IsOSWinPE
    if($IsOSWinPE -eq $False){
        if(Get-BitlockerProtectionStatus_C -eq $true){
            global:Write-CMLogEntry -Value "Info: C-drive is protected with Bitlocker, suspening Bitlocker on C: drive " -Severity 1
            $Output=Suspend-BitLocker -MountPoint C:
        }
    }

    # Build strings to download BIOS update
    $Uri=($DellDownloadBase +'/'+($DellBiosFinder | Select Path | Select -ExpandProperty Path))
    $SavePath=($global:TempDirectory+'\'+($DellBiosFinder | Select Path | Select -ExpandProperty Path | split-path -Leaf))
    $HashMD5=($DellBiosFinder | Select hashMD5 | Select -ExpandProperty hashMD5)
    Get-DellBIOSFile -Uri $uri -SavePath $SavePath -HashMD5 $HashMD5

    # Upgrade BIOS with or without BIOS Password
    $BIOSFileNameAndPath=$SavePath
    $WorkingDirectory=$BIOSFileNameAndPath | Split-path
    $BIOSLogFilePath=$global:TempDirectory+'\'+($BIOSFileNameAndPath | Split-Path -Leaf)+'.log'
    if($BIOSPassword -eq $null){
        $ArgumentList=('/s /l='+$BIOSLogFilePath)
    }
    elseif($BIOSPassword -ne $null){
        $ArgumentList=('/s /l='+$BIOSLogFilePath+' /p='+$BIOSPassword)
    }

	try {
        if(Get-IsOSWinPE -eq $True){
            global:Write-CMLogEntry -Value "Info: WinPE detected" -Severity 1
            Get-DellFlash64WUtil
            $ArgumentList=$ArgumentList+' /b='+$BIOSFileNameAndPath
            Start-Process ($global:TempDirectory+'\Flash64W.exe') -WorkingDirectory $WorkingDirectory -ArgumentList $ArgumentList -NoNewWindow
        }
        elseif(Get-IsTSRunning -eq $True){
            global:Write-CMLogEntry -Value "Info: TaskSequenceMode detected" -Severity 1
            global:Write-CMLogEntry -Value "Info: BIOS Upgrade will start now" -Severity 1
            Start-Process $BIOSFileNameAndPath -WorkingDirectory $WorkingDirectory -ArgumentList $ArgumentList -NoNewWindow -Wait
            $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
            $tsenv.Value("CustRestartRequired")=$True
            exit 3010
        }
        else{
            global:Write-CMLogEntry -Value "Info: Intune Mode detected, reboot will be enforced after BIOS Upgrade with a deplay of 10 minutes" -Severity 1
            #global:Write-CMLogEntry -Value "Info: Normal GUI Mode detected, reboot will be enforced after BIOS Upgrade" -Severity 1
            Start-Process $BIOSFileNameAndPath -WorkingDirectory $WorkingDirectory -ArgumentList $ArgumentList -NoNewWindow
            #Invoke-RestartComputerWithMsg
            shutdown /r /t 600 /c "Restart needed due to BIOS upgrade"
        }
	}
	catch {
		global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
	}
    global:Write-CMLogEntry -Value "Info: BIOS Upgrade log: $BIOSLogFilePath" -Severity 1
    global:Write-CMLogEntry -Value "Info: Restart needed for BIOS Upgrade to be completed" -Severity 2
}

function Start-LenovoBIOSUpgrade {
    
    # Upgrade BIOS only if the laptop have external AC connected
    if(Get-IsLaptop -eq $true){
        
        if(Get-IsLaptopACConnected -eq $True) {
            global:Write-CMLogEntry -Value "Info: Laptop is connected to external AC" -Severity 1
            
            $BatteryChargeLevel=Get-BatteryChargeLevel
            if($BatteryChargeLevel -gt 10){
                global:Write-CMLogEntry -Value "Info: Laptop battery charge level OK" -Severity 1
            }
            else {
                global:Write-CMLogEntry -Value "Info: Laptop battery change level is not OK, BIOS upgrade not possible, terminating script" -Severity 3; exit 1
            }
        }
        else {
            global:Write-CMLogEntry -Value "Error: Laptop is NOT connected to external AC, BIOS upgrade not possible, terminating script" -Severity 3; exit 1
        }
    }
    else{
        global:Write-CMLogEntry -Value "Info: This is not an laptop, skipping battery check" -Severity 1
    }
    # Suspend Bitlocker on C-Drive if needed, should not be required in WinPE
    $IsOSWinPE=Get-IsOSWinPE
    if($IsOSWinPE -eq $False){
        if(Get-BitlockerProtectionStatus_C -eq $true){
            global:Write-CMLogEntry -Value "Info: C-drive is protected with Bitlocker, suspening Bitlocker on C: drive " -Severity 1
            $Output=Suspend-BitLocker -MountPoint C:
        }
    }

    # Build download URL and download BIOS file
    $LenovoBIOSEXEURL=($LenovoBIOSURL | Split-Path).Replace("\","/")+'/'+$LenovoBIOSEXEFileName
    global:Write-CMLogEntry -Value "Info: BIOS Download URL: $LenovoBIOSEXEURL" -Severity 1
    Invoke-WebRequest -Uri $LenovoBIOSEXEURL -OutFile .\$LenovoBIOSEXEFileName

    # Check FileHash, SHA256 hashdata in xmlfile, return data is in SHA1 format
    $LenovoNewBIOSFileHash=$LenovoBIOSXML.Package.Files.Installer.File.CRC
    $LenovoDownloadedBIOSFileHash=Get-FileHash -Path ($StartPath+'\'+$LenovoBIOSEXEFileName) -Algorithm SHA1 | Select -ExpandProperty Hash
    if($LenovoNewBIOSFileHash -eq $LenovoDownloadedBIOSFileHash){
        global:Write-CMLogEntry -Value "Info: Downloaded BIOS SHA1 filehash is correct" -Severity 1
    }
    else{
        #global:Write-CMLogEntry -Value "Info: Downloaded SHA1 filehash mismatch, script will terminate" -Severity 3; exit 1
        global:Write-CMLogEntry -Value "Info: Downloaded SHA1 filehash mismatch, will continue anyway" -Severity 2
    }

    # Extract downloaded content, %PACKAGEPATH% must be set
    $LenovoBIOSExtractString=$LenovoBIOSXML.Package | Select -ExpandProperty ExtractCommand
    $Env:PACKAGEPATH=$TempDirectory
    # Example $LenovoBIOSExtractString: gjuj31us.exe /VERYSILENT /DIR=%PACKAGEPATH% /EXTRACT="YES"
    global:Write-CMLogEntry -Value "Info: Expanding BIOS file to Directory: $TempDirectory" -Severity 1
    Start-Process cmd.exe -WorkingDirectory ($StartPath) -ArgumentList (" /c "+$LenovoBIOSExtractString) -NoNewWindow -Wait

    # Install BIOS file based upon Installstrings in XML
    $LenovoBIOSInstallString=$LenovoBIOSXML.Package.Install.Cmdline.'#text'
    $LenovoBIOSInstallString=$LenovoBIOSInstallString.Replace("-r","-s")
    $BIOSLogFilePath=($TempDirectory+'\Winuptp.log')
    global:Write-CMLogEntry -Value "Info: BIOS Upgrade log: $BIOSLogFilePath" -Severity 1

    # Modify Install string to parse BIOS password if needed.
    if($BIOSPassword -eq $null){
        global:Write-CMLogEntry -Value "Info: No BIOS Password set" -Severity 1
    }
    elseif($BIOSPassword -ne $null){
        global:Write-CMLogEntry -Value "Error: Logics for BIOS password for Lenovo is not implemented yet" -Severity 3; exit 1
    }

	try {
        if(Get-IsOSWinPE -eq $True){
            global:Write-CMLogEntry -Value "Info: WinPE detected" -Severity 1
            global:Write-CMLogEntry -Value "Error: Lenovo BIOS files can't be expanded within WinPE, script will terminate" -Severity 3; exit 1
        }
        elseif(Get-IsTSRunning -eq $True){
            global:Write-CMLogEntry -Value "Info: TaskSequenceMode detected" -Severity 1
            global:Write-CMLogEntry -Value "Info: BIOS Upgrade will start now" -Severity 1
            Start-Process cmd.exe -WorkingDirectory ($env:PACKAGEPATH) -ArgumentList (" /c "+$LenovoBIOSInstallString) -Wait
            $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
            $tsenv.Value("CustRestartRequired")=$True
            exit 3010 
        }
        else{
            global:Write-CMLogEntry -Value "Info: Intune Mode detected, reboot will be enforced after BIOS Upgrade with a deplay of 10 minutes" -Severity 1
            #global:Write-CMLogEntry -Value "Info: Normal GUI Mode detected, reboot will be enforced after BIOS Upgrade" -Severity 1
            Start-Process cmd.exe -WorkingDirectory ($env:PACKAGEPATH) -ArgumentList (" /c "+$LenovoBIOSInstallString) -Wait
            #Invoke-RestartComputerWithMsg
            shutdown /r /t 600 /c "Restart needed due to BIOS upgrade"
        }
	}
	catch {
		global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
	}
}

function Invoke-RestartComputerWithMsg {
    $wshell = New-Object -ComObject Wscript.Shell
    $Output=$wshell.Popup("This computer is scheduled for restart due to BIOS upgrade",10,"Save Data NOW",0x0)
    $Output=$wshell.Popup("60 seconds to restart",10,"Save you document now",0x0)
    $xCmdString = {sleep 60}
    Invoke-Command $xCmdString
    Restart-Computer -ComputerName $env:COMPUTERNAME
}

function Get-IsTSRunning {
    try {
        $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
        if($tsenv){
            return $true
        }
        else{
            return $false
        }
    }
    catch [System.Exception] {
        if(!($tsenv)){
            return $false
        }
    }
}

# // =================== Main ================ //
global:Write-CMLogEntry -Value "=================== Start ================" -Severity 1

global:Write-CMLogEntry -Value "Info: Start Path is $StartPath" -Severity 1
global:Write-CMLogEntry -Value "Info: Temp directory is $global:TempDirectory" -Severity 1
global:Write-CMLogEntry -Value "Info: log directory is $global:LogDirectory" -Severity 1

# Dell Area
if((Get-WmiObject -Class Win32_BIOS).Manufacturer -match "Dell"){
    global:Write-CMLogEntry -Value "Info: Dell PC detected" -Severity 1
    # Get info from Dell site regarding the model and BIOS, URL etc
    $DellBiosFinder=Start-DellBiosFinder -Model (Get-WmiObject -Class win32_computersystem | select -ExpandProperty Model)

    $CurrentBIOSVersion=Get-WmiObject -Class win32_bios | Select -ExpandProperty SMBIOSBIOSVersion
    $NewBIOSVersion=$DellBiosFinder | Select dellVersion | Select -ExpandProperty dellVersion

    $IsBIOSUpgradeNeeded=Get-DellIsBIOSUpgradeNeeded -NewBIOSVersion $NewBIOSVersion
    #$IsBIOSUpgradeNeeded=$true # Testing only logics.

    if($IsBIOSUpgradeNeeded -eq $True){
        #Write-Host BIOS Upgrade needed Current version: $LenovoCurrentBIOSVersion New version: $NewLenovoBIOSVersion -ForegroundColor Green
        Start-DellBIOSUpgrade
    }
    else {
        global:Write-CMLogEntry -Value "Info: BIOS Upgrade is not needed, Current BIOS is up to date already: $CurrentBIOSVersion" -Severity 1
    }
}

# Lenovo Area 
if((Get-WmiObject -Class Win32_BIOS).Manufacturer -match "Lenovo"){
    try {
        global:Write-CMLogEntry -Value "Info: Lenovo PC detected" -Severity 1

        # Read computer type info from WMI type 20B7, (20AQ - T440s)
        # Can this be a hit and miss ? Model $null or something like that ?
        $LenovoTypeModel=((Get-WmiObject -Class Win32_Computersystem).Model).Substring("0","4") 
        # $LenovoTypeModel="10FM" # Testing only logics.
        # $LenovoTypeModels="2325","20AM","20BH","20AR","20AL","20CM","20BX","20CK","10HS","20EQ","2OCM","20F5","20FA","10NE","20FX","m900","10MV","20J6","20HN","20HF","4291","20HH","2429","10FM"
        # Not OK models, m900,4291(X220),10FM(Thinkcentre M900 - SHA1 hash error)
        global:Write-CMLogEntry -Value "Info: Lenovo Type: $LenovoTypeModel" -Severity 1

        # Build URL string download catalog file based upon Lenovo model type
        $LenovoTypeModelCatalog=$LenovoBaseCatalogURL+$LenovoTypeModel+$LenovoBaseCatalogURLEnd
        global:Write-CMLogEntry -Value "Info: Lenovo Type Model Catalog URL: $LenovoTypeModelCatalog" -Severity 1
        Invoke-WebRequest -Uri $LenovoTypeModelCatalog -OutFile .\LenovoTypeModelCatalog.xml
    
        # Extract URL from XML regarding BIOS info for english and not japan (pccbbs filter)
        $LenovoTypeModelCatalogXML=[xml](Get-Content .\LenovoTypeModelCatalog.xml)
        $LenovoBIOSURL=$LenovoTypeModelCatalogXML.packages.package | where {$_.Category -match "BIOS" -and $_.location -match "pccbbs"} | Select -ExpandProperty location
        global:Write-CMLogEntry -Value "Info: Lenovo BIOS URL: $LenovoBIOSURL" -Severity 1
    
        # It's time to find the filename of the BIOS EXE, basepath is always the same.
        Invoke-WebRequest -uri $LenovoBIOSURL -OutFile .\LenovoBIOSURL.xml
        $LenovoBIOSXML=[xml](Get-Content -Path .\LenovoBIOSURL.xml)
        $LenovoBIOSEXEFileName=$LenovoBIOSXML.Package.Files.Installer.File | Select -ExpandProperty Name
        global:Write-CMLogEntry -Value "Info: Lenovo BIOS File: $LenovoBIOSEXEFileName" -Severity 1
    
        # find new BIOS version from XML
        $NewLenovoBIOSVersion=[version](($LenovoBIOSXML.Package | select -ExpandProperty Version).Substring("0","4"))
        global:Write-CMLogEntry -Value "Info: Latest BIOS version: $NewLenovoBIOSVersion" -Severity 1
    
        # Read Current BIOS version from local computer with WMI
        $LenovoSMBIOSBIOSVersion=(Get-WmiObject -Class Win32_BIOS).SMBIOSBIOSVersion
        # $LenovoSMBIOSBIOSVersion="G2ET90WW (2.50 )" 
        # Some BIOS has no version number in string, check for date then, logics for that is not implemented yet.
        $LenovoCurrentBIOSVersion=[version]$LenovoSMBIOSBIOSVersion.Substring("10","4")
        # $LenovoCurrentBIOSVersion=[version]("1.0") # Override logics for testing

        global:Write-CMLogEntry -Value "Info: Current BIOS version: $LenovoCurrentBIOSVersion" -Severity 1
    
        # check if BIOS needs to be updated? 
        if($NewLenovoBIOSVersion -gt $LenovoCurrentBIOSVersion){
            global:Write-CMLogEntry -Value "Info: BIOS upgrade is needed" -Severity 1
            Start-LenovoBIOSUpgrade
        }
        else{
            global:Write-CMLogEntry -Value "Info: BIOS Upgrade not needed BIOS version is $LenovoSMBIOSBIOSVersion" -Severity 1
        }
    }
    catch {
		global:Write-CMLogEntry -Value "Error: $($_.Exception.Message)" -Severity 3
	}
}

#DetectionRule and logfile for Intune
$Output=New-Item -Path "C:\ProgramData\Custom\Intune\DetectionChecks\Invoke-BIOSUpgrade.txt" -Force
$out=New-Item -Path C:\ProgramData\Custom\Intune\ -ItemType Directory -Name Logs -Force
$Output=Copy-Item -Path ($global:LogDirectory+"\Invoke-BIOSUpgrade.log") -Destination "C:\ProgramData\Custom\Intune\Logs\Invoke-BIOSUpgrade.log" -Force

