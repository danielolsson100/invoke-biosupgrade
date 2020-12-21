# DetectionRule logics by Daniel Olsson - AddPro

$FileNameAndPath="C:\ProgramData\Custom\Intune\DetectionChecks\Invoke-BIOSUpgrade.txt"
$RerunIterval="30"
$RerunItervalDateTime=(Get-Date).AddDays(-$RerunIterval)

if(Test-Path -Path $FileNameAndPath){   
    if((Get-ChildItem -Path $FileNameAndPath | Select -ExpandProperty LastWriteTime) -ge $RerunItervalDateTime ){
        Return $True
    }
}
