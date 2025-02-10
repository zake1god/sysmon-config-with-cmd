# Enable PowerShell Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"

# Enable PowerShell Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable Command Line Process Creation Auditing
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Update group policy settings
gpupdate /force

# Test PowerShell logging
Write-Host "Test PowerShell Log Zake"

# Test CMD logging
Write-Host "ping zake.com -a"

# Install and configure Sysmon
sysmon.exe -i sysmonconfig-custom-by-zake.xml -accepteula

# Configure Splunk Universal Forwarder
# Adjust paths and restart service
$ConfFile = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$Config = @"
[WinEventLog://Security]
disabled = 0
index = fmi_internal
sourcetype = Wineventlog:Security

[WinEventLog://System]
disabled = 0
index = fmi_internal
sourcetype = Wineventlog:System

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = fmi_internal
sourcetype = WinEventLog:PowerShell
"@
Out-File -FilePath $ConfFile -InputObject $Config -Encoding ASCII

# Restart Splunk Forwarder
net stop splunkforwarder
net start splunkforwarder

# Verify that logs are created
Write-Host "Setup completed, verify logs in Event Viewer and Splunk"
