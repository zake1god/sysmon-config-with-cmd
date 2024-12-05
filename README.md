# Custom Sysmon configuration, add read CMD And Powershell by Zake #

This updated Sysmon configuration file has been customized to improve logging for **Command Prompt (cmd.exe)** and **PowerShell** activities. The configuration captures detailed information about command-line processes, ensuring visibility into executed commands, including their arguments. It is especially valuable for monitoring security-related events in environments where both cmd.exe and PowerShell are used extensively.

## Features

### 1. CMD Logging
- **Captures commands executed in `cmd.exe`**:
  - Includes full command-line arguments, e.g., `ping zake.com -a`.
  - Tracks all process creation events initiated from `cmd.exe`.
- **Parent-Child Process Tracking**:
  - Logs details about child processes spawned by `cmd.exe` (e.g., `ping.exe`).

### 2. PowerShell Logging
- **Tracks PowerShell Executions**:
  - Logs commands and script blocks executed via `powershell.exe`, `powershell_ise.exe`, and `pwsh.exe` (PowerShell Core).
  - Captures full command-line arguments for PowerShell processes.
- **Complements Native Logging**:
  - Works alongside Windows' Script Block Logging for more comprehensive monitoring.

### 3. Detailed Process Logging
- **Event ID 1 (Process Creation)**:
  - Captures process creation events, including parent-child relationships.
  - Logs executed commands with full arguments.
- **Parent-Child Process Relationships**:
  - Links parent processes (e.g., `cmd.exe`, `powershell.exe`) to child processes.

### 4. Use Cases
- Security auditing and forensic investigations.
- Detection of suspicious activity such as unauthorized scripts or commands.
- Monitoring administrative tasks executed via cmd.exe or PowerShell.

## How to Deploy

1. **Download the Configuration File**:
   - Use the provided `sysmonconfig-modified-powershell.xml`.

2. **Apply the Configuration**:
   Run the following command with administrative privileges:
   ```bash
   sysmon -c sysmonconfig-modified-powershell.xml
   ```

3. **Verify Sysmon Service**:
   Ensure the Sysmon service is running:
   ```bash
   sc query sysmon
   ```

4. **Enable Windows Audit Policies** (optional but recommended):
   - To capture `CommandLine` details in security logs, enable **Audit Command Line Process Creation**:
     ```powershell
     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
     ```
   - Apply group policy updates:
     ```bash
     gpupdate /force
     ```

## Where to Find the Logs

### CMD Logs
- **Location**: 
  - `Event Viewer > Windows Logs > Security`
- **Event ID**: 
  - `4688`
- **Details Captured**:
  - Command-line arguments if `Audit Command Line Process Creation` is enabled.

### PowerShell Logs
- **Location**:
  - `Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`
- **Event IDs**:
  - `4104` (Script Blocks)
  - `4103` (Modules)
- **Details Captured**:
  - Commands, script blocks, and module activities.

## Benefits
- Comprehensive visibility into command-line and script execution activities.
- Early detection of unauthorized or malicious activity.
- Enhanced forensic and auditing capabilities for compliance and security monitoring.

This configuration is a valuable tool for system administrators and security professionals aiming to strengthen monitoring and incident response processes.


## Use ##
### Install ###
Run with administrator rights
~~~~
sysmon.exe -i sysmonconfig-export.xml -accepteula
~~~~

### Update existing configuration ###
Run with administrator rights
~~~~
sysmon.exe -c sysmonconfig-export.xml
~~~~

### Uninstall ###
Run with administrator rights
~~~~
sysmon.exe -u
~~~~

## Required actions ##

### Prerequisites ###
Highly recommend using [Notepad++](https://notepad-plus-plus.org/) to edit this configuration. It understands UNIX newline format and does XML syntax highlighting, which makes this very understandable. I do not recommend using the built-in Notepad.exe.

### Customization ###
You will need to install and observe the results of the configuration in your own environment before deploying it widely. For example, you will need to exclude actions of your antivirus, which will otherwise likely fill up your logs with useless information.

The configuration is highly commented and designed to be self-explanatory to assist you in this customization to your environment.

### Design notes ###
This configuration expects software to be installed system-wide and NOT in the C:\Users folder. Various pieces of software install themselves in User directories, which are subject to extra monitoring. Where possible, you should install the system-wide version of these pieces of software, like Chrome. See the configuration file for more instructions.

### Credit ### 
I just update it, Original config is from [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
