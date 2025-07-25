#Requires -RunAsAdministrator

# --- Initialize Summary Data Structure FIRST ---
$scriptSummary = [System.Collections.Generic.List[PSCustomObject]]::new()

# --- Summary Status Constants ---
$StatusOk = "OK"
$StatusInfo = "INFO"
$StatusWarning = "WARNING"
$StatusError = "ERROR"
$StatusAction = "ACTION_REQUIRED"
$StatusCheckOutput = "CHECK_OUTPUT"
$StatusNeutral = "NEUTRAL" # For items that are just informational steps

# Ensure log directory exists
$logDir = "C:\Scripts\Logs"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $logDir)) {
        Write-Host "FATAL: Failed to create log directory: $logDir. Please create it manually and ensure permissions." -ForegroundColor Red
        # Now $scriptSummary is initialized, so this line is safe
        $scriptSummary.Add([PSCustomObject]@{ Section = "Log Directory"; Status = $StatusError; Details = "Failed to create $logDir" })
        # Since logging depends on this, we should exit if it fails. The summary will be minimal.
        # To show the summary before exiting, we need to call the function here, or just accept minimal logging.
        # For simplicity, we'll exit. The error is already on console.
        exit 1
    }
}
$logFile = "$logDir\TroubleshootLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Enhanced Log function with severity and color coding for console
function Log {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Good", "Warning", "Error", "Action", "Neutral", "Heading", "SubHeading", "Detail")]
        [string]$Severity = "Info"
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $timestampedMessageForConsole = "[$timestamp] $Message"
    $plainMessageForLog = "[$timestamp] $Message"

    if ($Severity -eq "Heading" -or $Severity -eq "SubHeading") {
        $plainMessageForLog = "`n[$timestamp] $Message"
    }

    $color = "White"
    switch ($Severity) {
        "Info"       { $color = "White" }
        "Good"       { $color = "Green" }
        "Warning"    { $color = "Yellow" }
        "Error"      { $color = "Red" }
        "Action"     { $color = "Magenta"}
        "Neutral"    { $color = "Cyan" }
        "Heading"    { $color = "Yellow"; Write-Host ""; } # Add a blank line before headings in console
        "SubHeading" { $color = "Cyan" }
        "Detail"     { $color = "Gray" }
    }
    Write-Host $timestampedMessageForConsole -ForegroundColor $color

    try {
        Add-Content -Path $logFile -Value $plainMessageForLog -ErrorAction Stop
    } catch {
        Write-Host "[$timestamp] CRITICAL: Failed to write to log file $logFile. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Function to Display Summary ---
function Show-ScriptSummary {
    Log "---- SCRIPT EXECUTION SUMMARY ----" -Severity "Heading"
    if ($scriptSummary.Count -eq 0) {
        Log "No summary data was collected." -Severity "Warning"
        return
    }

    # For better formatting of the summary in the log file
    $summaryForLogFile = [System.Collections.Generic.List[string]]::new()
    $summaryForLogFile.Add("`n---- SCRIPT EXECUTION SUMMARY ----") # Add extra newline for log file
    foreach ($item in $scriptSummary) {
        $logLine = "{0,-30} : {1,-18}" -f $item.Section, $item.Status
        if (-not [string]::IsNullOrWhiteSpace($item.Details)) {
            $logLine += " - $($item.Details)"
        }
        $summaryForLogFile.Add($logLine)
    }
    $summaryForLogFile.Add("------------------------------") # Footer for log summary
    Add-Content -Path $logFile -Value ($summaryForLogFile -join "`r`n")


    # Output to console with color (using Log function for consistency in timestamping and color)
    foreach ($item in $scriptSummary) {
        $summaryLine = "{0,-30} : {1,-18}" -f $item.Section, $item.Status # Adjusted spacing
        if (-not [string]::IsNullOrWhiteSpace($item.Details)) {
            $summaryLine += " - $($item.Details)"
        }

        $logSeverity = "Info"
        switch ($item.Status) {
            $StatusOk           { $logSeverity = "Good" }
            $StatusInfo         { $logSeverity = "Info" }
            $StatusWarning      { $logSeverity = "Warning" }
            $StatusError        { $logSeverity = "Error" }
            $StatusAction       { $logSeverity = "Action" }
            $StatusCheckOutput  { $logSeverity = "Warning" }
            $StatusNeutral      { $logSeverity = "Neutral" }
        }
        # Use a non-timestamped log for summary for cleaner console output, direct Write-Host might be better here.
        # Let's use direct Write-Host for the summary in console to avoid double timestamps and keep it compact
        $consoleColor = "White"
         switch ($item.Status) {
            $StatusOk           { $consoleColor = "Green" }
            $StatusInfo         { $consoleColor = "White" }
            $StatusWarning      { $consoleColor = "Yellow" }
            $StatusError        { $consoleColor = "Red" }
            $StatusAction       { $consoleColor = "Magenta" }
            $StatusCheckOutput  { $consoleColor = "Yellow" }
            $StatusNeutral      { $consoleColor = "Cyan" }
        }
        Write-Host $summaryLine -ForegroundColor $consoleColor
    }
}


Log "===== MASTER TROUBLESHOOT SCRIPT STARTED: $(Get-Date) =====" -Severity "Heading"
$isAdmin = $([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "Running as elevated user: $isAdmin" -Severity "Detail"
Log "Log file: $logFile" -Severity "Detail"
if (-not $isAdmin) {
    Log "SCRIPT MUST RUN AS ADMINISTRATOR. Some operations will fail." -Severity "Error"
    $scriptSummary.Add([PSCustomObject]@{ Section = "Permissions"; Status = $StatusError; Details = "Not running as Administrator." })
    # Optionally exit here, or let it continue and fail on operations. For now, let it continue.
} else {
    $scriptSummary.Add([PSCustomObject]@{ Section = "Permissions"; Status = $StatusOk; Details = "Running as Administrator." })
}


# 1. System Info
Log "---- 1. SYSTEM INFO ----" -Severity "Heading"
$sysInfoStatus = $StatusError
$sysInfoDetails = "Failed to retrieve system info."
try {
    $sysInfo = (Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsBuildNumber, WindowsProductName, OsArchitecture, OsLastBootUpTime | Format-List | Out-String).TrimEnd()
    Log $sysInfo -Severity "Good"
    $LastBootUpTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $Uptime = (Get-Date) - $LastBootUpTime
    Log "System Uptime: $($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes" -Severity "Good"
    $sysInfoStatus = $StatusOk
    $sysInfoDetails = "Successfully retrieved."
} catch {
    Log "Error retrieving System Info: $($_.Exception.Message)" -Severity "Error"
    $sysInfoDetails = "Exception: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "System Info"; Status = $sysInfoStatus; Details = $sysInfoDetails })


# 2. Disk Space (C: Drive)
Log "---- 2. DISK SPACE (C: DRIVE) ----" -Severity "Heading"
$diskSpaceStatus = $StatusError
$diskSpaceDetails = "Failed to retrieve disk space."
$lowSpaceFlag = $false # Keep this if used elsewhere, though summary handles the flag
try {
    $diskC_cim = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    if ($diskC_cim -and $diskC_cim.Size -gt 0) {
        $fileSystemLabel = "N/A"
        try {
            $volumeInfo = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue
            if ($volumeInfo) { $fileSystemLabel = $volumeInfo.FileSystemLabel }
        } catch { Log "Note: Could not retrieve FileSystemLabel via Get-Volume for C:." -Severity "Warning" }

        $percentFreeValue = $diskC_cim.FreeSpace/$diskC_cim.Size
        $diskInfoString = ($diskC_cim | Select-Object @{Name="DriveLetter";Expression={$_.DeviceID}},
                                    @{Name="FileSystemLabel";Expression={$fileSystemLabel}},
                                    @{Name="Size(GB)";Expression={"{0:N2}" -f ($_.Size/1GB)}},
                                    @{Name="FreeSpace(GB)";Expression={"{0:N2}" -f ($_.FreeSpace/1GB)}},
                                    @{Name="PercentFree";Expression={"{0:P0}" -f $percentFreeValue}} | Format-List | Out-String).TrimEnd()
        Log $diskInfoString -Severity "Good"
        $diskSpaceStatus = $StatusOk
        $diskSpaceDetails = "Free: {0:P0}" -f $percentFreeValue

        if ($percentFreeValue * 100 -lt 15) {
            Log "WARNING: Low disk space on C: drive (less than 15% free)." -Severity "Action"
            $diskSpaceStatus = $StatusAction
            $diskSpaceDetails += " - LOW SPACE WARNING!"
        }
    } else {
        Log "Could not retrieve valid disk space information for C: drive using Get-CimInstance." -Severity "Error"
        $diskSpaceDetails = "Get-CimInstance failed or returned invalid data."
        # Fallback attempt
        $diskC_volume_fallback = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue
        if ($diskC_volume_fallback -and $diskC_volume_fallback.Size -gt 0) {
            $fallbackPercentFree = $diskC_volume_fallback.FreeSpace/$diskC_volume_fallback.Size
            Log ( ($diskC_volume_fallback | Select-Object DriveLetter, FileSystemLabel, @{Name="Size(GB)";Expression={"{0:N2}" -f ($_.Size/1GB)}}, @{Name="FreeSpace(GB)";Expression={"{0:N2}" -f ($_.FreeSpace/1GB)}}, @{Name="PercentFree";Expression={"{0:P0}" -f $fallbackPercentFree}} | Format-List | Out-String).TrimEnd() ) -Severity "Warning"
            $diskSpaceStatus = $StatusWarning
            $diskSpaceDetails = "Using Get-Volume fallback. Free: {0:P0}" -f $fallbackPercentFree
            if ($fallbackPercentFree * 100 -lt 15) {
                Log "WARNING (from Get-Volume fallback): Low disk space on C: drive (less than 15% free)." -Severity "Action"
                $diskSpaceStatus = $StatusAction # Escalate to Action if low space
                $diskSpaceDetails += " - LOW SPACE WARNING (fallback)!"
            }
        } else {
            Log "Fallback Get-Volume C also failed or returned invalid data." -Severity "Error"
        }
    }
} catch {
    Log "Critical error retrieving disk space for C:: $($_.Exception.Message)" -Severity "Error"
    $diskSpaceDetails = "Exception: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Disk Space (C:)"; Status = $diskSpaceStatus; Details = $diskSpaceDetails })


# 3. Event Logs (System & Application Errors)
Log "---- 3. RECENT SYSTEM ERRORS (Last 10 Errors) ----" -Severity "Heading"
$systemErrorsStatus = $StatusError
$systemErrorsDetails = "Failed to query System event log."
$systemErrorCount = 0
try {
    $systemErrors = Get-WinEvent -LogName System -MaxEvents 50 | Where-Object {$_.LevelDisplayName -eq "Error"} | Select-Object -First 10 -ErrorAction Stop
    if ($systemErrors) {
        $systemErrorCount = ($systemErrors | Measure-Object).Count
        Log "Found $systemErrorCount recent System error(s):" -Severity "Action"
        Log ($systemErrors | Format-List TimeCreated, ProviderName, Id, Message | Out-String).TrimEnd() -Severity "Action"
        $systemErrorsStatus = $StatusAction
        $systemErrorsDetails = "$systemErrorCount error(s) found."
    } else {
        Log "No recent 'Error' level events found in System log." -Severity "Good"
        $systemErrorsStatus = $StatusOk
        $systemErrorsDetails = "No errors found."
    }
} catch {
    Log "Error querying System Event Log: $($_.Exception.Message)" -Severity "Error"
    $systemErrorsDetails = "Exception: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Recent System Errors"; Status = $systemErrorsStatus; Details = $systemErrorsDetails })

Log "---- 4. RECENT APPLICATION ERRORS (Last 10 Errors) ----" -Severity "Heading"
$appErrorsStatus = $StatusError
$appErrorsDetails = "Failed to query Application event log."
$appErrorCount = 0
try {
    $appErrors = Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object {$_.LevelDisplayName -eq "Error"} | Select-Object -First 10 -ErrorAction Stop
    if ($appErrors) {
        $appErrorCount = ($appErrors | Measure-Object).Count
        Log "Found $appErrorCount recent Application error(s):" -Severity "Action"
        Log ($appErrors | Format-List TimeCreated, ProviderName, Id, Message | Out-String).TrimEnd() -Severity "Action"
        $appErrorsStatus = $StatusAction
        $appErrorsDetails = "$appErrorCount error(s) found."
    } else {
        Log "No recent 'Error' level events found in Application log." -Severity "Good"
        $appErrorsStatus = $StatusOk
        $appErrorsDetails = "No errors found."
    }
} catch {
    Log "Error querying Application Event Log: $($_.Exception.Message)" -Severity "Error"
    $appErrorsDetails = "Exception: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Recent Application Errors"; Status = $appErrorsStatus; Details = $appErrorsDetails })


# 5. Pending Reboot Check
Log "---- 5. PENDING REBOOT CHECK ----" -Severity "Heading"
$rebootPendingOverallStatus = $StatusOk # Renamed from rebootPendingStatus to avoid confusion
$rebootPendingOverallDetails = "No reboot indicators found." # Renamed
$rebootIsActuallyPending = $false # Renamed from rebootIsPending
$rebootReasonsListForSummary = [System.Collections.Generic.List[string]]::new() # Renamed

try {
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") { $rebootReasonsListForSummary.Add("Pending File Renames"); $rebootIsActuallyPending = $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $rebootReasonsListForSummary.Add("Windows Update"); $rebootIsActuallyPending = $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $rebootReasonsListForSummary.Add("Component Based Servicing"); $rebootIsActuallyPending = $true }

    if (-not $rebootIsActuallyPending) {
        Log "No common indicators of a pending reboot found." -Severity "Good"
    } else {
        $reasonsString = $rebootReasonsListForSummary -join ", "
        Log "Reboot pending due to: $reasonsString" -Severity "Action"
        Log "RECOMMENDATION: Consider rebooting the system soon." -Severity "Action"
        $rebootPendingOverallStatus = $StatusAction
        $rebootPendingOverallDetails = "Reboot required for: $reasonsString"
    }
} catch {
    Log "Error checking for pending reboot: $($_.Exception.Message)" -Severity "Error"
    $rebootPendingOverallStatus = $StatusError
    $rebootPendingOverallDetails = "Exception during check: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Pending Reboot Check"; Status = $rebootPendingOverallStatus; Details = $rebootPendingOverallDetails })


# 6. Critical Services Status
Log "---- 6. CRITICAL SERVICES STATUS ----" -Severity "Heading"
$servicesOverallStatus = $StatusOk # Renamed
$servicesOverallDetails = "All critical services checked are running." # Renamed
$servicesNotRunningCount = 0
$servicesErrorCount = 0
$criticalServices = @("BITS", "CryptSvc", "Dhcp", "Dnscache", "eventlog", "RpcSs", "Schedule", "wuauserv")

foreach ($serviceName in $criticalServices) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq "Running") {
            Log ("Service: $($service.DisplayName) (`$($service.Name)`) - Status: $($service.Status)") -Severity "Good"
        } else {
            Log ("Service: $($service.DisplayName) (`$($service.Name)`) - Status: $($service.Status)") -Severity "Action"
            Log "  WARNING: Service $($service.DisplayName) is not running." -Severity "Action"
            $servicesNotRunningCount++
        }
    } catch {
        Log "Service: $serviceName - Error retrieving status: $($_.Exception.Message)" -Severity "Error"
        $servicesErrorCount++
    }
}
if ($servicesErrorCount -gt 0) {
    $servicesOverallStatus = $StatusError
    $servicesOverallDetails = "$servicesErrorCount service(s) had errors during check."
    if ($servicesNotRunningCount -gt 0) { $servicesOverallDetails += " Additionally, $servicesNotRunningCount service(s) not running." }
} elseif ($servicesNotRunningCount -gt 0) {
    $servicesOverallStatus = $StatusAction
    $servicesOverallDetails = "$servicesNotRunningCount critical service(s) not running."
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Critical Services"; Status = $servicesOverallStatus; Details = $servicesOverallDetails })


# 7. Basic Network Connectivity Tests
Log "---- 7. BASIC NETWORK CONNECTIVITY TESTS ----" -Severity "Heading"
$networkOverallStatus = $StatusOk # Renamed
$networkOverallDetails = "All pings successful." # Renamed
$pingFailCount = 0
$testHosts = @("8.8.8.8", "1.1.1.1", "google.com")
foreach ($hostName in $testHosts) {
    Log "Pinging $hostName..." -Severity "Neutral"
    $pingSucceeded = $false
    try {
        # Test-NetConnection with -Quiet is good for a quick boolean check
        if (Test-NetConnection -ComputerName $hostName -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop) {
            Log "  Ping to ${hostName}: Succeeded" -Severity "Good"
            $pingSucceeded = $true
        } else {
            Log "  Ping to ${hostName}: FAILED (basic test)" -Severity "Action"
            # If quiet test fails, then run the full test for details
            $detailedTest = Test-NetConnection -ComputerName $hostName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            if ($detailedTest) {
                Log ("  Detailed Test-NetConnection for $hostName (FAILURE DETAILS):" + ($detailedTest | Select-Object ComputerName,PingSucceeded,PingReplyDetails*,TcpTestSucceeded,HttpTestSucceeded | Format-List | Out-String).TrimEnd()) -Severity "Action"
            } else {
                 Log "  Detailed Test-NetConnection for ${hostName} also returned no results or failed to execute." -Severity "Warning"
            }
        }
    } catch { # Catch errors from Test-NetConnection itself (e.g., if cmdlet has issues)
        Log "  Ping to ${hostName}: FAILED (Exception during Test-NetConnection: $($_.Exception.Message))" -Severity "Error"
    }
    if (-not $pingSucceeded) { $pingFailCount++ }
}
if ($pingFailCount -gt 0) {
    $networkOverallStatus = $StatusAction
    $networkOverallDetails = "$pingFailCount host(s) failed to ping."
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Network Connectivity"; Status = $networkOverallStatus; Details = $networkOverallDetails })


# 8. Recently Installed Software (Last 5)
Log "---- 8. RECENTLY INSTALLED SOFTWARE (Last 5) ----" -Severity "Heading"
$recentSwOverallStatus = $StatusError # Renamed
$recentSwOverallDetails = "Failed to retrieve software list." # Renamed
try {
    $installedSoftware = @()
    $uninstallPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
    foreach ($path in $uninstallPaths) {
        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
        if ($items) { $installedSoftware += $items | Where-Object {$_.DisplayName -and $_.InstallDate} }
    }
    if ($installedSoftware.Count -gt 0) {
        $recentSoftware = ($installedSoftware | Sort-Object @{Expression={ try { [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null) } catch { Get-Date "1/1/1900" }}} -Descending | Select-Object -First 5 DisplayName, DisplayVersion, InstallDate, Publisher | Format-Table -AutoSize | Out-String).TrimEnd()
        Log $recentSoftware -Severity "Good"
        $recentSwOverallStatus = $StatusOk
        $recentSwOverallDetails = "Displayed last 5."
    } else {
        Log "Could not retrieve list of installed software or no software with install dates found." -Severity "Warning"
        $recentSwOverallStatus = $StatusWarning
        $recentSwOverallDetails = "No software with install dates found or list unavailable."
    }
} catch {
    Log "Error retrieving recently installed software: $($_.Exception.Message)" -Severity "Error"
    $recentSwOverallDetails = "Exception: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Recently Installed Software"; Status = $recentSwOverallStatus; Details = $recentSwOverallDetails })


# 9. Startup Programs (WMI Win32_StartupCommand)
Log "---- 9. STARTUP PROGRAMS (via Win32_StartupCommand) ----" -Severity "Heading"
$startupOverallStatus = $StatusError # Renamed
$startupOverallDetails = "Failed to retrieve startup items." # Renamed
try {
    $startupItems = Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String
    if ($startupItems.Trim()) {
        Log $startupItems.TrimEnd() -Severity "Good"
        $startupOverallStatus = $StatusOk
        $startupOverallDetails = "Displayed."
    } else {
        Log "No startup items found via Win32_StartupCommand." -Severity "Info"
        $startupOverallStatus = $StatusInfo
        $startupOverallDetails = "No items found (Win32_StartupCommand)."
    }
} catch {
    Log "Error retrieving startup items: $($_.Exception.Message)" -Severity "Warning"
    $startupOverallStatus = $StatusWarning
    $startupOverallDetails = "Error during retrieval: $($_.Exception.Message)"
}
$scriptSummary.Add([PSCustomObject]@{ Section = "Startup Programs (WMI)"; Status = $startupOverallStatus; Details = $startupOverallDetails })


# 10. Cleanup Temp and Prefetch
Log "---- 10. CLEANING TEMP AND PREFETCH ----" -Severity "Heading"
$cleanupOverallStatus = $StatusOk # Renamed
$cleanupOverallDetails = "All cleanup tasks attempted successfully." # Renamed
$cleanupErrorsList = [System.Collections.Generic.List[string]]::new() # Renamed

Log "Attempting to clear user TEMP folder: $env:TEMP" -Severity "Neutral"
try { Remove-Item "$env:TEMP\*" -Force -Recurse -ErrorAction Stop; Log "User TEMP folder items cleared." -Severity "Good" }
catch { Log "Error clearing user TEMP folder: $($_.Exception.Message)" -Severity "Error"; $cleanupErrorsList.Add("User TEMP (Error)") }

Log "Attempting to clear Windows Prefetch folder: C:\Windows\Prefetch" -Severity "Neutral"
try { Remove-Item "C:\Windows\Prefetch\*" -Force -Recurse -ErrorAction Stop; Log "Windows Prefetch folder items cleared." -Severity "Good" }
catch { Log "Error clearing Windows Prefetch folder: $($_.Exception.Message)." -Severity "Warning"; $cleanupErrorsList.Add("Prefetch (Warning)") }

if ($cleanupErrorsList.Count -gt 0) {
    $cleanupOverallStatus = if ($cleanupErrorsList -match "Error") { $StatusError } else { $StatusWarning } # Check if any error was critical
    $cleanupOverallDetails = "Issues with: $($cleanupErrorsList -join ', ')."
}
Log "Temp and Prefetch cleanup attempted." -Severity "Info"
$scriptSummary.Add([PSCustomObject]@{ Section = "Temp/Prefetch Cleanup"; Status = $cleanupOverallStatus; Details = $cleanupOverallDetails })


# 11. Run SFC
Log "---- 11. RUNNING SFC (System File Checker) ----" -Severity "Heading"
Log "This may take some time..." -Severity "Neutral"
$sfcRawOutput = @() # Initialize as an array to collect lines
try {
    # Execute SFC, tee to log file, and also send to pipeline to be captured by ForEach-Object
    sfc.exe /scannow | Tee-Object -FilePath $logFile -Append | ForEach-Object { $sfcRawOutput += $_ }
} catch {
    Log "SFC.exe failed to execute or threw an error: $($_.Exception.Message)" -Severity "Error"
    $sfcRawOutput = @("SFC.exe execution error: $($_.Exception.Message)") # Store error as output
}
$sfcOutputString = ($sfcRawOutput | Out-String).Trim() # Convert collected lines to a single string
Log "SFC scan finished." -Severity "Good"

$sfcStatus = $StatusCheckOutput
$sfcDetails = "Manual check of SFC output required."
if ([string]::IsNullOrWhiteSpace($sfcOutputString) -and -not ($sfcRawOutput -match "SFC.exe execution error")) { # Check if string is empty BUT no execution error logged
    $sfcStatus = $StatusWarning # Or Error, depends on how you see no output when no direct error.
    $sfcDetails = "No output captured from SFC, but no direct execution error. Check log."
} elseif ($sfcRawOutput -match "SFC.exe execution error") {
    $sfcStatus = $StatusError
    $sfcDetails = "SFC.exe failed to execute. Check error messages above."
} elseif ($sfcOutputString -match "Windows Resource Protection did not find any integrity violations.") {
    $sfcStatus = $StatusOk
    $sfcDetails = "No integrity violations found."
} elseif ($sfcOutputString -match "Windows Resource Protection found corrupt files and successfully repaired them.") {
    $sfcStatus = $StatusOk
    $sfcDetails = "Corrupt files found and repaired."
} elseif ($sfcOutputString -match "Windows Resource Protection found corrupt files but was unable to fix some of them.") {
    $sfcStatus = $StatusAction
    $sfcDetails = "Found corrupt files SFC could not fix. Check CBS.log."
} else { # If there's output but no clear success/failure identified above
    $sfcDetails = "Key success/repair phrase not detected. Manual check of output above/log required."
}
$scriptSummary.Add([PSCustomObject]@{ Section = "SFC Scan"; Status = $sfcStatus; Details = $sfcDetails })


# 12. Run DISM
Log "---- 12. RUNNING DISM ----" -Severity "Heading"
$dismScanStatus = $StatusCheckOutput; $dismScanDetails = "Manual check of DISM ScanHealth output required."
$dismRestoreStatus = $StatusCheckOutput; $dismRestoreDetails = "Manual check of DISM RestoreHealth output required."
$dismScanRawOutput = @(); $dismRestoreRawOutput = @()

Log "Step A: DISM ScanHealth..." -Severity "Neutral"
try {
    DISM.exe /Online /Cleanup-Image /ScanHealth | Tee-Object -FilePath $logFile -Append | ForEach-Object { $dismScanRawOutput += $_ }
} catch {
    Log "DISM ScanHealth failed to execute: $($_.Exception.Message)" -Severity "Error"
    $dismScanRawOutput = @("DISM ScanHealth execution error: $($_.Exception.Message)")
}
$dismScanOutputString = ($dismScanRawOutput | Out-String).Trim()
Log "DISM ScanHealth finished." -Severity "Good"

if ([string]::IsNullOrWhiteSpace($dismScanOutputString) -and -not ($dismScanRawOutput -match "DISM ScanHealth execution error")) {
    $dismScanStatus = $StatusWarning
    $dismScanDetails = "No output captured from DISM ScanHealth, but no direct execution error."
} elseif ($dismScanRawOutput -match "DISM ScanHealth execution error") {
    $dismScanStatus = $StatusError
    $dismScanDetails = "DISM ScanHealth failed to execute. Check error messages."
} elseif ($dismScanOutputString -match "No component store corruption detected.") {
    $dismScanStatus = $StatusOk
    $dismScanDetails = "No component store corruption detected."
} elseif ($dismScanOutputString -match "The component store is repairable.") {
    $dismScanStatus = $StatusWarning
    $dismScanDetails = "Component store is repairable."
} elseif ($dismScanOutputString -match "The component store cannot be repaired.") {
    $dismScanStatus = $StatusError
    $dismScanDetails = "Component store cannot be repaired (ScanHealth)."
} else {
    $dismScanDetails = "Key phrase not detected in ScanHealth. Manual check required."
}
$scriptSummary.Add([PSCustomObject]@{ Section = "DISM ScanHealth"; Status = $dismScanStatus; Details = $dismScanDetails })

Log "Step B: DISM RestoreHealth..." -Severity "Neutral"
try {
    DISM.exe /Online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath $logFile -Append | ForEach-Object { $dismRestoreRawOutput += $_ }
} catch {
    Log "DISM RestoreHealth failed to execute: $($_.Exception.Message)" -Severity "Error"
    $dismRestoreRawOutput = @("DISM RestoreHealth execution error: $($_.Exception.Message)")
}
$dismRestoreOutputString = ($dismRestoreRawOutput | Out-String).Trim()
Log "DISM RestoreHealth finished." -Severity "Good"

if ([string]::IsNullOrWhiteSpace($dismRestoreOutputString) -and -not ($dismRestoreRawOutput -match "DISM RestoreHealth execution error")) {
    $dismRestoreStatus = $StatusWarning
    $dismRestoreDetails = "No output captured from DISM RestoreHealth, but no direct execution error."
} elseif ($dismRestoreRawOutput -match "DISM RestoreHealth execution error") {
    $dismRestoreStatus = $StatusError
    $dismRestoreDetails = "DISM RestoreHealth failed to execute. Check error messages."
} elseif ($dismRestoreOutputString -match "The restore operation completed successfully.") {
    $dismRestoreStatus = $StatusOk
    $dismRestoreDetails = "Restore operation completed successfully."
} elseif ($dismRestoreOutputString -match "Error: (0x[0-9a-fA-F]+)") { # $matches will be populated by -match
    $dismRestoreStatus = $StatusError
    $dismRestoreDetails = "RestoreHealth reported error: $($matches[1]). Manual check required."
} elseif ($dismRestoreOutputString -match "Error:") {
    $dismRestoreStatus = $StatusError
    $dismRestoreDetails = "RestoreHealth reported an error. Manual check required."
} else {
    $dismRestoreDetails = "Key success phrase not detected in RestoreHealth. Manual check required."
}
$scriptSummary.Add([PSCustomObject]@{ Section = "DISM RestoreHealth"; Status = $dismRestoreStatus; Details = $dismRestoreDetails })

# 13. Reset Network Stack
Log "---- 13. RESETTING NETWORK STACK ----" -Severity "Heading"
$networkResetPerformed = $false
try {
    Log "Flushing DNS..." -Severity "Neutral"; ipconfig.exe /flushdns | Tee-Object -FilePath $logFile -Append
    Log "Resetting Winsock..." -Severity "Neutral"; netsh.exe winsock reset | Tee-Object -FilePath $logFile -Append
    Log "Resetting TCP/IP Stack..." -Severity "Neutral"; netsh.exe int ip reset | Tee-Object -FilePath $logFile -Append
    Log "Resetting Windows Firewall..." -Severity "Neutral"; netsh.exe advfirewall reset | Tee-Object -FilePath $logFile -Append
    Log "NETWORK RESET COMPLETE. A computer restart is highly recommended." -Severity "Action"
    $networkResetPerformed = $true
    $scriptSummary.Add([PSCustomObject]@{ Section = "Network Stack Reset"; Status = $StatusAction; Details = "Reboot highly recommended." })
    # Update overall reboot flag if not already set
    if (-not $rebootIsActuallyPending) { $rebootIsActuallyPending = $true; $rebootReasonsListForSummary.Add("Network Stack Reset") }
} catch {
    Log "Error during network stack reset: $($_.Exception.Message)" -Severity "Error"
    $scriptSummary.Add([PSCustomObject]@{ Section = "Network Stack Reset"; Status = $StatusError; Details = "Error during reset: $($_.Exception.Message)" })
}


# 14. Suggest CHKDSK
Log "---- 14. FURTHER SUGGESTIONS ----" -Severity "Heading"
Log "If you are experiencing disk-related issues, consider running Check Disk (chkdsk c: /f)." -Severity "Warning"
$scriptSummary.Add([PSCustomObject]@{ Section = "CHKDSK Suggestion"; Status = $StatusInfo; Details = "Recommended if disk issues persist." })


# --- Display Summary and Final Messages ---
Show-ScriptSummary # This will now log summary to file and write to console

Log "===== MASTER TROUBLESHOOT SCRIPT FINISHED: $(Get-Date) =====" -Severity "Heading"

Write-Host "`nTroubleshooting script finished. Log saved to: $logFile" -ForegroundColor Green
if ($rebootIsActuallyPending) {
    $reasonsForRebootMsg = if ($rebootReasonsListForSummary.Count -gt 0) { "due to: $($rebootReasonsListForSummary -join ', ')" } else { "(general recommendation)" }
    Write-Host "A REBOOT IS STRONGLY RECOMMENDED $reasonsForRebootMsg." -ForegroundColor Red
} elseif ($networkResetPerformed) { # Check if network reset specifically happened if no other reboot flags
    Write-Host "A REBOOT MAY BE RECOMMENDED for network reset changes to take full effect." -ForegroundColor Yellow
}
Read-Host "Press Enter to exit..."