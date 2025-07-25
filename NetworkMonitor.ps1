# --- Configuration ---
$LanTarget = "10.1.30.1"         # YOUR ROUTER'S IP - ALREADY SET CORRECTLY BY YOU
$WanTarget1 = "8.8.8.8"          # Google DNS
$WanTarget2 = "1.1.1.1"          # Cloudflare DNS
$DnsTestHost = "www.google.com"
$CheckIntervalSeconds = 5       # How often to check
$LogFile = "C:\NetworkMonitorLog.txt" # Optional: Path to log file (make sure C:\ drive is writable or change path)
$WarningLatencyThresholdMs = 100 # Latency in ms above which to log a WARNING for WAN

# --- Function to Log Messages ---
Function Write-Log {
    Param (
        [string]$Message,
        [string]$Level = "INFO" # INFO, WARNING, ERROR
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp - $Level - $Message"

    # Console Color Coding
    Switch ($Level) {
        "INFO"    { Write-Host $LogEntry }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        default   { Write-Host $LogEntry }
    }

    if ($LogFile) {
        try {
            Add-Content -Path $LogFile -Value $LogEntry -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file: $LogFile. Error: $($_.Exception.Message)"
        }
    }
}

# --- Main Monitoring Loop ---
Write-Host "Starting Network Health Monitor..."
Write-Log "Network Health Monitor Started."
Write-Log "LAN Target: $LanTarget"
Write-Log "WAN Targets: $WanTarget1, $WanTarget2"
Write-Log "DNS Test Host: $DnsTestHost"
Write-Log "Check Interval: $CheckIntervalSeconds seconds"
Write-Log "WAN Latency Warning Threshold: ${WarningLatencyThresholdMs}ms"
Write-Host "Press CTRL+C to stop."

while ($true) {
    Clear-Host # Optional: Clears the console each iteration for cleaner view

    Write-Log "--- Cycle Start ---"

    # 1. LAN Check
    Write-Host "`n--- LAN Check (Router: $LanTarget) ---"
    $LanConnection = Test-Connection -ComputerName $LanTarget -Count 1 -ErrorAction SilentlyContinue
    if ($LanConnection -and $LanConnection.StatusCode -eq 0) { # Check if the object exists and status is success (0)
        $LanLatency = $LanConnection.ResponseTime
        Write-Log "LAN: $LanTarget is UP. Latency: ${LanLatency}ms"
    } else {
        $ErrorMessage = if ($LanConnection) { $LanConnection.PrimaryStatusDescription } else { "No response" }
        Write-Log "LAN: $LanTarget is DOWN. Status: $ErrorMessage" -Level "ERROR"
    }

    # 2. WAN Check (Primary Target)
    Write-Host "`n--- WAN Check (Primary: $WanTarget1) ---"
    $PrimaryWanUp = $false
    $WanConnection1 = Test-Connection -ComputerName $WanTarget1 -Count 1 -ErrorAction SilentlyContinue
    if ($WanConnection1 -and $WanConnection1.StatusCode -eq 0) {
        $PrimaryWanUp = $true
        $WanLatency1 = $WanConnection1.ResponseTime
        $LogLevel = if ($WanLatency1 -ge $WarningLatencyThresholdMs) { "WARNING" } else { "INFO" }
        Write-Log "WAN: $WanTarget1 is UP. Latency: ${WanLatency1}ms" -Level $LogLevel
    } else {
        $ErrorMessage = if ($WanConnection1) { $WanConnection1.PrimaryStatusDescription } else { "No response" }
        Write-Log "WAN: $WanTarget1 is DOWN. Status: $ErrorMessage" -Level "ERROR"

        # 2a. WAN Check (Secondary Target if Primary Fails)
        Write-Host "`n--- WAN Check (Secondary: $WanTarget2) ---"
        $WanConnection2 = Test-Connection -ComputerName $WanTarget2 -Count 1 -ErrorAction SilentlyContinue
        if ($WanConnection2 -and $WanConnection2.StatusCode -eq 0) {
            $PrimaryWanUp = $true # Technically, *a* WAN connection is up
            $WanLatency2 = $WanConnection2.ResponseTime
            $LogLevel = if ($WanLatency2 -ge $WarningLatencyThresholdMs) { "WARNING" } else { "INFO" }
            Write-Log "WAN: $WanTarget2 (Secondary) is UP. Latency: ${WanLatency2}ms" -Level $LogLevel
        } else {
            $ErrorMessage2 = if ($WanConnection2) { $WanConnection2.PrimaryStatusDescription } else { "No response" }
            Write-Log "WAN: $WanTarget2 (Secondary) is also DOWN. Status: $ErrorMessage2" -Level "ERROR"
        }
    }

    # 3. DNS Resolution Check (Only if a WAN connection was up)
    Write-Host "`n--- DNS Check (Host: $DnsTestHost) ---"
    if ($PrimaryWanUp) {
        try {
            $DnsResult = Resolve-DnsName -Name $DnsTestHost -Type A -ErrorAction Stop -DnsOnly # -DnsOnly to ensure it's a pure DNS lookup
            if ($DnsResult) {
                Write-Log "DNS: Successfully resolved $DnsTestHost to $($DnsResult.IPAddress | Select-Object -First 1)"
            } else {
                Write-Log "DNS: Failed to resolve $DnsTestHost (no results)." -Level "WARNING"
            }
        } catch {
            Write-Log "DNS: Error resolving $DnsTestHost. Message: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log "DNS: Skipped (WAN is down)." -Level "WARNING"
    }

    Write-Log "--- Cycle End ---"
    Start-Sleep -Seconds $CheckIntervalSeconds
}