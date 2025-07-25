# List of remote computers
$computers = @("DT-000518")

foreach ($computer in $computers) {
    $winrmStatus = Invoke-Command -ComputerName $computer -ScriptBlock {
        try {
            # Check the WinRM service status
            Get-Service -Name "WinRM" | Select-Object -Property Status
        } catch {
            # If the command fails, assume WinRM is not configured
            return "Not Configured"
        }
    }

    Write-Host "${computer}: WinRM Status - $winrmStatus"
}
