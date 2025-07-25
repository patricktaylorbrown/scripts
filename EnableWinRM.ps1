# Specify the remote computer
$computer = "DT-000518"

Invoke-Command -ComputerName $computer -ScriptBlock {
    try {
        winrm quickconfig -force
        Set-Service -Name "WinRM" -StartupType Automatic
        Start-Service -Name "WinRM"
        Enable-PSRemoting -Force
        Write-Host "WinRM enabled successfully."
    } catch {
        Write-Host "Failed to enable WinRM: $_"
    }
}
