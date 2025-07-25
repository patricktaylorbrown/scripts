$servers = "DT-000518"  # List of machines to update
$credential = Get-Credential                # Prompt for credentials

Invoke-Command -ComputerName $servers -Credential $credential -ScriptBlock {
    Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
    Import-Module PSWindowsUpdate
    Install-WindowsUpdate -AcceptAll -AutoReboot
}
