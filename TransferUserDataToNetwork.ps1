<#
.SYNOPSIS
    Transfers OneDrive, Documents, and Downloads to a user-specific network folder.
.DESCRIPTION
    Copies all files from the user's OneDrive, Documents, and Downloads folders
    to \\lp-fs01\Users\%USERNAME%.
.NOTES
    File Name      : TransferUserDataToNetwork.ps1
    Prerequisite   : PowerShell 5.1 or later
#>

# Define source paths (using $env:USERNAME)
$sourcePaths = @(
    "C:\Users\$env:USERNAME\OneDrive - BUHLMANN Rohr-Fittings-Stahlhandel GmbH + Co. KG",
    "C:\Users\$env:USERNAME\Documents",
    "C:\Users\$env:USERNAME\Downloads"
)

# Define the network destination path (dynamic based on username)
$destinationRoot = "\\lp-fs01\Users\$env:USERNAME"

# Create destination directory if it doesn't exist
if (-not (Test-Path -Path $destinationRoot)) {
    try {
        New-Item -ItemType Directory -Path $destinationRoot -Force | Out-Null
        Write-Host "Created destination directory: $destinationRoot" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create destination directory: $_" -ForegroundColor Red
        exit 1
    }
}

# Initialize robocopy log (stored in the destination root)
$robocopyLog = Join-Path -Path $destinationRoot -ChildPath "DataTransfer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Transfer each source path
foreach ($sourcePath in $sourcePaths) {
    $folderName = Split-Path $sourcePath -Leaf
    
    # Rename "OneDrive - ..." to just "OneDrive" in destination
    if ($sourcePath -like "*OneDrive*") {
        $folderName = "OneDrive"
    }
    
    $destinationPath = Join-Path -Path $destinationRoot -ChildPath $folderName
    
    if (Test-Path -LiteralPath $sourcePath) {
        try {
            Write-Host "`nStarting transfer of $folderName to $destinationPath..." -ForegroundColor Cyan
            
            # Robocopy command (mirror mode, with exclusions)
            robocopy `"$sourcePath`" `"$destinationPath`" /MIR /ZB /R:1 /W:1 /NP /TEE /LOG+:$robocopyLog `
                /XD "~$*" "*.tmp" "$RECYCLE.BIN" "System Volume Information" `
                /XF "~$*" "*.tmp" "Thumbs.db" "desktop.ini"
            
            Write-Host "Completed transfer of $folderName" -ForegroundColor Green
        } catch {
            Write-Host "Error transferring $folderName : $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Source path not found: $sourcePath" -ForegroundColor Yellow
    }
}

Write-Host "`nAll transfers completed for user $env:USERNAME" -ForegroundColor Green
Write-Host "Detailed log available at: $robocopyLog" -ForegroundColor Cyan