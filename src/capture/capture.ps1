<#
.SYNOPSIS
    TShark Ring Buffer Capture Script (Smart Interface Selection)
    This script runs in the src/capture directory.
    It lists network interfaces to the user and prompts for selection.
#>

param(
  [int]$IfIndex = 0,             # If 0, ask the user to select an interface
  [string]$OutDir = $null,       
  [int]$DurationSeconds = 60,    
  [string]$Filter = ""           
)

$ScriptPath = $PSScriptRoot
# Navigate up: src/capture -> src -> ProjectRoot
$ProjectRoot = (Get-Item $ScriptPath).Parent.Parent.FullName

# Default output directory
if ([string]::IsNullOrEmpty($OutDir)) {
    $OutDir = Join-Path $ProjectRoot 'data\raw_pcaps'
}

$tshark = 'tshark'

# --- INTERFACE SELECTION (INTERACTIVE) ---
if ($IfIndex -eq 0) {
    Write-Host "----------------------------------------------------" -ForegroundColor Cyan
    Write-Host " Scanning Available Network Interfaces..." -ForegroundColor Cyan
    Write-Host "----------------------------------------------------"
    
    # Get the list using TShark -D command
    try {
        $interfaces = & $tshark -D 2>&1
    } catch {
        Write-Error "Could not run TShark. Ensure it is added to your system PATH."
        exit
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Could not list interfaces. Error: $interfaces"
        exit
    }

    # Print list to screen
    $interfaces | ForEach-Object { Write-Host $_ }
    
    Write-Host "----------------------------------------------------"
    Write-Host " Please enter the number of the network interface you want to monitor." -ForegroundColor Yellow
    Write-Host " (E.g., the number to the left of Ethernet or Wi-Fi)" -ForegroundColor Yellow
    
    # Wait for user input
    $selection = Read-Host " Interface Number"
    
    # Validate if input is a number
    if ($selection -match '^\d+$') {
        $IfIndex = [int]$selection
    } else {
        Write-Host "Invalid input! Stopping script." -ForegroundColor Red
        exit
    }
}
# -------------------------------------

# Directory check
if (-not (Test-Path $OutDir)) {
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    Write-Host "Directory created: $OutDir" -ForegroundColor Cyan
}

$CaptureFile = Join-Path $OutDir 'capture.pcap'

$cmd = @(
  '-i', $IfIndex,
  '-w', $CaptureFile,
  '-b', "duration:$DurationSeconds" 
)

if (-not [string]::IsNullOrEmpty($Filter)) {
    $cmd += '-f'
    $cmd += $Filter
}

Write-Host "----------------------------------------------------" -ForegroundColor Green
Write-Host " Starting TShark Capture..." 
Write-Host " Selected Interface : $IfIndex"
Write-Host " Target Directory   : $OutDir"
Write-Host " File Duration      : $DurationSeconds seconds"
Write-Host "----------------------------------------------------" -ForegroundColor Green

& $tshark $cmd