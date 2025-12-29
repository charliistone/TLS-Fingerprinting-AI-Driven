<#
.SYNOPSIS
    Automated Monitoring and Processing Script (Repo Compatible - FIXED)
    Runs in src/capture.
    Monitors data/raw_pcaps -> Processes with Python -> Saves to data/processed_csvs.
#>

param(
  [string]$PcapDir = $null,
  [string]$OutDir = $null,
  [string]$LogDir = $null,
  [string]$PythonExe = 'python',
  [string]$Extractor = $null,
  [int]$IdleSeconds = 10,
  [int]$PollInterval = 5
)

# --- PATH CALCULATIONS (After Param Block) ---
$ScriptPath = $PSScriptRoot
# Navigate up: src/capture -> src -> ProjectRoot
$ProjectRoot = (Get-Item $ScriptPath).Parent.Parent.FullName

# Assign default values (If not provided as parameters)
if ([string]::IsNullOrEmpty($PcapDir)) { $PcapDir = Join-Path $ProjectRoot 'data\raw_pcaps' }
if ([string]::IsNullOrEmpty($OutDir))  { $OutDir = Join-Path $ProjectRoot 'data\processed_csvs' }
if ([string]::IsNullOrEmpty($LogDir))  { $LogDir = Join-Path $ProjectRoot 'data\logs' }
if ([string]::IsNullOrEmpty($Extractor)) { $Extractor = Join-Path $ProjectRoot 'src\processing\extract_ja3.py' }
# -----------------------------------------------

$MasterCsvFile = Join-Path $OutDir 'master_ja3_results.csv'
$MasterRawCsvFile = Join-Path $OutDir 'master_raw_clienthellos.csv'

# Create directories
New-Item -Force -ItemType Directory $PcapDir, $OutDir, $LogDir | Out-Null

function Is-FileIdle($path, $seconds) {
  if (!(Test-Path $path)) { return $false }
  try {
    $f = Get-Item $path
    $age = (Get-Date) - $f.LastWriteTime
    # Check if file age is greater than threshold AND file is not empty
    return ($age.TotalSeconds -gt $seconds) -and ($f.Length -gt 0)
  } catch {
    return $false
  }
}

function Process-Pcap($pcapPath) {
  try {
    $done = "$pcapPath.done"
    
    # If file is still being written to or already processed, skip it
    if (!(Is-FileIdle $pcapPath $IdleSeconds) -or (Test-Path $done)) {
      return
    }

    Write-Host "$(Get-Date -Format 'HH:mm:ss') Processing: $(Split-Path $pcapPath -Leaf)" -ForegroundColor Yellow
    
    $logFile = Join-Path $LogDir 'watcher.log'
    Add-Content -Path $logFile -Value "$(Get-Date -Format o) Processing $pcapPath"

    $csvTempOut = "$pcapPath.clienthello.csv"
    $extractorErrorLog = Join-Path $LogDir 'extractor_errors.log'

    # Run Python Script
    $process = Start-Process -FilePath $PythonExe -ArgumentList "`"$Extractor`"", "`"$pcapPath`"", "`"$csvTempOut`"" -Wait -NoNewWindow -PassThru
    
    if ($process.ExitCode -ne 0) {
        Write-Host "ERROR: Python script returned with an error." -ForegroundColor Red
        Add-Content -Path $extractorErrorLog -Value "$(Get-Date -Format o) FAIL on $pcapPath"
        return
    }

    if (Test-Path $csvTempOut) {
        try {
            $contentToAppend = Get-Content $csvTempOut -Encoding utf8
            if (-not (Test-Path $MasterRawCsvFile)) {
                # If master file doesn't exist, write content with header
                $contentToAppend | Set-Content -Path $MasterRawCsvFile -Encoding utf8
            } else {
                # If master file exists, skip header and append content
                $contentToAppend | Select-Object -Skip 1 | Add-Content -Path $MasterRawCsvFile -Encoding utf8
            }
        } catch {
             Add-Content -Path $logFile -Value "$(Get-Date -Format o) ERROR appending raw data: $_"
        }
        
        # Remove temporary CSV
        Remove-Item $csvTempOut -ErrorAction SilentlyContinue
        
        try {
            # Delete processed PCAP file to save space
            Remove-Item $pcapPath -Force -ErrorAction Stop
            Write-Host "Finished and Deleted: $(Split-Path $pcapPath -Leaf)" -ForegroundColor Green
            Add-Content -Path $logFile -Value "$(Get-Date -Format o) FINISHED and DELETED $pcapPath"
        } catch {
            Write-Host "Warning: Could not delete Pcap." -ForegroundColor Magenta
        }

    } else {
        # If no CSV was generated, it means no ClientHellos were found
        Add-Content -Path $logFile -Value "$(Get-Date -Format o) No ClientHellos found in $pcapPath"
        Remove-Item $pcapPath -Force -ErrorAction SilentlyContinue
    }

  } catch {
    Write-Host "Critical Error: $_" -ForegroundColor Red
    Add-Content -Path (Join-Path $LogDir 'watcher.log') -Value "$(Get-Date -Format o) ERROR processing $pcapPath : $_"
  }
}

Write-Host "Watcher active. Monitoring folder: $PcapDir" -ForegroundColor Cyan
Write-Host "Press CTRL+C to exit."

while ($true) {
  $pcaps = Get-ChildItem -Path $PcapDir -Filter "*.pcap" | Sort-Object LastWriteTime
  foreach ($p in $pcaps) {
    Process-Pcap $p.FullName
  }
  Start-Sleep -Seconds $PollInterval
}