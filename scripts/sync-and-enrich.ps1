# Pull new VPS log exports and enrich them with GeoIP data.
# Run from the project root:
#   .\scripts\sync-and-enrich.ps1

param(
    [switch]$EnrichOnly
)

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$EnvFile = Join-Path $ProjectRoot ".env"
Set-Location $ProjectRoot

if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
        $name, $value = $_ -split '=', 2
        $name = $name.Trim()
        $value = $value.Trim().Trim('"').Trim("'")
        if ($name -and -not [Environment]::GetEnvironmentVariable($name)) {
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

function Get-Setting {
    param(
        [string]$Name,
        [string]$Default = ""
    )
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }
    return $value
}

$VPS = Get-Setting "HONEYPOT_VPS"
if (-not $EnrichOnly -and [string]::IsNullOrWhiteSpace($VPS)) {
    throw "Set HONEYPOT_VPS, for example admin@203.0.113.10"
}

$KEY = Get-Setting "HONEYPOT_SSH_KEY" "$env:USERPROFILE\.ssh\honeypot_ed25519"
$PORT = [int](Get-Setting "HONEYPOT_SSH_PORT" "2222")
$REMOTE = "/opt/honeypot/exports"
$LOCAL = "logs\exports"

New-Item -ItemType Directory -Force $LOCAL | Out-Null

$to_enrich = @()

if (-not $EnrichOnly) {
    Write-Host "Checking VPS for available exports..."

    $raw = ssh -p $PORT -i $KEY $VPS "ls $REMOTE" 2>$null
    $remote_dates = @($raw | Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}$' } | Sort-Object)

    if ($remote_dates.Count -eq 0) {
        Write-Host "No exports found on VPS yet (cron runs at 02:00 UTC)."
        exit 0
    }

    foreach ($date in $remote_dates) {
        $dest = "$LOCAL\$date"
        $has_export = (Test-Path "$dest\honeypot.ndjson.gz") -or (Test-Path "$dest\honeypot.ndjson")
        if ($has_export) {
            Write-Host "  [$date] already local - skipping"
        } else {
            Write-Host "  [$date] downloading..."
            New-Item -ItemType Directory -Force $dest | Out-Null
            scp -P $PORT -i $KEY -r "${VPS}:${REMOTE}/${date}/." "$dest\"
            if ($LASTEXITCODE -eq 0) {
                $to_enrich += $date
            } else {
                Write-Warning "  [$date] scp failed (exit $LASTEXITCODE)"
            }
        }
    }

    if ($to_enrich.Count -eq 0) {
        Write-Host "Nothing new to sync."
        exit 0
    }
} else {
    $dirs = Get-ChildItem $LOCAL -Directory | Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}$' }
    $to_enrich = @(
        $dirs |
            Where-Object { -not (Test-Path "logs\enriched\$($_.Name)\honeypot_enriched.ndjson") } |
            ForEach-Object { $_.Name } |
            Sort-Object
    )

    if ($to_enrich.Count -eq 0) {
        Write-Host "All local exports are already enriched."
        exit 0
    }
}

Write-Host ""
Write-Host "Enriching $($to_enrich.Count) date(s)..."
foreach ($date in $to_enrich) {
    python scripts/enrich.py $date
}

Write-Host ""
Write-Host "Done. Enriched output: logs\enriched\"
