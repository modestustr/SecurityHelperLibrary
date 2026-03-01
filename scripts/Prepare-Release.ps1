param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [string[]]$Changes,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$projectFile = Join-Path $repoRoot 'SecurityHelperLibrary\SecurityHelperLibrary.csproj'
$changelogFile = Join-Path $repoRoot 'CHANGELOG.md'

function Get-CurrentBranch {
    $branch = git -C $repoRoot rev-parse --abbrev-ref HEAD
    return ($branch | Out-String).Trim()
}

function Ensure-CleanWorkingTree {
    param([switch]$AllowDirty)

    $status = git -C $repoRoot status --porcelain
    if ($status) {
        if ($AllowDirty) {
            Write-Host 'Warning: Working tree is not clean. Continuing because -DryRun was provided.'
            return
        }
        throw 'Working tree is not clean. Commit or stash your changes first.'
    }
}

function Normalize-Changes {
    param([string[]]$InputChanges)

    if (-not $InputChanges -or $InputChanges.Count -eq 0) {
        return @("Chore: Bump package version to '$Version'.")
    }

    $normalized = @()
    foreach ($change in $InputChanges) {
        $line = $change.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line.StartsWith('- ')) {
            $line = $line.Substring(2).Trim()
        }

        $normalized += $line
    }

    if ($normalized.Count -eq 0) {
        $normalized = @("Chore: Bump package version to '$Version'.")
    }

    return $normalized
}

if (-not (Test-Path $projectFile)) {
    throw "Project file not found: $projectFile"
}

if (-not (Test-Path $changelogFile)) {
    throw "CHANGELOG file not found: $changelogFile"
}

$currentBranch = Get-CurrentBranch
if ([string]::IsNullOrWhiteSpace($Version)) {
    $branchMatch = [regex]::Match($currentBranch, '^release/(\d+\.\d+\.\d+)$')
    if (-not $branchMatch.Success) {
        throw "Version was not provided and branch name is not in release/x.y.z format. Current branch: '$currentBranch'."
    }

    $Version = $branchMatch.Groups[1].Value
}

$expectedBranch = "release/$Version"
if ($currentBranch -ne $expectedBranch) {
    throw "Branch/version mismatch. Use branch '$expectedBranch' or pass matching -Version. Current branch: '$currentBranch'."
}

Ensure-CleanWorkingTree -AllowDirty:$DryRun

$projectContent = Get-Content -Path $projectFile -Raw -Encoding UTF8
$currentVersionMatch = [regex]::Match($projectContent, '<Version>([^<]+)</Version>')
if (-not $currentVersionMatch.Success) {
    throw "<Version> element was not found in $projectFile"
}

$oldVersion = $currentVersionMatch.Groups[1].Value
$newProjectContent = [regex]::Replace($projectContent, '<Version>[^<]+</Version>', "<Version>$Version</Version>", 1)

$changelogContent = Get-Content -Path $changelogFile -Raw -Encoding UTF8
$releaseHeaderPattern = "(?m)^## \[$([regex]::Escape($Version))\] - "
if ([regex]::IsMatch($changelogContent, $releaseHeaderPattern)) {
    throw "CHANGELOG already contains an entry for version $Version"
}

$date = Get-Date -Format 'yyyy-MM-dd'
$normalizedChanges = Normalize-Changes -InputChanges $Changes
$changeLines = $normalizedChanges | ForEach-Object { "- $_" }

$entryText = "## [$Version] - $date`r`n" + ($changeLines -join "`r`n") + "`r`n`r`n"

$introMarker = "All notable changes to this project will be documented in this file.`r`n`r`n"
if ($changelogContent.Contains($introMarker)) {
    $newChangelogContent = $changelogContent.Replace($introMarker, $introMarker + $entryText)
}
else {
    $newChangelogContent = $entryText + $changelogContent
}

Write-Host "Branch check        : $currentBranch"
Write-Host "Project version     : $oldVersion -> $Version"
Write-Host "Changelog new entry : $Version ($date)"

if ($DryRun) {
    Write-Host ''
    Write-Host 'Dry run enabled. No files were changed.'
    Write-Host 'Planned changelog lines:'
    $changeLines | ForEach-Object { Write-Host $_ }
    exit 0
}

Set-Content -Path $projectFile -Value $newProjectContent -Encoding UTF8
Set-Content -Path $changelogFile -Value $newChangelogContent -Encoding UTF8

Write-Host ''
Write-Host 'Updated files:'
Write-Host "- $projectFile"
Write-Host "- $changelogFile"
Write-Host ''
Write-Host 'Next steps:'
Write-Host '1) dotnet test'
Write-Host "2) git add SecurityHelperLibrary/SecurityHelperLibrary.csproj CHANGELOG.md"
Write-Host ('3) git commit -m "chore(release): prepare ' + $Version + '"')
Write-Host ('4) git tag -a v' + $Version + ' -m "Release v' + $Version + '"')
