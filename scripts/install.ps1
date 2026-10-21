# Armis CLI Windows Installer
# Usage: irm https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.ps1 | iex
# Or: .\install.ps1 [-Version "v1.0.0"] [-InstallDir "C:\Program Files\armis-cli"] [-Verify]

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\armis-cli",
    [switch]$Verify = $true
)

$ErrorActionPreference = "Stop"

$Repo = "ArmisSecurity/armis-cli"
$BinaryName = "armis-cli.exe"

function Test-CIEnvironment {
    # Boolean vars: only treat as CI when value is an explicit true-like string.
    $trueValues = @('1', 'true', 'yes', 'y', 'on')
    $booleanVars = @('CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TF_BUILD')

    foreach ($envVarName in $booleanVars) {
        $envItem = Get-Item -Path "Env:$envVarName" -ErrorAction SilentlyContinue
        if ($null -ne $envItem -and -not [string]::IsNullOrWhiteSpace($envItem.Value)) {
            $normalized = $envItem.Value.Trim().ToLowerInvariant()
            if ($trueValues -contains $normalized) {
                return $true
            }
        }
    }

    # Presence vars: treat as CI when set to any non-empty value (e.g. JENKINS_HOME
    # is typically a filesystem path like /var/jenkins_home, not a boolean).
    $presenceVars = @('JENKINS_HOME')

    foreach ($envVarName in $presenceVars) {
        $envItem = Get-Item -Path "Env:$envVarName" -ErrorAction SilentlyContinue
        if ($null -ne $envItem -and -not [string]::IsNullOrWhiteSpace($envItem.Value)) {
            return $true
        }
    }

    return $false
}

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" {
            throw "Windows ARM64 is not currently supported by this installer. Please use an x64 (AMD64) environment."
        }
        default {
            throw "Unsupported architecture: $arch"
        }
    }
}

function Download-File {
    param(
        [string]$Url,
        [string]$Output
    )

    Write-Host "📥 Downloading from: $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing
    } catch {
        throw "Failed to download $Url`: $_"
    }
}

function Verify-Checksums {
    param(
        [string]$ArchiveFile,
        [string]$ChecksumsFile,
        [string]$ChecksumsBundle
    )

    # armis:ignore cwe:494 reason:$Verify defaults true; explicit opt-out for environments without cosign (documented flag)
    if (-not $Verify) {
        Write-Host "⚠️  Skipping verification (-Verify:`$false)"
        return
    }

    $cosignPath = Get-Command cosign -ErrorAction SilentlyContinue
    $hasBundle = $ChecksumsBundle -and (Test-Path $ChecksumsBundle)
    if ($cosignPath -and $hasBundle) {
        Write-Host "🔐 Verifying signature with cosign..."
        # cosign is a native command: failure shows up in $LASTEXITCODE, not as an exception.
        # It also writes progress to stderr, which would throw under -ErrorAction Stop on PS 5.1.
        $prevPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $cosignOutput = & cosign verify-blob `
                --certificate-identity-regexp 'https://github.com/ArmisSecurity/armis-cli/.github/workflows/release.yml@refs/tags/.*' `
                --certificate-oidc-issuer https://token.actions.githubusercontent.com `
                --bundle $ChecksumsBundle `
                $ChecksumsFile 2>&1
            $cosignExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevPreference
        }
        if ($cosignExit -ne 0) {
            throw "Signature verification failed (cosign exit code $cosignExit):`n$($cosignOutput | Out-String)"
        }
        Write-Host "✓ Signature verified successfully" -ForegroundColor Green
    } elseif ($cosignPath) {
        Write-Host "ℹ️  No signature bundle available, verifying checksums only"
    } else {
        Write-Host "ℹ️  cosign not found, verifying checksums only"
        Write-Host "   Install cosign for full signature verification: https://docs.sigstore.dev/cosign/installation/"
    }

    Write-Host "🔍 Verifying checksums..."
    $archiveName = Split-Path $ArchiveFile -Leaf
    # Exact match on the filename column (like install.sh), not a regex over the whole line.
    $checksumContent = @(Get-Content $ChecksumsFile | Where-Object {
        $fields = $_.Trim() -split '\s+'
        $fields.Count -ge 2 -and $fields[-1].TrimStart('*') -eq $archiveName
    }) | Select-Object -First 1

    if (-not $checksumContent) {
        throw "Checksum not found for $archiveName"
    }

    $expectedHash = ($checksumContent.Trim() -split '\s+')[0].ToLower()
    $actualHash = (Get-FileHash -Path $ArchiveFile -Algorithm SHA256).Hash.ToLower()

    if ($expectedHash -ne $actualHash) {
        throw "Checksum mismatch! Expected: $expectedHash, Got: $actualHash"
    }

    Write-Host "✓ Checksums verified successfully" -ForegroundColor Green
}

function Add-DirectoryToPath {
    param(
        [string]$ExistingPath,
        [string]$Directory
    )

    $segments = @()
    $installDirKey = $Directory.TrimEnd('\')
    $hasInstallDir = $false

    if (-not [string]::IsNullOrWhiteSpace($ExistingPath)) {
        foreach ($seg in $ExistingPath -split ';') {
            if ([string]::IsNullOrWhiteSpace($seg)) {
                continue
            }
            $segTrim = $seg.Trim()
            $segKey = $segTrim.TrimEnd('\')
            if (-not $hasInstallDir -and $segKey -ieq $installDirKey) {
                $hasInstallDir = $true
            }
            $segments += $segTrim
        }
    }

    if (-not $hasInstallDir) {
        $segments += $Directory
    }

    return ($segments -join ';')
}

function Main {
    Write-Host ""
    Write-Host "Installing Armis CLI..." -ForegroundColor Cyan
    Write-Host ""

    # Windows PowerShell 5.1: the Invoke-WebRequest progress bar slows large downloads
    # dramatically. Main is a function, so this assignment is local to it and cannot leak.
    $ProgressPreference = "SilentlyContinue"

    # Validate InstallDir to prevent path traversal attacks
    # First normalize the path to resolve any relative segments (like ..\..),
    # then validate the normalized result for defense-in-depth
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

    # armis:ignore cwe:22 reason:this IS the path traversal prevention check; rejects paths with ".." segments
    if ($InstallDir -match '(^|\\)\.\.($|\\)') {
        throw "Invalid install directory: path traversal detected after normalization"
    }

    # Validate Version format (except for the special 'latest' value)
    if ($Version -ne "latest" -and $Version -notmatch '^v?\d+\.\d+\.\d+(-[0-9A-Za-z\.-]+)?$') {
        throw "Invalid version format: '$Version'. Expected formats like 'v1.2.3' or '1.2.3' (optionally with suffix like -beta.1), or 'latest'."
    }

    $arch = Get-Architecture
    Write-Host "Detected Architecture: $arch"
    Write-Host ""

    if ($Version -eq "latest") {
        $baseUrl = "https://github.com/$Repo/releases/latest/download"
    } else {
        $baseUrl = "https://github.com/$Repo/releases/download/$Version"
    }

    $archiveName = "armis-cli-windows-$arch.zip"
    # armis:ignore cwe:426 reason:$env:TEMP is the standard Windows temp dir; GUID suffix prevents collision/hijacking
    $tmpDir = Join-Path $env:TEMP "armis-cli-install-$([guid]::NewGuid().ToString())"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    # Windows PowerShell 5.1 can default to protocols GitHub no longer accepts. Enable TLS 1.2
    # for the download only and restore the caller's setting afterwards (irm | iex runs in-session).
    $prevSecurityProtocol = $null
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $prevSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $prevSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    try {
        $archiveFile = Join-Path $tmpDir $archiveName
        $checksumsFile = Join-Path $tmpDir "armis-cli-checksums.txt"
        $checksumsBundle = Join-Path $tmpDir "armis-cli-checksums.txt.bundle"

        Write-Host "📦 Downloading $archiveName..."
        Download-File -Url "$baseUrl/$archiveName" -Output $archiveFile

        Write-Host "📥 Downloading checksums..."
        Download-File -Url "$baseUrl/armis-cli-checksums.txt" -Output $checksumsFile
        try {
            Download-File -Url "$baseUrl/armis-cli-checksums.txt.bundle" -Output $checksumsBundle
        } catch {
            Write-Host "⚠️  Signature bundle not found, skipping signature verification" -ForegroundColor Yellow
        }

        Write-Host ""
        Verify-Checksums -ArchiveFile $archiveFile -ChecksumsFile $checksumsFile -ChecksumsBundle $checksumsBundle
        Write-Host ""

        Write-Host "📂 Extracting archive..."
        # armis:ignore cwe:22 reason:archiveFile downloaded from verified GitHub release with checksum validation above; tmpDir is a temp directory created by New-TemporaryFile
        Expand-Archive -Path $archiveFile -DestinationPath $tmpDir -Force
        # armis:ignore cwe:22 reason:extracted content from verified GitHub release archive (checksum + signature validated)

        Write-Host "📥 Installing to $InstallDir..."
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        $binarySource = Join-Path $tmpDir $BinaryName
        $binaryDest = Join-Path $InstallDir $BinaryName

        # Detect upgrade vs fresh install
        if (Test-Path $binaryDest) {
            try {
                # armis:ignore cwe:78 cwe:426 reason:binaryDest constructed from Join-Path with validated InstallDir (absolute path, not a PATH search); executing our own just-installed binary
                $existingVersion = & $binaryDest --version 2>$null | Select-Object -First 1
                # armis:ignore cwe:78 cwe:426 reason:binaryDest is an absolute Join-Path of validated InstallDir; no untrusted search path
                if ($existingVersion) {
                    Write-Host "Upgrading existing installation..."
                    Write-Host "   Current: $existingVersion"
                } else {
                    Write-Host "Replacing existing installation..."
                }
            } catch {
                Write-Host "Replacing existing installation..."
            }
        }

        # A running exe (e.g. an editor-launched MCP server) can't be overwritten but can be
        # renamed, so move it aside first. The aside name is unique because an earlier .old may
        # still be locked by a process that is running. Leftovers are swept best-effort.
        Get-ChildItem -Path "$binaryDest.old*" -Force -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        $oldBinary = "$binaryDest.old.$([guid]::NewGuid().ToString('N'))"
        $movedAside = $false
        if (Test-Path $binaryDest) {
            Move-Item -Path $binaryDest -Destination $oldBinary -Force
            $movedAside = $true
        }
        try {
            Copy-Item -Path $binarySource -Destination $binaryDest -Force
        } catch {
            if ($movedAside) {
                Move-Item -Path $oldBinary -Destination $binaryDest -Force -ErrorAction SilentlyContinue
            }
            throw
        }
        Remove-Item -Path $oldBinary -Force -ErrorAction SilentlyContinue

        # Add to PATH (skip persistent changes in CI environments where PATH is ephemeral)
        if (-not (Test-CIEnvironment)) {
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
            # armis:ignore cwe:426 reason:InstallDir validated by Resolve-InstallDir; adds our own install directory to user PATH
            $newUserPath = Add-DirectoryToPath -ExistingPath $currentPath -Directory $InstallDir
            if ($newUserPath -ne $currentPath) {
                Write-Host "Adding to PATH..."
                # armis:ignore cwe:426 reason:installer adds its own validated InstallDir to user PATH; standard installer pattern
                [Environment]::SetEnvironmentVariable(
                    "Path", # armis:ignore cwe:426 reason:installer sets validated InstallDir to user PATH
                    $newUserPath,
                    "User"
                )
                $env:Path = Add-DirectoryToPath -ExistingPath $env:Path -Directory $InstallDir
                Write-Host "Added $InstallDir to user PATH" -ForegroundColor Green
                Write-Host "   (Restart your terminal for PATH changes to take effect)"
            }
        } else {
            $env:Path = Add-DirectoryToPath -ExistingPath $env:Path -Directory $InstallDir
        }

        Write-Host ""
        Write-Host "Armis CLI installed successfully!" -ForegroundColor Green

        # Show installed version
        try {
            $newVersion = & $binaryDest --version 2>$null | Select-Object -First 1
            if ($newVersion) {
                Write-Host "   Location: $binaryDest"
                Write-Host "   Version:  $newVersion"
            }
        } catch {}

        Write-Host ""
        Write-Host "Run 'armis-cli --help' to get started"

        if (-not (Test-CIEnvironment)) {
            Write-Host ""
            Write-Host "Tip: Enable tab completion by adding to your PowerShell profile:"
            Write-Host "   armis-cli completion powershell | Out-String | Invoke-Expression"
        }

        Write-Host ""

    } finally {
        if ($null -ne $prevSecurityProtocol) {
            [Net.ServicePointManager]::SecurityProtocol = $prevSecurityProtocol
        }
        if (Test-Path $tmpDir) {
            Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Main
