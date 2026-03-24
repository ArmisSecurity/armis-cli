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
            Write-Error "Windows ARM64 is not currently supported by this installer. Please use an x64 (AMD64) environment."
            exit 1
        }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
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
        Write-Error "Failed to download: $_"
        exit 1
    }
}

function Verify-Checksums {
    param(
        [string]$ArchiveFile,
        [string]$ChecksumsFile,
        [string]$ChecksumsSig
    )

    if (-not $Verify) {
        Write-Host "⚠️  Skipping verification (-Verify:`$false)"
        return
    }

    $cosignPath = Get-Command cosign -ErrorAction SilentlyContinue
    if ($cosignPath) {
        Write-Host "🔐 Verifying signature with cosign..."
        try {
            & cosign verify-blob `
                --certificate-identity-regexp 'https://github.com/ArmisSecurity/armis-cli/.github/workflows/release.yml@refs/tags/.*' `
                --certificate-oidc-issuer https://token.actions.githubusercontent.com `
                --signature $ChecksumsSig `
                $ChecksumsFile 2>&1 | Out-Null
            Write-Host "✓ Signature verified successfully" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Signature verification failed, falling back to checksum verification" -ForegroundColor Yellow
        }
    } else {
        Write-Host "ℹ️  cosign not found, verifying checksums only"
        Write-Host "   Install cosign for full signature verification: https://docs.sigstore.dev/cosign/installation/"
    }

    Write-Host "🔍 Verifying checksums..."
    $archiveName = Split-Path $ArchiveFile -Leaf
    $checksumContent = Get-Content $ChecksumsFile | Where-Object { $_ -match $archiveName }

    if (-not $checksumContent) {
        Write-Error "Checksum not found for $archiveName"
        exit 1
    }

    $expectedHash = ($checksumContent -split '\s+')[0]
    $actualHash = (Get-FileHash -Path $ArchiveFile -Algorithm SHA256).Hash.ToLower()

    if ($expectedHash -ne $actualHash) {
        Write-Error "Checksum mismatch! Expected: $expectedHash, Got: $actualHash"
        exit 1
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

    # Validate InstallDir to prevent path traversal attacks
    # First normalize the path to resolve any relative segments (like ..\..),
    # then validate the normalized result for defense-in-depth
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

    # CWE-22 false positive: this IS the path traversal defense.
    # GetFullPath (above) resolves ".." segments; this regex is defense-in-depth.
    if ($InstallDir -match '(^|\\)\.\.($|\\)') {
        Write-Error "Invalid install directory: path traversal detected after normalization"
        exit 1
    }

    # Validate Version format (except for the special 'latest' value)
    if ($Version -ne "latest" -and $Version -notmatch '^v?\d+\.\d+\.\d+(-[0-9A-Za-z\.-]+)?$') {
        Write-Error "Invalid version format: '$Version'. Expected formats like 'v1.2.3' or '1.2.3' (optionally with suffix like -beta.1), or 'latest'."
        exit 1
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
    # Use GUID for cryptographically secure random directory name
    $tmpDir = Join-Path $env:TEMP "armis-cli-install-$([guid]::NewGuid().ToString())"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        $archiveFile = Join-Path $tmpDir $archiveName
        $checksumsFile = Join-Path $tmpDir "armis-cli-checksums.txt"
        $checksumsSig = Join-Path $tmpDir "armis-cli-checksums.txt.sig"

        Write-Host "📦 Downloading $archiveName..."
        Download-File -Url "$baseUrl/$archiveName" -Output $archiveFile

        Write-Host "📥 Downloading checksums..."
        Download-File -Url "$baseUrl/armis-cli-checksums.txt" -Output $checksumsFile
        try {
            Download-File -Url "$baseUrl/armis-cli-checksums.txt.sig" -Output $checksumsSig
        } catch {
            Write-Host "⚠️  Signature file not found, skipping signature verification" -ForegroundColor Yellow
        }

        Write-Host ""
        if (Test-Path $checksumsSig) {
            Verify-Checksums -ArchiveFile $archiveFile -ChecksumsFile $checksumsFile -ChecksumsSig $checksumsSig
        } else {
            Verify-Checksums -ArchiveFile $archiveFile -ChecksumsFile $checksumsFile -ChecksumsSig ""
        }
        Write-Host ""

        Write-Host "📂 Extracting archive..."
        Expand-Archive -Path $archiveFile -DestinationPath $tmpDir -Force

        Write-Host "📥 Installing to $InstallDir..."
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        $binarySource = Join-Path $tmpDir $BinaryName
        $binaryDest = Join-Path $InstallDir $BinaryName

        # Detect upgrade vs fresh install
        if (Test-Path $binaryDest) {
            try {
                $existingVersion = & $binaryDest --version 2>$null | Select-Object -First 1
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

        Copy-Item -Path $binarySource -Destination $binaryDest -Force

        # Add to PATH (skip persistent changes in CI environments where PATH is ephemeral)
        if (-not (Test-CIEnvironment)) {
            # CWE-427: Only modify PATH if our binary was actually installed there
            # and the directory is under a known safe user location.
            $binaryInstalled = Test-Path (Join-Path $InstallDir $BinaryName)
            $safeLocations = @($env:LOCALAPPDATA, $env:APPDATA, $env:USERPROFILE, $env:ProgramFiles)
            $isSafe = $false
            foreach ($loc in $safeLocations) {
                if ($loc -and $InstallDir.StartsWith($loc, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $isSafe = $true
                    break
                }
            }
            if (-not $binaryInstalled -or -not $isSafe) {
                Write-Warning "Skipping PATH modification: directory is not a verified safe install location."
                Write-Host "   Add it manually if needed: `$env:Path += ';$InstallDir'"
            } else {
                # Use the hardcoded install dir value (not raw user input) for PATH
                $verifiedDir = [System.IO.Path]::GetFullPath($InstallDir)
                $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
                $newUserPath = Add-DirectoryToPath -ExistingPath $currentPath -Directory $verifiedDir
                if ($newUserPath -ne $currentPath) {
                    Write-Host "Adding to PATH..."
                    [Environment]::SetEnvironmentVariable(
                        "Path",
                        $newUserPath,
                        "User"
                    )
                    $env:Path = Add-DirectoryToPath -ExistingPath $env:Path -Directory $verifiedDir
                    Write-Host "Added $verifiedDir to user PATH" -ForegroundColor Green
                    Write-Host "   (Restart your terminal for PATH changes to take effect)"
                }
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
        if (Test-Path $tmpDir) {
            Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Main
