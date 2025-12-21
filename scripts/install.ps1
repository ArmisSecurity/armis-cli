# Armis CLI Windows Installer
# Usage: irm https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.ps1 | iex
# Or: .\install.ps1 [-Version "v1.0.0"] [-InstallDir "C:\Program Files\armis-cli"] [-Verify]

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\armis-cli",
    [switch]$Verify = $true
)

$ErrorActionPreference = "Stop"

$Repo = "armis/armis-cli"
$BinaryName = "armis-cli.exe"

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
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

function Main {
    Write-Host ""
    Write-Host "Installing Armis CLI..." -ForegroundColor Cyan
    Write-Host ""
    
    $arch = Get-Architecture
    Write-Host "Detected Architecture: $arch"
    Write-Host ""
    
    if ($Version -eq "latest") {
        $baseUrl = "https://github.com/$Repo/releases/latest/download"
    } else {
        $baseUrl = "https://github.com/$Repo/releases/download/$Version"
    }
    
    $archiveName = "armis-cli-windows-$arch.zip"
    $tmpDir = Join-Path $env:TEMP "armis-cli-install-$(Get-Random)"
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
        
        Copy-Item -Path $binarySource -Destination $binaryDest -Force
        
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*$InstallDir*") {
            Write-Host "📝 Adding to PATH..."
            [Environment]::SetEnvironmentVariable(
                "Path",
                "$currentPath;$InstallDir",
                "User"
            )
            $env:Path = "$env:Path;$InstallDir"
            Write-Host "✓ Added $InstallDir to user PATH" -ForegroundColor Green
            Write-Host "   (Restart your terminal for PATH changes to take effect)"
        }
        
        Write-Host ""
        Write-Host "✅ Armis CLI installed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Run 'armis-cli --help' to get started"
        Write-Host ""
        
    } finally {
        if (Test-Path $tmpDir) {
            Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Main
