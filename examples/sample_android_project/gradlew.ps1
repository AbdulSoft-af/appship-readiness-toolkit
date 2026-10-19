$ErrorActionPreference = 'Stop'
$Version = '8.14.6'
$ExpectedSha256 = '7988ed071b2a07900e2ec715fca15c6ab72bce6db433af301fa7fa7e9407bd24'
if ($env:GRADLE_USER_HOME) { $GradleUserHome = $env:GRADLE_USER_HOME } else { $GradleUserHome = Join-Path $HOME '.gradle' }
$DistRoot = Join-Path $GradleUserHome "wrapper\dists\appship-gradle-$Version-bin"
$GradleHome = Join-Path $DistRoot "gradle-$Version"
$GradleExe = Join-Path $GradleHome 'bin\gradle.bat'
if (-not (Test-Path $GradleExe)) {
    New-Item -ItemType Directory -Force -Path $DistRoot | Out-Null
    $ZipPath = Join-Path $DistRoot "gradle-$Version-bin.zip"
    if (-not (Test-Path $ZipPath)) {
        Write-Host "AppShip: downloading official Gradle $Version (first run only)..."
        Invoke-WebRequest -UseBasicParsing -Uri "https://services.gradle.org/distributions/gradle-$Version-bin.zip" -OutFile $ZipPath
    }
    $ActualSha256 = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha256 -ne $ExpectedSha256) {
        Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        throw 'Gradle SHA-256 verification failed; refusing to execute the downloaded archive.'
    }
    if (Test-Path $GradleHome) { Remove-Item -LiteralPath $GradleHome -Recurse -Force }
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $DistRoot -Force
    Remove-Item -LiteralPath $ZipPath -Force
    if (-not (Test-Path $GradleExe)) { throw 'Expected Gradle executable was not found after extraction.' }
}
& $GradleExe @args
exit $LASTEXITCODE
