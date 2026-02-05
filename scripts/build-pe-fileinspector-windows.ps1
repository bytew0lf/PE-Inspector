param(
    [string]$Configuration = "Release",
    [string]$Rid = "win-x64"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root "PE-FileInspector" "PE-FileInspector.csproj"
$outDir = Join-Path $root "artifacts" "pe-fileinspector" $Rid

dotnet publish $project `
    -c $Configuration `
    -r $Rid `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:PublishTrimmed=false `
    -o $outDir

Write-Host "Output: $outDir"
