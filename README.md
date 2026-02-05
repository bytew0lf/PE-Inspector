
# PE-Inspector

Extracts information from a PECOFF file.

Just execute the PE-Inspector like this:

    PE-Inspector.exe output.csv <Path to inspect>

## PE-FileInspector
Single-file inspector that writes a human-readable report and extracts certificates.

Usage:

    PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze> [--suppress-cssm <true|false>]

Notes:

- On macOS, `CSSM_ModuleLoad()` warnings can appear when the runtime touches the Security framework. They are suppressed by default in PE-FileInspector.
- Set `--suppress-cssm false` or `PE_INSPECTOR_SUPPRESS_CSSM=0` to allow these warnings.

The report contains all analysis details, and any embedded certificates are written to the output directory with their native extensions (e.g. `.cer`, `.p7b`) and additionally as PEM (`.pem`).

The report also includes CLR/.NET metadata when present (runtime version, metadata version, and stream list).
It now also includes assembly metadata (assembly name/version, MVID, target framework) and metadata-based assembly references.
Resource string tables and manifests are decoded and included in the report when available.
The report also includes debug directory entries, base relocations, TLS/load-config data, version-info details, icon-group reconstruction, Authenticode digest checks, message tables, manifest schema summaries (including MUI when present), ReadyToRun headers, and subsystem/security flags when present.

## Additional functionality
The PECOFF Library has also the ability to get all imports and exports of the PE-file as well as the certificate.
It now exposes debug directory entries, base relocations, TLS/load-config metadata, icon groups, version-info details, message tables, manifest schema details, ReadyToRun headers, subsystem/DllCharacteristics summaries, and Authenticode digest verification results.

### Library API options
The PECOFF parser supports options and an immutable result snapshot:

- `PECOFFOptions.StrictMode`: treat warnings as errors and throw `PECOFFParseException`.
- `PECOFFOptions.ComputeHash` / `ComputeChecksum`: toggle hashing/checksum work.
- `PECOFFOptions.ComputeAuthenticode`: toggle Authenticode digest verification.
- `PECOFFOptions.EnableAssemblyAnalysis`: controls reflection-based obfuscation analysis.
- `PECOFFOptions.ParseCertificateSigners`: extract PKCS7 signer info.
- `PECOFFOptions.UseMemoryMappedFile`: enable memory-mapped parsing.

You can retrieve a stable snapshot via `pe.Result` or `PECOFF.Parse(path, options)`.

### Snapshot regression tests
PECOFF.Tests uses a snapshot file for the `testfiles` corpus:

    PECOFF.Tests/Fixtures/testfiles.snap

Regenerate it with the snapshot generator:

    dotnet run --project tools/SnapshotGenerator/SnapshotGenerator.csproj

Optional parameters:

    dotnet run --project tools/SnapshotGenerator/SnapshotGenerator.csproj -- --input <testfiles-dir> --output <snapshot-path>

### Build scripts
Self-contained single-file builds are available via the scripts in `scripts/`.

PE-FileInspector:

    # Windows (PowerShell)
    ./scripts/build-pe-fileinspector-windows.ps1

    # Linux/macOS
    ./scripts/build-pe-fileinspector-linux.sh
    ./scripts/build-pe-fileinspector-macos.sh

PE-Inspector:

    # Windows (PowerShell)
    ./scripts/build-pe-inspector-windows.ps1

    # Linux/macOS
    ./scripts/build-pe-inspector-linux.sh
    ./scripts/build-pe-inspector-macos.sh

Defaults:

- Output goes to `artifacts/<app-name>/<rid>/`.
- Override `RID` and `CONFIGURATION` if needed (e.g. `RID=osx-arm64`).

## Contents of the output file
The CSV-Output currently contains the following values for each analyzed file.
 - Filename
 - Extension 
 - Path 
 - Product Version 
 - File Version 
 - IsDotNetFile
 - IsObfuscated 
 - Obfuscationpercentage 
 - SHA256 HASH 
 - HasCertificate   
 - Comments 
 - CompanyName 
 - FileDescription 
 - InternalName 
 - IsDebug 
 - IsPatched
 - IsPreRelease
 - IsPrivateBuild
 - IsSpecialBuild 
 - Language 
 - Copyright
 - Trademarks 
 - OriginalFilename 
 - PrivateBuild 
 - ProductName 
 - SpecialBuild
 - ParseErrors
 - ParseWarnings
