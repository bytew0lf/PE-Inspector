
# PE-Inspector

Extracts information from a PECOFF file.

Just execute the PE-Inspector like this:

    PE-Inspector.exe output.csv <Path to inspect>

## PE-FileInspector
Single-file inspector that writes a human-readable report and extracts certificates.

Usage:

    PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze> [--suppress-cssm <true|false>] [--sections <list>] [--exclude-sections <list>]

Notes:

- On macOS, `CSSM_ModuleLoad()` warnings can appear when the runtime touches the Security framework. They are suppressed by default in PE-FileInspector.
- Set `--suppress-cssm false` or `PE_INSPECTOR_SUPPRESS_CSSM=0` to allow these warnings.

The report contains all analysis details, and any embedded certificates are written to the output directory with their native extensions (e.g. `.cer`, `.p7b`) and additionally as PEM (`.pem`).
Use `--sections` to emit only selected report sections, or `--exclude-sections` to omit sections (comma-separated keys). Keys are normalized to lowercase with dashes, for example:

`file-info`, `version-info`, `pe-analysis`, `data-directories`, `section-entropy`, `section-permissions`, `section-padding`, `certificates`, `parse-status`, `findings`, `clr`, `strong-name`, `readytorun`, `assembly-refs`, `imports`, `import-details`, `import-descriptors`, `delay-import-details`, `delay-import-descriptors`, `bound-imports`, `exports`, `export-anomalies`, `export-details`, `exception`, `debug`, `coff-symbols`, `coff-string-table`, `coff-line-numbers`, `relocations`, `tls`, `load-config`, `rich-header`, `version-info-details`, `icon-groups`, `cursor-groups`, `bitmaps`, `resource-fonts`, `resource-fontdirs`, `resource-dlginit`, `resource-animated-cursors`, `resource-animated-icons`, `resource-rcdata`, `resources`, `resource-string-tables`, `resource-string-coverage`, `resource-message-tables`, `resource-dialogs`, `resource-accelerators`, `resource-menus`, `resource-toolbars`, `resource-manifests`, `resource-locale-coverage`.

The report also includes CLR/.NET metadata when present (runtime version, metadata version, stream list, module references, managed resource names/sizes/hashes).
It now also includes assembly metadata (assembly name/version, MVID, target framework, debuggable attribute, assembly/module attribute lists) and metadata-based assembly references (with public key tokens and resolution hints), plus a runtime hint (IL/Mixed/ReadyToRun).
Resource string tables and manifests are decoded and included in the report when available, along with string coverage summaries and strong-name signature validation details for .NET files.
The report also includes debug directory entries (CodeView/PDB IDs + identity checks, plus POGO/VC_FEATURE/EX_DLLCHARACTERISTICS/FPO summaries), data directory mapping (name/RVA/size/section), COFF symbol/line/string tables when present, base relocation summaries (top types + sample RVAs, anomaly counts), TLS/load-config data (guard flags/global flags, CHPE/GuardEH/GuardXFG fields, dynamic value relocation table details, GuardRF/HotPatch/Enclave/Volatile metadata pointers, callback resolution + section mapping, guard feature matrix, SEH handler table parsing), version-info details (string tables + translations + file flags), icon-group reconstruction (PNG detection), bitmap/cursor resource metadata, font/fontdir/rcdata/dlginit/animated cursor/icon parsing, Authenticode digest checks and signer status/policy summaries (RFC3161 timestamps, nested signatures, optional catalog lookup on Windows), message tables (entry ranges, flags/length), dialog/menu/toolbar/accelerator summaries, manifest schema summaries (including MUI, requestedExecutionLevel, DPI/UI language), ReadyToRun headers (with entry point section stats), import hash/overlay/entropy summaries and packing hints, import descriptor consistency/bind hints with API-set resolution confidence and canonical targets plus null-thunk/termination stats, export forwarder resolution hints plus export anomaly counts, section padding and permission analysis, exception directory summaries (unwind counts/details/range validity), resource locale coverage, and subsystem/security flags when present.

## Additional functionality
The PECOFF Library has also the ability to get all imports and exports of the PE-file as well as the certificate.
It now exposes debug directory entries (CodeView/PDB IDs + identity checks, plus POGO/VC_FEATURE/EX_DLLCHARACTERISTICS/FPO summaries), data directory mapping (name/RVA/size/section), COFF symbol/line/string tables when present, base relocation details + section summaries (with anomaly counts), TLS/load-config metadata (guard flags/global flags, CHPE/GuardEH/GuardXFG fields, dynamic value reloc table/GuardRF/HotPatch/Enclave/Volatile metadata pointers, callback resolution + section mapping, guard feature matrix, SEH handler table parsing), icon groups (PNG detection), version-info details (string tables + translations + file flags), bitmap/cursor metadata, font/fontdir/rcdata/dlginit/animated cursor/icon parsing, message tables (entry ranges, flags/length), dialog/menu/toolbar/accelerator parsing, manifest schema details (requestedExecutionLevel, DPI/UI language), ReadyToRun headers (with entry point section stats), import hash/overlay/section entropy and packing hints, import descriptor consistency/bind status with API-set resolution confidence and canonical targets plus null-thunk/termination stats, export forwarder resolution hints plus export anomaly counts, section padding/permission analysis, exception directory summaries (including unwind details + directory placement), resource locale and string coverage, strong-name signature validation, subsystem/DllCharacteristics summaries, Authenticode digest verification results, signer status/policy summaries (RFC3161 timestamps, nested signatures), plus CLR module references and managed resource summaries.

### Library API options
The PECOFF parser supports options and an immutable result snapshot:

- `PECOFFOptions.StrictMode`: treat warnings as errors and throw `PECOFFParseException`.
- `PECOFFOptions.ComputeHash` / `ComputeChecksum`: toggle hashing/checksum work.
- `PECOFFOptions.ComputeImportHash`: toggle imphash computation for imports.
- `PECOFFOptions.ComputeSectionEntropy`: toggle section entropy scanning.
- `PECOFFOptions.ComputeAuthenticode`: toggle Authenticode digest verification.
- `PECOFFOptions.EnableAssemblyAnalysis`: controls reflection-based obfuscation analysis.
- `PECOFFOptions.ParseCertificateSigners`: extract PKCS7 signer info.
- `PECOFFOptions.UseMemoryMappedFile`: enable memory-mapped parsing.
- `PECOFFOptions.LazyParseDataDirectories`: defer parsing resources/debug/relocations/exception/load-config/CLR until accessed.
- `PECOFFOptions.AuthenticodePolicy`: configure chain/timestamp/EKU policy checks in signer status (including optional trust-store checks and revocation settings).
- `AuthenticodePolicy.OfflineChainCheck`: disable certificate downloads and force offline chain evaluation.
- `AuthenticodePolicy.EnableCatalogSignatureCheck`: enable WinTrust catalog signature lookup (Windows only).
- `PECOFFOptions.ComputeManagedResourceHashes`: compute SHA256 for embedded managed resources.
- `PECOFFOptions.IssueCallback`: receive issues as they are raised (warnings/errors) in addition to the collected lists.
- `PECOFFOptions.PresetFast()` / `PresetDefault()` / `PresetStrictSecurity()`: convenience presets for common configurations.
- `PECOFFOptions.ValidationProfile`: `Default`, `Compatibility`, `Strict`, `Forensic` severity presets for warnings/errors.
- `PECOFFOptions.ApiSetSchemaPath`: optional path to an `apisetschema.dll` for precise API-set resolution (otherwise heuristics are used). On Windows, the parser attempts `%SystemRoot%\\System32\\apisetschema.dll` automatically when this is not set.
- `PECOFFOptions.IssuePolicy`: override per-category severity (e.g. treat Imports as warnings, Authenticode as errors).

You can retrieve a stable snapshot via `pe.Result` or `PECOFF.Parse(path, options)`.
`PECOFFResult.SchemaVersion` provides a stable DTO schema version for snapshot compatibility.

### JSON report
For CI/automation, you can emit a JSON report snapshot:

    string json = pe.Result.ToJsonReport();

Set `includeBinary: true` if you want raw byte arrays embedded; the default summarizes binary blobs by size.
Set `stableOrdering: false` to keep the natural parse order; the default orders common lists for diff-friendly snapshots.

### Corrupt fixtures
Small intentionally-corrupt fixtures live in `PECOFF.Tests/Fixtures/corrupt/` (e.g., bad RVA, overlapping sections) to validate warning behavior and profile policies.

### Snapshot regression tests
PECOFF.Tests uses a snapshot file for the `testfiles` corpus:

    PECOFF.Tests/Fixtures/testfiles.snap

Regenerate it with the snapshot generator:

    dotnet run --project tools/SnapshotGenerator/SnapshotGenerator.csproj

Optional parameters:

    dotnet run --project tools/SnapshotGenerator/SnapshotGenerator.csproj -- --input <testfiles-dir> --output <snapshot-path>

JSON golden snapshots for minimal fixtures live in:

    PECOFF.Tests/Fixtures/json/

Regenerate them by running the tests with:

    PECOFF_UPDATE_JSON_SNAPSHOTS=1 dotnet test

### Minimal fixtures
Small deterministic fixtures live in `PECOFF.Tests/Fixtures/minimal/` and are used for fast metadata sanity checks and option-policy coverage. The folder includes a handful of copied binaries from `testfiles` plus two synthetic stubs (`minimal-x86.exe`, `minimal-x64.exe`) that keep edge-case parsing stable across environments.

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

### SchemaVersion
`PECOFFResult.SchemaVersion` increments when report fields change:

- v3: resource metadata (bitmap/cursor), API-set schema, relocation summaries.
- v4: CLR module references and managed resource list; public key tokens for assembly references.
- v5: managed resource sizes, Pkcs7 chain element details, and stable JSON ordering support.
- v6: managed resource hashes, manifest validation details, and CLR attribute lists.
- v7: section permission summaries, resource locale coverage, export/relocation anomaly counts, guard feature matrix, and CLR metadata validation details.
- v8: resource string coverage, strong-name signature validation, certificate entry metadata (length/alignment), guard table sanity checks, forwarder-missing export counts, and exception directory placement metadata.
- v9: load config dynamic value reloc/GuardRF/HotPatch/Enclave pointers, import descriptor null-thunk/termination stats, message table entry ranges/flags, metadata table token ranges, and signer status summaries.
- v10: data directory mapping with Architecture/GlobalPtr/IAT details, plus COFF symbol/string/line table decoding.
- v11: extra resource parsing (fonts/fontdir/dlginit/animated/rcdata), debug directory POGO/VC_FEATURE/EX_DLLCHARACTERISTICS/FPO summaries, and SEH handler table parsing.
- v12: debug directory MISC/OMAP/REPRO details, ARM64 unwind summaries, and load-config code-integrity/enclave metadata.
- v13: debug directory COFF/FIXUP/ILTCG/MPX/CLSID details, load-config guard tables, and raw HTML/DLGINCLUDE/PLUGPLAY/VXD resource summaries.
- v14: full ARM64 unwind decoding, ARM/IA64 unwind headers, and enclave import list parsing.
- v15: COFF object + TE image metadata, image kind, and catalog signature lookup metadata.
- v16: COFF relocation decoding + aux symbol details, TLS raw data mapping/alignment, and SEH handler entry resolution.

### Coverage map
High-level PE/COFF structures and current coverage:

- DOS header + stub: implemented
- COFF file header: implemented
- Optional header (PE32/PE32+): implemented
- Data directories: implemented (name/section mapping, Architecture/GlobalPtr/IAT metadata)
- Sections: implemented (entropy, permissions, padding)
- Imports/Exports: implemented (INT/IAT, delay/bound, forwarders, anomalies)
- Resources: implemented (strings, manifests/MUI, dialogs/menus/toolbars/accelerators, icons/cursors/bitmaps, message tables, HTML/DLGINCLUDE/PLUGPLAY/VXD raw summaries)
- Resources (extended): implemented (fonts/fontdir, rcdata, dlginit, animated cursor/icon)
- Debug directory: implemented (CodeView/PDB, COFF, POGO, VC_FEATURE, EX_DLLCHARACTERISTICS, FPO, MISC, OMAP, REPRO, ILTCG, MPX, CLSID, FIXUP)
- Relocations: implemented (summaries + anomalies)
- Exception directory: implemented (unwind + validation, AMD64/ARM64 full decode, ARM/IA64 header parsing, x86 SEH handler table)
- TLS: implemented (callbacks + raw data mapping/alignment)
- Load config: implemented (guard flags, guard tables, code integrity, enclave config + imports, CHPE, dynamic reloc tables, SEH handler metadata + entries)
- CLR/.NET: implemented (metadata, references, ReadyToRun)
- Certificates/Authenticode: implemented (PKCS7/signers/timestamps, catalog lookup on Windows)
- COFF objects: basic header/sections + symbols/line numbers/relocations
- UEFI TE images: header + sections
- COFF symbols/line numbers/string table: implemented when present (aux symbol decoding)

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
