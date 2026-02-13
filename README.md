# PE-Inspector
[![Build](https://github.com/bytew0lf/PE-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/bytew0lf/PE-Inspector/actions/workflows/ci.yml)

Extracts information from PE/COFF files. Includes:

- **PE-Inspector**: CSV output for batch analysis.
- **PE-FileInspector**: single-file report + certificate extraction.
- **PECOFF** library: parse and inspect PE/COFF programmatically.

## Requirements

- .NET SDK **9.0+**
- Windows/macOS/Linux supported (some Authenticode policy checks are Windows-only)

## Installation

Prebuilt binaries are not published yet. Build from source:

    dotnet build PE-Inspector.sln -c Release

Executable outputs land in the project `bin/<Configuration>/net9.0/` folders.

## Features

- Imports/exports (INT/IAT, delay/bound, forwarders, anomalies, API-set hints)
- Data directories mapping + validation (Architecture/GlobalPtr/IAT deep decode)
- Sections (entropy, permissions, padding, alignment/overlap checks)
- TLS/load-config metadata (guard flags, CHPE/XFG, dynamic-reloc/volatile pointed-structure decode, callback mapping, raw data hash/preview)
- Exception/unwind decoding (x64/ARM64/ARM32/IA64 + x86 SEH)
- Resources (strings, dialogs/menus/toolbars, manifests/MUI, icons/cursors/bitmaps, RT_VERSION extensions, ordering/depth/cycle compliance checks)
- Debug directory decoding (CodeView/PDB identity, canonical-first type labeling for undefined/custom entries with compatibility aliases, reserved-field/type conformance checks including reserved debug types `6/9/10/11`, POGO/VC_FEATURE/FPO/Borland/reserved, EX_DLLCHARACTERISTICS symbolic flag decode + unsupported-bit conformance checks, raw fallback)
- PDB/MSF stream parsing + symbol record decoding
- CLR/.NET metadata deep-dive (tables, token refs, signature decode, IL/EH summaries, ReadyToRun)
- Authenticode/certificates (PKCS7 signers/timestamps, X509/TS-stack metadata, tuple-uniqueness checks + per-field uniqueness warnings with strict-profile escalation, CT hints, WinTrust on Windows, policy summaries)
- COFF objects/archives + UEFI TE images (expanded relocation families, linker-member mapping, import header reserved-bit validation, broader machine-type constant coverage including canonical `ALPHA`/`ALPHA64 (AXP64)`/`CEE` naming plus `R3000BE`/`TARGET_HOST`/`CHPE_X86`, spec-aligned storage-class constants, richer aux symbol decode including CLR-token structured fields, Aux Format 1/2 reserved-field conformance checks, weak-external symbol-table-index resolution, relocation SymbolTableIndex vs PAIR-displacement conformance plus PAIR ordering validation (ARM/PPC/MIPS/M32R/SH), ARM/PPC table-aligned constants, IA64 table-only defaults with explicit compatibility labels for disputed prose constants, configurable IA64 ADDEND and PPC PAIR ordering policies, per-relocation compatibility audit markers (`UsesCompatibilityMapping`/`CompatibilityPolicy`/`CompatibilityNote`) with policy notices, COFF extended relocation-overflow (`LNK_NRELOC_OVFL`) parsing, COFF `/nnn` section long-name resolution, UTF-8 short/string-table name decode with deterministic Latin-1 fallback, and PE-image COFF conformance checks for loader section-count limit (`<=96`), `EXECUTABLE_IMAGE`, deprecated/reserved file-header bits, symbol/line/relocation-pointer usage, stripped-bit consistency, section object-only/reserved characteristic flags, and optional-header `NumberOfRvaAndSizes` bounds)
- Overlay container parsing (ZIP/RAR/7z NextHeader + EncodedHeader notes)
- JSON report snapshotting (stable schema versioning)

## Current Coverage Map (auto-generated)

Status legend:
* `full`: Implemented and covered by unit/matrix tests
* `partial`: Implemented, but only partially covered by tests
* `open`: Not implemented yet

### Parser/Report Coverage

| Area | Status | Current coverage |
| --- | --- | --- |
| DOS header + stub | `full` | Header + relocation table summary. |
| COFF file header | `full` | Machine/characteristics with full documented machine-name matrix coverage (including canonical `ALPHA`, `ALPHA64 (AXP64)`, `CEE`, and additional IDs such as `R3000BE`/`TARGET_HOST`/`CHPE_X86`), bigobj header support, and image-vs-object COFF conformance checks including PE-image loader section-count limit (`NumberOfSections <= 96`), `EXECUTABLE_IMAGE`, deprecated/reserved file-header bits (`AGGRESSIVE_WS_TRIM`, `FUTURE_USE`, `BYTES_REVERSED_LO/HI`, deprecated line/local bits), symbol/line/relocation-pointer deprecation rules, stripped-bit consistency (`RELOCS_STRIPPED`/`LINE_NUMS_STRIPPED`/`LOCAL_SYMS_STRIPPED`/`DEBUG_STRIPPED`), section object-only/reserved characteristic enforcement (`LNK_INFO`/`LNK_REMOVE`/`LNK_COMDAT`/`GPREL`/`ALIGN_*`/reserved low bits including `0x00004000`), and optional-header `NumberOfRvaAndSizes`/`SizeOfOptionalHeader` consistency validation. |
| Optional header (PE32/PE32+) | `full` | Standard fields + checksum/timestamp decoding + reserved-field conformance checks + full documented subsystem mapping/classification (including `OS2_CUI` and `NATIVE_WINDOWS`) + explicit `NumberOfRvaAndSizes` bounds checks against `SizeOfOptionalHeader`. |
| Sections | `full` | Header decoding (sizes/flags/align), entropy, permissions, padding, overlaps/align checks, directory containment summaries. |
| Data directories | `full` | Name/section mapping + Architecture/GlobalPtr/IAT deep decode + size/mapping validation. |
| Imports/Exports | `full` | INT/IAT, delay/bound, forwarders, anomalies, API-set hints. |
| Relocations | `full` | Summaries + anomaly totals; machine-aware COFF relocation mapping with matrix tests across i386/AMD64/ARM/ARM64/IA64/PPC/MIPS/SH/M32R (including `SH3E`/`R3000BE` family behavior), table-aligned ARM/PPC constants, canonical latest-spec IA64/PPC behavior in `TableOnly` mode, true symbol-table-index resolution, PAIR displacement handling plus immediate-predecessor ordering validation (ARM/PPC/MIPS/M32R/SH), IA64 ADDEND immediate-predecessor/payload conformance checks, per-relocation compatibility audit markers and policy notices, COFF overflow-relocation (`IMAGE_SCN_LNK_NRELOC_OVFL`) marker parsing/validation, base-relocation HIGHADJ two-slot semantics, and 4K-page + 32-bit block-boundary conformance checks. Optional `CompatibilityProse` policies remain available as explicit non-canonical compatibility mode. |
| TLS | `full` | Callbacks + raw data mapping, hash/preview, template sizing + index mapping. |
| Load config | `full` | Guard/CHPE/Enclave/CodeIntegrity + versioned layout, trailing bytes + truncation, structured decode for dynamic-reloc/CHPE/volatile pointed metadata with deterministic malformed issues. |
| Exception directory | `full` | AMD64/ARM64/ARM32/IA64 decode + range validation, x86 SEH. |
| Resources | `full` | Strings, dialogs/menus/toolbars, manifests/MUI edge fields, icons/cursors/bitmaps, message tables, RT_VERSION extensions, ordering and malformed-tree checks. |
| Resources (tree compliance) | `full` | Named/ID ordering checks, circular-reference detection, malformed entry bounds checks, optional safe deep-tree validation beyond 3 levels. |
| Resources (extended) | `full` | Fonts/fontdir, rcdata format detection, dlginit, animated cursor/icon. |
| Debug directory | `full` | CodeView/PDB identity, POGO/VC_FEATURE/FPO/Borland/reserved, EX_DLLCHARACTERISTICS symbolic flag mapping (`CET_COMPAT`/`FORWARD_CFI_COMPAT`) with explicit unsupported-bit SPEC violations (including `0x00000002` as non-spec/unknown in default with strict-mode escalation), reserved `IMAGE_DEBUG_DIRECTORY.Characteristics` enforcement, reserved debug-type usage warnings for `IMAGE_DEBUG_TYPE_FIXUP (6)`, `IMAGE_DEBUG_TYPE_BORLAND (9)`, `IMAGE_DEBUG_TYPE_RESERVED10 (10)`, and `IMAGE_DEBUG_TYPE_CLSID (11)` with compatibility decode paths, canonical-first type labeling for `Undefined17`/`Undefined19` plus compatibility aliases (`EmbeddedPortablePdb`/`PdbHash`) and explicit custom-type handling for `Unknown18` (`Spgo` alias), embedded PDB/SPGO/PDB hash decode + raw fallback. |
| PDB/MSF streams | `full` | MSF directory + PDB signature/age, DBI/TPI/GSI/publics + symbol record parsing. |
| CLR/.NET | `full` | Metadata tables, token cross-refs, signature decode, method body IL sizes + EH clauses, R2R header. |
| Certificates/Authenticode | `full` | PKCS7 signers/timestamps, CT hints/logs, WinTrust (Windows), trust-store status + policy evaluation, tuple uniqueness for `(wRevision,wCertificateType)` plus per-field uniqueness warnings (strict-profile escalates to errors), X509/TS-stack typed metadata reporting. |
| COFF objects | `full` | Symbols/aux/relocs/line numbers, COMDAT selection hints, expanded aux formats (file multi-record with deterministic Latin-1 `.file` decode fidelity, spec-aligned function/.bf/.ef line info with reserved-field checks, function-definition reserved-tail validation, weak-external EXTERNAL+undefined compatibility plus symbol-table-index resolution, symbol definition, section class decoding), relocation SymbolTableIndex conformance (full-index lookup + PAIR displacement semantics), COFF overflow-relocation marker handling (`IMAGE_SCN_LNK_NRELOC_OVFL`) with malformed-combo detection, COFF section long-name (`/nnn`) resolution with explicit malformed-offset spec violations, UTF-8 short/string-table name handling with deterministic fallback warnings, structured CLR-token aux decode + reserved-field validation, malformed aux-layout conformance checks. |
| COFF archives/import libs | `full` | Archive headers, longnames, thin/SYM64 support, first/second linker member symbol-to-member mapping, import object variants + reserved-bit validation. |
| UEFI TE images | `full` | Header/sections, base relocations, entrypoint/base-of-code file offsets + mapping checks. |
| Overlay containers | `full` | ZIP/RAR4/5/7z container parsing + encoded-header method notes. |
| Rich header | `full` | Toolchain signature summaries + extended product mapping. |

### Relocation Policy Matrix

Canonical latest-spec conformance is `TableOnly` (`ProfileDefault` resolves to `TableOnly` for all validation profiles). `CompatibilityProse` is opt-in and non-canonical.

| Area | TableOnly | CompatibilityProse |
| --- | --- | --- |
| IA64 disputed constants (`0x000F`, `0x001D`, `0x001E`) | `TYPE_0xXXXX` fallback | Explicit compatibility aliases (`LTOFF64_COMPAT`, `PCREL21BI_COMPAT`, `PCREL22_COMPAT`) + policy notice |
| IA64 ADDEND predecessor (`0x001F`) | `0x000F` predecessor rejected (spec violation) | `0x000F` predecessor accepted |
| PPC `PAIR` predecessor (`0x0012`) | `REFHI` only | `REFHI` + legacy `0x0014` via `SECRELHI_COMPAT` alias + policy notice |

### Load-Config matrix (Win8→Win11)

The parser records a version hint based on which field groups are present and preserves any
trailing bytes beyond the known layout.

- pre-Win8: base layout only (no CodeIntegrity/Guard tables)
- Win8+: CodeIntegrity + GuardIAT + DynamicReloc/CHPE
- Win8.1+: GuardRF + HotPatch
- Win10+: Enclave/Volatile metadata or EHContinuation
- Win10+ (XFG): XFG fields present
- Win11+: trailing fields beyond known layout (captured as hash/preview; truncated layouts flagged)

## Usage

### PE-Inspector (CSV)

    PE-Inspector.exe output.csv <Path to inspect>

### PE-FileInspector (report + certificates)

    PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze> \
      [--suppress-cssm <true|false>] [--sections <list>] [--exclude-sections <list>]

Notes:

- On macOS, `CSSM_ModuleLoad()` warnings can appear when the runtime touches the Security framework.
  They are suppressed by default.
- Set `--suppress-cssm false` or `PE_INSPECTOR_SUPPRESS_CSSM=0` to allow these warnings.

Section filtering uses comma-separated keys (lowercase, dash-separated). Examples:

`file-info`, `version-info`, `pe-analysis`, `data-directories`, `section-entropy`, `section-permissions`,
`section-padding`, `certificates`, `parse-status`, `findings`, `clr`, `strong-name`, `readytorun`,
`assembly-refs`, `imports`, `import-details`, `import-descriptors`, `delay-import-details`,
`delay-import-descriptors`, `bound-imports`, `exports`, `export-anomalies`, `export-details`,
`exception`, `debug`, `coff-symbols`, `coff-string-table`, `coff-line-numbers`, `relocations`,
`tls`, `load-config`, `rich-header`, `version-info-details`, `icon-groups`, `resource-icons`,
`cursor-groups`, `resource-cursors`, `bitmaps`, `resource-fonts`, `resource-fontdirs`,
`resource-dlginit`, `resource-animated-cursors`, `resource-animated-icons`, `resource-rcdata`,
`resources`, `resource-string-tables`, `resource-string-coverage`, `resource-message-tables`,
`resource-dialogs`, `resource-accelerators`, `resource-menus`, `resource-toolbars`,
`resource-manifests`, `resource-locale-coverage`.

The report contains detailed analysis and extracts embedded certificates as native extensions
(e.g. `.cer`, `.p7b`) and as PEM (`.pem`).

### Library usage

The PECOFF library exposes a rich result model:

    PECOFF pe = new PECOFF(path);
    PECOFFResult result = pe.Result; // stable snapshot

## Library API options

- `PECOFFOptions.StrictMode`: treat warnings as errors and throw `PECOFFParseException`.
- `PECOFFOptions.ComputeHash` / `ComputeChecksum`: toggle hashing/checksum work.
- `PECOFFOptions.ComputeImportHash`: toggle imphash computation for imports.
- `PECOFFOptions.ComputeSectionEntropy`: toggle section entropy scanning.
- `PECOFFOptions.ComputeAuthenticode`: toggle Authenticode digest verification.
- `PECOFFOptions.EnableAssemblyAnalysis`: controls reflection-based obfuscation analysis.
- `PECOFFOptions.ParseCertificateSigners`: extract PKCS7 signer info.
- `PECOFFOptions.UseMemoryMappedFile`: enable memory-mapped parsing.
- `PECOFFOptions.LazyParseDataDirectories`: defer parsing resources/debug/relocations/exception/load-config/CLR until accessed.
- `PECOFFOptions.AuthenticodePolicy`: configure chain/timestamp/EKU policy checks in signer status (including optional trust-store checks and revocation settings on all platforms).
- `AuthenticodePolicy.RequireCertificateTransparency`: optionally require SCT data for code-signing certificates.
- `AuthenticodePolicy.OfflineChainCheck`: disable certificate downloads and force offline chain evaluation.
- `AuthenticodePolicy.EnableCatalogSignatureCheck`: enable WinTrust catalog signature lookup (Windows only).
- `PECOFFOptions.ComputeManagedResourceHashes`: compute SHA256 for embedded managed resources.
- `PECOFFOptions.EnableDeepResourceTreeParsing`: enable safe resource-directory traversal beyond the conventional 3 levels (depth/cycle guarded).
- `PECOFFOptions.IssueCallback`: receive issues as they are raised (warnings/errors) in addition to the collected lists.
- `PECOFFOptions.PresetFast()` / `PresetDefault()` / `PresetStrictSecurity()`: convenience presets for common configurations.
- `PECOFFOptions.ValidationProfile`: `Default`, `Compatibility`, `Strict`, `Forensic` severity presets for warnings/errors. Default profile reports per-field certificate uniqueness as warnings; strict profile escalates them to errors.
- `PECOFFOptions.Ia64AddendOrderingPolicy`: controls IA64 `ADDEND` predecessor semantics: `ProfileDefault` (default canonical `TableOnly`), `TableOnly`, or `CompatibilityProse` (non-canonical compatibility mode).
- `PECOFFOptions.Ia64RelocationTablePolicy`: controls IA64 disputed constant naming: `ProfileDefault` (default canonical `TableOnly`), `TableOnly`, or `CompatibilityProse` (`*_COMPAT` labels; non-canonical compatibility mode).
- `PECOFFOptions.PpcPairOrderingPolicy`: controls PPC `PAIR` predecessor handling: `ProfileDefault` (default canonical `TableOnly`), `TableOnly` (`REFHI` only), or `CompatibilityProse` (`REFHI` + legacy `SECRELHI`; non-canonical compatibility mode).
- `PECOFFOptions.ApiSetSchemaPath`: optional path to an `apisetschema.dll` for precise API-set resolution (otherwise heuristics are used). On Windows, the parser attempts `%SystemRoot%\System32\apisetschema.dll` automatically when this is not set.
- `PECOFFOptions.IssuePolicy`: override per-category severity (e.g. treat Imports as warnings, Authenticode as errors).

You can retrieve a stable snapshot via `pe.Result` or `PECOFF.Parse(path, options)`.
`PECOFFResult.SchemaVersion` provides a stable DTO schema version for snapshot compatibility.

## JSON report

For CI/automation, emit a JSON report snapshot:

    string json = pe.Result.ToJsonReport();

Options:

- `includeBinary: true` embeds raw byte arrays; default is size-only summaries.
- `stableOrdering: false` keeps natural parse order; default is diff-friendly ordering.

## Tests and fixtures

### Testfiles corpus

Tests that validate real-world parsing use the `testfiles` corpus (not checked into the repo).
Set a custom path using:

- `PECOFF_TESTFILES_DIR=/path/to/testfiles`

### Minimal fixtures

Small deterministic fixtures live in `PECOFF.Tests/Fixtures/minimal/` and are used for fast
metadata sanity checks and option-policy coverage. The folder includes a compact
`PE-Inspector.dll` sample plus two synthetic stubs (`minimal-x86.exe`, `minimal-x64.exe`).

### Corrupt fixtures

Intentionally-corrupt fixtures live in `PECOFF.Tests/Fixtures/corrupt/` (e.g., bad RVA,
overlapping sections) to validate warning behavior and profile policies.

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

Or use the standalone JSON snapshot generator (avoids VSTest):

    dotnet run --project tools/JsonSnapshotGenerator/JsonSnapshotGenerator.csproj

Optional parameters:

    dotnet run --project tools/JsonSnapshotGenerator/JsonSnapshotGenerator.csproj -- --fixtures <path> --output <path>

## Build notes

### Build

    dotnet build PE-Inspector.sln

### Test

    dotnet test

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

### Release workflow

A manual GitHub Actions workflow (`.github/workflows/release.yml`) builds, tests, and publishes a
GitHub Release. It requires a tag input (e.g. `v1.2.3`) and runs on demand.

## CSV output fields (PE-Inspector)

The CSV output contains the following values per file:

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

## SchemaVersion

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
- v17: overlay container parsing (ZIP/RAR/7z) and RCDATA format detection.
- v18: TLS raw data hash/preview, COFF bigobj + type decoding, richer RCDATA formats, and certificate transparency hints.
- v19: Architecture/GlobalPtr/IAT content summaries and COFF COMDAT association hints.
- v20: TLS template sizing/notes, extended base relocation type mapping, and Borland/reserved debug entries.
- v21: PDB/MSF parsing, WinTrust/CT log policy metadata, and CLR metadata deep-dive (token refs + method bodies).
- v22: COFF archive/import-library parsing, DOS relocation table summary, and additional debug directory types (Embedded PDB/SPGO/PDBHASH).
- v23: Architecture/GlobalPtr/IAT deep decode, ARM32/IA64 unwind details, and machine-aware base relocation types (RISC-V/LoongArch).
- v24: Load-config version info + trailing field capture, resource group variants, and RT_VERSION extensions.
- v25: TE header depth + relocations, COFF symbol scope details, COMDAT selection metadata, and raw icon/cursor resources.
- v26: PDB DBI/TPI/GSI stream parsing + publics extraction, and cross-platform trust-store status summaries.
- v27: Section header detail coverage (alignment/size checks + directory containment summary).
- v28: Data directory validation (size/alignment/mapping checks).
- v29: Relocation anomaly totals, TLS index mapping, and debug raw fallback entries.
- v30: Authenticode policy evaluation summary, CLR signature decoding + EH clause summary, and PDB symbol record parsing.
- v31: COFF archive thin/SYM64 handling + import object variants, TE entrypoint file offsets + mapping, and load-config truncation tracking.
- v32: Manifest edge metadata (supported OS/longPath/active code page), debug exception summaries, and richer overlay notes.
- v33: COFF aux CLR-token structured fields (aux type/index/reserved validation metadata), spec-aligned COFF storage-class/function aux handling, ARM relocation name-table refresh, and strict-profile certificate per-field uniqueness enforcement.
- v34: Aux Format 1/2 reserved-field conformance metadata, weak-external decode compatibility for EXTERNAL+undefined form plus symbol-table-index resolution semantics, broader COFF relocation constant alignment (ARM/IA64/PPC/SH/M32R), and default-profile per-field certificate uniqueness warnings.

## Security

See `SECURITY.md` for the security policy and reporting process.

## License

See `LICENSE` for details.
