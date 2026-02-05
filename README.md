
# PE-Inspector

Extracts information from a PECOFF file.

Just execute the PE-Inspector like this:

    PE-Inspector.exe output.csv <Path to inspect>

## PE-FileInspector
Single-file inspector that writes a human-readable report and extracts certificates.

Usage:

    PE-FileInspector --output report.txt --output-dir <output-path> --file <file-to-analyze>

The report contains all analysis details, and any embedded certificates are written to the output directory with their native extensions (e.g. `.cer`, `.p7b`) and additionally as PEM (`.pem`).

## Additional functionality
The PECOFF Library has also the ability to get all imports and exports of the PE-file as well as the certificate.

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
