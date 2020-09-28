
# PE-Inspector

Extracts information from a PECOFF file.

Just execute the PE-Inspector like this:

    PE-Inspector.exe output.csv <Path to inspect>

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


