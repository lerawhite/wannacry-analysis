
`Raw_string_dump located in` - [Raw_strings_(DIE)](Raw_strings_(DIE).txt).

---

### String Analysis Methodology

The initial string extraction produced a large and highly heterogeneous dataset. This is primarily due to the presence of multiple embedded PE images within the analyzed sample, resulting in strings originating from different executable components being mixed together.

Because the extracted strings could not always be reliably attributed to a specific PE component, the raw output was not treated as a direct representation of the main executable's functionality. Instead, the complete string dump was preserved as raw evidence, while the extracted strings were manually reviewed and filtered according to their potential behavioral relevance.

The analysis focused primarily on suspicious or contextually meaningful artifacts, including network indicators, file and process names, service-related identifiers, command-line strings, cryptographic references, URLs, domains, and other malware-specific data. Selected strings were then correlated with previously identified imports, resources, and other static-analysis findings.

**The purpose of this stage was not to classify every extracted string, but to identify potentially meaningful indicators that could support or contradict behavioral hypotheses for subsequent deep reverse engineering.**


---
### Notable Strings — `.rdata`

> **The `.rdata` section primarily contains function and API names. No additional suspicious or behaviorally significant strings were identified during the review.**

### Notable Strings — `.data`

The `.data` section contains several strings that provide additional evidence of embedded PE content and potentially relevant execution paths.

| String / Group                                                                                                                 | Observation                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| `!This program cannot be run in DOS mode.`                                                                                     | DOS stub signature; consistent with embedded PE content identified in the sample.                                    |
| `.text`, `.rdata`, `.data`, `.rsrc`, `.reloc`                                                                                  | PE section-name signatures; provide additional evidence of embedded PE structures.                                   |
| `CloseHandle`, `WriteFile`, `CreateFileA`, `SizeofResource`, `LockResource`, `LoadResource`, `FindResourceA`, `CreateProcessA` | API names present within the extracted string set; consistent with file, resource and process-related functionality. |
| `launcher.dll`                                                                                                                 | Potential DLL component/reference requiring correlation with dynamic loading or execution logic.                     |
| `C:\%s\%s`                                                                                                                     | Runtime path format string indicating dynamic Windows filesystem path construction.                                  |
| `WINDOWS`                                                                                                                      | Windows-related string; exact purpose requires contextual analysis.                                                  |
| `mssecsvc.exe`                                                                                                                 | Significant executable-name indicator; should be correlated with the identified Windows service functionality.       |
| `CorExitProcess`                                                                                                               | .NET/CLR-related API reference.                                                                                      |
| `mscoree.dll`                                                                                                                  | Microsoft .NET CLR runtime library reference.                                                                        |
| `HH:mm:ss`                                                                                                                     | Time formatting string.                                                                                              |
| `dddd, MMMM dd, yyyy`                                                                                                          | Full date formatting string.                                                                                         |
| `MM/dd/yy`                                                                                                                     | Short date formatting string.                                                                                        |
| `January` – `December`                                                                                                         | Month names.                                                                                                         |
| `Monday` – `Sunday`                                                                                                            | Day-of-week names.                                                                                                   |

### `.rdata` and `.data` Section — String Review

> **The `.data` section was also reviewed for potentially relevant artifacts. Apart from the previously identified indicators, it mainly contains function/API names originating from the two embedded PE images. No additional suspicious strings were identified.**
> 
> **Due to the presence of multiple embedded PE components, function names from different PE images are mixed within the extracted string set and are therefore not treated as direct evidence of the main sample's functionality.**




### Notable Strings — `.rsrc`

The `.rsrc` section contains a significantly different string set compared with `.text`, `.rdata`, and `.data`. This is expected due to the previously identified **embedded PE blob** stored within the resource section.

The extracted PE contains an embedded archive with additional WannaCry components. Therefore, a substantial portion of the strings observed in `.rsrc` originates from the embedded executable/archive rather than representing strings directly belonging to the outer PE.

### Embedded Archive / Compression Indicators

|String|Observation|
|---|---|
|`inflate 1.1.3 Copyright 1995-1998 Mark Adler`|Reference to the zlib `inflate` implementation, indicating the presence of zlib/DEFLATE-related decompression functionality within the embedded content.|
|`unzip 0.15 Copyright 1998 Gilles Vollant`|Reference to an unzip implementation, consistent with the previously identified ZIP archive embedded within the PE resource.|
|`c.wnry`, `b.wnry`, `s.wnry`, `r.wnry`, `t.wnry`, `u.wnry`|Filenames corresponding to components stored within the embedded archive.|
|`taskdl.exe`, `taskse.exe`|Executable payload components contained within the embedded archive.|
|`msg/m_*.wnry`|Multiple language-specific message/resource files contained within the archive.|

These strings are therefore consistent with the previously established resource structure:

```
Main PE
└── .rsrc
    └── Embedded PE
        └── ZIP archive
            ├── taskse.exe
            ├── taskdl.exe
            ├── *.wnry
            └── msg/m_*.wnry
```

### WannaCry-Specific Indicators

|String|Observation|
|---|---|
|`WanaCrypt0r`|Malware-specific identifier associated with the WannaCry/WanaCrypt0r family.|
|`WANACRY!`|Malware-specific marker identifying the embedded content as WannaCry-related.|
|`WNcry@2ol7`|WannaCry-specific string/identifier found within the embedded content.|

The presence of these identifiers provides additional evidence that the embedded resource is not generic compressed data but contains components belonging to the analyzed WannaCry sample.

### File Extension Set

The resource also contains a large collection of file extensions, including:

```
.lay6
.sqlite3
.sqlitedb
.accdb
.java
.class
.mpeg
.djvu
.tiff
.jpeg
.backup
.vmdk
.sldm
.sldx
.onetoc2
.vsdx
.potm
.potx
.ppam
.ppsx
.ppsm
.pptm
.pptx
.xltm
.xltx
.xlsb
.xlsm
.xlsx
.dotx
.dotm
.docm
.docb
.docx
```

These strings represent file types targeted by the ransomware's file-encryption logic. Their presence is consistent with the expected behavior of WannaCry, although **the strings alone do not prove that each extension is actually processed during execution**. This will be verified during deep reverse engineering and dynamic analysis.

### File System / Execution Indicators

|String|Observation|
|---|---|
|`%s\%s`|Generic runtime path-construction format string.|
|`%s\Intel`|Path-related string referencing an `Intel` directory.|
|`%s\ProgramData`|Path-related reference to `ProgramData`.|
|`cmd.exe /c "%s"`|Command-line execution pattern using `cmd.exe`.|
|`icacls . /grant Everyone:F /T /C /Q`|Command modifying filesystem permissions and granting broad access to the current directory tree.|
|`attrib +h .`|Command associated with setting the hidden attribute.|
|`Global\MsWinZonesCacheCounterMutexA`|Global named mutex identifier, potentially used for synchronization or single-instance/duplicate-execution control.|
|`tasksche.exe`|Executable name associated with the malware's service/task execution chain.|
|`TaskStart`|Execution/task-related identifier.|

---

## Preliminary Assessment

> **The `.rsrc` string set provides substantial supporting evidence for the previously identified embedded PE and archive structure. References to zlib/DEFLATE and unzip implementations are consistent with the embedded ZIP archive, while filenames such as `taskse.exe`, `taskdl.exe`, `*.wnry`, and `msg/m_*.wnry` correspond to components contained within that archive.**
> 
> **The presence of WannaCry-specific identifiers (`WanaCrypt0r`, `WANACRY!`, and `WNcry@2ol7`) further confirms the relationship between the embedded content and the analyzed malware. The extensive file-extension list, filesystem paths, service/task-related identifiers, and command-line strings provide preliminary evidence of file-processing, execution, and filesystem-manipulation capabilities. These observations are treated as static indicators and will be correlated with imports and control-flow analysis during the Deep Reverse Analysis stage.**