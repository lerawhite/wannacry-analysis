

```finding_by_die
Embedded Resource Analysis

The .rsrc section contains a one PE-formatted blob beginning with
the MZ signature.

After extraction, the embedded PE can be identified as a container
holding a ZIP archive.

The archive contains multiple files, including:

- msg
- b.wnry
- s.wnry
- taskse.exe
- taskdl.exe

The ZIP metadata is readable, while the archived file contents are
marked as encrypted.

SHA-256 - ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
```

![](SHA256_of_rsrc_blob.png)



**Wannacry.exe(rsrc_pe_blob_struct_1part)**
![](wannacry.exe(rsrc_pe_blob_struct_1part).png)


**Wannacry.exe(rsrc_pe_blob_struct_2part)** 
![](wannacry.exe(rsrc_pe_blob_struct_2part).png)




