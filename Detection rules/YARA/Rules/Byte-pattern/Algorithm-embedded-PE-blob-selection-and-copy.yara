rule WannaCry(network_module)-Embedded-PE-blob-selection-and-copy
{
    meta:
        description = "Detects a characteristic WannaCry code sequence that selects embedded PE blobs and copies them into a working data structure."
        author = "lerawhite"
        signature_scope = "Implementation-specific to the analyzed sample. Absolute addresses and branch offsets are wildcarded, while the blob-selection logic, size calculation, indexed data access, and memory-copy sequence are preserved."

    strings:
        $code = {
            33 D2
            85 D2
            BE ?? ?? ?? ??
            74 ??
            BE ?? ?? ?? ??
            8B C2
            8B 3C 95 ?? ?? ?? ??
            F7 D8
            1B C0
            89 7C 94 10
            25 44 88 00 00
            05 60 40 00 00
            8B C8
            8B D9
            C1 E9 02
            F3 A5
            8B CB
            83 E1 03
            F3 A4
            8B 74 94 10
            03 F0
            89 74 94 10
            42
            83 FA 02
            7C ??
        }

    condition:
        $code
}