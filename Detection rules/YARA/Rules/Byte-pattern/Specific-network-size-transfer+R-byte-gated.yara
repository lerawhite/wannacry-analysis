rule WannaCry(network_module)-Specific-size-transfer-R-acknowledgement
{
    meta:
        description = "Detects a characteristic WannaCry transfer sequence using 0x1052-byte sends, 0x1000-byte receives, and an 'R' acknowledgement check."
        author = "lerawhite"
        signature_scope = "Implementation-specific to the analyzed sample. The signature targets the combination of fixed transfer sizes and response-byte validation rather than generic send/recv usage."

    strings:
        $code = {
            68 52 10 00 00
            51
            56
            E8 ?? ?? ?? ??
            83 F8 FF
            74 ??
            6A 00
            8D 94 24 ?? ?? ?? ??
            68 00 10 00 00
            52
            56
            E8 ?? ?? ?? ??
            83 F8 FF
            74 ??
            80 BC 24 ?? ?? ?? ?? 52
            75 ??
        }

    condition:
        $code
}