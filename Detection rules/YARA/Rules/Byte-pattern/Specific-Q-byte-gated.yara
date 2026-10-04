rule WannaCry(network_module)-SMB-Q-response-gate
{
    meta:
        description = "Detects a characteristic WannaCry SMB sequence that sends a response-derived packet, receives up to 0x400 bytes, and validates an 'Q' response. (0x004072A0)"
        author = "lerawhite"
        signature_scope = "Implementation-specific to the analyzed sample. The signature targets the combination of response-derived packet construction, SMB send/receive operations, and the 'Q' response gate."

    strings:
        $code = {
            6A 00
            6A 52
            68 ?? ?? ?? ??
            56

            A2 ?? ?? ?? ??
            88 0D ?? ?? ?? ??
            88 1D ?? ?? ?? ??
            88 15 ?? ?? ?? ??
            A2 ?? ?? ?? ??
            88 0D ?? ?? ?? ??
            88 1D ?? ?? ?? ??
            88 15 ?? ?? ?? ??

            E8 ?? ?? ?? ??
            83 F8 FF
            74 ??

            6A 00
            8D 44 24 ??
            68 00 04 00 00
            50
            56

            E8 ?? ?? ?? ??
            83 F8 FF
            74 ??

            80 7C 24 ?? 51
            75 ??
        }

    condition:
        $code
}