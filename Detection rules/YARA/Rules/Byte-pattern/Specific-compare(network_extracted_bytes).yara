rule WannaCry(network_module)-SMB-response-validation
{
    meta:
        description = "Detects a characteristic WannaCry SMB response validation sequence associated with the SMB communication routine at 0x00401980."
        author = "lerawhite"
        signature_scope = "Implementation-specific response validation pattern derived from reverse engineering. Stack displacements and relative branch offsets are wildcarded while the validated response bytes are preserved."

    strings:
        $code = {
            80 7C 24 ?? 05
            75 ??
            80 7C 24 ?? 02
            75 ??
            8A 44 24 ??
            84 C0
            75 ??
            80 7C 24 ?? C0
            75 ??
        }

    condition:
        $code
}