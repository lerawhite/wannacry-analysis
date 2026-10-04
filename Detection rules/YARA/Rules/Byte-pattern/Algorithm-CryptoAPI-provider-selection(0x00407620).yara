rule WannaCry(network_module)-Crypt-provider-selection-algorithm
{
    meta:
        description = "Detects a characteristic WannaCry code sequence associated with cryptographic provider selection and retry logic."
        author = "lerawhite"
        signature_scope = "Implementation-specific to the analyzed sample. Equivalent implementations in other malware may produce different byte patterns due to compiler optimizations, register allocation, or instruction selection."

    strings:
        $code = {
            33 F6
            8B C6
            68 00 00 00 F0
            F7 D8
            1B C0
            6A 01
            25 ?? ?? ?? ??
            50
            6A 00
            68 ?? ?? ?? ??
            FF D7
            85 C0
            75 ??
            46
            83 FE 02
            7C ??
        }

    condition:
        $code
}