rule WannaCry(network_module)-DOUBLEPULSAR-XOR-key
{
    meta:
        description = "Detects the characteristic DOUBLEPULSAR XOR key derivation algorithm used by the WannaCry network module."
        author = "lerawhite"
        signature_scope = "Algorithm-specific signature derived from reverse engineering. The pattern represents the characteristic byte-reordering, doubling, and XOR operations used for DOUBLEPULSAR-related key derivation."

    strings:
        $code = {
            8B 4C 24 ??
            56
            8B C1
            8B D1
            25 00 FF 00 00
            8B F1
            C1 E2 10
            0B C2
            8B D1
            81 E2 00 00 FF 00
            03 C9
            C1 EE 10
            0B D6
            5E
            C1 E0 08
            C1 EA 08
            0B C2
            33 C1
        }

    condition:
        $code
}