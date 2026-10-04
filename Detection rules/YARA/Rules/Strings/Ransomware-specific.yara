rule Ransomware_Strings
{
    meta:
        author = "lerawhite"
        description = "Detects WannaCry based on specific strings"
        malware = "WannaCry (Network module)"
        date = "2026-10-03"

    strings:
        $wanacrypt = "WanaCrypt0r"
        $wanacry = "WANACRY!"

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}