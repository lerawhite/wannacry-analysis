rule WannaCry_KillSwitch_Domain
{
    meta:
        author = "lerawhite"
        description = "Detects WannaCry based on characteristic strings"
        malware = "WannaCry (Network module)"
        date = "2026-10-03"

    strings:
        $domain = "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"

    condition:
        uint16(0) == 0x5A4D and
        $domain
}