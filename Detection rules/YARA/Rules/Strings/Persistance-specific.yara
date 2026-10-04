rule WannaCry_Persistence_Strings
{
    meta:
        author = "lerawhite"
        description = "Detects WannaCry based on characteristic strings"
        malware = "WannaCry (Network module)"
        date = "2026-10-03"

    strings:
        $service = "mssecsvc2.0"
        $display = "Microsoft Security Center (2.0)"
        $command = "wannacry -m security"

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}