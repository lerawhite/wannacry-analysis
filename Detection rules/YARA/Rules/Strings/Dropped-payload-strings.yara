rule WannaCry_Payload_Execution
{
    meta:
        author = "lerawhite"
        description = "Detects WannaCry based on characteristic strings"
        malware = "WannaCry (Network module)"
        date = "2026-10-03"

    strings:
        $payload = "C:\\WINDOWS\\tasksche.exe"
        $directory = "C:\\WINDOWS\\qeriuwjhrf"
        $command = "C:\\WINDOWS\\tasksche.exe /i"

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}