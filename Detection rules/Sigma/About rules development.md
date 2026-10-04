
---
# Sigma Rule Development

Sigma rule development was approached differently from YARA because Sigma operates at the **behavioral and event-log level**, rather than matching the internal binary implementation of a malware sample.

The analyzed WannaCry sample contains a highly specific network-propagation component based on legacy **SMBv1 exploitation**. Its propagation logic includes SMB negotiation, Session Setup, IPC$ connections, transaction processing, and subsequent payload-transfer stages.

This significantly limits the number of strong and reliable Sigma rules that can be derived from the analyzed sample alone.

The main limitation is that the core propagation mechanism depends on an old SMBv1 vulnerability addressed by **MS17-010**. Microsoft documented that the vulnerability could allow remote code execution through specially crafted SMBv1 messages and recommended disabling SMBv1 as a workaround.

Consequently, many low-level behaviors observed during reverse engineering — such as internal SMB packet construction, response-dependent fields, DOUBLEPULSAR-related processing, and the exact payload-transfer sequence — do not necessarily produce stable, high-confidence endpoint events suitable for Sigma detection.

For this reason, the Sigma rules in this project focus only on **observable host-level behaviors** that can be represented reliably in security telemetry.

The rules were therefore designed conservatively:

- avoid generic process or network activity;
    
- avoid rules based solely on common Windows APIs;
    
- focus on distinctive process, service, file, or command-line behavior where telemetry can reliably expose it;
    
- avoid treating historical SMB protocol details as standalone endpoint detections;
    
- prefer high-confidence behavioral combinations over broad single-event matches.
    

The resulting Sigma rule set is intentionally smaller than the YARA rule set. This reflects the difference between the two detection approaches rather than a lack of analyzed behavior.

The reverse-engineering results provide considerably more binary-level detail than can be safely translated into endpoint-log detection. The Sigma rules therefore represent only the subset of the analyzed behavior that can be converted into **reliable and operationally meaningful telemetry-based detections**.  

