/*
 MalGuard defensive heuristic rules.
 Matches are suspicious evidence only, never a standalone malicious verdict.
*/
import "pe"

rule MG_Suspicious_Process_Injection_API_Cluster {
  meta:
    purpose = "defensive capability triage"
    confidence = "medium"
  strings:
    $a = "VirtualAllocEx" ascii wide
    $b = "WriteProcessMemory" ascii wide
    $c = "CreateRemoteThread" ascii wide
    $d = "NtWriteVirtualMemory" ascii wide
  condition:
    uint16(0) == 0x5A4D and 2 of them
}

rule MG_Suspicious_Credential_Access_String_Cluster {
  meta:
    purpose = "defensive capability triage"
    confidence = "medium"
  strings:
    $a = "CryptUnprotectData" ascii wide
    $b = "Login Data" ascii wide
    $c = "Local State" ascii wide
    $d = "cookies" ascii wide nocase
  condition:
    uint16(0) == 0x5A4D and 2 of them
}

rule MG_Suspicious_Persistence_API_Cluster {
  meta:
    purpose = "defensive capability triage"
    confidence = "low"
  strings:
    $a = "RegSetValueEx" ascii wide
    $b = "CurrentVersion\\Run" ascii wide
    $c = "CreateService" ascii wide
    $d = "schtasks" ascii wide nocase
  condition:
    uint16(0) == 0x5A4D and 2 of them
}
