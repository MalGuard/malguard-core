rule MG_HIGH_PROCESS_INJECTION_CLUSTER {
  meta:
    severity = "high"
    category = "process_injection"
  strings:
    $a = "VirtualAllocEx" ascii wide
    $b = "WriteProcessMemory" ascii wide
    $c = "CreateRemoteThread" ascii wide
    $d = "NtWriteVirtualMemory" ascii wide
  condition:
    2 of ($a,$b,$c,$d)
}

rule MG_HIGH_BROWSER_CREDENTIAL_CLUSTER {
  meta:
    severity = "high"
    category = "credential_access"
  strings:
    $a = "Login Data" ascii wide
    $b = "Local State" ascii wide
    $c = "Web Data" ascii wide
    $d = "Cookies" ascii wide
  condition:
    2 of ($a,$b,$c,$d)
}

rule MG_HIGH_SECURITY_TAMPERING_CLUSTER {
  meta:
    severity = "high"
    category = "defense_evasion"
  strings:
    $a = "DisableRealtimeMonitoring" ascii wide nocase
    $b = "DisableBehaviorMonitoring" ascii wide nocase
    $c = "Set-MpPreference" ascii wide nocase
    $d = "Add-MpPreference" ascii wide nocase
  condition:
    2 of ($a,$b,$c,$d)
}

rule MG_HIGH_SERVICE_PERSISTENCE_CLUSTER {
  meta:
    severity = "high"
    category = "persistence"
  strings:
    $a = "CreateServiceW" ascii wide
    $b = "StartServiceW" ascii wide
    $c = "SERVICE_AUTO_START" ascii wide
  condition:
    2 of ($a,$b,$c)
}

rule MG_MEDIUM_SCRIPT_DOWNLOAD_EXEC {
  meta:
    severity = "medium"
    category = "command_execution"
  strings:
    $a = "powershell" ascii wide nocase
    $b = "DownloadString" ascii wide nocase
    $c = "Invoke-WebRequest" ascii wide nocase
    $d = "FromBase64String" ascii wide nocase
  condition:
    2 of ($a,$b,$c,$d)
}

rule MG_INFO_GTA_MOD_CONTEXT {
  meta:
    severity = "info"
    category = "gta_context"
  strings:
    $a = "ScriptHookV" ascii wide nocase
    $b = "GTA5" ascii wide nocase
    $c = "dinput8.dll" ascii wide nocase
  condition:
    any of them
}
