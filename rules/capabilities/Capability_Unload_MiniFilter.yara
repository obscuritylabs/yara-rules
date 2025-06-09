import "pe"

rule Capability_Unload_MiniFilter : UnloadMiniFilter
{
    meta:
        author                       = "Obscurity Labs LLC"
        description                  = "Detects user-mode binaries that manage Windows mini-filter drivers via fltmc.exe or the Filter Manager API)"
        date                         = "2025-06-09"
        version                      = "1.0.0"
        yarahub_author_twitter       = "@obscuritylabs"
        yarahub_reference_md5        = ""
        yarahub_uuid                 = "90626ac0-e544-4d5b-b8c3-e70a7feb2b75"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        mitre_attack_tactic          = "TA0002"
        mitre_attack_technique       = "T1059.011"

    strings:
        // Kernal-mode APIs to interact with the Filter Manager
        $kernal_mode_lib = "Fltmgr.sys"  wide ascii nocase
        $kernal_mode_unload = "FltUnloadFilter" wide ascii nocase

        // User-mode functions to interact with the Filter Manager
        $user_mode_lib = "FltLib.dll"  wide ascii nocase
        $user_mode_unload = "FilterUnload"    wide ascii nocase

        // User-mode binaries that interact with the Filter Manager
        $s_fltmc_unld = /fltmc(\.exe)? unload/         wide ascii nocase

    condition:
        (
            // For PE files: detect direct imports of the Filter Manager API
            pe.is_pe and (
                pe.imports("fltlib.dll", "FilterUnload")
            )
        )
        or
        (
            // In any file (scripts, configs, text, etc.): look for the API or fltmc strings
            any of (
                    $kernal_mode_lib,
                    $kernal_mode_unload,
                    $user_mode_lib,
                    $user_mode_unload, 
                    $s_fltmc_exe,
                    $s_fltmc_load,
                    $s_fltmc_list,
                    $s_fltmc_unld
                )
        )
}