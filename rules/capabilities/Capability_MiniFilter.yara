import "pe"

rule Capability_MiniFilter : MiniFilter
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
        // User‐mode Filter Manager API
        $fltlib_dll     = "fltlib.dll"           wide ascii nocase
        $filter_load    = "FilterLoad"           wide ascii nocase
        $filter_unload  = "FilterUnload"         wide ascii nocase
        $filter_find    = "FilterFindFirst"      wide ascii nocase
        $filter_next    = "FilterFindNext"       wide ascii nocase
        $filter_close   = "FilterFindClose"      wide ascii nocase

        // fltmc.exe invocations or references
        $fltmc_exe      = "fltmc.exe"            wide ascii nocase
        $fltmc_list     = "fltmc list"           wide ascii nocase
        $fltmc_load     = "fltmc load"           wide ascii nocase
        $fltmc_unload   = "fltmc unload"         wide ascii nocase

    condition:
        pe.is_pe and (
            // Direct imports of Filter Manager API
            pe.imports("fltlib.dll", "FilterLoad") or
            pe.imports("fltlib.dll", "FilterUnload") or
            pe.imports("fltlib.dll", "FilterFindFirst") or
            pe.imports("fltlib.dll", "FilterFindNext") or
            pe.imports("fltlib.dll", "FilterFindClose")

            // Or embedding/invoking fltmc.exe
            or any of ($fltmc_*)
        )
}