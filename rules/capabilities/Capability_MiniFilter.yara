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
        // Unicode (UTF-16LE) and ASCII strings for Filter Manager API
        $s_dll        = "fltlib.dll"           wide ascii nocase
        $s_load       = "FilterLoad"           wide ascii nocase
        $s_unload     = "FilterUnload"         wide ascii nocase
        $s_find1      = "FilterFindFirst"      wide ascii nocase
        $s_findn      = "FilterFindNext"       wide ascii nocase
        $s_close      = "FilterFindClose"      wide ascii nocase

        // Unicode and ASCII strings for fltmc.exe invocations
        $s_fltmc_exe  = "fltmc.exe"            wide ascii nocase
        $s_fltmc_load = "fltmc load"           wide ascii nocase
        $s_fltmc_list = "fltmc list"           wide ascii nocase
        $s_fltmc_unld = "fltmc unload"         wide ascii nocase

    condition:
        pe.is_pe and
        (
            // Static imports of Filter Manager API
            pe.imports("fltlib.dll", "FilterLoad")          or
            pe.imports("fltlib.dll", "FilterUnload")        or
            pe.imports("fltlib.dll", "FilterFindFirst")     or
            pe.imports("fltlib.dll", "FilterFindNext")      or
            pe.imports("fltlib.dll", "FilterFindClose")

            // Or references any of the wide/unicode or ASCII API strings
            or any of ($s_dll, $s_load, $s_unload, $s_find1, $s_findn, $s_close)

            // Or embeds/invokes fltmc.exe commands
            or any of ($s_fltmc_exe, $s_fltmc_load, $s_fltmc_list, $s_fltmc_unld)
        )
}