import "pe"

rule Detect_Minidump_Header_Construction
{
    meta:
        description = "Detects code patterns that construct or check the 'MDMP' (0x504D444D) header in memory"
        date        = "2025-06-09"

    strings:
        // mov eax, 0x504D444D       → B8 4D 44 4D 50
        $mov_eax      = { B8 4D 44 4D 50 }

        // push 0x504D444D            → 68 4D 44 4D 50
        $push_dword   = { 68 4D 44 4D 50 }

        // mov dword ptr [addr], 0x504D444D
        //    → C7 05 <disp32> 4D 44 4D 50
        $mov_mem      = { C7 05 ?? ?? ?? ?? 4D 44 4D 50 }

        // x64: mov rax, 0x504D444D…  → 48 B8 4D 44 4D 50 ?? ?? ?? ??
        $mov_rax      = { 48 B8 4D 44 4D 50 ?? ?? ?? ?? }

        // cmp dword ptr [rax],0x504D444D
        //    → 81 38 4D 44 4D 50
        $cmp_mem      = { 81 38 4D 44 4D 50 }

    condition:
        pe.is_pe and any of ($mov_eax, $push_dword, $mov_mem, $mov_rax, $cmp_mem)
}