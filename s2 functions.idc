#include <idc/idc.idc>

static FindAddress(func, patrn) {
	auto value = 0;
	auto sig = FindBinary(get_imagebase(), SEARCH_DOWN, patrn);
	if(sig != -1) {
		auto insn_name = print_insn_mnem(sig);
		
		auto is_correct_side = 1;
		if((insn_name == "mov" || insn_name == "lea" || insn_name == "add") && decode_insn(sig).size > 6) {
			if(decode_insn(sig).Op1.addr > get_imagebase()) {
				is_correct_side = 1;
			}
			else {
				is_correct_side = 0;
			}
		}
		
		if(insn_name == "call" || insn_name == "jmp") {
			value = decode_insn(sig).Op0.addr;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
		else if((insn_name == "mov" || insn_name == "lea" || insn_name == "add") && decode_insn(sig).size > 6 && is_correct_side == 1) {
			value = decode_insn(sig).Op1.addr;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
		else {
			value = sig;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
	}
	else {
		Message("%s needs updating!\n", func);
	}
}


static main(void) {
	FindAddress("DB_CreateDefaultEntry", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 30 48 63 F1 4C 8D 3D ? ? ? ? 4C 8B F2 8B CE 48 8D 3C F5 ? ? ? ?");
	FindAddress("DB_FindXAssetDefaultHeaderInternal", "E8 ? ? ? ? 48 89 44 24 ? 48 8B D8 48 85 C0 75 4D F0 FF 0D ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 83 FE 1F");
	FindAddress("Sys_Error", "48 89 4C 24 ? 48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ?");
	FindAddress("DB_AllocXAssetEntry", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 48 8B 35 ? ? ? ? 48 8D 1D ? ? ? ? 48 63 E9 44 0F B7 F2 48 85 F6 74 0E");
	FindAddress("DB_GetXAssetTypeSize", "40 53 48 83 EC 20 48 63 C1 48 8D 1D ? ? ? ? 48 8B 1C C3 48 8B CB FF 15 ? ? ? ? 48 8B C3 48 83 C4 20 5B 48 FF E0");
	FindAddress("memmove", "4C 8B D9 4C 8B D2 49 83 F8 10 0F 86 ? ? ? ? 49 83 F8 20 76 4A 48 2B D1 73 0F 49 8B C2 49 03 C0 48 3B C8 0F 8C ? ? ? ?");
	FindAddress("errno", "48 83 EC 28 E8 ? ? ? ? 48 85 C0 75 09 48 8D 05 ? ? ? ? EB 04 48 83 C0 20 48 83 C4 28 C3");
	FindAddress("invalid_parameter_noinfo", "48 83 EC 38 48 83 64 24 ? ? 45 33 C9 45 33 C0 33 D2 33 C9 E8 ? ? ? ? 48 83 C4 38 C3");
	FindAddress("getptd_noexit", "48 89 5C 24 ? 57 48 83 EC 20 FF 15 ? ? ? ? 8B 0D ? ? ? ? 8B D8 83 F9 FF 74 35 E8 ? ? ? ?");
	FindAddress("invalid_parameter", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 41 8B D9 49 8B F8 48 8B F2 48 8B E9 E8 ? ? ? ? 48 85 C0 74 3D 48 8B 80 ? ? ? ? 48 85 C0 74 31");
	FindAddress("Sys_TempPriorityEnd", "8B 51 08 85 D2 79 0A 48 8B 09 48 FF 25 ? ? ? ?");
	FindAddress("DB_GetXAssetName", "48 89 5C 24 ? 57 48 83 EC 20 48 63 01 48 8D 59 08 48 8D 3D ? ? ? ? 48 8B 3C C7 48 8B CF FF 15 ? ? ? ? 48 8B CB 48 8B C7 48 8B 5C 24 ? 48 83 C4 20 5F 48 FF E0");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");
	
	
}
