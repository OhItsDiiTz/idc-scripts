#include <idc/idc.idc>

/*
This gives a more clean decompile when you are using a decompiler with PPC for xbox since most functions have the gprlr save and restore inside them, this just removes them.

*/

static main() {
	auto index = 14;
	auto savegprlr = 0;
	auto ref = 0;
	auto start_ref = 0;
	auto insn_type = "";
	
	while(index != 32) {
		savegprlr = get_name_ea_simple(sprintf("__savegprlr_%i", index));
		ref = get_first_cref_to(savegprlr);
		start_ref = ref;
		while(ref != -1) {
			insn_type = print_insn_mnem(ref);
			Message("0x%X - 0x%X - %s\n", ref, savegprlr, insn_type);
			if(insn_type == "b") {
				patch_dword(ref, 0x4E800020);
			}
			else if(insn_type == "bl") {
				patch_dword(ref, 0x60000000);
			}
			ref = get_next_cref_to(savegprlr, ref);
		}
		index++;
	}
	index = 14;
	while(index != 32) {
		savegprlr = get_name_ea_simple(sprintf("__restgprlr_%i", index));
		ref = get_first_cref_to(savegprlr);
		start_ref = ref;
		while(ref != -1) {
			insn_type = print_insn_mnem(ref);
			Message("0x%X - 0x%X - %s\n", ref, savegprlr, insn_type);
			if(insn_type == "b") {
				patch_dword(ref, 0x4E800020);
			}
			else if(insn_type == "bl") {
				patch_dword(ref, 0x60000000);
			}
			ref = get_next_cref_to(savegprlr, ref);
		}
		index++;
	}
	index = 14;
	while(index != 32) {
		savegprlr = get_name_ea_simple(sprintf("__savegpfrlr_%i", index));
		ref = get_first_cref_to(savegprlr);
		start_ref = ref;
		while(ref != -1) {
			insn_type = print_insn_mnem(ref);
			Message("0x%X - 0x%X - %s\n", ref, savegprlr, insn_type);
			if(insn_type == "b") {
				patch_dword(ref, 0x4E800020);
			}
			else if(insn_type == "bl") {
				patch_dword(ref, 0x60000000);
			}
			ref = get_next_cref_to(savegprlr, ref);
		}
		index++;
	}
	index = 14;
	while(index != 32) {
		savegprlr = get_name_ea_simple(sprintf("__restgpfrlr_%i", index));
		ref = get_first_cref_to(savegprlr);
		start_ref = ref;
		while(ref != -1) {
			insn_type = print_insn_mnem(ref);
			Message("0x%X - 0x%X - %s\n", ref, savegprlr, insn_type);
			if(insn_type == "b") {
				patch_dword(ref, 0x4E800020);
			}
			else if(insn_type == "bl") {
				patch_dword(ref, 0x60000000);
			}
			ref = get_next_cref_to(savegprlr, ref);
		}
		index++;
	}
}
