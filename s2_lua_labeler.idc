#include <idc/idc.idc>

static main(void) {
	auto prefix = "Clientscript_CoD_LuaCall_";
	auto reg_1 = FindBinary(0, SEARCH_DOWN, "48 83 EC 38 45 33 C9 C7 44 24 ? ? ? ? ? E8 ? ? ? ? 48 83 C4 38 C3");
	auto reg_2 = FindBinary(0, SEARCH_DOWN, "48 89 5C 24 ? 57 48 83 EC 20 49 8B D8 48 8B FA E8 ? ? ? ? 4C 8B C3 33 D2");
	auto xref = get_first_cref_to(reg_1);
	while(xref != 0xFFFFFFFFFFFFFFFF) {
		if(xref != 0x1403CC96D) {
			auto table = FindBinary(xref, SEARCH_UP, "4C 8D 05");
			auto type = FindBinary(xref, SEARCH_UP, "48 8D 15");
			table = decode_insn(table).Op1.addr;
			type = decode_insn(type).Op1.addr;
			//Message("0x%X - 0x%X\n", table, type);
			
			while(Qword(table) && Qword(table + 8)) {
				auto func_name = GetString(Qword(table), -1, 0);
				auto func_addr = Qword(table + 8);
				//Message("%s - %X\n", func_name, func_addr);
				if(!MakeName(func_addr, sprintf("%s%s", prefix, func_name))) {
					MakeName(func_addr, sprintf("%s%s_0", prefix, func_name));
				}
				table = table + 16;
			}
		}
		xref = get_next_cref_to(reg_1, xref);
	}
	xref = get_first_cref_to(reg_2);
	while(xref != 0xFFFFFFFFFFFFFFFF) {
		if(xref != 0x1403CC96D) {
			table = FindBinary(xref, SEARCH_UP, "4C 8D 05");
			table = decode_insn(table).Op1.addr;
			//Message("0x%X\n", table);
			
			while(Qword(table) && Qword(table + 8)) {
				func_name = GetString(Qword(table), -1, 0);
				func_addr = Qword(table + 8);
				//Message("%s - %X\n", func_name, func_addr);
				if(!MakeName(func_addr, sprintf("%s%s", prefix, func_name))) {
					MakeName(func_addr, sprintf("%s%s_0", prefix, func_name));
				}
				table = table + 16;
			}
		}
		xref = get_next_cref_to(reg_2, xref);
	}
}

