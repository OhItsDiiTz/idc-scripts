#include <idc/idc.idc>

/*

this has only been tested on 2 unreal engine games, will be updating it to support more when I work on more unreal engine games
also I know there are sdk dumpers for unreal engine but I can't stand most of them

*/

//shitty function to remove the "+2" in the name
static strip(str) {
    auto temp_str = str;
    temp_str[strlen(temp_str)-1] = 0;
    temp_str[strlen(temp_str)-1] = 0;
    return temp_str;
}

static main() {
	
	//first we find the function that registers the "native" functions for unreal engine, not sure what they are actually called tho I could check unreal engines source, just lazy is all
    auto register_natives = FindBinary(get_imagebase(), SEARCH_DOWN, "45 85 C0 0F 84 ? ? ? ? 4C 8B DC 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 49 89 5B 18 45 8B F8 49 89 6B 20 4C 8B F2 49 89 7B E0 48 8D A9 ? ? ? ?");
    if(register_natives != -1) {
		//once found we wanna find the first "cref" aka the first "xref" of it, then loop through all of the xrefs
        auto first = get_first_cref_to(register_natives);
        auto current = first;
        while(current != -1) {
			//for the current xref we are on we wanna find the first function called within the function we are in, this function usually returns to the first param of the "RegisterNatives" function, this could fuck up in some cases
            auto callee = FindBinary(current, SEARCH_UP, "48 83 EC 28 E8 ? ? ? ?") + 4;
			//we then find the "mov r8d, #" instruction to be able to get the function count for the table
            auto func_count = FindBinary(current, SEARCH_UP, "41 B8");
			//we then search for the "lea rdx, 0x%X" instruction to be able to get the native function table
            auto func_table = FindBinary(current, SEARCH_UP, "48 8D 15");
			//read the function count
            func_count = Dword(func_count + 2);
			//get the address of the function that returns to the first param
            callee = get_name_ea(0, print_operand(callee, 0));
            func_table = get_name_ea(0, print_operand(func_table, 1));
			//we then search for the "lea rdx, 0x%X" instruction inside of the function found earlier to get the classname, note this does not always work but it seems to work for the games I tested it on.
            auto classname = FindBinary(callee, SEARCH_DOWN, "48 8D 15");
            classname = get_name_ea(0, strip(print_operand(classname, 1)));
            MakeName(callee, sprintf("%s::GetPrivateStaticClass", GetString(classname, -1, 0))); //
            auto i = 0;
            for(i = 0;i < func_count;i++) {
                MakeName(Qword(func_table + (0x10 * i) + 8), sprintf("%s::exec%s", GetString(classname, -1, 0), GetString(Qword(func_table + (0x10 * i)), -1, 0)));
            }
            
            //Message("0x%X - %X - %s - 0x%X - %i\n", current, callee, GetString(classname, -1, 1), func_table, func_count);
            current = get_next_cref_to(register_natives, current);
        }
    }
    else {
        Message("unable to find \"RegisterNatives\", You must update the signature for this game!");
    }
}
