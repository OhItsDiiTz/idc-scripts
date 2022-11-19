#include <idc/idc.idc>

static make_colon(func) {
    auto i = 0;
    for(i = 0;i < strlen(func) - 2;i++) {
        if(func[i] == "_" && func[i + 1] == "_") {
            func[i] = ":";
            func[i + 1] = ":";
        }
    }
    return func;
}

static main() {

    auto func = FindBinary(0, SEARCH_DOWN, "E8 ? ? ? ? 48 8D 1D ? ? ? ? BE ? ? ? ? 48 8D B8 ? ? ? ?");
    
    auto call = get_name_ea(0, make_colon(print_operand(func, 0)));
    while(func != -1) {
        auto ea = FindBinary(call, SEARCH_DOWN, "E8 ?? ?? ?? ?? 48");
        ea = FindBinary(ea, SEARCH_UP, "48 8D 15 ?? ?? ?? ??");
        
        ea = ea + Dword(ea + 3) + 7;
        auto func_name = GetString(ea - 2, -1, 1);
        if(func_name == "_DataLayer") {
            func_name = "DataLayer";
        }
        MakeName(call, sprintf("%s::GetPrivateStaticClass", func_name));
        
        auto table = get_name_ea(0, print_operand(func + 5, 1));
        auto table_size = Dword(func + 13);
        auto i = 0;
        for(i = 0;i < table_size;i++) {
            auto NativeName = sprintf("%s::exec%s", func_name, GetString(Qword(table + (i * 0x10)), -1, 0));
            Message("0x%X - %i - 0x%X - %s\n", table, table_size, Qword(table + (i * 0x10) + 8), NativeName);
            MakeName(Qword(table + (i * 0x10) + 8), NativeName);
        }


        call = get_name_ea(0, make_colon(print_operand(func, 0)));
        func = FindBinary(func + 1, SEARCH_DOWN, "E8 ? ? ? ? 48 8D 1D ? ? ? ? BE ? ? ? ? 48 8D B8 ? ? ? ?");
    }
}