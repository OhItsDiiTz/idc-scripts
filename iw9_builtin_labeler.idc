#include <idc/idc.idc>
//this could change in the future

static resolve(hash) {
    
    return sprintf("GScr_%X", hash);
}

static main(void) {
    auto start = FindBinary(0, SEARCH_DOWN, "48 89 5C 24 ? 55 48 8B EC 48 83 EC 30 48 8B D9 E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ? E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ? E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ? E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ?");
    auto end = FindBinary(start, SEARCH_DOWN, "48 83 C4 30 5D C3");
    auto ea = start;
    ea = FindBinary(ea, SEARCH_DOWN, "C5 F8 10");
    while(ea < end) {
        auto table = ea + Dword(ea + 4) + 8;
        auto i = 0;
        for(i = 0;i < Dword(table + 8);i++) {
            Message("%s: 0x%X\n", resolve(Qword(Qword(table) + (0x18 * i))), Qword(Qword(table) + (0x18 * i) + 8) - get_imagebase());
            MakeName(Qword(Qword(table) + (0x18 * i) + 8), resolve(Qword(Qword(table) + (0x18 * i))));
        }
        ea = FindBinary(ea + 1, SEARCH_DOWN, "C5 F8 10");
    }
}
