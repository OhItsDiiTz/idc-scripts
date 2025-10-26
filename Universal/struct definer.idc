#include <idc/idc.idc>

/*
Something for making structs if you know the name/size making for reversing them directly in ida easier? or more convenient?
*/

static main() {
    auto struct_name = ask_str("struct name", HIST_TYPE, "Please enter in your class/struct name you wish to create");
    auto struct_size = ask_addr(1, "Please enter the size of the class/struct you wish to create\nDon't know the size? Then figure it out or you should not be using this -_-");
    auto ea = 0;

    auto id = GetStrucIdByName(struct_name);
    if(id == -1) {
        id = AddStrucEx(-1, struct_name, 0);
        while(ea < struct_size) {
            AddStrucMember(id, sprintf("field_%X", ea), ea, FF_BYTE, 0, 1);
            ea++;
        }
    }
}