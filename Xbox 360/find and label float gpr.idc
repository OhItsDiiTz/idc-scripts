#include <idc/idc.idc>

static main() {
    auto index = 14;
    auto gpfr = FindBinary(get_imagebase(), SEARCH_DOWN, "D9 CC FF 70");
    if(gpfr != -1) {
        while(index != 32) {
            MakeName(gpfr, sprintf("__savegpfrlr_%i", index));
            index++;
            gpfr = gpfr + 4;
        }
    }
    index = 14;
    gpfr = FindBinary(get_imagebase(), SEARCH_DOWN, "C9 CC FF 70");
    if(gpfr != -1) {
        while(index != 32) {
            MakeName(gpfr, sprintf("__restgpfrlr_%i", index));
            index++;
            gpfr = gpfr + 4;
        }
    }
}
