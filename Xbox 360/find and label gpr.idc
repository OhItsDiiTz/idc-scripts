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
	index = 14;
	gpfr = FindBinary(get_imagebase(), SEARCH_DOWN, "F9 C1 FF 68");
    if(gpfr != -1) {
        while(index != 32) {
            MakeName(gpfr, sprintf("__savegprlr_%i", index));
            index++;
            gpfr = gpfr + 4;
        }
    }
    index = 14;
    gpfr = FindBinary(get_imagebase(), SEARCH_DOWN, "E9 C1 FF 68");
    if(gpfr != -1) {
        while(index != 32) {
            MakeName(gpfr, sprintf("__restgprlr_%i", index));
            index++;
            gpfr = gpfr + 4;
        }
    }
}
