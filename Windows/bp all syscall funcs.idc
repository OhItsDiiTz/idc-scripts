#include <idc/idc.idc>


static main(void) {
	auto ea = FindBinary(0, SEARCH_DOWN, "4C 8B D1 B8 ? ? ? ? F6 04 25 ? ? ? ? ? 75 03 0F 05 C3 CD 2E C3");
	while(ea != -1) {
		add_func(ea);
		AddBpt(ea);
		ea = FindBinary(ea + 1, SEARCH_DOWN, "4C 8B D1 B8 ? ? ? ? F6 04 25 ? ? ? ? ? 75 03 0F 05 C3 CD 2E C3");
	}
}
