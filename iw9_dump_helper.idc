/*
		this script is for setting up MW2 (IW9) for dumping, basically what it does is it sets a
		breakpoint on the end of the "unpacking" process. And once that is set, and you dump you
		are given a "clean" dump/unpack of the executable. You can then load that dump into ida
		and start reversing the game. This is for arxan (the "packer" cod uses)
*/

#include <idc/idc.idc>

static main() {
	auto end = FindBinary(0, SEARCH_DOWN, "8B 45 00 83 F8 FF 0F 85 ? ? ? ? E9 ? ? ? ?");
	AddBpt(end + 12);
	SetBptCnd(end + 12, "PauseProcess();Warning(\"Ready to dump with scylla or any other dumping software you may use!\");");
	LoadDebugger("win32", 0);
	StartDebugger(GetInputFilePath(), "", "");
}

