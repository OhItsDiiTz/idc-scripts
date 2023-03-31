/*
		this script is for setting up most games that use arxan for dumping, basically what it does
		is it sets a breakpoint on the end of the "unpacking" process. And once that is set, and you
		dump. You are given a "clean" dump/unpack of the executable. You can then load that dump into
		ida and start reversing the game. Please note that this won't work for every single game that
		uses arxan because things can change with different versions and the sig can break.
		Games Tested On: mw 2019, bo3, mw 2022 (mw2), gta v, fortnite (older builds that contained arxan)
		
		8B 45 ? 83 F8 FF 0F 85 ? ? ? ? E9 ? ? ? ?
		8B 45 00 83 F8 FF 0F 85 ? ? ? ? E9 ? ? ? ?
*/

#include <idc/idc.idc>

static main() {
	auto end = FindBinary(0, SEARCH_DOWN, "8B 45 00 83 F8 FF 0F 85 ? ? ? ? E9 ? ? ? ?");
	AddBpt(end + 12);
	SetBptCnd(end + 12, "PauseProcess();Warning(\"Ready to dump with scylla or any other dumping software you may use!\");");
	LoadDebugger("win32", 0);
	StartDebugger(GetInputFilePath(), "", "");
}

