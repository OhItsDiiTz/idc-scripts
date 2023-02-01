#include <idc/idc.idc>

static FindAddress(func, patrn) {
	auto value = 0;
	auto sig = FindBinary(get_imagebase(), SEARCH_DOWN, patrn);
	if(sig != -1) {
		auto insn_name = print_insn_mnem(sig);
		
		auto is_correct_side = 1;
		if((insn_name == "mov" || insn_name == "lea" || insn_name == "add") && decode_insn(sig).size > 6) {
			if(decode_insn(sig).Op1.addr > get_imagebase()) {
				is_correct_side = 1;
			}
			else {
				is_correct_side = 0;
			}
		}
		
		if(insn_name == "call" || insn_name == "jmp") {
			value = decode_insn(sig).Op0.addr;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
		else if((insn_name == "mov" || insn_name == "lea" || insn_name == "add") && decode_insn(sig).size > 6 && is_correct_side == 1) {
			value = decode_insn(sig).Op1.addr;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
		else {
			value = sig;
			Message("Found %s at 0x%X\n", func, value);
			MakeName(value, func);
		}
	}
	else {
		Message("%s needs updating!\n", func);
	}
}


static main(void) {
	
	//LiveAntiCheat_ Functions
	FindAddress("LiveAntiCheat_FeatureIsBanned", "48 83 EC 28 4C 63 D1 45 33 C9 49 69 C2 ? ? ? ? 48 63 CA 45 8B C1 48 8D 15 ? ? ? ? 48 03 C2");
	FindAddress("LiveAntiCheat_BanDisconnect", "48 83 EC 28 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? E8 ? ? ? ? 33 D2 33 C9 48 83 C4 28 E9 ? ? ? ?");
	
	//LiveStorage_ Functions
	FindAddress("LiveStorage_IsTimeSynced", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? E8 ? ? ? ? 44 8B 05 ? ? ? ? 89 44 24 38");
	FindAddress("LiveStorage_GetUTC", "E8 ? ? ? ? 44 8B 05 ? ? ? ? 89 44 24 38 45 85 C0 74 09");
	FindAddress("LiveStorage_GetPersistentDataDefVersion", "48 83 EC 28 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 75 0A B8 ? ? ? ? 48 83 C4 28 C3");
	FindAddress("LiveStorage_EnsureWeHaveStats", "40 53 48 83 EC 20 48 63 D9 48 8D 05 ? ? ? ? 48 69 CB ? ? ? ? 80 BC 01 ? ? ? ? ? 74 0E 83 BC 01 ? ? ? ? ? 0F 84 ? ? ? ?");
	FindAddress("LiveStorage_DiscardStats", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8D 2D ? ? ? ? 48 63 FA 4C 69 CF ? ? ? ? 48 63 F1 8B D7 4C 69 C6 ? ? ? ? 48 69 DE ? ? ? ?");
	FindAddress("LiveStorage_BeginGame", "40 53 48 83 EC 20 E8 ? ? ? ? 48 63 D8 48 8D 0D ? ? ? ? 48 8B C3 80 BC D9 ? ? ? ? ? 75 08");
	
	//UI_ Functions
	FindAddress("UI_SetMap", "48 89 5C 24 ? 57 48 83 EC 20 48 8B FA 48 8B D9 4C 8B C1 BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 80 3B 00");
	
	//Scr_ functions
	FindAddress("Scr_SetString", "48 89 5C 24 ? 57 48 83 EC 20 48 8B F9 8B DA 39 11 0F 84 ? ? ? ? 85 D2 74 77 48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("Scr_ParamError", "40 53 48 83 EC 20 41 8D 40 01 48 8B DA 89 82 ? ? ? ? 8B D1 48 8D 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("Scr_ObjectError", "40 53 48 83 EC 20 48 8B DA C7 82 ? ? ? ? ? ? ? ? 8B D1 48 8D 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("Scr_Error", "40 53 48 83 EC 20 48 8B DA 8B D1 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 83 BB ? ? ? ? ?");
	FindAddress("Scr_GetType", "48 89 5C 24 ? 57 48 83 EC 20 48 8B D9 8B FA 0F B6 89 ? ? ? ? E8 ? ? ? ? 3B BB ? ? ? ? 73 1F 48 8B 83 ? ? ? ?");
	FindAddress("Scr_GetNumParam", "E8 ? ? ? ? 83 F8 03 76 13 BA ? ? ? ? 48 8B CB E8 ? ? ? ? C4 C1 7A 11 45 ?");
	FindAddress("Scr_GetInt", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B D9 8B FA 0F B6 89 ? ? ? ? E8 ? ? ? ? 48 8D 35 ? ? ? ? 3B BB ? ? ? ? 73 62 48 8B 8B ? ? ? ? 8B C7");
	FindAddress("Scr_GetAnim", "48 89 5C 24 ? 55 56 41 56 48 83 EC 20 48 8B F1 8B DA 0F B6 89 ? ? ? ? 49 8B E8 E8 ? ? ? ? 3B 9E ? ? ? ? 73 7E 4C 8B B6 ? ? ? ? 8B C3");
	
	//Dlog_ Functions
	FindAddress("DLog_RecordContext", "40 53 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B D9 E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 48 8B CB E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 83 7B 3C 00 0F 85 ? ? ? ? 44 8B 0B");
	FindAddress("DLog_GetHooks", "E8 ? ? ? ? 48 8B C8 48 8B 10 48 83 C4 28 48 FF A2 C0 00 00 00");
	FindAddress("DLog_Record", "40 55 56 57 41 54 41 55 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 63 B5 ? ? ? ? 4C 8B F1 4C 8B AD ? ? ? ? 49 8B F8 48 89 4C 24 ? 4C 8B E2 48 8B 0D ? ? ? ?");
	FindAddress("DLog_strcpy", "48 8D 42 FF 48 3B D0 48 0F 43 D0 48 85 D2 74 17 4C 2B C1 41 0F B6 04 08 84 C0 74 0B 88 01 48 FF C1 48 83 EA 01");
	FindAddress("DLog_sprintf_256", "E8 ? ? ? ? 4D 8B C6 48 8D 4C 24 ? 4C 8B CE BA ? ? ? ? E8 ? ? ? ?");
	FindAddress("DLog_sendpacket", "E8 ? ? ? ? 8B 5C 24 30 E8 ? ? ? ? 44 8B C3 48 8B D7 E9 ? ? ? ?");
	FindAddress("DLog_GetDebugSocket", "E8 ? ? ? ? 48 8B C8 44 8D 46 04 48 8D 54 24 ? E8 ? ? ? ? 8B 5C 24 30 E8 ? ? ? ?");
	FindAddress("DLog_UInt8", "E8 ? ? ? ? 84 C0 74 3C 44 0F B6 C6 48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("DLog_Int8", "E8 ? ? ? ? 84 C0 74 23 44 0F B6 C7 48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 84 C0 74 0A 48 8D 4C 24 ? E8 ? ? ? ? 8B 1D ? ? ? ? 48 8D 8C 24 ? ? ? ? E8 ? ? ? ?");
	FindAddress("DLog_UInt64", "48 89 5C 24 ? 57 48 83 EC 20 83 79 3C 00 49 8B F8 48 8B D9 75 26 41 B0 0E");
	FindAddress("DLog_UInt32", "48 89 5C 24 ? 57 48 83 EC 20 83 79 3C 00 41 8B F8 48 8B D9 75 26 41 B0 0D E8 ? ? ? ?");
	FindAddress("DLog_Int32", "48 89 5C 24 ? 57 48 83 EC 20 83 79 3C 00 41 8B F8 48 8B D9 75 26 41 B0 09 E8 ? ? ? ? 84 C0");
	FindAddress("DLog_String", "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC 30 83 79 3C 00 45 0F B6 F1 49 8B F8 48 8B F2 48 8B D9");
	FindAddress("DLog_Serialize_ZLib_0", "48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 45 33 C0 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 45 33 C0 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 41 B0 01 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 41 B0 01 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 45 33 C0 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? 48 83 C4 28 E9 ? ? ? ?");
	FindAddress("DLog_Serialize_Size", "40 53 48 83 EC 20 48 8B D9 4D 8B D0 8B 49 20 8D 41 04 44 3B C8 7D 08 33 C0 48 83 C4 20 5B C3");
	FindAddress("DLog_Serialize_Protobuf", "48 89 54 24 ? 48 89 4C 24 ? 55 56 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 49 8B C0 48 8B F2 48 8B F9 4D 63 C1");
	FindAddress("DLog_Serialize_MsgPackValue", "E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8D 4C 24 ? C7 47 ? ? ? ? ? E8 ? ? ? ? 48 8B 8C 24 ? ? ? ? 48 33 CC E8 ? ? ? ? 48 81 C4 ? ? ? ? 5F 5B C3");
	FindAddress("DLog_Serialize_MsgPack", "40 53 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 49 8B C0 48 8B FA 48 8B D9 4D 63 C1 48 8B D0 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("DLog_Serialize_MessageEnvelope", "40 55 56 57 41 54 41 55 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 4C 8B E9 48 89 4C 24 ?");
	FindAddress("DLog_Serialize_Json", "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B D9 4D 63 C9 48 8D 4C 24 ? 33 D2 49 8B F8 E8 ? ? ? ?");
	FindAddress("DLog_Serialize_CmdStream", "48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 41 B0 01 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 41 B0 01 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 45 33 C0 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? 48 83 C4 28 E9 ? ? ? ?");
	FindAddress("DLog_Serialize", "E8 ? ? ? ? 4C 63 F0 E8 ? ? ? ? 48 8B F0 48 2B F3 45 85 F6 78 38 E8 ? ? ? ?");
	FindAddress("DLog_RecordBinary", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 41 8B F9 49 8B F0 48 8B DA 48 8B E9 E8 ? ? ? ? 84 C0 74 21 48 8B 0D ? ? ? ?");
	FindAddress("DLog_PrintError", "E8 ? ? ? ? 32 C0 48 8B 5C 24 ? 48 8B 74 24 ? 48 83 C4 50 5F C3");
	FindAddress("DLog_PeekEventName", "4C 8B 41 08 41 0F B6 00 24 0F 3C 01 75 0A 49 8D 40 01 48 89 02 B0 01 C3");
	FindAddress("DLog_Microseconds", "E8 ? ? ? ? 48 8B 0F 4C 8D 8D ? ? ? ? 48 89 4C 24 ? 4C 8D 85 ? ? ? ? 48 8B D8 48 C7 44 24 ? ? ? ? ? 8B 51 10 48 8B 49 08");
	FindAddress("DLog_EnterCriticalSection", "40 53 48 83 EC 20 0F B6 D9 E8 ? ? ? ? 0F B6 D3 48 8B C8 4C 8B 00 48 83 C4 20 5B 49 FF 60 70");
	FindAddress("DLog_LeaveCriticalSection", "40 53 48 83 EC 20 0F B6 D9 E8 ? ? ? ? 0F B6 D3 48 8B C8 4C 8B 00 48 83 C4 20 5B 49 FF 60 78");
	FindAddress("DLog_IsMetricsActive", "48 83 EC 28 E8 ? ? ? ? 48 8B C8 48 8B 10 48 83 C4 28 48 FF A2 20 01 00 00");
	FindAddress("DLog_IsMainThread", "48 83 EC 28 FF 15 ? ? ? ? 39 05 ? ? ? ? 0F 94 C0 48 83 C4 28 C3");
	FindAddress("DLog_IsInitialized", "E8 ? ? ? ? 84 C0 75 05 48 83 C4 28 C3 E8 ? ? ? ? 48 8B C8 48 8B 10 48 83 C4 28 48 FF A2 C0 00 00 00");
	FindAddress("DLog_IsActive", "48 83 EC 28 E8 ? ? ? ? 84 C0 75 05 48 83 C4 28 C3 E8 ? ? ? ? 48 8B C8 48 8B 10 48 83 C4 28 48 FF A2 C0 00 00 00");
	FindAddress("DLog_HashTableFind", "48 89 5C 24 ? 48 89 7C 24 ? 44 8B 51 08 45 33 DB 41 FF CA 49 8B F8 48 8B D9 45 8B CB 48 85 D2");
	FindAddress("DLog_GetUserId", "E8 ? ? ? ? 0F B6 3D ? ? ? ? 48 8B D8 0F B6 35 ? ? ? ? 0F B6 2D ? ? ? ? E8 ? ? ? ?");
	FindAddress("DLog_GetSchema", "48 8B 0D ? ? ? ? 48 8B 01 48 FF 60 40");
	FindAddress("DLog_GetNextEvent", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 50 48 8B FA 48 8B D9 48 8B CF 33 D2 41 B8 ? ? ? ? E8 ? ? ? ? 48 8B 43 28 48 89 47 40 48 63 43 10 3B 43 20 0F 8D ? ? ? ?");
	FindAddress("DLog_GetNextCmd", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B 41 20 48 8B FA 48 8B D9 39 41 10");
	FindAddress("DLog_GetGluttonInfo", "E8 ? ? ? ? 48 8B 58 50 48 85 DB 75 04 48 8B 58 48");
	FindAddress("DLog_FindEvent", "40 55 41 54 41 55 41 57 48 83 EC 28 44 8B 49 50 45 33 FF 41 FF C9 4C 8B E2 48 8B E9 45 8B D7 45 8B C7 4D 8D 6F FF 48 85 D2 74 39");
	FindAddress("DLog_FinalizeContext", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 83 7B 3C 00 0F 85 ? ? ? ? 44 8B 0B 48 8D 8C 24 ? ? ? ?");
	FindAddress("DLog_ErrorUnexpected", "40 53 48 83 EC 30 4C 89 44 24 ? 4C 8D 0D ? ? ? ? 4C 8D 05 ? ? ? ? 48 8B D9 E8 ? ? ? ? C7 43 ? ? ? ? ? 48 83 C4 30 5B C3");
	FindAddress("DLog_CreateReadContext", "C5 F9 EF C0 C5 FC 11 01 C5 FC 11 41 ? C5 FC 11 41 ? C5 FC 11 41 ? 4C 89 41 18 44 89 49 20 48 89 51 28 C5 F8 77 C3");
	FindAddress("DLog_CreateContext", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 49 8B D8 48 8B FA 33 D2 41 B8 ? ? ? ? 41 8B F1 48 8B E9 E8 ? ? ? ?");
	FindAddress("DLog_Bool", "48 89 5C 24 ? 57 48 83 EC 20 83 79 3C 00 41 0F B6 F8 48 8B D9 75 26 41 B0 04");
	FindAddress("DLog_BeginEvent", "40 53 55 57 48 83 EC 20 41 0F B6 F8 48 8B EA 48 8B D9 E8 ? ? ? ?");
	FindAddress("DLog_AddMetric", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 49 8B D9 49 8B F8 48 8B F2 48 8B E9 E8 ? ? ? ? 4C 8B CF 48 89 5C 24 ? 4C 8B C6 48 8B D5 48 8B C8 4C 8B 10 41 FF 52 60");
	FindAddress("DLogEvent_Base::Send", "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 0F B6 FA 48 8B D9 BA ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ?");
	
	//LUI_ Functions
	FindAddress("LUI_SetTableString", "E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 0D ? ? ? ? 48 8B D3 E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 0D ? ? ? ? B2 01 E8 ? ? ? ?");
	FindAddress("LUI_SetTableInt", "E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 0D ? ? ? ? B2 01 E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 83 C4 20 5B E9 ? ? ? ?");
	FindAddress("LUI_SetTableBool", "E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 0D ? ? ? ? 48 8B D7 E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("LUI_EndEvent", "40 53 48 83 EC 20 48 8B D1 B9 ? ? ? ? E8 ? ? ? ? 8B 0D ? ? ? ? 0F B6 D8 85 C9 7E 30");
	FindAddress("LUI_BeginTable", "E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 0D ? ? ? ? 48 8B D3 E8 ? ? ? ? 4C 8B 05 ? ? ? ? 48 8D 0D ? ? ? ?");
	FindAddress("LUI_BeginEvent", "E8 ? ? ? ? 84 C0 74 7B 4C 8B 0D ? ? ? ? 48 8D 0D ? ? ? ? 33 D2 44 8D 42 01 E8 ? ? ? ?");
	
	//Dvar_ Functions
	FindAddress("Dvar_SetBool_Internal", "E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 33 D2 E8 ? ? ? ? E8 ? ? ? ? 33 D2 33 C9 48 83 C4 28 E9 ? ? ? ?");
	FindAddress("Dvar_SetBoolByName", "E9 ? ? ? ? E8 ? ? ? ? 84 C0 75 07 B1 01 E8 ? ? ? ?");
	FindAddress("Dvar_SetString_Internal", "E8 ? ? ? ? 48 8B 0D ? ? ? ? 45 33 C0 B2 01 E8 ? ? ? ? 33 C0 48 83 C4 20 5B C3");
	FindAddress("Dvar_SetStringByName", "E8 ? ? ? ? 45 33 C9 C6 44 24 ? ? 41 B0 01 C6 44 24 ? ? 48 8D 15 ? ? ? ? 33 C9 E8 ? ? ? ? 48 8B CF C6 47 70 00 E8 ? ? ? ?");
	FindAddress("Dvar_SetInt_Internal", "E8 ? ? ? ? 80 BB ? ? ? ? ? 76 45 90 45 33 C0 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 41 8D 50 02 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 90 48 8B 0D ? ? ? ? E8 ? ? ? ? 80 3D ? ? ? ? ? 74 45 90 45 33 C0 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 41 8D 50 01 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 90 48 8B 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("Dvar_SetIntByName", "E8 ? ? ? ? 48 69 D7 ? ? ? ? 48 8D 05 ? ? ? ? 8B CF 8B 1C 02 E8 ? ? ? ?");
	FindAddress("Dvar_GetStringByName", "E8 ? ? ? ? 4C 8B C0 48 8D 4D 50 BA ? ? ? ? E8 ? ? ? ? 48 8D 05 ? ? ? ? C6 05 ? ? ? ? ? B9 ? ? ? ? C6 05 ? ? ? ? ? C6 05 ? ? ? ? ? C6 05 ? ? ? ? ? C6 05 ? ? ? ? ?");
	FindAddress("Dvar_FindMalleableVar", "E8 ? ? ? ? 48 85 C0 75 0C 48 8D 05 ? ? ? ? 48 83 C4 28 C3");
	
	//Live_ Functions
	FindAddress("Live_ThrowError", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B F1 49 8B F8 48 8D 0D ? ? ? ? 48 8B DA E8 ? ? ? ?");
	FindAddress("Live_GetOnlineUserName", "48 89 5C 24 ? 57 48 83 EC 20 49 63 F8 48 8B DA 4C 8B C7 E8 ? ? ? ? 84 C0 74 0D");
	FindAddress("Live_GetMapSource", "40 53 48 83 EC 20 8B D9 85 C9 79 0B B8 ? ? ? ? 48 83 C4 20 5B C3");
	FindAddress("Live_GetMapIndex", "40 53 48 83 EC 20 48 8B D9 B9 ? ? ? ? E8 ? ? ? ? 33 D2 84 C0 0F 95 C2 85 D2 74 17");
	FindAddress("Live_GetMACAddressAsUint64", "E8 ? ? ? ? 48 8B 44 24 ? 48 8D 15 ? ? ? ? 4C 8B CB 48 89 44 24 ? 44 8B C7 48 8D 8C 24 ? ? ? ?");
	FindAddress("Live_GetMACAddressAsUint64_0", "48 89 5C 24 ? 57 B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B D9 C7 44 24 ? ? ? ? ? 48 8D 44 24 ? BF ? ? ? ? 8B CF 48 89 44 24 ?");
	FindAddress("Live_Disconnected", "E8 ? ? ? ? E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 C7 05 ? ? ? ? ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("Live_DWLoginComplete", "48 89 5C 24 ? 57 48 83 EC 20 8B F9 E8 ? ? ? ? 8B D7 48 8B C8 E8 ? ? ? ? 48 8B C8 48 8B D8 E8 ? ? ? ?");
	FindAddress("Live_CancelConnecting", "48 83 EC 28 B2 1E 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 0D ? ? ? ? 48 83 C4 28 E9 ? ? ? ?");
	FindAddress("Live_DemonwareDisconnected", "E8 ? ? ? ? 33 D2 48 8B CB 48 83 C4 20 5B E9 ? ? ? ? 48 83 C4 20 5B C3");
	FindAddress("Live_IsInLiveGame", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 41 8B CE E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 41 8B CE 4C 89 BC 24 ? ? ? ? E8 ? ? ? ? BA ? ? ? ? 8B C8 44 8B F8 E8 ? ? ? ?");
	
	//GetInstance Functions
	FindAddress("PublisherVariableManager::GetInstance", "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 74 10 E8 ? ? ? ? 84 C0 74 07");
	FindAddress("Online_PatchStreamer::GetInstance", "E8 ? ? ? ? 33 D2 48 8B C8 E8 ? ? ? ? 0F B7 C0 48 83 C4 28 C3");
	FindAddress("DWServicesAccess::GetInstance", "E8 ? ? ? ? 8B 93 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 83 C0 FE 83 F8 02");
	FindAddress("GWeaponMap::GetInstance", "E8 ? ? ? ? 66 39 74 24 ? 74 24 4C 8D 44 24 ? 48 8B D7");
	
	//MSG_ Functions
	FindAddress("MSG_WriteBitsCompress", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 30 4C 8B 7C 24 ? 33 DB 89 5C 24 68 49 8B E8 49 63 F9 4C 8B F2 41 89 1F 45 85 C9 7E 3D");
	FindAddress("MSG_ReadByte", "E8 ? ? ? ? 8B 15 ? ? ? ? 48 8B CB 8B E8 E8 ? ? ? ? 48 8B CB 48 8B F0 E8 ? ? ? ? 48 69 D7 ? ? ? ? 48 8D 0D ? ? ? ? 89 AC 0A ? ? ? ? 89 B4 0A ? ? ? ?");
	FindAddress("MSG_ReadBits", "E8 ? ? ? ? 48 8B CB 48 8B F0 E8 ? ? ? ? 48 69 D7 ? ? ? ? 48 8D 0D ? ? ? ? 89 AC 0A ? ? ? ? 89 B4 0A ? ? ? ? 89 84 0A ? ? ? ? E8 ? ? ? ?");
	FindAddress("MSG_ReadLong", "E8 ? ? ? ? 48 69 D7 ? ? ? ? 48 8D 0D ? ? ? ? 89 AC 0A ? ? ? ? 89 B4 0A ? ? ? ? 89 84 0A ? ? ? ? E8 ? ? ? ? 2B 05 ? ? ? ? 3D ? ? ? ? 7E 3D E8 ? ? ? ?");
	FindAddress("MSG_WriteBits", "48 89 5C 24 ? 57 8B 59 28 45 8B D8 8B 79 18 4C 8B D1 46 8D 0C 03 8D 04 FD ? ? ? ? 44 3B C8 7E 0A C6 01 01 48 8B 5C 24 ? 5F C3");
	FindAddress("MSG_Init", "33 C0 C5 F9 EF C0 C5 FC 11 01 C5 F8 11 41 ? 48 89 41 30 48 89 51 08 44 89 41 18 88 41 01 48 89 41 10 89 41 20 C5 F8 77 C3");
	FindAddress("MSG_WriteByte", "4C 8B C9 8B 49 28 45 8B 41 18 8D 41 20 41 C1 E0 03 41 3B C0 7E 05 41 C6 01 01 C3");
	FindAddress("MSG_WriteLong", "4C 8B C9 8B 49 28 45 8B 41 18 8D 41 08 41 C1 E0 03 41 3B C0 7E 05 41 C6 01 01 C3");
	FindAddress("MSG_WriteData", "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 48 8B F9 4D 63 F0 8B 49 28 48 8B DA 8B 47 18 42 8D 34 F5 ? ? ? ?");
	FindAddress("MSG_WriteString", "48 83 EC 28 4C 8B D1 48 C7 C0 ? ? ? ? 66 90 48 FF C0 80 3C 02 00 75 F7 48 3D ? ? ? ?");
	
	//CL_ Functions
	FindAddress("CL_UICharacter_Reset", "40 53 48 83 EC 20 48 63 C1 33 D2 48 69 D8 ? ? ? ? 48 8D 05 ? ? ? ? 41 B8 ? ? ? ? 48 03 D8 48 8D 4B 02 E8 ? ? ? ? B8 ? ? ? ? 66 89 03 48 83 C4 20 5B C3");
	FindAddress("CL_Streaming_SetMaxWorldRequestCount", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 63 E9 48 8D 3D ? ? ? ? 8B F2 48 8B 3C EF 48 8D 4F 30 FF 15 ? ? ? ?");
	FindAddress("CL_Streaming_SetMaxClientRequestCount", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 63 C1 48 8D 3D ? ? ? ? 48 63 EA 41 8B F0 48 8D 0C 80 4C 8D 0C 4D ? ? ? ?");
	FindAddress("CL_StreamSync_Start", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 33 F6 8B DE 8B 15 ? ? ? ? 8B CB");
	FindAddress("CL_Mgr_IsControllerMappedToClient", "83 3D ? ? ? ? ? 74 1F 85 C9 75 1B 48 63 C1 48 8D 0D ? ? ? ? 8B 0C 81 48 85 D2 74 02 89 0A 83 F9 FF 0F 95 C0 C3");
	FindAddress("CL_Mgr_IsClientActive", "48 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? 66 90 39 08 74 0C 48 83 C0 04 48 3B C2 7C F3 32 C0 C3");
	FindAddress("CL_Mgr_GetControllerFromClient", "83 3D ? ? ? ? ? 8B D1 75 03 33 C0 C3 33 C9 48 8D 05 ? ? ? ? 4C 8D 05 ? ? ? ? 66 90 39 10 74 11 FF C1 48 83 C0 04 49 3B C0 7C F1 B8 ? ? ? ? C3");
	FindAddress("CL_Mgr_GetClientFromController", "83 3D ? ? ? ? ? 74 16 85 C9 75 12 48 63 C1 48 8D 0D ? ? ? ? 8B 04 81 83 F8 FF 75 02 33 C0 C3");
	FindAddress("CL_Main_InitRenderer", "40 53 48 83 EC 60 48 8D 54 24 ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 0F B6 D0 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("CL_MainSP_DisconnectLocalClient", "48 89 5C 24 ? 57 48 83 EC 20 48 63 F9 E8 ? ? ? ? E8 ? ? ? ?");
	FindAddress("CL_MainSP_Disconnect", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 63 D9 48 8D 35 ? ? ? ? 48 69 FB ? ? ? ? 80 7C 37 ? ?");
	FindAddress("CL_MainMP_PreloadMap", "E8 ? ? ? ? 48 8B CB E8 ? ? ? ? EB 1C 44 8B C5 49 8B D6 48 8B CB");
	FindAddress("CL_MainMP_MapLoading_SetupClientForConnection", "48 89 5C 24 ? 55 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 63 F9 4C 8D 3D ? ? ? ? 48 69 DF ? ? ? ? 0F B6 F2");
	FindAddress("CL_MainMP_MapLoading_Internal", "40 57 48 83 EC 20 C6 05 ? ? ? ? ? 0F B6 F9 84 C9 75 2A 33 C9 E8 ? ? ? ?");
	FindAddress("CL_MainMP_InitializeGamestate", "E8 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 41 8B CD E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? EB 0F");
	FindAddress("CL_MainMP_InitMapLoad", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B D9 41 0F B6 E8 B1 01 48 8B F2 E8 ? ? ? ? E8 ? ? ? ?");
	FindAddress("CL_MainMP_Disconnect_Internal", "48 8B C4 89 48 08 55 56 57 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 48 63 F9 4C 8D 3D ? ? ? ?");
	FindAddress("CL_MainMP_Disconnect", "E8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 C0 89 05 ? ? ? ? 89 05 ? ? ? ? 8D 48 01 E8 ? ? ? ? 8B 05 ? ? ? ? 85 C0");
	FindAddress("CL_Keys_IsCatcherActive", "48 63 C1 48 69 C8 ? ? ? ? 48 8D 05 ? ? ? ? 85 14 01 0F 95 C0 C3");
	FindAddress("CL_IsLocalClientActive", "E8 ? ? ? ? 84 C0 74 19 33 C9 E8 ? ? ? ? B2 01");
	FindAddress("CL_GetLocalClientActiveCount", "E8 ? ? ? ? 3B 05 ? ? ? ? 7E 17 41 B8 ? ? ? ? 48 8D 15 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ?");
	FindAddress("CL_AllLocalClientsDisconnected", "48 83 EC 28 E8 ? ? ? ? 84 C0 75 07 B0 01 48 83 C4 28 C3 83 3D ? ? ? ? ? 0F 94 C0 48 83 C4 28 C3");
	FindAddress("CL_Main_InvalidateSkeletonCache", "40 53 48 83 EC 20 BB ? ? ? ? 33 C0 F0 0F B1 1D ? ? ? ? 74 1A 3B C3 74 16 B9 ? ? ? ? E8 ? ? ? ? 33 C0 F0 0F B1 1D ? ? ? ? 75 E6 48 83 C4 20 5B C3");
	FindAddress("CL_InputMP_IsReadyForUserCommand", "48 63 C1 48 69 C8 ? ? ? ? 48 8D 05 ? ? ? ? 83 3C 01 08 0F 9D C0 C3");
	FindAddress("CL_MigrationFrame", "41 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 4C 63 F1 E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 41 8B CE E8 ? ? ? ? 84 C0 0F 84 ? ? ? ?");
	FindAddress("CL_VoiceFrame", "E8 ? ? ? ? E8 ? ? ? ? 48 8B C8 8B D6 E8 ? ? ? ? 8B CE E8 ? ? ? ?");
	FindAddress("CL_MainMP_ClientFrame", "40 55 53 56 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 63 F1");
	FindAddress("CL_MainMP_GetUserInfoString", "E8 ? ? ? ? 90 48 8D 4C 24 ? 65 FE 04 25 ? ? ? ? 48 8B F8 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ?");
	FindAddress("CL_MainMP_CheckForResend", "40 53 48 83 EC 40 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 63 D9 8B CB E8 ? ? ? ? 84 C0 0F 85 ? ? ? ?");
	FindAddress("CL_GamepadRepeatScrollingButtons", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 8B F2 48 8D 2D ? ? ? ?");
	FindAddress("CL_Keys_IsKeyDown", "E8 ? ? ? ? 84 C0 74 1F E8 ? ? ? ? 44 0F B6 04 2B 41 B1 01 8B D6 C6 44 24 ? ? 8B CF 89 44 24 20 E8 ? ? ? ?");
	FindAddress("CL_GamepadButtonEvent", "E8 ? ? ? ? 48 FF C3 48 83 FB 0C 7C C9 48 8B 5C 24 ? 48 8B 6C 24 ? 48 8B 74 24 ? 48 83 C4 30");
	FindAddress("CL_InputMP_ReadyToSendPacket", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 74 0D E8 ? ? ? ? 84 C0 0F 85 ? ? ? ?");
	FindAddress("CL_InputMP_SavePredictedData", "E8 ? ? ? ? 8B CB E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 74 0D E8 ? ? ? ? 84 C0 0F 85 ? ? ? ?");
	FindAddress("CL_MainMP_TogglePauseResumeGame", "E8 ? ? ? ? 8B CF E8 ? ? ? ? 4C 8B AC 24 ? ? ? ? 4C 8B A4 24 ? ? ? ? 84 C0 74 1B");
	
	//CG_ Functions
	FindAddress("CG_ViewmodelShieldHitsProcess", "E8 ? ? ? ? 33 C9 E8 ? ? ? ? 33 C9 E8 ? ? ? ? 33 C9 E8 ? ? ? ? 48 8B 03 48 8B CB 48 83 C4 20 5B 48 FF 60 10");
	FindAddress("CG_EventLod_ShouldPerformEvent", "40 57 48 83 EC 20 49 8B F8 4D 85 C0 74 6F 41 80 38 00 74 69 44 0F B6 CA");
	FindAddress("CG_CameraUpdateOrderFix_PostPhysicsWorkers_Phase2", "48 89 5C 24 ? 57 48 83 EC 20 48 8B F9 E8 ? ? ? ? 8B 8F ? ? ? ? E8 ? ? ? ? 8B 9F ? ? ? ? 48 8D 15 ? ? ? ?");
	FindAddress("CG_SnapshotMP_ProcessSnapshots", "E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 8B CE E8 ? ? ? ? 45 85 FF 79 19");
	FindAddress("CG_SnapshotMP_SetInitialSnapshot", "E8 ? ? ? ? 48 8B D6 8B CB E8 ? ? ? ? 8B CB E8 ? ? ? ? 48 8D 97 ? ? ? ? 41 B8 ? ? ? ? 8B CB E8 ? ? ? ?");
	FindAddress("CG_SnapshotMP_SetNextSnap", "E8 ? ? ? ? 8B CB E8 ? ? ? ? 48 8D 97 ? ? ? ? 41 B8 ? ? ? ? 8B CB E8 ? ? ? ?");
	FindAddress("CG_SnapshotMP_TransitionSnapshot", "E8 ? ? ? ? 48 8D 97 ? ? ? ? 41 B8 ? ? ? ? 8B CB E8 ? ? ? ?");
	FindAddress("CG_ViewMP_Init", "E8 ? ? ? ? 48 C7 87 ? ? ? ? ? ? ? ? 48 8B 4C 24 ? 48 33 CC E8 ? ? ? ? 48 8B 9C 24 ? ? ? ?");
	FindAddress("CG_ViewMP_UpdateThirdPerson", "E8 ? ? ? ? 8B CB E8 ? ? ? ? 8B CB E8 ? ? ? ? E8 ? ? ? ? 8B CB E8 ? ? ? ? 8B CB E8 ? ? ? ? 8B CB 48 83 C4 20 5B E9 ? ? ? ?");
	FindAddress("CG_View_CalcFov", "48 8B C4 48 89 58 18 48 89 70 20 55 57 41 55 41 56 41 57 48 8D 68 C8 48 81 EC ? ? ? ?");
	FindAddress("CG_MainMP_Frame", "E8 ? ? ? ? 8B CF E8 ? ? ? ? 8B CF E8 ? ? ? ? 4C 8B AC 24 ? ? ? ? 4C 8B A4 24 ? ? ? ? 84 C0");
	
	//CgWeaponSystemMP Functions
	FindAddress("CgWeaponSystemMP::BulletHitEvent_Internal", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 41 8B F8 8B EA 4C 8B 84 24 ? ? ? ?");
	FindAddress("CgWeaponSystemMP::BulletImpactEffects", "4C 8B DC 49 89 5B 10 45 89 4B 20 49 89 4B 08 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 9C 24 ? ? ? ?");
	FindAddress("CgWeaponSystemMP::BulletHitEvent_SimulateExit", "40 55 53 56 57 41 54 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? C5 F8 29 B4 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? C5 FA 10 1D ? ? ? ?");
	
	//BlackBox Functions
	FindAddress("Blackbox_SendSession", "48 89 5C 24 ? 4C 89 4C 24 ? 4C 89 44 24 ? 88 54 24 10 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? E8 ? ? ? ?");
	FindAddress("BB_WriteInstanceData", "40 55 53 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 8B D9");
	FindAddress("BB_Throttle_f", "40 53 48 83 EC 20 48 63 0D ? ? ? ? 48 8D 1D ? ? ? ? 83 7C 8B ? ? 7C 44 48 8B 4C CB ? 48 8B 49 10 E8 ? ? ? ?");
	FindAddress("BB_Start_f", "48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 D2 48 8D 1D ? ? ? ?");
	FindAddress("BB_Start", "E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 C7 C3 ? ? ? ? 4C 8B D3 0F 1F 80 ? ? ? ? 49 FF C2 42 80 3C 10 ? 75 F6");
	FindAddress("BB_SetupMsg", "48 83 EC 28 41 B8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 15 ? ? ? ? 48 8B 05 ? ? ? ? 48 83 05 ? ? ? ? ? 48 89 15 ? ? ? ? 48 89 02 8B 05 ? ? ? ? 89 42 0C 33 C0 48 89 42 10 C7 42 ? ? ? ? ? E8 ? ? ? ?");
	FindAddress("BB_SetThrottle", "40 56 41 54 41 57 48 83 EC 20 44 8B FA 48 C7 C2 ? ? ? ? 48 FF C2 80 3C 11 00 75 F7 48 89 5C 24 ? E8 ? ? ? ?");
	FindAddress("BB_Send_f", "48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 D2 48 8D 1D ? ? ? ?");
	FindAddress("BB_Send", "41 56 48 83 EC 40 80 3D ? ? ? ? ? 44 0F B6 F2 0F 84 ? ? ? ? 45 84 C0 0F 84 ? ? ? ?");
	FindAddress("BB_RewriteDefinitions", "48 C7 05 ? ? ? ? ? ? ? ? E9 ? ? ? ? 48 83 EC 08 48 8B 15 ? ? ? ? 4C 8B C1 48 8B 0D ? ? ? ? 48 3B D1");
	FindAddress("BB_MsgInit", "40 53 48 83 EC 20 33 DB 48 89 11 48 8B C2 44 89 41 10 48 89 59 18 33 D2 88 59 20 48 89 59 30 48 89 59 08 48 8B C8 4D 63 C0");
	FindAddress("BB_LoadWhitelists", "40 53 48 83 EC 20 80 3D ? ? ? ? ? BB ? ? ? ? 75 2B 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("BB_IsInitializedAndActive", "E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 85 DB 0F 88 ? ? ? ? 4C 89 A4 24 ? ? ? ? 48 8D 4C 24 ?");
	FindAddress("BB_InitStringCache", "48 83 EC 28 33 D2 48 8D 0D ? ? ? ? 41 B8 ? ? ? ? E8 ? ? ? ? 33 C0 89 05 ? ? ? ? 89 05 ? ? ? ? 89 05 ? ? ? ? 89 05 ? ? ? ? 89 05 ? ? ? ? 48 83 C4 28 C3");
	FindAddress("BB_InitDefinitions", "40 53 48 83 EC 20 33 DB 48 8D 0D ? ? ? ? BA ? ? ? ? 89 1D ? ? ? ? 41 B8 ? ? ? ? 48 89 1D ? ? ? ? E8 ? ? ? ? 48 8D 0D ? ? ? ? C7 05 ? ? ? ? ? ? ? ? 33 D2 48 89 0D ? ? ? ? 41 B8 ? ? ? ? 48 89 1D ? ? ? ? 88 1D ? ? ? ? 48 89 1D ? ? ? ? 48 89 1D ? ? ? ? E8 ? ? ? ? 89 1D ? ? ? ? 48 83 C4 20 5B C3");
	FindAddress("BB_Init", "40 53 48 83 EC 30 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ?");
	FindAddress("BB_HashString", "B8 ? ? ? ? 48 85 D2 74 1A 66 0F 1F 44 00 ? 44 0F BE 01 48 8D 49 01 6B C0 21 41 03 C0 48 83 EA 01 75 EC C3");
	FindAddress("BB_Enable_f", "48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 D2");
	FindAddress("BB_Disable_f", "48 8D 15 ? ? ? ? E8 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B C8 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 33 D2 48 8D 1D ? ? ? ?");
	FindAddress("BB_ClearStringCache", "E8 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 33 C9 48 83 C4 28 E9 ? ? ? ?");
	
	//Party_ Functions
	FindAddress("Party_PartiesAcrossGamemodesFeatureEnabled", "E8 ? ? ? ? 84 C0 75 16 8B CE E8 ? ? ? ? E8 ? ? ? ? 48 8B C8 8B D6 E8 ? ? ? ?");
	
	//Misc/Unsorted Functions
	FindAddress("I_CleanStr", "E8 ? ? ? ? BE ? ? ? ? 4D 8B C7 48 8D 8C 24 ? ? ? ?");
	FindAddress("ScrCmd_Unlink_Internal", "40 53 48 83 EC 70 48 8B D9 0F B6 CA E8 ? ? ? ? 48 8B 8B ? ? ? ? 48 85 C9 74 30 8B 81 ? ? ? ? C1 E8 0B A8 01");
	FindAddress("R_RegisterFont", "E8 ? ? ? ? 48 BB ? ? ? ? ? ? ? ? 48 89 05 ? ? ? ? 48 8B CB BA ? ? ? ? E8 ? ? ? ? BA ? ? ? ? 48 89 05 ? ? ? ? 48 8B CB E8 ? ? ? ? 48 89 05 ? ? ? ? 8B 05 ? ? ? ? 83 C0 D0 89 05 ? ? ? ?");
	FindAddress("Material_RegisterHandle", "E8 ? ? ? ? 48 B9 ? ? ? ? ? ? ? ? 48 89 05 ? ? ? ? BA ? ? ? ? E8 ? ? ? ? 48 BB ? ? ? ? ? ? ? ? 48 89 05 ? ? ? ? 48 8B CB BA ? ? ? ? E8 ? ? ? ?");
	FindAddress("I_stricmp", "4C 8B D9 4C 8B CA 4C 2B DA 0F 1F 80 ? ? ? ? 47 0F B6 04 0B 45 0F B6 11 4D 8D 49 01 41 0F BE C0 41 0F BE CA 3B C1 74 3D");
	FindAddress("HandleStateMsg", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 63 F9 49 8B D8 49 8B C8 E8 ? ? ? ?");
	FindAddress("Sys_Milliseconds", "E8 ? ? ? ? 2B 05 ? ? ? ? 3D ? ? ? ? 7E 3D E8 ? ? ? ? 89 05 ? ? ? ? 90 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 90 48 8B 5C 24 ?");
	FindAddress("GetAdvertisedPatchVersion", "E8 ? ? ? ? 8B D8 E8 ? ? ? ? 44 8B C8 89 5C 24 20 4C 8D 05 ? ? ? ? BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("DS_GetDataBuildNumber", "E8 ? ? ? ? 44 8B C8 89 5C 24 20 4C 8D 05 ? ? ? ? BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("memset", "4C 8B D9 0F B6 D2 49 B9 ? ? ? ? ? ? ? ? 4C 0F AF CA 49 83 F8 10 0F 86 ? ? ? ? 66 49 0F 6E C1 66 0F 60 C0 49 81 F8 ? ? ? ? 77 10 E9 ? ? ? ?");
	FindAddress("CreateUniqueId", "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? E8 ? ? ? ? 84 C0 74 07 E8 ? ? ? ?");
	FindAddress("Core_strcpy", "48 83 EA 01 74 1E 4C 2B C1 0F 1F 80 ? ? ? ? 41 0F B6 04 08 84 C0 74 0B 88 01 48 FF C1 48 83 EA 01 75 EC C6 01 00 C3");
	FindAddress("Content_DoWeHaveContentPack", "8B D1 83 F9 02 75 03 B0 01 C3 44 8B 05 ? ? ? ? 33 C0");
	FindAddress("Cmd_AddCommandInternal", "48 89 5C 24 ? 4C 8B 15 ? ? ? ? 48 8B DA 4C 8B D9 4D 85 D2 74 72 66 0F 1F 84 00 ? ? ? ? 49 8B 42 08 4D 8B CB");
	FindAddress("DWServicesAccess::GetDWLobbyService", "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 83 C0 FE 83 F8 02 76 1A 8B 8B ? ? ? ? E8 ? ? ? ? 33 D2 48 8B CB 48 83 C4 20 5B E9 ? ? ? ?");
	FindAddress("DWLobbyService::getStatus", "E8 ? ? ? ? 83 C0 FE 83 F8 02 76 1A 8B 8B ? ? ? ? E8 ? ? ? ? 33 D2 48 8B CB 48 83 C4 20 5B E9 ? ? ? ?");
	FindAddress("InviteJoinHSM::ResetDemonwareLogonRetry", "48 83 EC 28 E8 ? ? ? ? 84 C0 74 12 33 C9 E8 ? ? ? ? 8B C8 48 83 C4 28 E9 ? ? ? ? 48 83 C4 28 C3");
	FindAddress("dwAllDemonWareReconnectsDisabled", "E8 ? ? ? ? 84 C0 74 12 33 C9 E8 ? ? ? ? 8B C8 48 83 C4 28 E9 ? ? ? ? 48 83 C4 28 C3");
	FindAddress("DW_ResetLogon", "E8 ? ? ? ? 33 D2 E9 ? ? ? ? ? ? 48 8D 0D ? ? ? ? E9 ? ? ? ?");
	FindAddress("dwLogOnHSM_base::HSM_TriggerEvent", "83 FA 23 77 1B 8B 41 74 03 41 70 25 ? ? ? ? 7D 07 FF C8 83 C8 F0 FF C0 89 54 81 30 FF 41 70 C3");
	FindAddress("AimAssist_Setup", "E8 ? ? ? ? 48 83 BF ? ? ? ? ? 74 AE 8B CB");
	FindAddress("CgMLGSpectator::GetMLGSpectator", "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 0F 85 ? ? ? ?");
	FindAddress("CgMLGSpectator::GetCameraManager", "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 80 BB ? ? ? ? ?");
	FindAddress("CgMLGCameraManager::ShouldRenderThirdPerson", "E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? 80 BB ? ? ? ? ? 0F 85 ? ? ? ?");
	FindAddress("ComCharacterLimits::UpdateGameLimits", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 89 0D ? ? ? ? 41 8B F9 41 8B F0 8B EA 8B D9 83 F9 01");
	FindAddress("BG_GetClipSize", "48 8B C4 48 89 58 08 48 89 70 18 57 48 81 EC ? ? ? ? C5 F8 29 70 ? C5 F8 29 78 ? 48 8B 05 ? ? ? ?");
	FindAddress("Com_GameMode_SupportsFeature", "0F B6 05 ? ? ? ? 4C 8D 05 ? ? ? ? 48 69 D0 ? ? ? ? 8B C9 42 0F B6 84 02 ? ? ? ? 41 8B 84 80 ? ? ? ? 41 85 84 88 ? ? ? ? 0F 95 C0 C3");
	FindAddress("ClNetperfTelemetry::TrackUsercmd", "48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 30 41 0F B6 F1 41 8B E8 44 8B F2 48 8B F9 E8 ? ? ? ? 84 C0");
	FindAddress("NetConnection::SendP2P", "40 53 56 57 48 83 EC 50 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B D9 41 8B F1 48 8B 09 49 8B F8 E8 ? ? ? ? 48 8D 54 24 ? 48 8B C8 E8 ? ? ? ?");
	FindAddress("OnlineMgr::OnDisconnect", "48 89 5C 24 ? 57 48 83 EC 20 90 0F B6 FA 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 65 FE 04 25 ? ? ? ? 90 48 8B 99 ? ? ? ? 48 85 DB");
	FindAddress("Online_Telemetry_Frame", "E8 ? ? ? ? E8 ? ? ? ? 84 C0 74 16 8B CB E8 ? ? ? ?");
	FindAddress("ClNetperfTelemetry::Frame", "40 53 48 83 EC 20 48 8B D9 E8 ? ? ? ? 84 C0 74 75 80 BB ? ? ? ? ?");
	FindAddress("Online_Loot::GetItemQuantity", "E8 ? ? ? ? 89 45 7F 85 C0 74 6D 49 8B 0C 24 E8 ? ? ? ? 89 45 77 85 C0 75 1A 44 8B C6 41 8B D7 49 8B CE");
	FindAddress("CgCompassSystemMP::ActorUpdatePos", "E8 ? ? ? ? 48 8B CB E8 ? ? ? ? 8B 43 08 89 43 60");
	FindAddress("CompassActor_SetLastEnemyPosFromLastPos", "E8 ? ? ? ? 8B 43 08 89 43 60 4C 8B B4 24 ? ? ? ?");
	FindAddress("atof", "E8 ? ? ? ? 48 8B 83 ? ? ? ? C5 FB 5A C8 C5 FA 11 88 ? ? ? ?");
	
	//Host only functions
	FindAddress("G_Items_FillClip", "40 55 57 41 54 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 40 4C 8B F9");
	FindAddress("G_Items_AddAmmo", "40 55 53 57 41 54 41 55 41 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 60");
	FindAddress("G_Items_InitializeAmmo", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 54 41 56 41 57 48 83 EC 30 48 8B F1 45 0F B6 F1 48 8B CA 45 0F B6 E0 48 8B FA E8 ? ? ? ?");
	FindAddress("G_Weapon_GivePlayerWeapon", "E8 ? ? ? ? 84 C0 74 19 44 0F B6 44 24 ? 48 8D 54 24 ? 45 0F B6 CE 48 8B CF E8 ? ? ? ? EB 10");
	FindAddress("SvGameModeAppMP::ServerStart_PreSpawn", "48 83 EC 38 8B 05 ? ? ? ? 48 89 5C 24 ? 48 8D 1C C5 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 89 6C 24 ? 48 89 7C 24 ?"); //unsure about this one, has Sv in the beginning which could be server?
	FindAddress("SV_Game_BroadcastServerCommand", "E8 ? ? ? ? 88 9C 2E ? ? ? ? C6 84 2E ? ? ? ? ? 48 8B D3 48 8B CF");
	FindAddress("G_ClientMP_OnSameTeam", "48 8B 81 ? ? ? ? 48 85 C0 74 22 48 8B 8A ? ? ? ? 48 85 C9 74 16 0F B6 80 ? ? ? ? 84 C0 74 0B 3A 81 ? ? ? ? 75 03 B0 01 C3");
	FindAddress("G_ClientMP_IsPlaying", "48 8B 81 ? ? ? ? F7 80 ? ? ? ? ? ? ? ? 0F 94 C0 C3");
	FindAddress("G_CmdsMP_SayTo", "E8 ? ? ? ? FF C3 3B 1D ? ? ? ? 7C BB");
	FindAddress("G_CmdsMP_ClientCommand", "E8 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8B 0C 18 80 3C 29 00 75 05 E8 ? ? ? ? 65 48 8B 0C 25 ? ? ? ?");
	FindAddress("G_CmdsMP_SpectateCycle_f", "40 53 48 83 EC 20 8B 81 ? ? ? ? 44 8B CA 83 C0 FE 48 8B D9 A9 ? ? ? ? 0F 85 ? ? ? ? 83 B9 ? ? ? ? ? 0F 8D ? ? ? ? 83 B9 ? ? ? ? ?");
	FindAddress("Cmd_SetExtraGameRevenueRate", "E8 ? ? ? ? E9 ? ? ? ? 4C 8D 84 24 ? ? ? ? 48 8D 15 ? ? ? ?");
	FindAddress("SV_Cmd_ArgInt", "E8 ? ? ? ? B9 ? ? ? ? 8B D8 E8 ? ? ? ? 44 8B CF");
	FindAddress("G_CalloutMarkerPings_ProcessPredictedCommand", "40 55 56 57 41 54 41 55 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 10 8B 05 ? ? ? ?");
	
	//Variables
	FindAddress("level.clients", "4C 8B 05 ? ? ? ? 48 63 C2 FF C2 48 69 D8 ? ? ? ? 89 15 ? ? ? ? 48 03 D9 E8 ? ? ? ?");
	FindAddress("g_entities", "48 03 15 ? ? ? ? 41 FF 52 20 48 8B C3 48 83 C4 20 5B C3");
	FindAddress("bg_weaponDefs", "48 8D 2D ? ? ? ? 48 8B 6C C5 ? E8 ? ? ? ? 66 39 74 24 ?");
	FindAddress("bg_weaponCompleteDefs", "48 8D 0D ? ? ? ? 4C 8D 4C 24 ? 44 8B C5 4C 8B 3C C1 48 8B CF E8 ? ? ? ?");
	FindAddress("CgEntitySystem::ms_entitySystemArray", "48 8B 05 ? ? ? ? 49 89 5B 08 49 89 73 F0 0F B7 32 48 8B 40 10");
	FindAddress("CgStatic::ms_cgameStaticsArray", "48 8D 15 ? ? ? ? 48 8B 0C CA 48 8B 11 4C 8B 82 ? ? ? ? 8B D3 41 FF D0");
	FindAddress("cg_t::ms_cgArray", "4C 8D 05 ? ? ? ? 4D 8B 04 D0 90");
	FindAddress("CgCompassSystem::ms_compassSystemArray", "48 8D 1D ? ? ? ? 48 8B 1C CB 48 85 DB 74 4F");
	FindAddress("SvClient::ms_clients", "48 8D 35 ? ? ? ? 48 89 7C 24 ? 48 8B 04 DE 48 8D 3C DE 80 78 08 06");
	//FindAddress("s_aab_set_pointer_lastpos", "8B 05 ? ? ? ? 4C 33 C0 41 FF D0 F6 03 01"); //bad spot need to fix
	
}
