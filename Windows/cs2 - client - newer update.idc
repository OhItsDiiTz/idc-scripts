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

static label_list_funcs(void) {
	auto list_rfunc;
	auto list_rclass;
	auto list_rfunclist;
	auto list_rfunclistend;
	auto list_cfuncptr;
	auto list_cfunc;
	auto list_cfuncnameptr;
	auto list_cfuncname;
	//48 83 C4 ?? E9 ?? ?? ?? ?? - use this when more then 1 function is registered, else you can use this E9 ?? ?? ?? ??
	
	list_rfunc = FindBinary(get_imagebase(), SEARCH_DOWN, "40 53 48 83 EC 40 48 8B D9 4C 8D 05 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 5C 24 ?? 4C 8D 44 24 ?? 48 89 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 4C 8B C3 C6 44 24 ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 83 C4 40 5B C3");
	
	list_rclass = FindBinary(list_rfunc, SEARCH_DOWN, "48 8D 15 ?? ?? ?? ??");
	list_rclass = GetString(decode_insn(list_rclass).Op1.addr, -1, 0);
	
	list_rfunclist = FindBinary(list_rfunc, SEARCH_DOWN, "48 8D 05 ?? ?? ?? ??");
	list_rfunclist = decode_insn(list_rfunclist).Op1.addr;
	
	list_rfunclistend = FindBinary(list_rfunclist, SEARCH_DOWN, "E9 ?? ?? ?? ??");
	
	Message("0x%X - %s - %X - %X\n", list_rfunc, list_rclass, list_rfunclist, list_rfunclistend);
	
	list_cfuncptr = FindBinary(list_rfunclist, SEARCH_DOWN, "48 8D 15 ?? ?? ?? ??");
	list_cfunc = decode_insn(list_cfuncptr).Op1.addr;
	list_cfuncnameptr = FindBinary(list_cfuncptr + 1, SEARCH_DOWN, "48 8D 0D ?? ?? ?? ??");
	list_cfuncname = GetString(decode_insn(list_cfuncnameptr).Op1.addr, -1, 0);
	
	Message("%X - %X - %X - %s\n", list_cfuncptr, list_cfunc, list_cfuncnameptr, list_cfuncname);
	
	
	while(list_rfunc != -1) {
		list_rfunc = FindBinary(list_rfunc + 1, SEARCH_DOWN, "40 53 48 83 EC 40 48 8B D9 4C 8D 05 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 5C 24 ?? 4C 8D 44 24 ?? 48 89 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 4C 8B C3 C6 44 24 ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 83 C4 40 5B C3");;
		if(list_rfunc == -1) {
			break;
		}
		list_rclass = FindBinary(list_rfunc, SEARCH_DOWN, "48 8D 15 ?? ?? ?? ??");
		list_rclass = GetString(decode_insn(list_rclass).Op1.addr, -1, 0);
	
		list_rfunclist = FindBinary(list_rfunc, SEARCH_DOWN, "48 8D 05 ?? ?? ?? ??");
		list_rfunclist = decode_insn(list_rfunclist).Op1.addr;
	
		list_rfunclistend = FindBinary(list_rfunclist, SEARCH_DOWN, "4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 83 C4 ?? E9 ?? ?? ?? ??");
		if(list_rfunclistend == -1) {
			list_rfunclistend = FindBinary(list_rfunclist, SEARCH_DOWN, "48 83 C4 ?? C3");
		}
	
		Message("0x%X - %s - %X - %X\n", list_rfunc, list_rclass, list_rfunclist, list_rfunclistend);
		list_cfuncptr = list_rfunclist;
		while(list_cfuncptr < list_rfunclistend) {
			if(list_cfuncptr < list_rfunclistend) {
				list_cfuncptr = FindBinary(list_cfuncptr + 1, SEARCH_DOWN, "48 8D 15 ?? ?? ?? ??");
				list_cfunc = decode_insn(list_cfuncptr).Op1.addr;
				if(SegStart(list_cfunc) == 0x0000000180001000) {
					list_cfuncnameptr = FindBinary(list_cfuncptr + 1, SEARCH_DOWN, "48 8D 0D ?? ?? ?? ??");
					list_cfuncname = GetString(decode_insn(list_cfuncnameptr).Op1.addr, -1, 0);
					MakeName(list_cfunc, sprintf("%s::%s", list_rclass, list_cfuncname));
					Message("%X - %X - %X - %s::%s\n", list_cfuncptr, list_cfunc, list_cfuncnameptr, list_rclass, list_cfuncname);
				}
			}
		}
	}
}

static main(void) {
	FindAddress("engine", "48 8B 0D ?? ?? ?? ?? 48 8D 54 24 ?? 48 8B 01 FF 90 ?? ?? ?? ?? 8B 08 48 63 C1 48 8D 0D ?? ?? ?? ??"); //global variable
	FindAddress("view", "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 18 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??"); //global variable
	FindAddress("g_pNetworkMessages", "48 8B 0D ?? ?? ?? ?? 4C 8B 09 44 8B C0 48 8B D7 41 FF 91 ?? ?? ?? ?? 48 8B C7 48 83 C4 20 5F C3"); //global variable
	FindAddress("g_pFlattenedSerializers", "48 8B 0D ? ? ? ? 48 89 44 24 ? 48 8B 01 FF 90 ? ? ? ? 84 C0 0F 94 C0 88 83 ? ? ? ? 48 8B CB"); //global variable
	FindAddress("g_pGameEventSystem", "48 8B 1D ? ? ? ? 48 85 D2 75 48 48 8B 15 ? ? ? ? 48 8B 0D ? ? ? ? 48 85 D2 75 2E 48 8B 01"); //global variable
	FindAddress("gpGlobals", "48 8B 0D ?? ?? ?? ?? 44 8B 7E 40 45 3B FE 89 45 AF 41 0F 95 C5 80 BE ?? ?? ?? ?? ??"); //global variable
	FindAddress("dummyvars", "48 8D 0D ?? ?? ?? ?? 48 89 0D ?? ?? ?? ?? 48 89 41 28 C3"); //global variable
	FindAddress("g_pGameEntitySystem", "48 8B 0D ?? ?? ?? ?? 0F 28 CE E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ??"); //global variable
	FindAddress("g_pNetworkClientService", "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 85 C0 74 1D"); //global variable

	FindAddress("AngleVectors", "48 8B C4 48 89 58 08 48 89 70 10 57 48 83 EC 70 F3 0F 10 01 49 8B F0 0F 29 70 E8 4C 8D 40 B8 F3 0F 10 71 ?? 48 8B FA 0F 29 78 D8 48 8D 50 A8 F3 0F 10 3D ?? ?? ?? ??");
	FindAddress("CGameEventManager::ConPrintEvent", "41 56 41 57 48 81 EC ?? ?? ?? ?? 4C 8B F2 4C 8D 0D ?? ?? ?? ?? 45 33 FF 4C 8D 05 ?? ?? ?? ?? 49 8B CE 44 89 7C 24 ?? 33 D2 E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 40 08 48 85 C0 0F 84 ?? ?? ?? ?? 41 8B D7");
	FindAddress("CGameEventManager::CreateEvent", "40 53 56 48 83 EC 38 48 89 6C 24 ?? 48 8D 99 ?? ?? ?? ?? 4C 89 64 24 ?? 48 8B EA 4C 89 74 24 ?? 45 0F B6 E0 4C 89 7C 24 ?? 4D 8B F1 4C 8B F9");
	FindAddress("CGameEventManager::FireEvent", "40 53 57 41 54 41 55 41 56 48 83 EC 30 4C 8B F2 4C 8B E1 BA ? ? ? ? 48 8D 0D ? ? ? ? 45 0F B6 E8 E8 ? ? ? ?");
	FindAddress("CGameEventManager::FireEventClientSide", "48 89 5C 24 ?? 56 57 41 54 48 83 EC 30 48 8B F2 48 8D 99 ?? ?? ?? ?? 4C 8B E1 FF 15 ?? ?? ?? ?? 90");
	FindAddress("CGameEventManager::HasClientListenersChanged", "80 B9 ? ? ? ? ? 75 03 32 C0 C3 84 D2 74 07 C6 81 ? ? ? ? ? B0 01 C3");
	FindAddress("CGameEventManager::Init", "40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 50 10 48 8B 03 48 8D 15 ? ? ? ? 45 33 C0 48 8B CB FF 50 08");
	FindAddress("CGameEventManager::UpdateListenEventList", "48 89 5C 24 ?? 56 57 41 56 48 81 EC ?? ?? ?? ?? 8B DA 48 8D 05 ?? ?? ?? ?? 33 D2");
	FindAddress("CGameEvent::CGameEvent", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC 40 48 8D 79 18 C7 41 ?? ?? ?? ?? ??");
	FindAddress("CSource2Client::GetBugReportInfo", "49 8B C1 4D 8B D0 4C 8B 4C 24 ? 8B CA 4C 8B C0 49 8B D2 E9 ? ? ? ?");
	FindAddress("CSource2Client::PlayerInfoChanged", "48 89 5C 24 ?? 57 48 83 EC 70 8B DA 48 8D 4C 24 ?? 33 D2 45 33 C0 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 44 24 ?? 4C 8D 44 24 ??");
	FindAddress("C_BaseEntity::Instance", "E8 ? ? ? ? 48 8B C8 48 85 C0 75 38 8B 0D ? ? ? ? 8D 50 02 FF 15 ? ? ? ? 84 C0");
	FindAddress("C_BasePlayer::HasAnyLocalPlayer", "E8 ? ? ? ? 84 C0 74 71 80 BB ? ? ? ? ? 74 68 48 83 BB ? ? ? ? ? 75 5E 48 8B 43 10 8B 48 30 C1 E9 07 F6 C1 01 75 4F 8B 83 ? ? ? ? 83 F8 FF 74 08");
	FindAddress("C_BaseFlex::Connect", "40 53 48 83 EC 30 48 8B D9 E8 ? ? ? ? 48 8B CB E8 ? ? ? ? 84 C0 74 04 B0 01 EB 41 48 8B 43 10 4C 8D 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 08 48 8B 81 ? ? ? ? 48 89 44 24 ? 48 8B 81 ? ? ? ? 48 8B 0D ? ? ? ? 48 89 44 24 ?");
	FindAddress("CEntityInstance::IsAuthoritative", "E8 ? ? ? ? 84 C0 74 04 B0 01 EB 41 48 8B 43 10 4C 8D 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 08 48 8B 81 ? ? ? ? 48 89 44 24 ? 48 8B 81 ? ? ? ?");
	FindAddress("CBaseLesson::ShouldShowSpew", "40 57 48 83 EC 20 48 8B F9 BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 75 0B 48 8B 05 ? ? ? ? 48 8B 40 08 48 8B 10 48 85 D2 74 74 80 3A 00 74 6F BA ? ? ? ? 48 89 5C 24 ? 48 8D 0D ? ? ? ?");
	FindAddress("CGameInstructorSymbol::String", "48 83 EC 28 0F B7 01 48 8D 54 24 ?? 48 8D 0D ?? ?? ?? ?? 66 89 44 24 ?? FF 15 ?? ?? ?? ?? 48 83 C4 28 C3");
	FindAddress("C_BaseEntity::EmitSound", "48 8B C4 48 89 70 10 48 89 78 18 55 41 56 41 57 48 8D 68 B1 48 81 EC ?? ?? ?? ?? 41 8B F8 4C 8B FA 4C 8B F1 4D 85 C9");
	FindAddress("C_BaseEntity::AddFlag", "44 8B 81 ?? ?? ?? ?? 44 85 C2 75 19 41 8B C0 0B C2 44 3B C0 74 06 89 81 ?? ?? ?? ?? F6 C2 08 0F 85 ?? ?? ?? ?? C3");
	FindAddress("CGameEntitySystem::GetBaseEntity", "81 FA ?? ?? ?? ?? 77 36 8B C2 C1 F8 09 83 F8 3F 77 2C 48 98 48 8B 4C C1 ?? 48 85 C9 74 20 8B C2 25 ?? ?? ?? ?? 48 6B C0 78 48 03 C8 74 10 8B 41 10 25 ?? ?? ?? ?? 3B C2 75 04 48 8B 01 C3");
	FindAddress("CGameEntitySystem::GetHighestEntityIndex", "E8 ? ? ? ? 8B 08 FF C1 3B D9 0F 8C ? ? ? ? 48 8B BC 24 ? ? ? ?");
	FindAddress("cl_showents", "40 53 48 81 EC ? ? ? ? 48 8B 0D ? ? ? ? 48 8D 94 24 ? ? ? ? 33 DB E8 ? ? ? ? 8B 08");
	FindAddress("C_BaseEntity::GetAbsOrigin", "E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 8D 4D 0F 48 8B D8 E8 ?? ?? ?? ?? F3 0F 10 03 48 8D 4D 67");
	FindAddress("NDebugOverlay::Sphere", "48 8B C4 48 89 58 18 55 56 57 48 8D 68 B8 48 81 EC ?? ?? ?? ?? 48 8B D9 44 0F 29 58 ??");
	FindAddress("CGameEntitySystem::FindEntityByClassname", "48 83 EC 68 45 33 C9 C7 44 24 ?? ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 83 C4 68 C3");
	FindAddress("CSource1GameConfiguration::InitGameSession", "48 83 EC 28 E8 ? ? ? ? 84 C0 75 05 48 83 C4 28 C3");
	FindAddress("UI_PopupManager::ShowPopup", "E8 ?? ?? ?? ?? 48 8B 06 48 8B CE FF 10 48 8B 5C 24 ?? 48 83 C4 20 41 5E 5E 5D C3");
	FindAddress("C_BaseEntity::OnDataChanged", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 01 8B F2 48 8B D9 FF 90 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B F8");
	FindAddress("MainViewOrigin", "E8 ? ? ? ? 8B CB F2 0F 10 00 F2 0F 11 06 8B 40 08 89 46 08 E8 ? ? ? ? 4C 8D 4E 24 8B D3");
	FindAddress("MainViewAngles", "E8 ? ? ? ? 4C 8D 4E 24 8B D3 4C 8D 46 18 48 8B CF F2 0F 10 00 F2 0F 11 46 ? 8B 40 08");
	FindAddress("ReadSteamRemoteStorageFile", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 33 FF 48 8B F2 F7 41 ? ? ? ? ? 48 8B D9 48 89 79 10");
	FindAddress("UI_Popup_Generic::SetDisplayTwoOptions", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 54 41 56 41 57 48 83 EC 50 48 8B 84 24 ? ? ? ? 4C 8B FA 33 D2 4C 89 4C 24 ?");
	
	
	label_list_funcs();

}


