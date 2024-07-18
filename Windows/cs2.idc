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
	FindAddress("engine", "48 8B 0D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 48 8D 94 24 ? ? ? ? 44 8B C3 48 8B 01 FF 90 ? ? ? ? 4C 8B 35 ? ? ? ?"); //global variable
	FindAddress("view", "48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 89 7C 24 ? 48 8B 01 FF 50 60 0F 2E B3 ? ? ? ? 75 5E E8 ? ? ? ?"); //global variable
	FindAddress("g_pNetworkMessages", "48 8B 05 ? ? ? ? 48 8B 00 44 8B 05 ? ? ? ? 48 8B 54 24 ? 48 8B 0D ? ? ? ? FF 90 ? ? ? ? 48 8B 44 24 ? 48 83 C4 38 C3"); //global variable
	FindAddress("g_pFlattenedSerializers", "48 8B 0D ? ? ? ? 48 89 44 24 ? 48 8B 01 FF 90 ? ? ? ? 84 C0 0F 94 C0 88 83 ? ? ? ? 48 8B CB"); //global variable
	FindAddress("g_pGameEventSystem", "48 8B 1D ? ? ? ? 48 85 D2 75 48 48 8B 15 ? ? ? ? 48 8B 0D ? ? ? ? 48 85 D2 75 2E 48 8B 01"); //global variable
	FindAddress("gpGlobals", "48 8B 1D ? ? ? ? 4C 8D 25 ? ? ? ? 48 8B 48 10 48 8B 41 20 48 85 C0 4C 0F 45 E0 44 38 73 3D 75 16 44 38 73 3C 75 10 48 8B 43 20 48 85 C0"); //global variable
	FindAddress("dummyvars", "48 8D 0D ? ? ? ? F3 0F 11 05 ? ? ? ? 48 89 0D ? ? ? ? 48 89 41 20 C3"); //global variable
	FindAddress("g_pGameEntitySystem", "48 8B 0D ? ? ? ? 8D 53 01 E8 ? ? ? ? 48 85 C0 74 2E 48 8B 10 48 8B C8 FF 92 ? ? ? ? 84 C0 74 1E 48 8B 05 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 39 58 10 0F 8E ? ? ? ? 8D 53 01 EB 76"); //global variable
	FindAddress("g_pNetworkClientService", "48 8B 0D ? ? ? ? 48 8B 01 FF 90 ? ? ? ? 48 85 C0 74 1D 4C 8B 00 48 8B C8 41 FF 50 28 48 8B D6"); //global variable

	FindAddress("AngleVectors", "E8 ? ? ? ? 4C 8D 7F 08 4C 8D 4D 98 4C 89 7C 24 ? 4C 8D 45 88 48 8D 54 24 ? 48 8D 4D 10 E8 ? ? ? ? 49 8B 06 49 8B CE FF 90 ? ? ? ? 48 8B C8 E8 ? ? ? ?");
	FindAddress("CGameEventManager::ConPrintEvent", "48 89 74 24 ? 57 48 83 EC 30 48 8B F2 4C 8D 0D ? ? ? ? 33 FF 4C 8D 05 ? ? ? ? 48 8B CE");
	FindAddress("CGameEventManager::CreateEvent", "44 88 44 24 ? 56 41 54 48 83 EC 58 48 89 6C 24 ? 48 8D B1 ? ? ? ? 48 89 7C 24 ? 41 0F B6 E8 4C 89 6C 24 ?");
	FindAddress("CGameEventManager::FireEvent", "40 53 57 41 54 41 55 41 56 48 83 EC 30 4C 8B F2 4C 8B E1 BA ? ? ? ? 48 8D 0D ? ? ? ? 45 0F B6 E8 E8 ? ? ? ?");
	FindAddress("CGameEventManager::FireEventClientSide", "48 89 5C 24 ? 57 41 54 41 56 48 83 EC 30 4C 8B F2 48 8D 99 ? ? ? ? 4C 8B E1 FF 15 ? ? ? ? 90 33 FF");
	FindAddress("CGameEventManager::HasClientListenersChanged", "80 B9 ? ? ? ? ? 75 03 32 C0 C3 84 D2 74 07 C6 81 ? ? ? ? ? B0 01 C3");
	FindAddress("CGameEventManager::Init", "40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 50 10 48 8B 03 48 8D 15 ? ? ? ? 45 33 C0 48 8B CB FF 50 08");
	FindAddress("CGameEventManager::UpdateListenEventList", "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 8B DA 48 8D 4C 24 ? 33 D2 45 33 C0 E8 ? ? ? ? 48 8B 0D ? ? ? ?");
	FindAddress("CGameEvent::CGameEvent", "48 89 5C 24 ? 57 48 83 EC 20 48 8D 05 ? ? ? ? 48 89 51 08 48 89 01 48 8B D9 B9 ? ? ? ? 49 8B F8 FF 15 ? ? ? ? 48 85 C0");
	FindAddress("CSource2Client::GetBugReportInfo", "49 8B C1 4D 8B D0 4C 8B 4C 24 ? 8B CA 4C 8B C0 49 8B D2 E9 ? ? ? ?");
	FindAddress("CSource2Client::PlayerInfoChanged", "48 89 5C 24 ? 57 48 83 EC 60 8B DA 48 8D 4C 24 ? 33 D2 45 33 C0 E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 4C 8D 44 24 ?");
	FindAddress("C_BaseEntity::Instance", "E8 ? ? ? ? 48 8B C8 48 85 C0 75 38 8B 0D ? ? ? ? 8D 50 02 FF 15 ? ? ? ? 84 C0");
	FindAddress("C_BasePlayer::HasAnyLocalPlayer", "E8 ? ? ? ? 84 C0 74 71 80 BB ? ? ? ? ? 74 68 48 83 BB ? ? ? ? ? 75 5E 48 8B 43 10 8B 48 30 C1 E9 07 F6 C1 01 75 4F 8B 83 ? ? ? ? 83 F8 FF 74 08");
	FindAddress("C_BaseFlex::Connect", "40 53 48 83 EC 30 48 8B D9 E8 ? ? ? ? 48 8B CB E8 ? ? ? ? 84 C0 74 04 B0 01 EB 41 48 8B 43 10 4C 8D 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 08 48 8B 81 ? ? ? ? 48 89 44 24 ? 48 8B 81 ? ? ? ? 48 8B 0D ? ? ? ? 48 89 44 24 ?");
	FindAddress("CEntityInstance::IsAuthoritative", "E8 ? ? ? ? 84 C0 74 04 B0 01 EB 41 48 8B 43 10 4C 8D 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 08 48 8B 81 ? ? ? ? 48 89 44 24 ? 48 8B 81 ? ? ? ?");
	FindAddress("CBaseLesson::ShouldShowSpew", "40 57 48 83 EC 20 48 8B F9 BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 75 0B 48 8B 05 ? ? ? ? 48 8B 40 08 48 8B 10 48 85 D2 74 74 80 3A 00 74 6F BA ? ? ? ? 48 89 5C 24 ? 48 8D 0D ? ? ? ?");
	FindAddress("CGameInstructorSymbol::String", "E8 ? ? ? ? 4D 8B C5 4C 2B C0 66 0F 1F 84 00 ? ? ? ? 0F B6 10 42 0F B6 0C 00");
	FindAddress("C_BaseEntity::EmitSound", "4C 8B DC 49 89 5B 10 49 89 6B 18 57 48 81 EC ? ? ? ? 41 8B D8 48 8B EA 48 8B F9 4D 85 C9 0F 84 ? ? ? ? 41 80 39 00");
	FindAddress("C_BaseEntity::AddFlag", "E8 ? ? ? ? 48 8B 4F 30 48 8B 01 FF 90 ? ? ? ? 48 8B 16");
	FindAddress("CGameEntitySystem::GetBaseEntity", "E8 ? ? ? ? 48 85 C0 74 2E 48 8B 10 48 8B C8 FF 92 ? ? ? ? 84 C0 74 1E 48 8B 05 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 39 58 10 0F 8E ? ? ? ? 8D 53 01 EB 76");
	FindAddress("CGameEntitySystem::GetHighestEntityIndex", "E8 ? ? ? ? 8B 08 FF C1 3B D9 0F 8C ? ? ? ? 48 8B BC 24 ? ? ? ?");
	FindAddress("cl_showents", "40 53 48 81 EC ? ? ? ? 48 8B 0D ? ? ? ? 48 8D 94 24 ? ? ? ? 33 DB E8 ? ? ? ? 8B 08");
	FindAddress("C_BaseEntity::GetAbsOrigin", "E8 ? ? ? ? F3 0F 10 13 F3 0F 10 5B ? F2 0F 10 08 8B 40 08 F3 0F 5C D1 0F 28 C1 89 44 24 28");
	FindAddress("NDebugOverlay::Sphere", "48 8B C4 48 89 58 18 55 56 57 48 8D 68 D8 48 81 EC ? ? ? ? 48 8B D9 44 0F 29 48 ? 48 8B 0D ? ? ? ? 41 8B F9 41 8B F0");
	FindAddress("CGameEntitySystem::FindEntityByClassname", "E8 ? ? ? ? 4C 8B F8 41 B8 ? ? ? ? 48 85 C0 0F 85 ? ? ? ? 4C 8B 74 24 ? 4C 8B 6C 24 ? 4C 8B 64 24 ?");
	FindAddress("IGameSystem::Add", "40 57 48 81 EC ? ? ? ? 48 8B F9 48 8D 94 24 ? ? ? ? 4C 8B C1 48 8D 0D ? ? ? ? FF 15 ? ? ? ? 0F B7 84 24 ? ? ? ? B9 ? ? ? ? 66 3B C1 75 05 B8 ? ? ? ?");
	FindAddress("CSource1GameConfiguration::InitGameSession", "48 83 EC 28 E8 ? ? ? ? 84 C0 75 05 48 83 C4 28 C3");
	FindAddress("UI_PopupManager::ShowPopup", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 20 65 48 8B 04 25 ? ? ? ? 48 8B F9 44 8B 05 ? ? ? ? 4C 8B FA");
	FindAddress("GetClientVersionForGCMessage", "48 8B 0D ? ? ? ? 48 8B 01 48 FF A0 58 02 00 00");
	FindAddress("CMsgStartFindingMatch::Clear", "48 83 EC 28 48 89 6C 24 ? 33 ED 48 89 74 24 ? 8B 71 10 48 89 7C 24 ? 48 8B F9");
	FindAddress("C_BaseEntity::OnDataChanged", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 01 8B F2 48 8B D9 FF 90 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B F8");
	FindAddress("MainViewOrigin", "E8 ? ? ? ? 8B CB F2 0F 10 00 F2 0F 11 06 8B 40 08 89 46 08 E8 ? ? ? ? 4C 8D 4E 24 8B D3");
	FindAddress("MainViewAngles", "E8 ? ? ? ? 4C 8D 4E 24 8B D3 4C 8D 46 18 48 8B CF F2 0F 10 00 F2 0F 11 46 ? 8B 40 08");
	FindAddress("ReadSteamRemoteStorageFile", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 33 FF 48 8B F2 F7 41 ? ? ? ? ? 48 8B D9 48 89 79 10");
	FindAddress("UI_Popup_Generic::SetDisplayTwoOptions", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 54 41 56 41 57 48 83 EC 50 48 8B 84 24 ? ? ? ? 4C 8B FA 33 D2 4C 89 4C 24 ?");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");

}


