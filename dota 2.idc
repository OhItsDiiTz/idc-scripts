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
	FindAddress("g_pDOTAPlayerResource", "48 8B 0D ? ? ? ? 8B 14 07 89 54 24 58 E8 ? ? ? ? 4C 8D 44 24 ? 89 44 24 50 48 8D 54 24 ?"); //global variable
	FindAddress("gameeventmanager", "48 8B 0D ? ? ? ? 48 8D 15 ? ? ? ? 45 33 C9 45 33 C0 48 8B 01 FF 50 30 48 85 C0 74 11 48 8B 0D ? ? ? ? 48 8B D0 4C 8B 01 41 FF 50 40 44 8B 83 ? ? ? ? 41 83 F8 FD"); //global variable
	FindAddress("engine", "48 8B 0D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 48 8D 94 24 ? ? ? ? 44 8B C3 48 8B 01 FF 90 ? ? ? ? 4C 8B 35 ? ? ? ?"); //global variable
	FindAddress("g_pEntitySystem" /* CEntityHandle::gm_pEntityList */, "4C 8B 1D ? ? ? ? 4C 8D 05 ? ? ? ? 33 C0 49 8B 08 48 85 C9 74 3E 8B 91 ? ? ? ? 83 FA FD 77 33 8B CA"); //global variable
	FindAddress("g_pGameRules", "48 8B 0D ? ? ? ? 0F 29 74 24 ? 0F 57 F6 48 85 C9 74 3D 45 33 C0"); //global variable
	FindAddress("input", "48 8B 0D ? ? ? ? 80 B9 ? ? ? ? ? F2 0F 10 81 ? ? ? ? F2 0F 11 44 24 ? 75 2D F3 0F 10 44 24 ?"); //global variable
	FindAddress("g_ViewRender", "48 8D 0D ? ? ? ? E8 ? ? ? ? 83 7C 24 ? ? 48 C7 C7 ? ? ? ? 0F 84 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 05 ? ? ? ? 4C 8D 45 D0 48 89 45 D0"); //global variable
	FindAddress("view", "48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 89 7C 24 ? 48 8B 01 FF 50 60 0F 2E B3 ? ? ? ? 75 5E E8 ? ? ? ?"); //global variable
	FindAddress("g_pSoundOpSystem", "48 8B 0D ? ? ? ? 48 85 C9 75 0B 89 0B 48 8B C3 48 83 C4 30 5B C3"); //global variable
	FindAddress("g_ClientSteamContext", "48 8D 1D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 1D ? ? ? ? 8D 57 66 48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? FF 15 ? ? ? ? 48 8D 05 ? ? ? ? 40 88 3D ? ? ? ? 48 89 05 ? ? ? ?"); //global variable
	FindAddress("steamapicontext", "48 8B 0D ? ? ? ? 48 8B D0 48 8B 49 10 4C 8B 01 41 FF 50 28 83 F8 03 0F 85 ? ? ? ?"); //global variable
	FindAddress("g_pNetworkMessages", "48 8B 05 ? ? ? ? 48 8B 00 44 8B 05 ? ? ? ? 48 8B 54 24 ? 48 8B 0D ? ? ? ? FF 90 ? ? ? ? 48 8B 44 24 ? 48 83 C4 38 C3"); //global variable
	FindAddress("g_pFlattenedSerializers", "48 8B 0D ? ? ? ? 48 89 44 24 ? 48 8B 01 FF 90 ? ? ? ? 84 C0 0F 94 C0 88 83 ? ? ? ? 48 8B CB"); //global variable
	FindAddress("g_pGameEventSystem", "48 8B 1D ? ? ? ? 48 85 D2 75 48 48 8B 15 ? ? ? ? 48 8B 0D ? ? ? ? 48 85 D2 75 2E 48 8B 01"); //global variable
	FindAddress("gpGlobals", "48 8B 1D ? ? ? ? 4C 8D 25 ? ? ? ? 48 8B 48 10 48 8B 41 20 48 85 C0 4C 0F 45 E0 44 38 73 3D 75 16 44 38 73 3C 75 10 48 8B 43 20 48 85 C0"); //global variable
	FindAddress("dummyvars", "48 8D 0D ? ? ? ? F3 0F 11 05 ? ? ? ? 48 89 0D ? ? ? ? 48 89 41 20 C3"); //global variable
	
	FindAddress("AngleVectors", "E8 ? ? ? ? 4C 8D 7F 08 4C 8D 4D 98 4C 89 7C 24 ? 4C 8D 45 88 48 8D 54 24 ? 48 8D 4D 10 E8 ? ? ? ? 49 8B 06 49 8B CE FF 90 ? ? ? ? 48 8B C8 E8 ? ? ? ?");
	FindAddress("CDOTALobby::DumpToTextBuffer", "48 89 6C 24 ? 56 48 83 EC 60 48 8B 49 18 33 ED 48 8B F2 48 89 6C 24 ? 48 83 C1 08 48 89 6C 24 ?");
	FindAddress("CDOTA_DB_Page_Profile::OnRecentGamesReceived", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 4C 8B F1 48 8D 15 ? ? ? ?");
	FindAddress("CGameEventManager::ConPrintEvent", "48 89 74 24 ? 57 48 83 EC 30 48 8B F2 4C 8D 0D ? ? ? ? 33 FF 4C 8D 05 ? ? ? ? 48 8B CE");
	FindAddress("CGameEventManager::CreateEvent", "44 88 44 24 ? 56 41 54 48 83 EC 58 48 89 6C 24 ? 48 8D B1 ? ? ? ? 48 89 7C 24 ? 41 0F B6 E8 4C 89 6C 24 ?");
	FindAddress("CGameEventManager::FireEvent", "40 53 57 41 54 41 55 41 56 48 83 EC 30 4C 8B F2 4C 8B E1 BA ? ? ? ? 48 8D 0D ? ? ? ? 45 0F B6 E8 E8 ? ? ? ?");
	FindAddress("CGameEventManager::FireEventClientSide", "48 89 5C 24 ? 57 41 54 41 56 48 83 EC 30 4C 8B F2 48 8D 99 ? ? ? ? 4C 8B E1 FF 15 ? ? ? ? 90 33 FF");
	FindAddress("CGameEventManager::HasClientListenersChanged", "80 B9 ? ? ? ? ? 75 03 32 C0 C3 84 D2 74 07 C6 81 ? ? ? ? ? B0 01 C3");
	FindAddress("CGameEventManager::Init", "40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 50 10 48 8B 03 48 8D 15 ? ? ? ? 45 33 C0 48 8B CB FF 50 08");
	FindAddress("CGameEventManager::LoadEventsFromFile", "48 8B C4 55 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 48 89 58 E0 4C 8D B9 ? ? ? ? 4C 89 60 D0");
	FindAddress("CGameEventManager::UpdateListenEventList", "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 8B DA 48 8D 4C 24 ? 33 D2 45 33 C0 E8 ? ? ? ? 48 8B 0D ? ? ? ?");
	FindAddress("CGameEvent::CGameEvent", "48 89 5C 24 ? 57 48 83 EC 20 48 8D 05 ? ? ? ? 48 89 51 08 48 89 01 48 8B D9 B9 ? ? ? ? 49 8B F8 FF 15 ? ? ? ? 48 85 C0");
	FindAddress("CScriptBindingSF_Players::GetGold", "48 89 5C 24 ? 56 48 83 EC 20 8B DA 83 FA 17 77 79 48 8B 35 ? ? ? ? 48 85 F6 74 6D 48 8B CE");
	FindAddress("CSource2Client::GetBugReportInfo", "49 8B C1 4D 8B D0 4C 8B 4C 24 ? 8B CA 4C 8B C0 49 8B D2 E9 ? ? ? ?");
	FindAddress("CSource2Client::PlayerInfoChanged", "48 89 5C 24 ? 57 48 83 EC 60 8B DA 48 8D 4C 24 ? 33 D2 45 33 C0 E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8D 05 ? ? ? ? 48 89 44 24 ? 4C 8D 44 24 ?");
	FindAddress("CSource2Client::UpdateEventListeners", "48 83 EC 28 48 8B 0D ? ? ? ? B2 01 E8 ? ? ? ? 84 C0 74 22 48 89 5C 24 ? 33 DB 0F 1F 00");
	FindAddress("C_BaseEntity::Instance", "E8 ? ? ? ? 48 8B C8 48 85 C0 75 38 8B 0D ? ? ? ? 8D 50 02 FF 15 ? ? ? ? 84 C0");
	FindAddress("C_BasePlayer::GetLocalPlayer", "E8 ? ? ? ? 48 8B F8 48 85 C0 0F 84 ? ? ? ? 0F B7 90 ? ? ? ? 0F B7 4D 38 66 3B CA 66 0F 45 CA 48 8D 90 ? ? ? ? 66 89 4D 38 48 8D 4D 3C");
	FindAddress("C_BasePlayer::HasAnyLocalPlayer", "E8 ? ? ? ? 84 C0 74 71 80 BB ? ? ? ? ? 74 68 48 83 BB ? ? ? ? ? 75 5E 48 8B 43 10 8B 48 30 C1 E9 07 F6 C1 01 75 4F 8B 83 ? ? ? ? 83 F8 FF 74 08");
	FindAddress("C_BasePlayer::IsLocalPlayer", "40 53 48 83 EC 20 48 8B D9 48 85 C9 0F 84 ? ? ? ? 48 8B 01 FF 90 ? ? ? ? 84 C0 74 73 48 8B 03 48 8B CB FF 90 ? ? ? ? 33 C9");
	FindAddress("C_DOTABaseAbility::GetEffectiveLevel", "48 83 EC 28 E8 ? ? ? ? FF C8 48 83 C4 28 C3");
	FindAddress("C_DOTABaseAbility::GetLevel", "E8 ? ? ? ? 85 C0 0F 8E ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CF E8 ? ? ? ? 4C 8B F0 48 85 C0");
	FindAddress("C_DOTABaseAbility::ProcessAbilityData", "4D 85 C0 0F 84 ? ? ? ? 48 8B C4 4C 89 48 20 4C 89 40 18 89 50 10 48 89 48 08 55 56 57 41 55");
	FindAddress("C_DOTA_PlayerResource::GetGoldPerMin", "40 53 48 83 EC 40 48 63 DA 85 D2 0F 88 ? ? ? ? 3B 99 ? ? ? ? 0F 8D ? ? ? ? 48 8B 81 ? ? ? ? 48 69 D3 ? ? ? ? 80 7C 02 ? ? 74 73");
	FindAddress("Cmd_CAM_ToThirdPerson", "48 83 EC 38 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? ? F2 0F 10 81 ? ? ? ? F2 0F 11 44 24 ? 75 2D F3 0F 10 44 24 ? F3 0F 10 4C 24 ? C6 81 ? ? ? ? ?");
	FindAddress("FX_Tracer", "E8 ? ? ? ? 48 8B B4 24 ? ? ? ? 48 8B 9C 24 ? ? ? ? 0F 28 B4 24 ? ? ? ? 48 81 C4 ? ? ? ? 5F C3");
	FindAddress("GDOTAGCClientSystem", "E8 ? ? ? ? 48 8D 88 ? ? ? ? E8 ? ? ? ? 48 85 C0 74 2F 48 8B 40 18 80 B8 ? ? ? ? ? 74 0D 83 B8 ? ? ? ? ? 0F 84 ? ? ? ?");
	FindAddress("GetClientBugReportInfo", "48 89 5C 24 ? 57 48 83 EC 20 49 8B F9 48 8B DA 85 C9 74 0D 32 C0 48 8B 5C 24 ? 48 83 C4 20 5F C3");
	FindAddress("GetTracerOrigin", "48 89 5C 24 ? 56 48 81 EC ? ? ? ? F2 0F 10 42 ? 48 8B DA F2 0F 11 01 48 8B F1 8B 42 1C 89 41 08 F6 42 63 02 0F 84 ? ? ? ? 8B 52 38");
	FindAddress("GetViewEffects", "48 89 5C 24 ? 57 48 83 EC 20 65 48 8B 04 25 ? ? ? ? 8B D9 8B 0D ? ? ? ? 33 FF 41 B8 ? ? ? ? 48 8B 14 C8 41 8B 04 10 39 05 ? ? ? ?");
	FindAddress("GetViewRenderInstance", "E8 ? ? ? ? 0F B6 95 ? ? ? ? 48 8B C8 48 8B F8 E8 ? ? ? ? 0F B6 95 ? ? ? ? 48 8B CF 66 0F 6E F8 0F 5B FF F3 0F 11 BD ? ? ? ?");
	FindAddress("PlayUISoundScript", "40 53 48 83 EC 30 48 8B D9 48 8B 0D ? ? ? ? 48 85 C9 75 0B 89 0B 48 8B C3 48 83 C4 30 5B C3");
	FindAddress("TracerCallback", "40 57 48 81 EC ? ? ? ? 48 8B F9 E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ?");
	FindAddress("dota_invite_debug", "48 83 EC 28 48 8B 0D ? ? ? ? 48 85 C9 75 12 48 8D 0D ? ? ? ? 48 83 C4 28 48 FF 25 ? ? ? ? 48 89 5C 24 ? BA ? ? ? ? 48 89 6C 24 ?");
	FindAddress("C_DOTA_PlayerResource::OnPlayerSteamIDsChanged", "48 83 EC 28 48 8B 0D ? ? ? ? 48 8D 15 ? ? ? ? 45 33 C9 45 33 C0 48 8B 01 FF 50 30 48 85 C0 74 11");
	FindAddress("CDOTARichPresence::UpdateLocalRichPresence", "40 55 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 80 79 55 00 48 8B F9 0F 29 B4 24 ? ? ? ? 0F 28 F1 74 0A F2 0F 10 0D ? ? ? ? EB 08");
	FindAddress("C_DOTA_PlayerResource::UpdatePlayerName", "48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 63 DA 48 8B F1 BA ? ? ? ? 48 8D 0D ? ? ? ? 49 8B F8 E8 ? ? ? ? 48 85 C0 75 0B 48 8B 05 ? ? ? ? 48 8B 40 08");
	FindAddress("C_BaseFlex::Connect", "40 53 48 83 EC 30 48 8B D9 E8 ? ? ? ? 48 8B CB E8 ? ? ? ? 84 C0 74 04 B0 01 EB 41 48 8B 43 10 4C 8D 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 08 48 8B 81 ? ? ? ? 48 89 44 24 ? 48 8B 81 ? ? ? ? 48 8B 0D ? ? ? ? 48 89 44 24 ?");
	FindAddress("CEntityInstance::IsAuthoritative", "E8 ? ? ? ? 84 C0 74 04 B0 01 EB 41 48 8B 43 10 4C 8D 05 ? ? ? ? 48 8D 54 24 ? 48 8B 48 08 48 8B 81 ? ? ? ? 48 89 44 24 ? 48 8B 81 ? ? ? ?");
	FindAddress("GDOTADefaultCamera", "48 83 EC 38 E8 ? ? ? ? 48 85 C0 74 4D 48 8B 10 48 8B C8 48 89 5C 24 ? FF 92 ? ? ? ? 48 8B D8 48 85 C0 74 25");
	FindAddress("CDOTA_Camera::MoveToEntity", "48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 57 48 83 EC 60 48 8B F9 48 8B DA 33 C9 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ?");
	FindAddress("C_DOTAPlayer::GetLocalDOTAPlayer", "33 C0 83 F9 FF 0F 44 C8 48 63 C1 48 8D 0D ? ? ? ? 48 8B 04 C1 C3");
	FindAddress("C_DOTAPlayer::GetNumSelectedUnits", "40 53 48 83 EC 20 44 8B 81 ? ? ? ? 48 8D 54 24 ? 48 8B D9 48 8B 0D ? ? ? ? E8 ? ? ? ? 44 8B 00");
	FindAddress("C_DOTAPlayer::GetSelectedUnit", "48 89 5C 24 ? 57 48 83 EC 20 44 8B 81 ? ? ? ? 48 8B F9 48 8B 0D ? ? ? ? 48 63 DA 48 8D 54 24 ? E8 ? ? ? ? 44 8B 00");
	FindAddress("C_DOTABaseAbility::GetCaster", "E8 ? ? ? ? 48 8B CF 0F B6 98 ? ? ? ? E8 ? ? ? ? 41 B9 ? ? ? ? 48 89 44 24 ? 8B D6 89 5C 24 20 48 8B CD 45 8D 41 03 E8 ? ? ? ?");
	FindAddress("", "");
	FindAddress("", "");
	FindAddress("", "");
}
