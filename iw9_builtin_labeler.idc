#include <idc/idc.idc>
//this could change in the future

static resolve(hash) {
    
	if(hash == 0xE170DE7C1E9A3DDE) return "GScr_GetDvar";
	if(hash == 0xFBDB5FD2AC2902F) return "GScr_GetDvarInt";
	if(hash == 0xAB10A695B43FC2B4) return "GScr_GetDvarFloat";
	if(hash == 0xF54D1AAD9E652735) return "GScr_GetDvarVector";
	if(hash == 0xF3C26D3E51ABB52C) return "ScrCmd_SetSlowMotion";
	if(hash == 0x8CAEC943F9B91CB4) return "ScrCmd_SetThirdPersonCamVehicle";
	if(hash == 0x161AC8F19725E406) return "PlayerCmd_SetSuit";
	if(hash == 0x209934EB42F1E1B0) return "GScr_TeleportWorldUpReferenceAngles";
	if(hash == 0x23DFCEBDC04B68F1) return "GScr_StartAC130";
	if(hash == 0x1921FD97E5663AE3) return "GScr_StopAC130";
	if(hash == 0x781859B0776375B1) return "GScr_EmissiveBlend";
	if(hash == 0xBD8324262B651D7E) return "GScr_SetMiniMap";
	if(hash == 0x9A71A972D2912E4A) return "GScr_ViewKick";
	if(hash == 0x9F346919D86CFB0E) return "GScr_BRMatchStarted";
	if(hash == 0x4351D0A15B2E02E7) return "GScr_SortByDistance";
	if(hash == 0xC84955F6378CCA4) return "GScr_IncrementPersistentStat";
	if(hash == 0x2BFB04C093125E04) return "GScr_GetOmnvar";
	if(hash == 0x1C542EB7ACBD2FB8) return "GScr_Turret_FireEnable";
	if(hash == 0xF11A7F097572F54C) return "GScr_SpawnBrCircle";
	if(hash == 0xF9DC057C609A5954) return "GScr_GetBuildNumber";
	if(hash == 0x5C65B7A7F92DA697) return "GScr_SetUAVJammed";
	if(hash == 0xD0943990D5EEF45C) return "GScr_BBPrint";
	if(hash == 0x420B956C70B8A9B5) return "PlayerCmd_SetClientDvar";
	if(hash == 0xF823637BE61D5E72) return "PlayerCmd_SetClientDvars";
	if(hash == 0xDB073176839D77FB) return "GScr_ReportChallengeUserEvent";
	if(hash == 0x617F7D9B0B9FF8E7) return "GScr_CameraLinkTo";
	if(hash == 0xEE3AE75954C1CE25) return "GScr_Detonate";
	if(hash == 0x1413B6BF238DF91B) return "BGScr_GenerateAxisAnglesFromForwardVector";
	if(hash == 0x6410D7AAAD3C0D81) return "BGScr_GenerateAxisAnglesFromUpVector";
	
    return sprintf("GScr_%X", hash);
}

static main(void) {
    auto start = FindBinary(0, SEARCH_DOWN, "48 89 5C 24 ? 55 48 8B EC 48 83 EC 30 48 8B D9 E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ? E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ? E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ? E8 ? ? ? ? C5 F8 10 05 ? ? ? ? 48 8D 55 F0 48 8B CB C5 F8 11 45 ?");
    auto end = FindBinary(start, SEARCH_DOWN, "48 83 C4 30 5D C3");
    auto ea = start;
    ea = FindBinary(ea, SEARCH_DOWN, "C5 F8 10");
    while(ea < end) {
        auto table = ea + Dword(ea + 4) + 8;
        auto i = 0;
        for(i = 0;i < Dword(table + 8);i++) {
            Message("%s: 0x%X\n", resolve(Qword(Qword(table) + (0x18 * i))), Qword(Qword(table) + (0x18 * i) + 8) - get_imagebase());
            MakeName(Qword(Qword(table) + (0x18 * i) + 8), resolve(Qword(Qword(table) + (0x18 * i))));
        }
        ea = FindBinary(ea + 1, SEARCH_DOWN, "C5 F8 10");
    }
}
