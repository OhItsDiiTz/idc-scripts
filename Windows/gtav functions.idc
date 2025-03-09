#include <idc/idc.idc>

/*

this script is incomplete, only did a few things inside of it just to get some stuff done quickly, will be adding more in the future

script is being made for a build of gta from sept 9th of 2020, but most sigs are checked to see if they work with more newer builds of gta.

*/


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

static resolve_network_event(event) {
	if(event == "SCRIPT_ARRAY_DATA_VERIFY_EVENT") return "CScriptArrayDataVerifyEvent::EventHandler";
	if(event == "REQUEST_CONTROL_EVENT") return "CRequestControlEvent::EventHandler";
	if(event == "GIVE_CONTROL_EVENT") return "CGiveControlEvent::EventHandler";
	if(event == "WEAPON_DAMAGE_EVENT") return "CWeaponDamageEvent::EventHandler";
	if(event == "REQUEST_PICKUP_EVENT") return "CRequestPickupEvent::EventHandler";
	if(event == "REQUEST_MAP_PICKUP_EVENT") return "CRequestMapPickupEvent::EventHandler";
	if(event == "GAME_CLOCK_EVENT") return "CGameClockEvent::EventHandler";
	if(event == "GAME_WEATHER_EVENT") return "CGameWeatherEvent::EventHandler";
	if(event == "RESPAWN_PLAYER_PED_EVENT") return "CRespawnPlayerPedEvent::EventHandler";
	if(event == "GIVE_WEAPON_EVENT") return "CGiveWeaponEvent::EventHandler";
	if(event == "REMOVE_WEAPON_EVENT") return "CRemoveWeaponEvent::EventHandler";
	if(event == "REMOVE_ALL_WEAPONS_EVENT") return "CRemoveAllWeaponsEvent::EventHandler";
	if(event == "VEHICLE_COMPONENT_CONTROL_EVENT") return "CVehicleComponentControlEvent::EventHandler";
	if(event == "FIRE_EVENT") return "CFireEvent::EventHandler";
	if(event == "EXPLOSION_EVENT") return "CExplosionEvent::EventHandler";
	if(event == "START_PROJECTILE_EVENT") return "CStartProjectileEvent::EventHandler";
	if(event == "UPDATE_PROJECTILE_TARGET_EVENT") return "CUpdateProjectileTargetEntity::EventHandler";
	if(event == "BREAK_PROJECTILE_TARGET_LOCK_EVENT") return "CBreakProjectileTargetLock::EventHandler";
	if(event == "REMOVE_PROJECTILE_ENTITY_EVENT") return "CRemoveProjectileEntity::EventHandler";
	if(event == "ALTER_WANTED_LEVEL_EVENT") return "CAlterWantedLevelEvent::EventHandler";
	if(event == "CHANGE_RADIO_STATION_EVENT") return "CChangeRadioStationEvent::EventHandler";
	if(event == "RAGDOLL_REQUEST_EVENT") return "CRagdollRequestEvent::EventHandler";
	if(event == "PLAYER_TAUNT_EVENT") return "CPlayerTauntEvent::EventHandler";
	if(event == "PLAYER_CARD_STAT_EVENT") return "CPlayerCardStatEvent::EventHandler";
	if(event == "DOOR_BREAK_EVENT") return "CDoorBreakEvent::EventHandler";
	if(event == "SCRIPTED_GAME_EVENT") return "CScriptedGameEvent::EventHandler";
	if(event == "REMOTE_SCRIPT_INFO_EVENT") return "CRemoteScriptInfoEvent::EventHandler";
	if(event == "REMOTE_SCRIPT_LEAVE_EVENT") return "CRemoteScriptLeaveEvent::EventHandler";
	if(event == "MARK_AS_NO_LONGER_NEEDED_EVENT") return "CMarkAsNoLongerNeededEvent::EventHandler";
	if(event == "CONVERT_TO_SCRIPT_ENTITY_EVENT") return "CConvertToScriptEntityEvent::EventHandler";
	if(event == "SCRIPT_WORLD_STATE_EVENT") return "CScriptWorldStateEvent::EventHandler";
	if(event == "INCIDENT_ENTITY_EVENT") return "CIncidentEntityEvent::EventHandler";
	if(event == "CLEAR_AREA_EVENT") return "CClearAreaEvent::EventHandler";
	if(event == "CLEAR_RECTANGLE_AREA_EVENT") return "CClearRectangleAreaEvent::EventHandler";
	if(event == "NETWORK_REQUEST_SYNCED_SCENE_EVENT") return "CRequestNetworkSyncedSceneEvent::EventHandler";
	if(event == "NETWORK_START_SYNCED_SCENE_EVENT") return "CStartNetworkSyncedSceneEvent::EventHandler";
	if(event == "NETWORK_UPDATE_SYNCED_SCENE_EVENT") return "CUpdateNetworkSyncedSceneEvent::EventHandler";
	if(event == "NETWORK_STOP_SYNCED_SCENE_EVENT") return "CStopNetworkSyncedSceneEvent::EventHandler";
	if(event == "GIVE_PED_SCRIPTED_TASK_EVENT") return "CGivePedScriptedTaskEvent::EventHandler";
	if(event == "GIVE_PED_SEQUENCE_TASK_EVENT") return "CGivePedSequenceTaskEvent::EventHandler";
	if(event == "NETWORK_CLEAR_PED_TASKS_EVENT") return "CClearPedTasksEvent::EventHandler";
	if(event == "NETWORK_START_PED_ARREST_EVENT") return "CStartNetworkPedArrestEvent::EventHandler";
	if(event == "NETWORK_START_PED_UNCUFF_EVENT") return "CStartNetworkPedUncuffEvent::EventHandler";
	if(event == "NETWORK_SOUND_CAR_HORN_EVENT") return "CCarHornEvent::EventHandler";
	if(event == "NETWORK_ENTITY_AREA_STATUS_EVENT") return "CEntityAreaStatusEvent::EventHandler";
	if(event == "NETWORK_GARAGE_OCCUPIED_STATUS_EVENT") return "CGarageOccupiedStatusEvent::EventHandler";
	if(event == "PED_CONVERSATION_LINE_EVENT") return "CPedConversationLineEvent::EventHandler";
	if(event == "SCRIPT_ENTITY_STATE_CHANGE_EVENT") return "CScriptEntityStateChangeEvent::EventHandler";
	if(event == "NETWORK_PLAY_SOUND_EVENT") return "CPlaySoundEvent::EventHandler";
	if(event == "NETWORK_STOP_SOUND_EVENT") return "CStopSoundEvent::EventHandler";
	if(event == "NETWORK_PLAY_AIRDEFENSE_FIRE_EVENT") return "CPlayAirDefenseFireEvent::EventHandler";
	if(event == "NETWORK_BANK_REQUEST_EVENT") return "CAudioBankRequestEvent::EventHandler";
	if(event == "NETWORK_AUDIO_BARK_EVENT") return "CAudioBarkingEvent::EventHandler";
	if(event == "REQUEST_DOOR_EVENT") return "CRequestDoorEvent::EventHandler";
	if(event == "NETWORK_TRAIN_REQUEST_EVENT") return "CNetworkTrainRequestEvent::EventHandler";
	if(event == "NETWORK_TRAIN_REPORT_EVENT") return "CNetworkTrainReportEvent::EventHandler";
	if(event == "NETWORK_INCREMENT_STAT_EVENT") return "CNetworkIncrementStatEvent::EventHandler";
	if(event == "MODIFY_VEHICLE_LOCK_WORD_STATE_DATA") return "CModifyVehicleLockWorldStateDataEvent::EventHandler";
	if(event == "MODIFY_PTFX_WORD_STATE_DATA_SCRIPTED_EVOLVE_EVENT") return "CModifyPtFXWorldStateDataScriptedEvolveEvent::EventHandler";
	if(event == "REQUEST_PHONE_EXPLOSION_EVENT") return "CRequestPhoneExplosionEvent::EventHandler";
	if(event == "REQUEST_DETACHMENT_EVENT") return "CRequestDetachmentEvent::EventHandler";
	if(event == "KICK_VOTES_EVENT") return "CSendKickVotesEvent::EventHandler";
	if(event == "GIVE_PICKUP_REWARDS_EVENT") return "CGivePickupRewardsEvent::EventHandler";
	if(event == "NETWORK_CRC_HASH_CHECK_EVENT") return "CNetworkCrcHashCheckEvent::EventHandler";
	if(event == "BLOW_UP_VEHICLE_EVENT") return "CBlowUpVehicleEvent::EventHandler";
	if(event == "NETWORK_SPECIAL_FIRE_EQUIPPED_WEAPON") return "CNetworkSpecialFireEquippedWeaponEvent::EventHandler";
	if(event == "NETWORK_RESPONDED_TO_THREAT_EVENT") return "CNetworkRespondedToThreatEvent::EventHandler";
	if(event == "NETWORK_SHOUT_TARGET_POSITION") return "CNetworkShoutTargetPositionEvent::EventHandler";
	if(event == "VOICE_DRIVEN_MOUTH_MOVEMENT_FINISHED_EVENT") return "CVoiceDrivenMouthMovementFinishedEvent::EventHandler";
	if(event == "PICKUP_DESTROYED_EVENT") return "CPickupDestroyedEvent::EventHandler";
	if(event == "UPDATE_PLAYER_SCARS_EVENT") return "CUpdatePlayerScarsEvent::EventHandler";
	if(event == "NETWORK_CHECK_EXE_SIZE_EVENT") return "CNetworkCheckExeSizeEvent::EventHandler";
	if(event == "NETWORK_PTFX_EVENT") return "CNetworkPtFXEvent::EventHandler";
	if(event == "NETWORK_PED_SEEN_DEAD_PED_EVENT") return "CNetworkPedSeenDeadPedEvent::EventHandler";
	if(event == "REMOVE_STICKY_BOMB_EVENT") return "CRemoveStickyBombEvent::EventHandler";
	if(event == "NETWORK_CHECK_CODE_CRCS_EVENT") return "CNetworkInfoChangeEvent::EventHandler";
	if(event == "INFORM_SILENCED_GUNSHOT_EVENT") return "CInformSilencedGunShotEvent::EventHandler";
	if(event == "PED_PLAY_PAIN_EVENT") return "CPedPlayPainEvent::EventHandler";
	if(event == "CACHE_PLAYER_HEAD_BLEND_DATA_EVENT") return "CCachePlayerHeadBlendDataEvent::EventHandler";
	if(event == "REMOVE_PED_FROM_PEDGROUP_EVENT") return "CRemovePedFromPedGroupEvent::EventHandler";
	if(event == "REPORT_MYSELF_EVENT") return "CUpdateFxnEvent::EventHandler";
	if(event == "REPORT_CASH_SPAWN_EVENT") return "CReportCashSpawnEvent::EventHandler";
	if(event == "ACTIVATE_VEHICLE_SPECIAL_ABILITY_EVENT") return "CActivateVehicleSpecialAbilityEvent::EventHandler";
	if(event == "BLOCK_WEAPON_SELECTION") return "CBlockWeaponSelectionEvent::EventHandler";
	if(event == "NETWORK_CHECK_CATALOG_CRC") return "CNetworkCheckCatalogCrc::EventHandler";
	if(event == "OBJECT_ID_FREED_EVENT") return "rage::objectIdFreedEvent::EventHandler";
	if(event == "OBJECT_ID_REQUEST_EVENT") return "rage::objectIdRequestEvent::EventHandler";
	if(event == "ARRAY_DATA_VERIFY_EVENT") return "rage::arrayDataVerifyEvent::EventHandler";
	return sprintf("EVENT_%s", event);
}

static resolve_game_presence(str) {
	if(str == "StatUpdate") return "s_CStatUpdatePresenceEventInst";
	if(str == "FriendCrewJoined") return "s_CFriendCrewJoinedPresenceEventInst";
	if(str == "FriendCreatedCrew") return "s_CFriendCrewCreatedPresenceEventInst";
	if(str == "mission_verified") return "s_CMissionVerifiedPresenceEventInst";
	if(str == "rockstar_message") return "s_CRockstarMsgPresenceEventInst";
	if(str == "crew_message") return "s_CRockstarCrewMsgPresenceEventInst";
	if(str == "game_award") return "s_CGameAwardPresenceEventInst";
	if(str == "vinv") return "s_CVoiceSessionInviteInst";
	if(str == "vres") return "s_CVoiceSessionResponseInst";
	if(str == "ginv") return "s_CGameInviteInst";
	if(str == "ginvc") return "s_CGameInviteCancelInst";
	if(str == "grep") return "s_CGameInviteReplyInst";
	if(str == "tinv") return "s_CTournamentInviteInst";
	if(str == "finv") return "s_CFollowInviteInst";
	if(str == "ainv") return "s_CAdminInviteInst";
	if(str == "jreq") return "s_CJoinQueueRequestInst";
	if(str == "jqup") return "s_CJoinQueueUpdateInst";
	if(str == "news") return "s_CNewsItemPresenceEventInst";
	if(str == "finger") return "s_CFingerOfGodPresenceEventInst";
	if(str == "ForceSessionUpdate") return "s_CForceSessionUpdatePresenceEventInst";
	if(str == "gtri") return "s_CGameTriggerEventInst";
	if(str == "TextMessage") return "s_CTextMessageEventInst";
	if(str == "gs_award") return "s_GameServerPresenceEventInst";
	return sprintf("s_GamePresence_%s", str);
}

static resolve_draw_commands(id) {
	if(id == 181) return "dlCmdRenderPhasesDrawInit::ExecuteStatic";
	if(id == 217) return "OcclusionQueries::dlCmdBoxOcclusionQueries::ExecuteStatic";
	if(id == 218) return "OcclusionQueries::dlCmdBoxConditionalQueries::ExecuteStatic";
	if(id == 183) return "dlCmdPlantMgrRender::ExecuteStatic";
	if(id == 184) return "dlCmdPlantMgrRenderDecal::ExecuteStatic";
	if(id == 225) return "dlCmdDistantCarsRender::ExecuteStatic";
	if(id == 185) return "dlCmdPlantMgrShadowRender::ExecuteStatic";
	if(id == 200) return "dlCmdRopeShadowRender::ExecuteStatic";
	if(id == 213) return "dlCmdParticleShadowRender::ExecuteStatic";
	if(id == 214) return "dlCmdParticleShadowRenderAllCascades::ExecuteStatic";
	if(id == 195) return "dlCmdDebug2dStaticRender::ExecuteStatic";
	if(id == 193) return "dlCmdDebug3dStaticRender::ExecuteStatic";
	if(id == 196) return "dlCmdDebugRenderReleaseInfo::ExecuteStatic";
	if(id == 192) return "dlCmdProcessNonDepthFX::ExecuteStatic";
	if(id == 208) return "dlCmdSetupLightsFrameInfo::ExecuteStatic";
	if(id == 209) return "dlCmdClearLightsFrameInfo::ExecuteStatic";
	if(id == 220) return "dlCmdLightOverride::ExecuteStatic";
	if(id == 187) return "dlCmdWaterRender::ExecuteStatic";
	if(id == 128) return "CDrawEntityDC::ExecuteStatic";
	if(id == 129) return "CDrawEntityFmDC::ExecuteStatic";
	if(id == 227) return "CDrawEntityInstancedDC::ExecuteStatic";
	if(id == 228) return "CDrawGrassBatchDC::ExecuteStatic";
	if(id == 130) return "CDrawSkinnedEntityDC::ExecuteStatic";
	if(id == 131) return "CDrawPedBIGDC::ExecuteStatic";
	if(id == 132) return "CDrawStreamPedDC::ExecuteStatic";
	if(id == 133) return "CDrawDetachedPedPropDC::ExecuteStatic";
	if(id == 204) return "CDrawVehicleVariationDC::ExecuteStatic";
	if(id == 134) return "CDrawFragDC::ExecuteStatic";
	if(id == 135) return "CDrawFragTypeDC::ExecuteStatic";
	if(id == 136) return "CDrawPrototypeBatchDC::ExecuteStatic";
	if(id == 137) return "CCustomShaderEffectDC::ExecuteStatic";
	if(id == 202) return "dlCmdBeginOcclusionQuery::ExecuteStatic";
	if(id == 203) return "dlCmdEndOcclusionQuery::ExecuteStatic";
	if(id == 197) return "dlCmdAddSkeleton::ExecuteStatic";
	if(id == 198) return "dlCmdAddCompositeSkeleton::ExecuteStatic";
	if(id == 199) return "dlCmdDrawTwoSidedDrawable::ExecuteStatic";
	if(id == 138) return "CMiniMap_UpdateBlips::ExecuteStatic";
	if(id == 142) return "CMiniMap_ResetBlipConeFlags::ExecuteStatic";
	if(id == 143) return "CMiniMap_RemoveUnusedBlipConesFromStage::ExecuteStatic";
	if(id == 144) return "CMiniMap_RenderBlipCone::ExecuteStatic";
	if(id == 141) return "CMiniMap_AddSonarBlipToStage::ExecuteStatic";
	if(id == 140) return "CMiniMap_RenderState_Setup::ExecuteStatic";
	if(id == 145) return "CDrawSpriteDC::ExecuteStatic";
	if(id == 146) return "CDrawSpriteUVDC::ExecuteStatic";
	if(id == 229) return "CDrawUIWorldIcon::ExecuteStatic";
	if(id == 147) return "CDrawRectDC::ExecuteStatic";
	if(id == 153) return "CDrawRadioHudTextDC::ExecuteStatic";
	if(id == 154) return "CRenderTextDC::ExecuteStatic";
	if(id == 174) return "CDrawPtxEffectInst::ExecuteStatic";
	if(id == 175) return "CDrawVehicleGlassComponent::ExecuteStatic";
	if(id == 177) return "CSetDrawableLODCalcPos::ExecuteStatic";
	if(id == 178) return "CDrawBreakableGlassDC::ExecuteStatic";
	if(id == 211) return "dlCmdOverrideSkeleton::ExecuteStatic";
	if(id == 212) return "CSetDrawableStatContext::ExecuteStatic";
	if(id == 221) return "dlCmdRenderPedDamageSet::ExecuteStatic";
	if(id == 222) return "dlCmdRenderPedCompressedDamageSet::ExecuteStatic";
	if(id == 179) return "dlCmdBeginRender::ExecuteStatic";
	if(id == 189) return "dlCmdEndRender::ExecuteStatic";
	if(id == 210) return "dlCmdDrawGlowQuads::ExecuteStatic";
	if(id == 234) return "dlCmdDrawFullScreenGlowQuads::ExecuteStatic";
	if(id == 226) return "dlCmdDrawScriptIM::ExecuteStatic";
	if(id == 223) return "dlCmdSetupCoronasFrameInfo::ExecuteStatic";
	if(id == 224) return "dlCmdClearCoronasFrameInfo::ExecuteStatic";
	if(id == 230) return "dlCmdSetupFogVolumesFrameInfo::ExecuteStatic";
	if(id == 231) return "dlCmdClearFogVolumesFrameInfo::ExecuteStatic";
	if(id == 215) return "dlCmdSetupLODLightsFrameInfo::ExecuteStatic";
	if(id == 216) return "dlCmdClearLODLightsFrameInfo::ExecuteStatic";
	if(id == 232) return "dlCmdSetupVfxLightningFrameInfo::ExecuteStatic";
	if(id == 233) return "dlCmdClearVfxLightningFrameInfo::ExecuteStatic";
	if(id == 78) return "dlCmdSetGPUDropRenderSettings::ExecuteStatic";
	if(id == 206) return "dlCmdSetupTimeCycleFrameInfo::ExecuteStatic";
	if(id == 207) return "dlCmdClearTimeCycleFrameInfo::ExecuteStatic";
	if(id == 1) return "rage::dlCmdNewDrawList::ExecuteStatic";
	if(id == 2) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 6) return "rage::dlComputeShaderBatch::ExecuteStatic";
	if(id == 3) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 4) return "rage::dlCmdBeginDraw::ExecuteStatic";
	if(id == 5) return "rage::dlCmdEndDraw::ExecuteStatic";
	if(id == 7) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 8) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 30) return "rage::dlCmdLockRenderTarget::ExecuteStatic";
	if(id == 31) return "rage::dlCmdUnLockRenderTarget::ExecuteStatic";
	if(id == 90) return "rage::dlCmdSetRasterizerState::ExecuteStatic";
	if(id == 91) return "rage::dlCmdSetDepthStencilState::ExecuteStatic";
	if(id == 92) return "rage::dlCmdSetDepthStencilStateEx::ExecuteStatic";
	if(id == 93) return "rage::dlCmdSetBlendState::ExecuteStatic";
	if(id == 94) return "rage::dlCmdSetBlendStateEx::ExecuteStatic";
	if(id == 95) return "rage::dlCmdSetStates::ExecuteStatic";
	if(id == 96) return "rage::dlCmdSetStatesEx::ExecuteStatic";
	if(id == 33) return "rage::dlCmdSetCurrentViewport::ExecuteStatic";
	if(id == 34) return "rage::dlCmdClearRenderTarget::ExecuteStatic";
	if(id == 35) return "rage::dlCmdSetClipPlane::ExecuteStatic";
	if(id == 36) return "rage::dlCmdSetClipPlaneEnable::ExecuteStatic";
	if(id == 37) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 40) return "rage::dlCmdGrcLightStateSetEnabled::ExecuteStatic";
	if(id == 41) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 42) return "rage::dlCmdSetCurrentViewportToNULL::ExecuteStatic";
	if(id == 60) return "rage::dlCmdAddDrawListMarker::ExecuteStatic";
	if(id == 26) return "rage::dlCmdDrawTriShape::ExecuteStatic";
	if(id == 61) return "rage::dlCmdPushTimebar::ExecuteStatic";
	if(id == 62) return "rage::dlCmdPopTimebar::ExecuteStatic";
	if(id == 63) return "rage::dlCmdPushGPUTimebar::ExecuteStatic";
	if(id == 64) return "rage::dlCmdPopGPUTimebar::ExecuteStatic";
	if(id == 65) return "rage::dlCmdEntityGPUTimePush::ExecuteStatic";
	if(id == 66) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 67) return "rage::dlCmdEntityGPUTimeFlush::ExecuteStatic";
	if(id == 68) return "rage::dlCmdPushMarker::ExecuteStatic";
	if(id == 69) return "rage::dlCmdPopMarker::ExecuteStatic";
	if(id == 75) return "rage::dlCmdSetGeometryVertexOffsets::ExecuteStatic";
	if(id == 77) return "rage::dlCmdSetBucketsAndRenderMode::ExecuteStatic";
	if(id == 127) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 80) return "rage::dlCmdSwitchPage::ExecuteStatic";
	if(id == 81) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 82) return "audVehicleAudioEntity::TriggerEngineFailedToStart";
	if(id == 17) return "rage::dlCmdShaderFxPushForcedTechnique::ExecuteStatic";
	if(id == 18) return "rage::dlCmdShaderFxPopForcedTechnique::ExecuteStatic";
	if(id == 123) return "rage::dlCmdBeginConditionalRender::ExecuteStatic";
	if(id == 124) return "rage::dlCmdEndConditionalRender::ExecuteStatic";
	if(id == 125) return "rage::dlCmdSetArrayView::ExecuteStatic";
	if(id == 50) return "rage::dlCmdCallBackNoArg::ExecuteStatic";
	if(id == 51) return "rage::dlCmdGenericArgBase::ExecuteStatic";
	if(id == 10) return "rage::dlCmdSetGlobalVar_F::ExecuteStatic";
	if(id == 11) return "rage::dlCmdSetGlobalVar_V4::ExecuteStatic";
	if(id == 12) return "rage::dlCmdSetGlobalVar_M44::ExecuteStatic";
	if(id == 13) return "rage::dlCmdSetGlobalVar_RT::ExecuteStatic";
	if(id == 14) return "rage::dlCmdSetGlobalVarArrayFloat::ExecuteStatic";
	if(id == 19) return "rage::dlCmdSetGlobalVarArrayV4::ExecuteStatic";
	if(id == 43) return "rage::dlCmdGrcDeviceSetScissor::ExecuteStatic";
	if(id == 44) return "rage::dlCmdGrcDeviceDisableScissor::ExecuteStatic";
	if(id == 45) return "rage::dlCmdGrcDeviceLockOrUnlockContext::ExecuteStatic";
	if(id == 46) return "rage::dlCmdGrcDeviceUpdateBuffer::ExecuteStatic";
	return sprintf("draw_id_%i", id);
}

static resolve_ptx_behaviour_functions(str) {
	if(str == "ptxu_Decal") return "??$PlaceBehaviour@Vptxu_Decal@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_DecalPool") return "??$PlaceBehaviour@Vptxu_DecalPool@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_FogVolume") return "??$PlaceBehaviour@Vptxu_FogVolume@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Light") return "??$PlaceBehaviour@Vptxu_Light@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Liquid") return "??$PlaceBehaviour@Vptxu_Liquid@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_River") return "??$PlaceBehaviour@Vptxu_River@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_ZCull") return "??$PlaceBehaviour@Vptxu_ZCull@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Acceleration") return "??$PlaceBehaviour@Vptxu_Acceleration@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Age") return "??$PlaceBehaviour@Vptxu_Age@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_AnimateTexture") return "??$PlaceBehaviour@Vptxu_AnimateTexture@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Attractor") return "??$PlaceBehaviour@Vptxu_Attractor@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Collision") return "??$PlaceBehaviour@Vptxu_Collision@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Colour") return "??$PlaceBehaviour@Vptxu_Colour@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Dampening") return "??$PlaceBehaviour@Vptxu_Dampening@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_MatrixWeight") return "??$PlaceBehaviour@Vptxu_MatrixWeight@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Noise") return "??$PlaceBehaviour@Vptxu_Noise@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Pause") return "??$PlaceBehaviour@Vptxu_Pause@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Rotation") return "??$PlaceBehaviour@Vptxu_Rotation@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Size") return "??$PlaceBehaviour@Vptxu_Size@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Velocity") return "??$PlaceBehaviour@Vptxu_Velocity@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxu_Wind") return "??$PlaceBehaviour@Vptxu_Wind@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxd_Sprite") return "??$PlaceBehaviour@Vptxd_Sprite@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxd_Model") return "??$PlaceBehaviour@Vptxd_Model@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	if(str == "ptxd_Trail") return "??$PlaceBehaviour@Vptxd_Trail@rage@@@ptxManager@rage@@SAXPEAVptxBehaviour@1@AEAVdatResource@1@@Z";
	return sprintf("ptxd_behaviour_%s", str);
}

//network events
static NameNetworkEvents() {
	auto register_event = FindBinary(get_imagebase(), SEARCH_DOWN, "66 83 FA 5B 73 13 0F B7 C2 4C 89 84 C1 ? ? ? ? 4C 89 8C C1 ? ? ? ? C3");
    if(register_event != -1) {
        MakeName(register_event, "rage::netEventMgr::RegisterNetworkEvent");
    }
    else {
        Message("rage::netEventMgr::RegisterNetworkEvent was not found, signature is out dated!\n");
    }
    
    auto cur = get_first_cref_to(register_event);
    while(cur != -1) {
        
        auto r8 = get_operand_value(FindBinary(cur, SEARCH_UP, "4C 8D 05"), 1);
        auto r9 = GetString(get_operand_value(FindBinary(cur, SEARCH_UP, "4C 8D 0D"), 1), -1, 0);
        MakeName(r8, resolve_network_event(r9));
		Message("%s named at 0x%X!\n", resolve_network_event(r9), r8);
        cur = get_next_cref_to(register_event, cur);
    }
	Message("Network Events Done!\n");
}

//misc functions from ida
static NameFunctions() {
	//variables
	FindAddress("CPedFactory::ms_pInstance", "48 8B 05 ? ? ? ? 44 8B C2 89 94 24 ? ? ? ? 48 8B 48 08 BB ? ? ? ? 48 85 C9 74 33 0F 28 89 ? ? ? ? 0F 5C 0D ? ? ? ? 0F 59 C9 66 0F 70 C1 ? 66 0F 70 D1 ? 66 0F 70 C9 ? 0F 58 C8");
	FindAddress("lastFrameCheatDone", "8B 05 ? ? ? ? 39 05 ? ? ? ? 74 35 48 8D 15 ? ? ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8D 4C 24 ? 41 B8 ? ? ? ? F3 0F 10 0D ? ? ? ? E8 ? ? ? ? 8B 05 ? ? ? ? 89 05 ? ? ? ?");
	
	//functions
	FindAddress("FindPlayerPed", "E8 ? ? ? ? C6 44 24 ? ? 40 88 7C 24 ? 0F 57 F6 4C 8B 00 C6 44 24 ? ? 48 8D 55 D7 0F 28 D6 45 33 C9");
	FindAddress("FindPlayerVehicle", "48 83 EC 28 48 85 C9 75 0D E8 ? ? ? ? 48 8B C8 48 85 C0 74 07 48 8B 81 ? ? ? ? 48 85 C0 74 17 8B 88 ? ? ? ?");
	FindAddress("CBootupScreen::GetEventButtonText", "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 40 8A F9 E8 ? ? ? ? 83 78 38 FF 0F 84 ? ? ? ? E8 ? ? ? ? 8B 58 38 E8 ? ? ? ? 4C 8D 44 24 ? 48 8B C8");
	FindAddress("SocialClubEventMgr::Get", "E8 ? ? ? ? 48 8B D3 48 8B C8 E8 ? ? ? ? 8B C7 87 05 ? ? ? ? 48 8B 1D ? ? ? ? 89 3D ? ? ? ? E8 ? ? ? ? 66 C7 43 ? ? ? 89 7B 10 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B 01 FF 50 10 48 8B 0D ? ? ? ?");
	FindAddress("GetDamageZoneFromBoneTag", "BA ? ? ? ? 81 F9 ? ? ? ? 0F 8F ? ? ? ? 81 F9 ? ? ? ? 0F 8D ? ? ? ? B8 ? ? ? ? 3B C8 0F 8F ? ? ? ? 0F 84 ? ? ? ? 81 F9 ? ? ? ? 7F 73 81 F9 ? ? ? ? 7D 64");
	FindAddress("InitWinSock", "48 81 EC ? ? ? ? 8B 05 ? ? ? ? 8B C8 FF C0 89 05 ? ? ? ? 85 C9 75 2B FF 15 ? ? ? ? 48 8D 54 24 ?");
	FindAddress("rage::netEventMgr::RegisterNetworkEvent", "66 83 FA 5B 73 13 0F B7 C2 4C 89 84 C1 ? ? ? ? 4C 89 8C C1 ? ? ? ? C3");
	FindAddress("CGameWorld::GetMainPlayerInfo", "48 8B 05 ? ? ? ? 48 8B 48 08 33 C0 48 85 C9 74 07 48 8B 81 ? ? ? ? C3");
	
	//CNetwork
	FindAddress("CNetwork::GetSocketPort", "E8 ? ? ? ? 44 0F B7 C0 41 8B D0 41 8B C0 44 89 43 08 C1 EA 18 C1 E8 10 32 D0 41 8B C0 C1 E8 08 32 D0");
	FindAddress("CNetwork::GetGoStraightToMPEvent", "E8 ? ? ? ? 84 C0 74 49 BA ? ? ? ? 4C 8D 05 ? ? ? ? 8D 4A E1 E8 ? ? ? ? 40 84 FF 74 17");
	FindAddress("CNetwork::GetGoStraightToMultiplayer", "E8 ? ? ? ? 84 C0 74 1A 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? B9 ? ? ? ?");
	FindAddress("CNetwork::SetGoStraightToMPEvent", "E8 ? ? ? ? 33 C9 E8 ? ? ? ? C6 05 ? ? ? ? ? E8 ? ? ? ? 40 8A 78 34 E8 ? ? ? ? 83 78 38 FF");
	FindAddress("CNetwork::SetGoStraightToMPRandomJob", "E8 ? ? ? ? C6 05 ? ? ? ? ? E8 ? ? ? ? 40 8A 78 34 E8 ? ? ? ? 83 78 38 FF 0F 95 C3 E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 8A 05 ? ? ? ? 4C 8D 05 ? ? ? ? F6 D8 1B D2 33 C9");
	
	//CWanted
	FindAddress("CWanted::CheatWantedLevel", "83 FA 05 0F 8F ? ? ? ? 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 50 33 FF 8B DA 48 8B F1 85 D2 75 35 48 8B 91 ? ? ? ? 48 85 D2 74 29");
	FindAddress("CWanted::CopsCommentOnSwat", "E8 ? ? ? ? 8B 83 ? ? ? ? 3B F8 0F 84 ? ? ? ? 7E 4D 44 89 BB ? ? ? ? 85 C0 75 42");
	FindAddress("CWanted::PassengersCommentOnPolice", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B 35 ? ? ? ? 48 8B F9 8B C6 2B 81 ? ? ? ? 3D ? ? ? ?");
	FindAddress("CWanted::ReportPoliceSpottingPlayer", "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 41 56 48 81 EC ? ? ? ? 48 8B FA 8B 91 ? ? ? ? 41 8B F1 4D 8B F0 48 8B D9");
	FindAddress("CWanted::SetMaximumWantedLevel", "45 33 C0 85 C9 0F 84 ? ? ? ? FF C9 0F 84 ? ? ? ? FF C9 74 7F FF C9 74 57 FF C9 74 2F FF C9 0F 85 ? ? ? ?");
	FindAddress("CWanted::SetWantedLevel", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 40 44 8B B4 24 ? ? ? ? 33 F6 45 8B F9 41 8B F8 4C 8B EA 48 8B D9 45 85 C0");
	FindAddress("CWanted::Update", "48 8B C4 48 89 58 08 48 89 50 10 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 A9 48 81 EC ? ? ? ? F3 0F 10 0D ? ? ? ? 4C 8B B9 ? ? ? ?");
	FindAddress("CWanted::UpdateWantedLevel", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 30 8B 05 ? ? ? ? 8B B9 ? ? ? ? 41 8A F1");
	
	//NetworkBaseConfig
	FindAddress("NetworkBaseConfig::Init", "40 53 48 83 EC 20 48 8B D9 E8 ? ? ? ? 44 0F B7 C0 41 8B D0 41 8B C0 44 89 43 08 C1 EA 18 C1 E8 10 32 D0 41 8B C0 C1 E8 08 32 D0 41 32 D0 88 53 0C E8 ? ? ? ? 81 63 ? ? ? ? ? 83 E0 0F B1 01 C1 E0 08 09 43 0C E8 ? ? ? ? 81 63 ? ? ? ? ? C1 E0 12 09 43 0C 48 83 C4 20 5B C3");
	FindAddress("NetworkBaseConfig::GetMatchmakingVersion", "E8 ? ? ? ? 81 63 ? ? ? ? ? 83 E0 0F B1 01 C1 E0 08 09 43 0C");
	FindAddress("NetworkBaseConfig::GetMatchmakingUser", "E8 ? ? ? ? 81 63 ? ? ? ? ? C1 E0 12 09 43 0C 48 83 C4 20 5B C3");
	
	//CCheat
	FindAddress("CCheat::WeaponCheat1", "48 83 EC 48 E8 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 80 3D ? ? ? ? ? 74 4E E8 ? ? ? ? 48 83 64 24 ? ? 83 64 24 ? ? 80 64 24 ? ? 48 8D 0D ? ? ? ?");
	FindAddress("CCheat::HealthCheat", "48 83 EC 58 0F 29 74 24 ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ?");
	FindAddress("CCheat::IncrementTimesCheatedStat", "48 83 EC 28 E8 ? ? ? ? 48 85 C0 74 04 48 8B 40 20 48 85 C0 74 43 8B 05 ? ? ? ? 39 05 ? ? ? ?");
	
	//StatsInterface
	FindAddress("StatsInterface::GetStatsModelHashId", "E8 ? ? ? ? 48 8D 4C 24 ? 41 B8 ? ? ? ? F3 0F 10 0D ? ? ? ? E8 ? ? ? ? 8B 05 ? ? ? ? 89 05 ? ? ? ? 48 83 C4 28");
	FindAddress("StatsInterface::IncrementStat", "E8 ? ? ? ? 8B 05 ? ? ? ? 89 05 ? ? ? ? 48 83 C4 28 C3");
	
	//CPed
	FindAddress("CPed::SwitchToRagdoll", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 70 48 8B 02 48 8B F1 48 8B CA 48 8B DA FF 90 ? ? ? ? 84 C0");
	FindAddress("CPed::SetHeadBlendPaletteColor", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 40 48 8B 41 20 41 8A F9 41 8A F0");
	FindAddress("CPed::SetArmour", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8D 99 ? ? ? ? 0F 29 74 24 ?");
	FindAddress("CPed::IsFirstPersonShooterModeEnabledForPlayer", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 83 B9 ? ? ? ? ? 41 8A F1");
	FindAddress("CPed::HasHeadBlend", "48 83 EC 28 48 8B 41 20 F6 80 ? ? ? ? ? 75 04 32 C0 EB 15");
	FindAddress("CPed::GetIsDrivingVehicle", "8B 81 ? ? ? ? 48 8B D1 C1 E8 1E A8 01 74 19 48 8B 89 ? ? ? ? 48 85 C9 74 0D");
	FindAddress("CPed::GetBoneTagFromRagdollComponent", "48 89 5C 24 ? 57 48 83 EC 20 48 8B F9 33 DB E8 ? ? ? ? 83 F8 FF 7E 0C 8B D0");
	FindAddress("CPed::GetBonePositionVec3V", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 60 48 8B 01 41 8B E8 48 8B F2 48 8B F9 33 DB");
	FindAddress("CPed::GetBoneIndexFromRagdollComponent", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 99 ? ? ? ? 83 CE FF 33 FF");
	FindAddress("CPed::ClearDamageAndScars", "40 53 48 83 EC 20 8A 91 ? ? ? ? 48 8B D9 80 FA FF 0F 84 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 8A 93 ? ? ? ? 48 8B 0D ? ? ? ?");
	FindAddress("CPed::CalcRagdollStackKey", "E8 ? ? ? ? 41 B8 ? ? ? ? 48 8B CB 8B D0 E8 ? ? ? ? 44 8B F0 39 44 24 20 7D 44");
	FindAddress("CPed::SetMyVehicle", "48 89 5C 24 ? 57 48 83 EC 20 48 8D B9 ? ? ? ? 48 8B DA 48 39 17 74 19 0F BA B1 ? ? ? ? ? 8B 81 ? ? ? ?");
	FindAddress("CPed::SetPedInVehicle", "48 8B C4 44 89 48 20 44 89 40 18 48 89 50 10 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 83 BA ? ? ? ? ? 0F 29 70 A8 45 8B E9 41 8B F8 4C 8B F2 48 8B F1 41 BC ? ? ? ? 75 0B");
	
	//CNetObjPlayer
	FindAddress("CNetObjPlayer::CalcStatValue", "48 8B C4 48 89 58 08 48 89 68 10 56 57 41 56 48 83 EC 40 41 8B D9 41 8B F8 48 8B F2 0F 29 70 D8 4C 8B F1 45 33 C9 44 8B C3");
	FindAddress("CNetObjPlayer::ConvertEntityTargetPosToWeaponRangePos", "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 60 20 55 41 56 41 57 48 8B EC 48 81 EC ? ? ? ? 48 8B 79 50 45 33 E4 49 8B D8");
	FindAddress("CNetObjPlayer::DoOnscreenVisibilityTest", "48 8B C4 48 89 58 08 48 89 78 10 4C 89 70 18 4C 89 78 20 55 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70 E8 0F 29 78 D8 44 0F 29 40 ? 8B 81 ? ? ? ? 45 33 FF 48 8B F9 85 C0 74 24");
	FindAddress("CNetObjPlayer::SanityCheckVisibility", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B 79 50 48 8B D9 48 85 FF 0F 84 ? ? ? ? 40 8A B1 ? ? ? ? BA ? ? ? ? 48 8B CF 40 C0 EE 05");
	FindAddress("CNetObjPlayer::ShouldFixAndDisableCollisionDueToControls", "48 83 EC 28 80 79 4B 00 74 32 4C 8B 41 50 49 8B 80 ? ? ? ? 48 85 C0 74 22 8B 90 ? ? ? ? C1 EA 05 F6 C2 01 74 14 41 F6 40 ? ? 75 0D");
	FindAddress("CNetObjPlayer::ShouldOverrideBlenderForSecondaryAnim", "40 53 48 83 EC 30 33 D2 38 51 4B 0F 84 ? ? ? ? 39 91 ? ? ? ? 0F 84 ? ? ? ? 39 91 ? ? ? ? 0F 84 ? ? ? ? 8B 81 ? ? ? ?");
	FindAddress("CNetObjPlayer::TargetCloningInformation::Clear", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 F3 0F 10 15 ? ? ? ? F3 0F 10 0D ? ? ? ? F3 0F 10 05 ? ? ? ? 48 8D 79 40 48 8B D9 33 F6 F3 0F 11 41 ? F3 0F 11 49 ?");
	FindAddress("CNetObjPlayer::Update", "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 79 50 45 33 FF 48 8B D9");
	FindAddress("CNetObjPlayer::UpdateAnimVehicleStreamingTarget", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 79 50 83 89 ? ? ? ? ? 33 F6 48 8B D9 66 89 B1 ? ? ? ? 48 85 FF 74 5F 8A 87 ? ? ? ? A8 01");
	FindAddress("CNetObjPlayer::UpdateCloneStandingOnObjectStreamIn", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 33 F6 48 8B D9 40 38 71 4B 0F 84 ? ? ? ? 48 39 71 50 0F 84 ? ? ? ? 48 8B 01");
	FindAddress("CNetObjPlayer::UpdateLocalWantedSystemFromRemoteVisibility", "48 83 EC 48 44 8A 89 ? ? ? ? 4C 8B D1 41 F6 C1 40 0F 84 ? ? ? ? B8 ? ? ? ? F7 25 ? ? ? ? C1 EA 04 6B D2 1E 39 15 ? ? ? ?");
	FindAddress("CNetObjPlayer::UpdateLookAt", "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 70 20 55 48 8D 68 A1 48 81 EC ? ? ? ? 48 8B 71 50");
	FindAddress("CNetObjPlayer::UpdateNonPhysicalPlayerData", "48 89 5C 24 ? 57 48 83 EC 20 80 79 4B 00 48 8B D9 75 64 E8 ? ? ? ? 48 8B F8 48 85 C0");
	FindAddress("CNetObjPlayer::UpdatePendingCameraData", "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8B EC 48 83 EC 70 F6 81 ? ? ? ? ? 48 8B D9 0F 84 ? ? ? ? E8 ? ? ? ? 48 85 C0");
	FindAddress("CNetObjPlayer::UpdatePendingTargetData", "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 55 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 8A 81 ? ? ? ? 48 8B F9");
	FindAddress("CNetObjPlayer::UpdateRemotePlayerAppearance", "48 89 5C 24 ? 57 48 83 EC 20 48 8B 79 50 48 8B D9 48 85 FF 74 58 48 83 BF ? ? ? ? ? 74 4E E8 ? ? ? ? 48 85 C0");
	FindAddress("CNetObjPlayer::UpdateRemotePlayerFade", "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 57 48 83 EC 30 80 79 4B 00 48 8B 79 50 48 8B D9");
	FindAddress("CNetObjPlayer::UpdateSecondaryPartialAnimTask", "48 8B C4 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 8A 91 ? ? ? ?");
	FindAddress("CNetObjPlayer::UpdateStats", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 20 45 33 ED 48 8B F1 44 38 69 4B");
	FindAddress("CNetObjPlayer::UpdateTargettedEntityPosition", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 40 48 8B 71 50 48 8D B9 ? ? ? ? 48 8B D9 48 8B 0F 33 ED");
	FindAddress("CNetObjPlayer::UpdateVehicleWantedDirtyState", "48 83 EC 68 4C 8B 49 50 48 8B D1 33 C9 4D 85 C9 0F 84 ? ? ? ? 41 8B 81 ? ? ? ? 44 8D 59 01 C1 E8 1E");
	FindAddress("CNetObjPlayer::UpdateWeaponAimPosition", "48 8B C4 48 89 58 08 48 89 70 10 57 48 83 EC 70 48 8B 79 50 0F 29 70 E8 0F 29 78 D8 33 F6 48 8B D9 44 0F 29 40 ? 44 0F 29 48 ?");
	FindAddress("CNetObjPlayer::UpdateWeaponTarget", "E8 ? ? ? ? F6 83 ? ? ? ? ? 74 08 0F BA AF ? ? ? ? ? 48 8B 8B ? ? ? ? 48 85 C9 74 45 44 84 B3 ? ? ? ? 75 3C 0F 28 89 ? ? ? ? 0F 28 81 ? ? ? ? 48 8D 55 F7 0F 29 4D 07 0F 28 8B ? ? ? ?");
	
	//CMiniMap_RenderThread
	FindAddress("CMiniMap_RenderThread::AddHigherLowerBlip", "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8D 6C 24 ? 48 81 EC ? ? ? ? 83 3D ? ? ? ? ? 41 8B F0 48 8B DA");
	FindAddress("CMiniMap_RenderThread::CheckForHeight", "40 53 48 83 EC 30 0F 29 74 24 ? 48 8B D9 48 85 C9 74 6F F3 0F 10 35 ? ? ? ? BA ? ? ? ? E8 ? ? ? ? 84 C0 75 23");
	FindAddress("CMiniMap_RenderThread::ColourBlipOnStage", "48 8B C4 48 89 58 08 48 89 70 10 55 57 41 55 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 83 3D ? ? ? ? ? 0F 29 70 D8 48 8B F2 48 8B F9 0F 84 ? ? ? ? 48 85 D2");
	FindAddress("CMiniMap_RenderThread::GetBlipScalerValue", "48 83 EC 38 0F 29 74 24 ? F3 0F 10 35 ? ? ? ? 84 D2 74 15 8A 41 5C D0 E8 2C 07 A8 FB");
	FindAddress("CMiniMap_RenderThread::NumberBlipOnStage", "48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8B EC 48 83 EC 70 48 8B D9 48 85 C9 0F 84 ? ? ? ? 8B 41 08 24 8F 3C 08");
	FindAddress("CMiniMap_RenderThread::PulseBlipOnStage", "48 85 D2 0F 84 ? ? ? ? 53 48 83 EC 50 48 8B D9 48 85 C9 0F 84 ? ? ? ? 8B 41 08 24 8F 3C 08 0F 85 ? ? ? ? 48 8B 51 10");
	FindAddress("CMiniMap_RenderThread::UpdateCrewIndicatorOnBlipOnStage", "E8 ? ? ? ? 41 8B C7 C1 E8 0D A8 01 74 0B 48 8B D7 48 8B CE");
	FindAddress("CMiniMap_RenderThread::UpdateFriendIndicatorOnBlipOnStage", "E8 ? ? ? ? 41 8B C7 C1 E8 11 A8 01 74 0B 48 8B D7 48 8B CE E8 ? ? ? ?");
	FindAddress("CMiniMap_RenderThread::UpdateHeadingIndicatorOnBlipOnStage", "48 85 D2 0F 84 ? ? ? ? 48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 70 20 55 48 8D 68 98 48 81 EC ? ? ? ? 0F 29 70 E8 45 8B F0 48 8B FA");
	FindAddress("CMiniMap_RenderThread::UpdateOutlineIndicatorOnBlipOnStage", "E8 ? ? ? ? 41 8B C7 C1 E8 10 A8 01 74 0B 48 8B D7 48 8B CE E8 ? ? ? ?");
	FindAddress("CMiniMap_RenderThread::UpdateTickBlipOnStage", "E8 ? ? ? ? 41 8B C7 C1 E8 0E A8 01 74 0B 48 8B D7 48 8B CE E8 ? ? ? ?");
	
	//CPauseMenu
	FindAddress("CPauseMenu::CheckIncomingFunctions", "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 55 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 45 33 F6");
	FindAddress("CPauseMenu::CheckWhatToDoWhenClosed", "E8 ? ? ? ? C7 05 ? ? ? ? ? ? ? ? C6 05 ? ? ? ? ? C6 05 ? ? ? ? ? 48 83 C4 28 C3");
	FindAddress("CPauseMenu::Close", "40 55 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 85 C0 74 6D");
	FindAddress("CPauseMenu::CloseInternal", "E8 ? ? ? ? 33 C9 E8 ? ? ? ? E8 ? ? ? ? 33 D2 33 C9 E8 ? ? ? ?");
	FindAddress("CPauseMenu::CloseInternal2", "48 83 EC 28 80 3D ? ? ? ? ? 74 0C 48 8B 0D ? ? ? ? E8 ? ? ? ? 33 C9 C7 44 24 ? ? ? ? ? E8 ? ? ? ?");
	FindAddress("CPauseMenu::EnterSocialClub", "E8 ? ? ? ? 44 89 67 28 41 8A C6 E9 ? ? ? ?");
	FindAddress("CPauseMenu::IsActive", "48 89 5C 24 ? 57 48 83 EC 20 80 3D ? ? ? ? ? 8B F9 75 0D 80 3D ? ? ? ? ? 75 04");
	FindAddress("CPauseMenu::LayoutChanged", "48 8B C4 48 89 58 18 89 50 10 89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 A9 48 81 EC ? ? ? ?");
	FindAddress("CPauseMenu::PlayInputSound", "40 55 53 48 8B EC 48 83 EC 48 8B D9 83 F9 0A 0F 8F ? ? ? ? 83 F9 09 0F 8D ? ? ? ? 85 C9 0F 88 ? ? ? ?");
	FindAddress("CPauseMenu::TogglePauseRenderPhases", "48 83 EC 28 45 33 D2 44 8A C1 44 38 15 ? ? ? ? 74 74 4C 39 15 ? ? ? ? 74 6B 44 8B CA 81 FA ? ? ? ?");
	
	//CPedIntelligence
	FindAddress("CPedIntelligence::AddEvent", "E8 ? ? ? ? 48 8D 4D B0 48 85 C0 48 89 7D B0 0F 95 C3 E8 ? ? ? ? EB 57");
	FindAddress("CPedIntelligence::FindTaskByType", "48 89 5C 24 ? 57 48 83 EC 20 48 8B F9 48 8B 89 ? ? ? ? 41 B8 ? ? ? ? 8B DA E8 ? ? ? ? 48 85 C0 75 7B 48 8B 8F ? ? ? ?");
	FindAddress("CPedIntelligence::FlushEvents", "40 53 48 83 EC 20 48 8B D9 48 81 C1 ? ? ? ? 48 8B 01 FF 50 10 48 8D 8B ? ? ? ? 48 83 C4 20 5B E9 ? ? ? ?");
	FindAddress("CPedIntelligence::FlushImmediately", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 81 ? ? ? ? 45 8A F9 45 8A E0 80 88 ? ? ? ? ? 44 8A EA");
	
	//CSubmarineHandling
	FindAddress("CSubmarineHandling::ComputeTimeForNextImplosionEvent", "48 89 5C 24 ? 57 48 83 EC 20 8B 1D ? ? ? ? 48 8B F9 E8 ? ? ? ? 0F B7 D0 66 0F 6E C2 0F 5B C0 F3 0F 59 05 ? ? ? ?");
	FindAddress("CSubmarineHandling::DisplayCrushDepthMessages", "48 89 5C 24 ? 57 48 83 EC 50 48 8B FA 48 8B D9 E8 ? ? ? ? 0F 2F 83 ? ? ? ? 73 09 48 8D 15 ? ? ? ? EB 38");
	FindAddress("CSubmarineHandling::GetCurrentDepth", "48 8B C4 48 83 EC 58 0F 28 82 ? ? ? ? 48 83 60 ? ? 48 83 60 ? ? F3 0F 10 1D ? ? ? ? 0F 29 40 E8 0F 57 C9 F3 0F 10 05 ? ? ? ? 48 8D 8A ? ? ? ?");
	FindAddress("CSubmarineHandling::Implode", "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 57 48 81 EC ? ? ? ? 0F 29 70 E8 0F 29 78 D8 41 8A F0 48 8B DA 48 8B F9 44 0F 29 40 ? E8 ? ? ? ? 0F 2F 87 ? ? ? ?");
	FindAddress("CSubmarineHandling::ProcessCrushDepth", "48 89 5C 24 ? 57 48 83 EC 20 48 8B FA 48 8B D9 E8 ? ? ? ? F3 0F 10 4B ? F3 0F 5C 0D ? ? ? ? 0F 2F C1 73 05 F3 0F 11 43 ?");
	FindAddress("CSubmarineHandling::ProcessDepthLimit", "40 53 48 83 EC 40 0F 28 8A ? ? ? ? 0F 29 74 24 ? F3 0F 10 35 ? ? ? ? 48 8B DA 0F 28 C1 0F C6 C1 AA 0F 2F C6 73 7F");
	
	
	FindAddress("rage::fwEntity::InitTransformFromDefinition", "48 8B C4 48 89 58 10 48 89 70 18 55 57 41 56 48 8D 68 D8 48 81 EC ?? ?? ?? ?? 0F 29 70 D8 0F 29 78 C8 44 0F 29 40 ?? 48 8B DA 32 D2 48 8B F1 44 0F 29 48 ?? 49 8B 40 58 48 85 C0 74 09");
	FindAddress("rage::fwEntity::InitExtensionsFromDefinition", "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 56 41 57 48 83 EC 20 45 33 E4 45 8B F9 48 8B FA 48 8B E9 41 8B DC 66 44 3B 62 ?? 73 60");
	FindAddress("CEntity::InitEntityFromDefinition", "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 57 48 83 EC 20 49 8B F0 48 8B FA 48 8B D9 E8 ?? ?? ?? ?? 44 8B 4F 0C 41 0F BA E1 ?? 73 08 0F BA B3 ?? ?? ?? ?? ?? 41 0F BA E1 ??");
	FindAddress("CPed::SetModelId", "48 89 5C 24 ?? 57 48 83 EC 20 66 81 3A ?? ?? 48 8B DA 48 8B F9 0F 84 ?? ?? ?? ?? 48 8B CA E8 ?? ?? ?? ?? 44 8B 0B 48 8D 54 24 ?? 66 89 44 24 ?? 8B 44 24 38 45 8B C1");
	FindAddress("rage::fwEntity::GetGlobalMtx", "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 48 8B 01 49 8B F0 8B EA 48 8B F9 FF 50 58 33 DB 48 85 C0 74 18");
	FindAddress("", "");
	FindAddress("", "");
	
	
	Message("Misc Functions Done!\n");
}

//native functions
static NativeFunctions() {
	//need to finish
	
}

//GameSkeleton callback functions
static GameSeletonCallbackFunctions() {
	
}

static GamePresenceEventStructs() {
	auto event_func = FindBinary(get_imagebase(), SEARCH_DOWN, "40 53 48 83 EC 20 8B 05 ? ? ? ? 33 DB A8 01 75 3D");
	if(event_func != -1) {
		auto GamePresenceEvent = FindBinary(event_func, SEARCH_DOWN, "E8 ? ? ? ? 8B 05 ? ? ? ? A8 02 75 59");
		if(GamePresenceEvent != -1) {
			auto func = decode_insn(GamePresenceEvent).Op0.addr;
			//MakeName(func, "CGamePresenceEventDispatcher::RegisterEvent");
			auto cur = get_first_cref_to(func);
			while(cur != -1) {
				
				auto r8 = get_operand_value(FindBinary(cur, SEARCH_UP, "4C 8D 05"), 1);
				auto rdx = GetString(get_operand_value(FindBinary(cur, SEARCH_UP, "48 8D 15"), 1), -1, 0);
				MakeName(r8, resolve_game_presence(rdx));
				Message("%s named at 0x%X!\n", resolve_game_presence(rdx), r8);
				cur = get_next_cref_to(func, cur);
			}
			Message("GamePresenceEventStructs Done!\n");
		}
	}
}

//RegisterSceneUpdate functions
static RegisterSceneUpdateFunctions() {
	
}

//draw command functions
static DrawCommandFunctions() {
	auto func = FindBinary(get_imagebase(), SEARCH_DOWN, "48 63 C2 4C 89 44 C1 ? C3");
	if(func != -1) {
		MakeName(func, "rage::dlDrawCommandBuffer::RegisterCommand");
		auto cur = get_first_cref_to(func);
		while(cur != -1) {
			
			auto edx = get_operand_value(FindBinary(cur, SEARCH_UP, "BA ? ? ? ?"), 1);
			auto r8 = decode_insn(FindBinary(cur, SEARCH_UP, "4C 8D 05")).Op1.addr;
			//Message("if(insn == \"%i\") return \"%s\";\n", edx, get_func_off_str(r8));
			MakeName(r8, resolve_draw_commands(edx));
			cur = get_next_cref_to(func, cur);
		}
	}
}

static PtxBehaviourFunctions() {
	auto func = FindBinary(get_imagebase(), SEARCH_DOWN, "48 8B C4 4C 89 48 20 4C 89 40 18 48 89 50 10 53 56 57 48 83 EC 20 48 8D B1 ? ? ? ?");
	if(func != -1) {
		MakeName(func, "rage::ptxManager::RegisterBehaviour");
		auto cur = get_first_cref_to(func);
		while(cur != -1) {
			auto rdx = decode_insn(FindBinary(cur, SEARCH_UP, "48 8D 15")).Op1.addr;
			auto r9 = decode_insn(FindBinary(cur, SEARCH_UP, "4C 8D 0D")).Op1.addr;
			//Message("if(str == \"%s\") return \"%s\";\n", GetString(rdx, -1, 0), GetFunctionName(r9));
			Message("0x%X - %s\n", r9, resolve_ptx_behaviour_functions(GetString(rdx, -1, 0)));
			MakeName(r9, resolve_ptx_behaviour_functions(GetString(rdx, -1, 0)));
			cur = get_next_cref_to(func, cur);
		}
	}
}

static main(void) {
	NameNetworkEvents();
	NameFunctions();
	NativeFunctions();
	GameSeletonCallbackFunctions();
	GamePresenceEventStructs();
	RegisterSceneUpdateFunctions();
	DrawCommandFunctions();
	PtxBehaviourFunctions();
}

