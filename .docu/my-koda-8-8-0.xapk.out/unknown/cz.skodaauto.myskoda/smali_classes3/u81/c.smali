.class public final Lu81/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

.field public final d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

.field public final e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

.field public final f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

.field public final g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

.field public final h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

.field public final i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

.field public final j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;


# direct methods
.method public synthetic constructor <init>()V
    .locals 74

    .line 12
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    const/16 v8, 0x7f

    const/4 v9, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;-><init>(IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILkotlin/jvm/internal/g;)V

    .line 13
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    const/16 v9, 0x7f

    const/4 v10, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    invoke-direct/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;-><init>(IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILkotlin/jvm/internal/g;)V

    .line 14
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    const/4 v2, 0x3

    const/4 v4, 0x0

    invoke-direct {v3, v4, v4, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;ILkotlin/jvm/internal/g;)V

    .line 15
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    const/4 v6, 0x1

    invoke-direct {v2, v5, v6, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;-><init>(ZILkotlin/jvm/internal/g;)V

    .line 16
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    const/16 v14, 0x3f

    const/4 v15, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-object v7, v6

    invoke-direct/range {v7 .. v15}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;-><init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILkotlin/jvm/internal/g;)V

    .line 17
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    const v72, 0x7fffffff

    const/16 v73, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const/16 v45, 0x0

    const/16 v46, 0x0

    const/16 v47, 0x0

    const/16 v48, 0x0

    const/16 v49, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const/16 v52, 0x0

    const/16 v53, 0x0

    const/16 v54, 0x0

    const/16 v55, 0x0

    const/16 v56, 0x0

    const/16 v57, 0x0

    const/16 v58, 0x0

    const/16 v59, 0x0

    const/16 v60, 0x0

    const/16 v61, 0x0

    const/16 v62, 0x0

    const/16 v63, 0x0

    const/16 v64, 0x0

    const/16 v65, 0x0

    const/16 v66, 0x0

    const/16 v67, 0x0

    const/16 v68, 0x0

    const/16 v69, 0x0

    const/16 v70, 0x0

    const/16 v71, -0x1

    invoke-direct/range {v7 .. v73}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;-><init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryLastMovePPE;IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIILkotlin/jvm/internal/g;)V

    .line 18
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    const/16 v14, 0x1f

    const/4 v15, 0x0

    invoke-direct/range {v8 .. v15}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;IIIILkotlin/jvm/internal/g;)V

    .line 19
    new-instance v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    const/16 v23, 0x1fff

    const/16 v24, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    invoke-direct/range {v9 .. v24}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;ILkotlin/jvm/internal/g;)V

    .line 20
    new-instance v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    const/16 v19, 0xff

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    invoke-direct/range {v10 .. v20}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;-><init>(IIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/AvailableScenarioPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TPAStatusPPE;ZILjava/lang/String;ILkotlin/jvm/internal/g;)V

    const/4 v5, 0x0

    move-object v4, v2

    move-object v2, v1

    move-object v1, v0

    move-object/from16 v0, p0

    .line 21
    invoke-direct/range {v0 .. v10}, Lu81/c;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 3
    iput-object p2, p0, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 4
    iput-object p3, p0, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 5
    iput-object p4, p0, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 6
    iput-object p5, p0, Lu81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 7
    iput-object p6, p0, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 8
    iput-object p7, p0, Lu81/c;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 9
    iput-object p8, p0, Lu81/c;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 10
    iput-object p9, p0, Lu81/c;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 11
    iput-object p10, p0, Lu81/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    return-void
.end method

.method public static a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;
    .locals 11

    .line 1
    move/from16 v0, p10

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 8
    .line 9
    :cond_0
    move-object v1, p1

    .line 10
    and-int/lit8 p1, v0, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p2, p0, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 15
    .line 16
    :cond_1
    move-object v2, p2

    .line 17
    and-int/lit8 p1, v0, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-object p3, p0, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 22
    .line 23
    :cond_2
    move-object v3, p3

    .line 24
    and-int/lit8 p1, v0, 0x8

    .line 25
    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    iget-object p4, p0, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 29
    .line 30
    :cond_3
    move-object v4, p4

    .line 31
    and-int/lit8 p1, v0, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget-object p1, p0, Lu81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 36
    .line 37
    move-object v5, p1

    .line 38
    goto :goto_0

    .line 39
    :cond_4
    move-object/from16 v5, p5

    .line 40
    .line 41
    :goto_0
    and-int/lit8 p1, v0, 0x20

    .line 42
    .line 43
    if-eqz p1, :cond_5

    .line 44
    .line 45
    iget-object p1, p0, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 46
    .line 47
    move-object v6, p1

    .line 48
    goto :goto_1

    .line 49
    :cond_5
    move-object/from16 v6, p6

    .line 50
    .line 51
    :goto_1
    and-int/lit8 p1, v0, 0x40

    .line 52
    .line 53
    if-eqz p1, :cond_6

    .line 54
    .line 55
    iget-object p1, p0, Lu81/c;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 56
    .line 57
    move-object v7, p1

    .line 58
    goto :goto_2

    .line 59
    :cond_6
    move-object/from16 v7, p7

    .line 60
    .line 61
    :goto_2
    and-int/lit16 p1, v0, 0x80

    .line 62
    .line 63
    if-eqz p1, :cond_7

    .line 64
    .line 65
    iget-object p1, p0, Lu81/c;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 66
    .line 67
    move-object v8, p1

    .line 68
    goto :goto_3

    .line 69
    :cond_7
    move-object/from16 v8, p8

    .line 70
    .line 71
    :goto_3
    and-int/lit16 p1, v0, 0x100

    .line 72
    .line 73
    if-eqz p1, :cond_8

    .line 74
    .line 75
    iget-object p1, p0, Lu81/c;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 76
    .line 77
    move-object v9, p1

    .line 78
    goto :goto_4

    .line 79
    :cond_8
    move-object/from16 v9, p9

    .line 80
    .line 81
    :goto_4
    iget-object v10, p0, Lu81/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 82
    .line 83
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    const-string p0, "currentP2CHighPrio"

    .line 87
    .line 88
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    const-string p0, "latestSentP2CHighPrio"

    .line 92
    .line 93
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    const-string p0, "latestSentP2CNormalPrio"

    .line 97
    .line 98
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string p0, "latestSentP2CComfortCommands"

    .line 102
    .line 103
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    const-string p0, "latestReceivedC2PHighPrio"

    .line 107
    .line 108
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    const-string p0, "latestReceivedC2PNormalPrioTrajectoryInfo"

    .line 112
    .line 113
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    const-string p0, "latestReceivedC2PNormalPrioTrajectoryMetadata"

    .line 117
    .line 118
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    const-string p0, "latestReceivedC2PNormalPrioManeuver"

    .line 122
    .line 123
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const-string p0, "latestReceivedC2PTPAParkingSpaceInfo"

    .line 127
    .line 128
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    new-instance v0, Lu81/c;

    .line 132
    .line 133
    invoke-direct/range {v0 .. v10}, Lu81/c;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;)V

    .line 134
    .line 135
    .line 136
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lu81/c;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lu81/c;

    .line 12
    .line 13
    iget-object v1, p0, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 14
    .line 15
    iget-object v3, p1, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 25
    .line 26
    iget-object v3, p1, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 36
    .line 37
    iget-object v3, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 47
    .line 48
    iget-object v3, p1, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lu81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 58
    .line 59
    iget-object v3, p1, Lu81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 69
    .line 70
    iget-object v3, p1, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lu81/c;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 80
    .line 81
    iget-object v3, p1, Lu81/c;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Lu81/c;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 91
    .line 92
    iget-object v3, p1, Lu81/c;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lu81/c;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 102
    .line 103
    iget-object v3, p1, Lu81/c;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object p0, p0, Lu81/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 113
    .line 114
    iget-object p1, p1, Lu81/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 115
    .line 116
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    if-nez p0, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 10
    .line 11
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object v0, p0, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 19
    .line 20
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v1

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object v1, p0, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 28
    .line 29
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    add-int/2addr v1, v0

    .line 34
    mul-int/lit8 v1, v1, 0x1f

    .line 35
    .line 36
    iget-object v0, p0, Lu81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 37
    .line 38
    if-nez v0, :cond_0

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    :goto_0
    add-int/2addr v1, v0

    .line 47
    mul-int/lit8 v1, v1, 0x1f

    .line 48
    .line 49
    iget-object v0, p0, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 50
    .line 51
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    add-int/2addr v0, v1

    .line 56
    mul-int/lit8 v0, v0, 0x1f

    .line 57
    .line 58
    iget-object v1, p0, Lu81/c;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 59
    .line 60
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    add-int/2addr v1, v0

    .line 65
    mul-int/lit8 v1, v1, 0x1f

    .line 66
    .line 67
    iget-object v0, p0, Lu81/c;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 68
    .line 69
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    add-int/2addr v0, v1

    .line 74
    mul-int/lit8 v0, v0, 0x1f

    .line 75
    .line 76
    iget-object v1, p0, Lu81/c;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 77
    .line 78
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->hashCode()I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    add-int/2addr v1, v0

    .line 83
    mul-int/lit8 v1, v1, 0x1f

    .line 84
    .line 85
    iget-object p0, p0, Lu81/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 86
    .line 87
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    add-int/2addr p0, v1

    .line 92
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "PPEMessages(currentP2CHighPrio="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", latestSentP2CHighPrio="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", latestSentP2CNormalPrio="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", latestSentP2CComfortCommands="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", latestSentP2CTPAParkingSlotSelection="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lu81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", latestReceivedC2PHighPrio="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", latestReceivedC2PNormalPrioTrajectoryInfo="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lu81/c;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", latestReceivedC2PNormalPrioTrajectoryMetadata="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lu81/c;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", latestReceivedC2PNormalPrioManeuver="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lu81/c;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", latestReceivedC2PTPAParkingSpaceInfo="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Lu81/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 99
    .line 100
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string p0, ")"

    .line 104
    .line 105
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0
.end method
