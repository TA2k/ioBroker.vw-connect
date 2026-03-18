.class public final Lu81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

.field public final d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

.field public final e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

.field public final f:Ljava/util/Set;

.field public final g:Ll71/c;

.field public final h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;


# direct methods
.method public synthetic constructor <init>()V
    .locals 44

    .line 11
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    const/16 v7, 0x3f

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;-><init>(IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILkotlin/jvm/internal/g;)V

    .line 12
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    const/16 v15, 0x1fff

    const/16 v16, 0x0

    const/4 v2, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    invoke-direct/range {v1 .. v16}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;ILkotlin/jvm/internal/g;)V

    .line 13
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    const/16 v42, 0x3f

    const/16 v43, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v13, 0x0

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

    const/16 v41, -0x1

    invoke-direct/range {v2 .. v43}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/SunroofModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/LockStatusPPE;ZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DoorStatusPPE;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/EngineTypePPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/WheelBaseStatusPPE;ZZIIIIIIILkotlin/jvm/internal/g;)V

    .line 14
    sget-object v6, Lmx0/u;->d:Lmx0/u;

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v3, v2

    move-object v2, v1

    move-object v1, v0

    move-object/from16 v0, p0

    .line 15
    invoke-direct/range {v0 .. v8}, Lu81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/Set;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/Set;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 3
    iput-object p2, p0, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 4
    iput-object p3, p0, Lu81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 5
    iput-object p4, p0, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 6
    iput-object p5, p0, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 7
    iput-object p6, p0, Lu81/a;->f:Ljava/util/Set;

    .line 8
    iput-object p7, p0, Lu81/a;->g:Ll71/c;

    .line 9
    iput-object p8, p0, Lu81/a;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 10
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    move-result-object p0

    invoke-static {p0}, Lpm/a;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/h;

    return-void
.end method

.method public static a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;
    .locals 9

    .line 1
    move/from16 v0, p9

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

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
    iget-object p2, p0, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

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
    iget-object p3, p0, Lu81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

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
    iget-object p4, p0, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

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
    iget-object p5, p0, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 36
    .line 37
    :cond_4
    move-object v5, p5

    .line 38
    and-int/lit8 p1, v0, 0x20

    .line 39
    .line 40
    if-eqz p1, :cond_5

    .line 41
    .line 42
    iget-object p6, p0, Lu81/a;->f:Ljava/util/Set;

    .line 43
    .line 44
    :cond_5
    move-object v6, p6

    .line 45
    and-int/lit8 p1, v0, 0x40

    .line 46
    .line 47
    if-eqz p1, :cond_6

    .line 48
    .line 49
    iget-object p1, p0, Lu81/a;->g:Ll71/c;

    .line 50
    .line 51
    move-object v7, p1

    .line 52
    goto :goto_0

    .line 53
    :cond_6
    move-object/from16 v7, p7

    .line 54
    .line 55
    :goto_0
    and-int/lit16 p1, v0, 0x80

    .line 56
    .line 57
    if-eqz p1, :cond_7

    .line 58
    .line 59
    iget-object p1, p0, Lu81/a;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 60
    .line 61
    move-object v8, p1

    .line 62
    goto :goto_1

    .line 63
    :cond_7
    move-object/from16 v8, p8

    .line 64
    .line 65
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    const-string p0, "highPrioMessage"

    .line 69
    .line 70
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const-string p0, "normalPrioManeuverInfoMessage"

    .line 74
    .line 75
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string p0, "normalPrioVehicleInfoMessage"

    .line 79
    .line 80
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    const-string p0, "parkingSpaceInfoMessage"

    .line 84
    .line 85
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    new-instance v0, Lu81/a;

    .line 89
    .line 90
    invoke-direct/range {v0 .. v8}, Lu81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/Set;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;)V

    .line 91
    .line 92
    .line 93
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
    instance-of v1, p1, Lu81/a;

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
    check-cast p1, Lu81/a;

    .line 12
    .line 13
    iget-object v1, p0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 14
    .line 15
    iget-object v3, p1, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

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
    iget-object v1, p0, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 25
    .line 26
    iget-object v3, p1, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

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
    iget-object v1, p0, Lu81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 36
    .line 37
    iget-object v3, p1, Lu81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

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
    iget-object v1, p0, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 47
    .line 48
    iget-object v3, p1, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

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
    iget-object v1, p0, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 58
    .line 59
    iget-object v3, p1, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

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
    iget-object v1, p0, Lu81/a;->f:Ljava/util/Set;

    .line 69
    .line 70
    iget-object v3, p1, Lu81/a;->f:Ljava/util/Set;

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
    iget-object v1, p0, Lu81/a;->g:Ll71/c;

    .line 80
    .line 81
    iget-object v3, p1, Lu81/a;->g:Ll71/c;

    .line 82
    .line 83
    if-eq v1, v3, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object p0, p0, Lu81/a;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 87
    .line 88
    iget-object p1, p1, Lu81/a;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 89
    .line 90
    if-eq p0, p1, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 10
    .line 11
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->hashCode()I

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
    iget-object v0, p0, Lu81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 19
    .line 20
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->hashCode()I

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
    const/4 v1, 0x0

    .line 28
    iget-object v2, p0, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 29
    .line 30
    if-nez v2, :cond_0

    .line 31
    .line 32
    move v2, v1

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    :goto_0
    add-int/2addr v0, v2

    .line 39
    mul-int/lit8 v0, v0, 0x1f

    .line 40
    .line 41
    iget-object v2, p0, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 42
    .line 43
    if-nez v2, :cond_1

    .line 44
    .line 45
    move v2, v1

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    :goto_1
    add-int/2addr v0, v2

    .line 52
    mul-int/lit8 v0, v0, 0x1f

    .line 53
    .line 54
    iget-object v2, p0, Lu81/a;->f:Ljava/util/Set;

    .line 55
    .line 56
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    add-int/2addr v2, v0

    .line 61
    mul-int/lit8 v2, v2, 0x1f

    .line 62
    .line 63
    iget-object v0, p0, Lu81/a;->g:Ll71/c;

    .line 64
    .line 65
    if-nez v0, :cond_2

    .line 66
    .line 67
    move v0, v1

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    :goto_2
    add-int/2addr v2, v0

    .line 74
    mul-int/lit8 v2, v2, 0x1f

    .line 75
    .line 76
    iget-object p0, p0, Lu81/a;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 77
    .line 78
    if-nez p0, :cond_3

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    :goto_3
    add-int/2addr v2, v1

    .line 86
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "PPECarData(highPrioMessage="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", normalPrioManeuverInfoMessage="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", normalPrioVehicleInfoMessage="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lu81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", normalPrioTrajectoryMetadataMessage="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lu81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", normalPrioTrajectoryInfoMessage="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lu81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", parkingSpaceInfoMessage="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lu81/a;->f:Ljava/util/Set;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", internalTimeout="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lu81/a;->g:Ll71/c;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", functionResponseStatus="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lu81/a;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 79
    .line 80
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string p0, ")"

    .line 84
    .line 85
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0
.end method
