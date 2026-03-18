.class public final Ln81/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

.field public final d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

.field public final e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

.field public final f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;


# direct methods
.method public synthetic constructor <init>()V
    .locals 32

    .line 8
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    const/16 v7, 0x3f

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;-><init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;ILkotlin/jvm/internal/g;)V

    .line 9
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    const/16 v8, 0x3f

    const/4 v9, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;-><init>(IIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;ILkotlin/jvm/internal/g;)V

    .line 10
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    const/16 v8, 0x1f

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v2 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;ZILkotlin/jvm/internal/g;)V

    .line 11
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    const/16 v13, 0x1ff

    const/4 v14, 0x0

    const/4 v8, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    invoke-direct/range {v3 .. v14}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILkotlin/jvm/internal/g;)V

    .line 12
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    const v26, 0x1fffff

    const/16 v27, 0x0

    const/4 v7, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

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

    invoke-direct/range {v4 .. v27}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILkotlin/jvm/internal/g;)V

    .line 13
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    const v30, 0xffffff

    const/16 v31, 0x0

    const/4 v6, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    invoke-direct/range {v5 .. v31}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIIIILkotlin/jvm/internal/g;)V

    move-object v6, v5

    move-object v5, v4

    move-object v4, v3

    move-object v3, v2

    move-object v2, v1

    move-object v1, v0

    move-object/from16 v0, p0

    .line 14
    invoke-direct/range {v0 .. v6}, Ln81/c;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ln81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 3
    iput-object p2, p0, Ln81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 4
    iput-object p3, p0, Ln81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    .line 5
    iput-object p4, p0, Ln81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 6
    iput-object p5, p0, Ln81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 7
    iput-object p6, p0, Ln81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    return-void
.end method

.method public static a(Ln81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;I)Ln81/c;
    .locals 7

    .line 1
    and-int/lit8 v0, p7, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ln81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    and-int/lit8 p1, p7, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p2, p0, Ln81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 13
    .line 14
    :cond_1
    move-object v2, p2

    .line 15
    and-int/lit8 p1, p7, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-object p3, p0, Ln81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    .line 20
    .line 21
    :cond_2
    move-object v3, p3

    .line 22
    and-int/lit8 p1, p7, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-object p4, p0, Ln81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 27
    .line 28
    :cond_3
    move-object v4, p4

    .line 29
    and-int/lit8 p1, p7, 0x10

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    iget-object p5, p0, Ln81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 34
    .line 35
    :cond_4
    move-object v5, p5

    .line 36
    and-int/lit8 p1, p7, 0x20

    .line 37
    .line 38
    if-eqz p1, :cond_5

    .line 39
    .line 40
    iget-object p6, p0, Ln81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 41
    .line 42
    :cond_5
    move-object v6, p6

    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    const-string p0, "currentP2CHighPrio"

    .line 47
    .line 48
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string p0, "latestSentP2CHighPrio"

    .line 52
    .line 53
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string p0, "latestSentP2CNormalPrio"

    .line 57
    .line 58
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string p0, "latestReceivedC2PHighPrio"

    .line 62
    .line 63
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const-string p0, "latestReceivedC2PNormalPrioManeuver"

    .line 67
    .line 68
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string p0, "latestReceivedC2PNormalPrioTrajectory"

    .line 72
    .line 73
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Ln81/c;

    .line 77
    .line 78
    invoke-direct/range {v0 .. v6}, Ln81/c;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;)V

    .line 79
    .line 80
    .line 81
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
    instance-of v1, p1, Ln81/c;

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
    check-cast p1, Ln81/c;

    .line 12
    .line 13
    iget-object v1, p0, Ln81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 14
    .line 15
    iget-object v3, p1, Ln81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

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
    iget-object v1, p0, Ln81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 25
    .line 26
    iget-object v3, p1, Ln81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

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
    iget-object v1, p0, Ln81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    .line 36
    .line 37
    iget-object v3, p1, Ln81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

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
    iget-object v1, p0, Ln81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 47
    .line 48
    iget-object v3, p1, Ln81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

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
    iget-object v1, p0, Ln81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 58
    .line 59
    iget-object v3, p1, Ln81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

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
    iget-object p0, p0, Ln81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 69
    .line 70
    iget-object p1, p1, Ln81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 71
    .line 72
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-nez p0, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Ln81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Ln81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 10
    .line 11
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->hashCode()I

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
    iget-object v0, p0, Ln81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    .line 19
    .line 20
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;->hashCode()I

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
    iget-object v1, p0, Ln81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 28
    .line 29
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->hashCode()I

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
    iget-object v0, p0, Ln81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 37
    .line 38
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    add-int/2addr v0, v1

    .line 43
    mul-int/lit8 v0, v0, 0x1f

    .line 44
    .line 45
    iget-object p0, p0, Ln81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 46
    .line 47
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    add-int/2addr p0, v0

    .line 52
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MLBMessages(currentP2CHighPrio="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ln81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

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
    iget-object v1, p0, Ln81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

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
    iget-object v1, p0, Ln81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", latestReceivedC2PHighPrio="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ln81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", latestReceivedC2PNormalPrioManeuver="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Ln81/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", latestReceivedC2PNormalPrioTrajectory="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Ln81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, ")"

    .line 64
    .line 65
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method
