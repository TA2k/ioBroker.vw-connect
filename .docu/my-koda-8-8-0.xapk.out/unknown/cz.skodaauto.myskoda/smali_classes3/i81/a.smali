.class public final Li81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

.field public final d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

.field public final e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

.field public final f:Ll71/c;


# direct methods
.method public synthetic constructor <init>()V
    .locals 28

    .line 8
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 9
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    const/16 v10, 0x7f

    const/4 v11, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    invoke-direct/range {v2 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILkotlin/jvm/internal/g;)V

    .line 10
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    const/16 v15, 0x7ff

    const/16 v16, 0x0

    const/4 v5, 0x0

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    invoke-direct/range {v3 .. v16}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILkotlin/jvm/internal/g;)V

    .line 11
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    const v26, 0x1fffff

    const/16 v27, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

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

    invoke-direct/range {v4 .. v27}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;-><init>(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;ILkotlin/jvm/internal/g;)V

    .line 12
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    const/16 v13, 0x7f

    const/4 v14, 0x0

    invoke-direct/range {v5 .. v14}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;-><init>(BBBZZZZILkotlin/jvm/internal/g;)V

    const/4 v6, 0x0

    move-object/from16 v0, p0

    .line 13
    invoke-direct/range {v0 .. v6}, Li81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;Ll71/c;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;Ll71/c;)V
    .locals 1

    const-string v0, "parkingFunctionStatus"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Li81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 3
    iput-object p2, p0, Li81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 4
    iput-object p3, p0, Li81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 5
    iput-object p4, p0, Li81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 6
    iput-object p5, p0, Li81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 7
    iput-object p6, p0, Li81/a;->f:Ll71/c;

    return-void
.end method

.method public static a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;
    .locals 8

    .line 1
    sget-object v0, Ll71/c;->e:Ll71/c;

    .line 2
    .line 3
    and-int/lit8 v1, p6, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p1, p0, Li81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 8
    .line 9
    :cond_0
    move-object v2, p1

    .line 10
    and-int/lit8 p1, p6, 0x2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p2, p0, Li81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 15
    .line 16
    :cond_1
    move-object v3, p2

    .line 17
    and-int/lit8 p1, p6, 0x4

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-object p3, p0, Li81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 22
    .line 23
    :cond_2
    move-object v4, p3

    .line 24
    and-int/lit8 p1, p6, 0x8

    .line 25
    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    iget-object p4, p0, Li81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 29
    .line 30
    :cond_3
    move-object v5, p4

    .line 31
    and-int/lit8 p1, p6, 0x10

    .line 32
    .line 33
    if-eqz p1, :cond_4

    .line 34
    .line 35
    iget-object p5, p0, Li81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 36
    .line 37
    :cond_4
    move-object v6, p5

    .line 38
    and-int/lit8 p1, p6, 0x20

    .line 39
    .line 40
    if-eqz p1, :cond_5

    .line 41
    .line 42
    iget-object v0, p0, Li81/a;->f:Ll71/c;

    .line 43
    .line 44
    :cond_5
    move-object v7, v0

    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    const-string p0, "parkingFunctionStatus"

    .line 49
    .line 50
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const-string p0, "highPrioMessage"

    .line 54
    .line 55
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string p0, "normalPrioManeuverInfoMessage"

    .line 59
    .line 60
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string p0, "normalPrioVehicleInfoMessage"

    .line 64
    .line 65
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string p0, "vehicleDataResponseMessage"

    .line 69
    .line 70
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    new-instance v1, Li81/a;

    .line 74
    .line 75
    invoke-direct/range {v1 .. v7}, Li81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;Ll71/c;)V

    .line 76
    .line 77
    .line 78
    return-object v1
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
    instance-of v1, p1, Li81/a;

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
    check-cast p1, Li81/a;

    .line 12
    .line 13
    iget-object v1, p0, Li81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 14
    .line 15
    iget-object v3, p1, Li81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Li81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 21
    .line 22
    iget-object v3, p1, Li81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Li81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 32
    .line 33
    iget-object v3, p1, Li81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Li81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 43
    .line 44
    iget-object v3, p1, Li81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Li81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 54
    .line 55
    iget-object v3, p1, Li81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object p0, p0, Li81/a;->f:Ll71/c;

    .line 65
    .line 66
    iget-object p1, p1, Li81/a;->f:Ll71/c;

    .line 67
    .line 68
    if-eq p0, p1, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Li81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Li81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 10
    .line 11
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->hashCode()I

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
    iget-object v0, p0, Li81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 19
    .line 20
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->hashCode()I

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
    iget-object v1, p0, Li81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 28
    .line 29
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->hashCode()I

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
    iget-object v0, p0, Li81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 37
    .line 38
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->hashCode()I

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
    iget-object p0, p0, Li81/a;->f:Ll71/c;

    .line 46
    .line 47
    if-nez p0, :cond_0

    .line 48
    .line 49
    const/4 p0, 0x0

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    :goto_0
    add-int/2addr v0, p0

    .line 56
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MEBCarData(parkingFunctionStatus="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Li81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", highPrioMessage="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Li81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", normalPrioManeuverInfoMessage="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Li81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", normalPrioVehicleInfoMessage="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Li81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", vehicleDataResponseMessage="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Li81/a;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", internalTimeout="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Li81/a;->f:Ll71/c;

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
