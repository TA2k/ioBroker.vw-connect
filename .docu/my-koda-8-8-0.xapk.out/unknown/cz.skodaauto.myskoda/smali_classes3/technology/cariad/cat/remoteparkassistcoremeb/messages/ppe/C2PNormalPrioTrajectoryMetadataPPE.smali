.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0007\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 %2\u00020\u0001:\u0001%B9\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0008\u0010\u0016\u001a\u00020\u0017H\u0016J\t\u0010\u0018\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001b\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001c\u001a\u00020\u0003H\u00c6\u0003J;\u0010\u001d\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u001e\u001a\u00020\u001f2\u0008\u0010 \u001a\u0004\u0018\u00010!H\u00d6\u0003J\t\u0010\"\u001a\u00020\u0003H\u00d6\u0001J\t\u0010#\u001a\u00020$H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u000cR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000eR\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u000cR\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\u000cR\u0011\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u000cR\u0014\u0010\u0012\u001a\u00020\u0013X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010\u0015\u00a8\u0006&"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "parkingTrajTransId",
        "",
        "parkingTrajDrivingDirection",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;",
        "parkingTrajVehiclePosX",
        "parkingTrajVehiclePosY",
        "parkingTrajVehicleAngle",
        "<init>",
        "(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;III)V",
        "getParkingTrajTransId",
        "()I",
        "getParkingTrajDrivingDirection",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;",
        "getParkingTrajVehiclePosX",
        "getParkingTrajVehiclePosY",
        "getParkingTrajVehicleAngle",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "copy",
        "equals",
        "",
        "other",
        "",
        "hashCode",
        "toString",
        "",
        "Companion",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;

.field private static final PARKING_SM_TRAJ_TRANS_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

.field private final parkingTrajTransId:I

.field private final parkingTrajVehicleAngle:I

.field private final parkingTrajVehiclePosX:I

.field private final parkingTrajVehiclePosY:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x25

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250400501000000L    # 3.2326162256214436E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->address:J

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->priority:B

    .line 22
    .line 23
    const/4 v1, 0x7

    .line 24
    sput v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->byteLength:I

    .line 25
    .line 26
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    const/4 v3, 0x4

    .line 30
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_SM_TRAJ_TRANS_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    invoke-direct {v1, v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 41
    .line 42
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    const/4 v1, 0x6

    .line 45
    const/16 v2, 0x10

    .line 46
    .line 47
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 48
    .line 49
    .line 50
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 51
    .line 52
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 53
    .line 54
    const/16 v1, 0x16

    .line 55
    .line 56
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 60
    .line 61
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 62
    .line 63
    const/16 v1, 0x26

    .line 64
    .line 65
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 66
    .line 67
    .line 68
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 69
    .line 70
    return-void
.end method

.method public constructor <init>()V
    .locals 8

    .line 1
    const/16 v6, 0x1f

    const/4 v7, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;IIIILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;III)V
    .locals 1

    const-string v0, "parkingTrajDrivingDirection"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 4
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 5
    iput p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 6
    iput p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 7
    iput p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 8
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;IIIILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p7, p6, 0x1

    const/4 v0, 0x0

    if-eqz p7, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p7, p6, 0x2

    if-eqz p7, :cond_1

    .line 9
    sget-object p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;->STILLSTAND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    :cond_1
    and-int/lit8 p7, p6, 0x4

    if-eqz p7, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p7, p6, 0x8

    if-eqz p7, :cond_3

    move p4, v0

    :cond_3
    and-int/lit8 p6, p6, 0x10

    if-eqz p6, :cond_4

    move p5, v0

    .line 10
    :cond_4
    invoke-direct/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;III)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPARKING_SM_TRAJ_TRANS_ID$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_SM_TRAJ_TRANS_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_DRIVING_DIRECTION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_VEHICLE_ANGLE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_VEHICLE_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_VEHICLE_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;IIIILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;
    .locals 0

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p7, p6, 0x2

    .line 8
    .line 9
    if-eqz p7, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p7, p6, 0x4

    .line 14
    .line 15
    if-eqz p7, :cond_2

    .line 16
    .line 17
    iget p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p7, p6, 0x8

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    iget p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p6, p6, 0x10

    .line 26
    .line 27
    if-eqz p6, :cond_4

    .line 28
    .line 29
    iget p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 30
    .line 31
    :cond_4
    move p6, p4

    .line 32
    move p7, p5

    .line 33
    move-object p4, p2

    .line 34
    move p5, p3

    .line 35
    move-object p2, p0

    .line 36
    move p3, p1

    .line 37
    invoke-virtual/range {p2 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->copy(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;III)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component5()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;III)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;
    .locals 6

    .line 1
    const-string p0, "parkingTrajDrivingDirection"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 7
    .line 8
    move v1, p1

    .line 9
    move-object v2, p2

    .line 10
    move v3, p3

    .line 11
    move v4, p4

    .line 12
    move v5, p5

    .line 13
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;III)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 12
    .line 13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 14
    .line 15
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 21
    .line 22
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 28
    .line 29
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 35
    .line 36
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 42
    .line 43
    iget p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 44
    .line 45
    if-eq p0, p1, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingTrajDrivingDirection()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingTrajTransId()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajVehicleAngle()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajVehiclePosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajVehiclePosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 19
    .line 20
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 25
    .line 26
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 31
    .line 32
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    add-int/2addr p0, v0

    .line 37
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_SM_TRAJ_TRANS_ID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 21
    .line 22
    .line 23
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 24
    .line 25
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 26
    .line 27
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 28
    .line 29
    .line 30
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 31
    .line 32
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 35
    .line 36
    .line 37
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 38
    .line 39
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 40
    .line 41
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 42
    .line 43
    .line 44
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajTransId:I

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 4
    .line 5
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosX:I

    .line 6
    .line 7
    iget v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehiclePosY:I

    .line 8
    .line 9
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->parkingTrajVehicleAngle:I

    .line 10
    .line 11
    new-instance v4, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v5, "C2PNormalPrioTrajectoryMetadataPPE(parkingTrajTransId="

    .line 14
    .line 15
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v0, ", parkingTrajDrivingDirection="

    .line 22
    .line 23
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, ", parkingTrajVehiclePosX="

    .line 30
    .line 31
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v0, ", parkingTrajVehiclePosY="

    .line 35
    .line 36
    const-string v1, ", parkingTrajVehicleAngle="

    .line 37
    .line 38
    invoke-static {v4, v2, v0, v3, v1}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v0, ")"

    .line 42
    .line 43
    invoke-static {p0, v0, v4}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method
