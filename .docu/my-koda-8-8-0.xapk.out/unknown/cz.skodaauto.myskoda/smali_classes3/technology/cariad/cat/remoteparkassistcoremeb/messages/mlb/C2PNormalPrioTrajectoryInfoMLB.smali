.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u00083\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u001a\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 `2\u00020\u0001:\u0001`B\u00f7\u0001\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\r\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0011\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0013\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0019\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u001b\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\u0008\u0010>\u001a\u00020?H\u0016J\t\u0010@\u001a\u00020\u0003H\u00c6\u0003J\t\u0010A\u001a\u00020\u0005H\u00c6\u0003J\t\u0010B\u001a\u00020\u0007H\u00c6\u0003J\t\u0010C\u001a\u00020\u0003H\u00c6\u0003J\t\u0010D\u001a\u00020\u0003H\u00c6\u0003J\t\u0010E\u001a\u00020\u0003H\u00c6\u0003J\t\u0010F\u001a\u00020\u0003H\u00c6\u0003J\t\u0010G\u001a\u00020\u0003H\u00c6\u0003J\t\u0010H\u001a\u00020\u0003H\u00c6\u0003J\t\u0010I\u001a\u00020\u0003H\u00c6\u0003J\t\u0010J\u001a\u00020\u0003H\u00c6\u0003J\t\u0010K\u001a\u00020\u0003H\u00c6\u0003J\t\u0010L\u001a\u00020\u0003H\u00c6\u0003J\t\u0010M\u001a\u00020\u0003H\u00c6\u0003J\t\u0010N\u001a\u00020\u0003H\u00c6\u0003J\t\u0010O\u001a\u00020\u0003H\u00c6\u0003J\t\u0010P\u001a\u00020\u0003H\u00c6\u0003J\t\u0010Q\u001a\u00020\u0003H\u00c6\u0003J\t\u0010R\u001a\u00020\u0003H\u00c6\u0003J\t\u0010S\u001a\u00020\u0003H\u00c6\u0003J\t\u0010T\u001a\u00020\u0003H\u00c6\u0003J\t\u0010U\u001a\u00020\u0003H\u00c6\u0003J\t\u0010V\u001a\u00020\u0003H\u00c6\u0003J\t\u0010W\u001a\u00020\u0003H\u00c6\u0003J\u00f9\u0001\u0010X\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u00032\u0008\u0008\u0002\u0010\t\u001a\u00020\u00032\u0008\u0008\u0002\u0010\n\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u00032\u0008\u0008\u0002\u0010\r\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0011\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0013\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0019\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u001b\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010Y\u001a\u00020Z2\u0008\u0010[\u001a\u0004\u0018\u00010\\H\u00d6\u0003J\t\u0010]\u001a\u00020\u0003H\u00d6\u0001J\t\u0010^\u001a\u00020_H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001f\u0010 R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008!\u0010\"R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008#\u0010$R\u0011\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008%\u0010 R\u0011\u0010\t\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008&\u0010 R\u0011\u0010\n\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\'\u0010 R\u0011\u0010\u000b\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008(\u0010 R\u0011\u0010\u000c\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008)\u0010 R\u0011\u0010\r\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008*\u0010 R\u0011\u0010\u000e\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008+\u0010 R\u0011\u0010\u000f\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008,\u0010 R\u0011\u0010\u0010\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008-\u0010 R\u0011\u0010\u0011\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008.\u0010 R\u0011\u0010\u0012\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008/\u0010 R\u0011\u0010\u0013\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00080\u0010 R\u0011\u0010\u0014\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00081\u0010 R\u0011\u0010\u0015\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00082\u0010 R\u0011\u0010\u0016\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00083\u0010 R\u0011\u0010\u0017\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00084\u0010 R\u0011\u0010\u0018\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00085\u0010 R\u0011\u0010\u0019\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00086\u0010 R\u0011\u0010\u001a\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00087\u0010 R\u0011\u0010\u001b\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00088\u0010 R\u0011\u0010\u001c\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00089\u0010 R\u0014\u0010:\u001a\u00020;X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008<\u0010=\u00a8\u0006a"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "parkingTrajNumberPoints",
        "",
        "parkingTrajLatestMove",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;",
        "parkingTrajDrivingDirection",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;",
        "parkingTrajVehiclePosX",
        "parkingTrajVehiclePosY",
        "parkingTrajVehicleAngle",
        "parkingTrajP1PosX",
        "parkingTrajP1PosY",
        "parkingTrajP2PosX",
        "parkingTrajP2PosY",
        "parkingTrajP3PosX",
        "parkingTrajP3PosY",
        "parkingTrajP4PosX",
        "parkingTrajP4PosY",
        "parkingTrajP5PosX",
        "parkingTrajP5PosY",
        "parkingTrajP6PosX",
        "parkingTrajP6PosY",
        "parkingTrajP7PosX",
        "parkingTrajP7PosY",
        "parkingTrajP8PosX",
        "parkingTrajP8PosY",
        "parkingTrajP9PosX",
        "parkingTrajP9PosY",
        "<init>",
        "(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIII)V",
        "getParkingTrajNumberPoints",
        "()I",
        "getParkingTrajLatestMove",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;",
        "getParkingTrajDrivingDirection",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;",
        "getParkingTrajVehiclePosX",
        "getParkingTrajVehiclePosY",
        "getParkingTrajVehicleAngle",
        "getParkingTrajP1PosX",
        "getParkingTrajP1PosY",
        "getParkingTrajP2PosX",
        "getParkingTrajP2PosY",
        "getParkingTrajP3PosX",
        "getParkingTrajP3PosY",
        "getParkingTrajP4PosX",
        "getParkingTrajP4PosY",
        "getParkingTrajP5PosX",
        "getParkingTrajP5PosY",
        "getParkingTrajP6PosX",
        "getParkingTrajP6PosY",
        "getParkingTrajP7PosX",
        "getParkingTrajP7PosY",
        "getParkingTrajP8PosX",
        "getParkingTrajP8PosY",
        "getParkingTrajP9PosX",
        "getParkingTrajP9PosY",
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
        "component6",
        "component7",
        "component8",
        "component9",
        "component10",
        "component11",
        "component12",
        "component13",
        "component14",
        "component15",
        "component16",
        "component17",
        "component18",
        "component19",
        "component20",
        "component21",
        "component22",
        "component23",
        "component24",
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
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB$Companion;

.field private static final PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_LATEST_MOVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_NUMBER_POINTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P1_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P1_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P2_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P2_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P3_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P3_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P4_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P4_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P5_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P5_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P6_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P6_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P7_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P7_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P8_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P8_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P9_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_TRAJ_P9_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

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

.field private final parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

.field private final parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

.field private final parkingTrajNumberPoints:I

.field private final parkingTrajP1PosX:I

.field private final parkingTrajP1PosY:I

.field private final parkingTrajP2PosX:I

.field private final parkingTrajP2PosY:I

.field private final parkingTrajP3PosX:I

.field private final parkingTrajP3PosY:I

.field private final parkingTrajP4PosX:I

.field private final parkingTrajP4PosY:I

.field private final parkingTrajP5PosX:I

.field private final parkingTrajP5PosY:I

.field private final parkingTrajP6PosX:I

.field private final parkingTrajP6PosY:I

.field private final parkingTrajP7PosX:I

.field private final parkingTrajP7PosY:I

.field private final parkingTrajP8PosX:I

.field private final parkingTrajP8PosY:I

.field private final parkingTrajP9PosX:I

.field private final parkingTrajP9PosY:I

.field private final parkingTrajVehicleAngle:I

.field private final parkingTrajVehiclePosX:I

.field private final parkingTrajVehiclePosY:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB$Companion;

    .line 8
    .line 9
    const/16 v0, 0x23

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->messageID:B

    .line 12
    .line 13
    const-wide v1, 0x5250410301000000L    # 3.233387222338046E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->address:J

    .line 19
    .line 20
    const/4 v1, 0x3

    .line 21
    sput-byte v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->priority:B

    .line 22
    .line 23
    sput v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->byteLength:I

    .line 24
    .line 25
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    const/4 v2, 0x4

    .line 29
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_NUMBER_POINTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 33
    .line 34
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 35
    .line 36
    const/4 v1, 0x1

    .line 37
    invoke-direct {v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_LATEST_MOVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 41
    .line 42
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    const/4 v2, 0x5

    .line 45
    invoke-direct {v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 49
    .line 50
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 51
    .line 52
    const/4 v1, 0x6

    .line 53
    const/16 v2, 0xd

    .line 54
    .line 55
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 56
    .line 57
    .line 58
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 59
    .line 60
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 61
    .line 62
    const/16 v1, 0x13

    .line 63
    .line 64
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 65
    .line 66
    .line 67
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 68
    .line 69
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 70
    .line 71
    const/16 v1, 0x20

    .line 72
    .line 73
    const/16 v3, 0xa

    .line 74
    .line 75
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 76
    .line 77
    .line 78
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 79
    .line 80
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    const/16 v1, 0x2a

    .line 83
    .line 84
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 85
    .line 86
    .line 87
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P1_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 88
    .line 89
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 90
    .line 91
    const/16 v1, 0x37

    .line 92
    .line 93
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 94
    .line 95
    .line 96
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P1_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 97
    .line 98
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 99
    .line 100
    const/16 v1, 0x44

    .line 101
    .line 102
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 103
    .line 104
    .line 105
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P2_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 106
    .line 107
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 108
    .line 109
    const/16 v1, 0x51

    .line 110
    .line 111
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 112
    .line 113
    .line 114
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P2_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 115
    .line 116
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 117
    .line 118
    const/16 v1, 0x5e

    .line 119
    .line 120
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 121
    .line 122
    .line 123
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P3_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 124
    .line 125
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 126
    .line 127
    const/16 v1, 0x6b

    .line 128
    .line 129
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 130
    .line 131
    .line 132
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P3_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 133
    .line 134
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 135
    .line 136
    const/16 v1, 0x78

    .line 137
    .line 138
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 139
    .line 140
    .line 141
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P4_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 142
    .line 143
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 144
    .line 145
    const/16 v1, 0x85

    .line 146
    .line 147
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 148
    .line 149
    .line 150
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P4_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 151
    .line 152
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 153
    .line 154
    const/16 v1, 0x92

    .line 155
    .line 156
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 157
    .line 158
    .line 159
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P5_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 160
    .line 161
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 162
    .line 163
    const/16 v1, 0x9f

    .line 164
    .line 165
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 166
    .line 167
    .line 168
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P5_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 169
    .line 170
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 171
    .line 172
    const/16 v1, 0xac

    .line 173
    .line 174
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 175
    .line 176
    .line 177
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P6_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 178
    .line 179
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 180
    .line 181
    const/16 v1, 0xb9

    .line 182
    .line 183
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 184
    .line 185
    .line 186
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P6_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 187
    .line 188
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 189
    .line 190
    const/16 v1, 0xc6

    .line 191
    .line 192
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 193
    .line 194
    .line 195
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P7_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 196
    .line 197
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 198
    .line 199
    const/16 v1, 0xd3

    .line 200
    .line 201
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 202
    .line 203
    .line 204
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P7_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 205
    .line 206
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 207
    .line 208
    const/16 v1, 0xe0

    .line 209
    .line 210
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 211
    .line 212
    .line 213
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P8_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 214
    .line 215
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 216
    .line 217
    const/16 v1, 0xed

    .line 218
    .line 219
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 220
    .line 221
    .line 222
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P8_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 223
    .line 224
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 225
    .line 226
    const/16 v1, 0xfa

    .line 227
    .line 228
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 229
    .line 230
    .line 231
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P9_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 232
    .line 233
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 234
    .line 235
    const/16 v1, 0x107

    .line 236
    .line 237
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 238
    .line 239
    .line 240
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P9_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 241
    .line 242
    return-void
.end method

.method public constructor <init>()V
    .locals 27

    .line 1
    const v25, 0xffffff

    const/16 v26, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

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

    move-object/from16 v0, p0

    invoke-direct/range {v0 .. v26}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIIIILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIII)V
    .locals 1

    const-string v0, "parkingTrajLatestMove"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingTrajDrivingDirection"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 4
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 6
    iput p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 7
    iput p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 8
    iput p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 9
    iput p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 10
    iput p8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 11
    iput p9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 12
    iput p10, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 13
    iput p11, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 14
    iput p12, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 15
    iput p13, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 16
    iput p14, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    move/from16 p1, p15

    .line 17
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    move/from16 p1, p16

    .line 18
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    move/from16 p1, p17

    .line 19
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    move/from16 p1, p18

    .line 20
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    move/from16 p1, p19

    .line 21
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    move/from16 p1, p20

    .line 22
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    move/from16 p1, p21

    .line 23
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    move/from16 p1, p22

    .line 24
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    move/from16 p1, p23

    .line 25
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    move/from16 p1, p24

    .line 26
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 27
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIIIILkotlin/jvm/internal/g;)V
    .locals 25

    move/from16 v0, p25

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    goto :goto_0

    :cond_0
    move/from16 v1, p1

    :goto_0
    and-int/lit8 v3, v0, 0x2

    if-eqz v3, :cond_1

    .line 28
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;->TURNING_POINT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v0, 0x4

    if-eqz v4, :cond_2

    .line 29
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v0, 0x8

    if-eqz v5, :cond_3

    const/4 v5, 0x0

    goto :goto_3

    :cond_3
    move/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v0, 0x10

    if-eqz v6, :cond_4

    const/4 v6, 0x0

    goto :goto_4

    :cond_4
    move/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v0, 0x20

    if-eqz v7, :cond_5

    const/4 v7, 0x0

    goto :goto_5

    :cond_5
    move/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v0, 0x40

    if-eqz v8, :cond_6

    const/4 v8, 0x0

    goto :goto_6

    :cond_6
    move/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v0, 0x80

    if-eqz v9, :cond_7

    const/4 v9, 0x0

    goto :goto_7

    :cond_7
    move/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v0, 0x100

    if-eqz v10, :cond_8

    const/4 v10, 0x0

    goto :goto_8

    :cond_8
    move/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v0, 0x200

    if-eqz v11, :cond_9

    const/4 v11, 0x0

    goto :goto_9

    :cond_9
    move/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v0, 0x400

    if-eqz v12, :cond_a

    const/4 v12, 0x0

    goto :goto_a

    :cond_a
    move/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v0, 0x800

    if-eqz v13, :cond_b

    const/4 v13, 0x0

    goto :goto_b

    :cond_b
    move/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v0, 0x1000

    if-eqz v14, :cond_c

    const/4 v14, 0x0

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v0, 0x2000

    if-eqz v15, :cond_d

    const/4 v15, 0x0

    goto :goto_d

    :cond_d
    move/from16 v15, p14

    :goto_d
    and-int/lit16 v2, v0, 0x4000

    if-eqz v2, :cond_e

    const/4 v2, 0x0

    goto :goto_e

    :cond_e
    move/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v0, v16

    if-eqz v16, :cond_f

    const/16 v16, 0x0

    goto :goto_f

    :cond_f
    move/from16 v16, p16

    :goto_f
    const/high16 v17, 0x10000

    and-int v17, v0, v17

    if-eqz v17, :cond_10

    const/16 v17, 0x0

    goto :goto_10

    :cond_10
    move/from16 v17, p17

    :goto_10
    const/high16 v18, 0x20000

    and-int v18, v0, v18

    if-eqz v18, :cond_11

    const/16 v18, 0x0

    goto :goto_11

    :cond_11
    move/from16 v18, p18

    :goto_11
    const/high16 v19, 0x40000

    and-int v19, v0, v19

    if-eqz v19, :cond_12

    const/16 v19, 0x0

    goto :goto_12

    :cond_12
    move/from16 v19, p19

    :goto_12
    const/high16 v20, 0x80000

    and-int v20, v0, v20

    if-eqz v20, :cond_13

    const/16 v20, 0x0

    goto :goto_13

    :cond_13
    move/from16 v20, p20

    :goto_13
    const/high16 v21, 0x100000

    and-int v21, v0, v21

    if-eqz v21, :cond_14

    const/16 v21, 0x0

    goto :goto_14

    :cond_14
    move/from16 v21, p21

    :goto_14
    const/high16 v22, 0x200000

    and-int v22, v0, v22

    if-eqz v22, :cond_15

    const/16 v22, 0x0

    goto :goto_15

    :cond_15
    move/from16 v22, p22

    :goto_15
    const/high16 v23, 0x400000

    and-int v23, v0, v23

    if-eqz v23, :cond_16

    const/16 v23, 0x0

    goto :goto_16

    :cond_16
    move/from16 v23, p23

    :goto_16
    const/high16 v24, 0x800000

    and-int v0, v0, v24

    if-eqz v0, :cond_17

    const/16 p25, 0x0

    :goto_17
    move-object/from16 p1, p0

    move/from16 p2, v1

    move/from16 p16, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move/from16 p5, v5

    move/from16 p6, v6

    move/from16 p7, v7

    move/from16 p8, v8

    move/from16 p9, v9

    move/from16 p10, v10

    move/from16 p11, v11

    move/from16 p12, v12

    move/from16 p13, v13

    move/from16 p14, v14

    move/from16 p15, v15

    move/from16 p17, v16

    move/from16 p18, v17

    move/from16 p19, v18

    move/from16 p20, v19

    move/from16 p21, v20

    move/from16 p22, v21

    move/from16 p23, v22

    move/from16 p24, v23

    goto :goto_18

    :cond_17
    move/from16 p25, p24

    goto :goto_17

    .line 30
    :goto_18
    invoke-direct/range {p1 .. p25}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIII)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_DRIVING_DIRECTION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_LATEST_MOVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_LATEST_MOVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_NUMBER_POINTS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_NUMBER_POINTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P1_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P1_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P1_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P1_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P2_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P2_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P2_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P2_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P3_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P3_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P3_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P3_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P4_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P4_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P4_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P4_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P5_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P5_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P5_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P5_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P6_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P6_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P6_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P6_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P7_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P7_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P7_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P7_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P8_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P8_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P8_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P8_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P9_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P9_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_P9_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P9_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_VEHICLE_ANGLE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_VEHICLE_POS_X$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_TRAJ_VEHICLE_POS_Y$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIIIILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p25

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    goto :goto_0

    :cond_0
    move/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    goto :goto_3

    :cond_3
    move/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    goto :goto_4

    :cond_4
    move/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    goto :goto_5

    :cond_5
    move/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    goto :goto_6

    :cond_6
    move/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    goto :goto_7

    :cond_7
    move/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    goto :goto_8

    :cond_8
    move/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    goto :goto_9

    :cond_9
    move/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    goto :goto_a

    :cond_a
    move/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    goto :goto_b

    :cond_b
    move/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    goto :goto_d

    :cond_d
    move/from16 v15, p14

    :goto_d
    move/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    goto :goto_e

    :cond_e
    move/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    goto :goto_f

    :cond_f
    move/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p25, v16

    move/from16 p2, v1

    if-eqz v16, :cond_10

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    goto :goto_10

    :cond_10
    move/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p25, v16

    move/from16 p3, v1

    if-eqz v16, :cond_11

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    goto :goto_11

    :cond_11
    move/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p25, v16

    move/from16 p4, v1

    if-eqz v16, :cond_12

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    goto :goto_12

    :cond_12
    move/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p25, v16

    move/from16 p5, v1

    if-eqz v16, :cond_13

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    goto :goto_13

    :cond_13
    move/from16 v1, p20

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p25, v16

    move/from16 p6, v1

    if-eqz v16, :cond_14

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    goto :goto_14

    :cond_14
    move/from16 v1, p21

    :goto_14
    const/high16 v16, 0x200000

    and-int v16, p25, v16

    move/from16 p7, v1

    if-eqz v16, :cond_15

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    goto :goto_15

    :cond_15
    move/from16 v1, p22

    :goto_15
    const/high16 v16, 0x400000

    and-int v16, p25, v16

    move/from16 p8, v1

    if-eqz v16, :cond_16

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    goto :goto_16

    :cond_16
    move/from16 v1, p23

    :goto_16
    const/high16 v16, 0x800000

    and-int v16, p25, v16

    if-eqz v16, :cond_17

    move/from16 p9, v1

    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    move/from16 p24, p9

    move/from16 p25, v1

    :goto_17
    move/from16 p17, p2

    move/from16 p18, p3

    move/from16 p19, p4

    move/from16 p20, p5

    move/from16 p21, p6

    move/from16 p22, p7

    move/from16 p23, p8

    move/from16 p16, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move/from16 p5, v5

    move/from16 p6, v6

    move/from16 p7, v7

    move/from16 p8, v8

    move/from16 p9, v9

    move/from16 p10, v10

    move/from16 p11, v11

    move/from16 p12, v12

    move/from16 p13, v13

    move/from16 p14, v14

    move/from16 p15, v15

    move/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_18

    :cond_17
    move/from16 p25, p24

    move/from16 p24, v1

    goto :goto_17

    :goto_18
    invoke-virtual/range {p1 .. p25}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->copy(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIII)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 2
    .line 3
    return p0
.end method

.method public final component10()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component11()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component12()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component13()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component14()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component15()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component16()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component17()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component18()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component19()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component21()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component22()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component23()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component24()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component5()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component6()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 2
    .line 3
    return p0
.end method

.method public final component7()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final component8()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final component9()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIII)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;
    .locals 26

    .line 1
    const-string v0, "parkingTrajLatestMove"

    move-object/from16 v3, p2

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingTrajDrivingDirection"

    move-object/from16 v4, p3

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    move/from16 v2, p1

    move/from16 v5, p4

    move/from16 v6, p5

    move/from16 v7, p6

    move/from16 v8, p7

    move/from16 v9, p8

    move/from16 v10, p9

    move/from16 v11, p10

    move/from16 v12, p11

    move/from16 v13, p12

    move/from16 v14, p13

    move/from16 v15, p14

    move/from16 v16, p15

    move/from16 v17, p16

    move/from16 v18, p17

    move/from16 v19, p18

    move/from16 v20, p19

    move/from16 v21, p20

    move/from16 v22, p21

    move/from16 v23, p22

    move/from16 v24, p23

    move/from16 v25, p24

    invoke-direct/range {v1 .. v25}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIII)V

    return-object v1
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 12
    .line 13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 14
    .line 15
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 21
    .line 22
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 28
    .line 29
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 35
    .line 36
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 42
    .line 43
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 49
    .line 50
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 56
    .line 57
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 58
    .line 59
    if-eq v1, v3, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 63
    .line 64
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 65
    .line 66
    if-eq v1, v3, :cond_9

    .line 67
    .line 68
    return v2

    .line 69
    :cond_9
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 70
    .line 71
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 72
    .line 73
    if-eq v1, v3, :cond_a

    .line 74
    .line 75
    return v2

    .line 76
    :cond_a
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 77
    .line 78
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 79
    .line 80
    if-eq v1, v3, :cond_b

    .line 81
    .line 82
    return v2

    .line 83
    :cond_b
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 84
    .line 85
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 86
    .line 87
    if-eq v1, v3, :cond_c

    .line 88
    .line 89
    return v2

    .line 90
    :cond_c
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 91
    .line 92
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 93
    .line 94
    if-eq v1, v3, :cond_d

    .line 95
    .line 96
    return v2

    .line 97
    :cond_d
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 98
    .line 99
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 100
    .line 101
    if-eq v1, v3, :cond_e

    .line 102
    .line 103
    return v2

    .line 104
    :cond_e
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 105
    .line 106
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 107
    .line 108
    if-eq v1, v3, :cond_f

    .line 109
    .line 110
    return v2

    .line 111
    :cond_f
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 112
    .line 113
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 114
    .line 115
    if-eq v1, v3, :cond_10

    .line 116
    .line 117
    return v2

    .line 118
    :cond_10
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 119
    .line 120
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 121
    .line 122
    if-eq v1, v3, :cond_11

    .line 123
    .line 124
    return v2

    .line 125
    :cond_11
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 126
    .line 127
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 128
    .line 129
    if-eq v1, v3, :cond_12

    .line 130
    .line 131
    return v2

    .line 132
    :cond_12
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 133
    .line 134
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 135
    .line 136
    if-eq v1, v3, :cond_13

    .line 137
    .line 138
    return v2

    .line 139
    :cond_13
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 140
    .line 141
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 142
    .line 143
    if-eq v1, v3, :cond_14

    .line 144
    .line 145
    return v2

    .line 146
    :cond_14
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 147
    .line 148
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 149
    .line 150
    if-eq v1, v3, :cond_15

    .line 151
    .line 152
    return v2

    .line 153
    :cond_15
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 154
    .line 155
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 156
    .line 157
    if-eq v1, v3, :cond_16

    .line 158
    .line 159
    return v2

    .line 160
    :cond_16
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 161
    .line 162
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 163
    .line 164
    if-eq v1, v3, :cond_17

    .line 165
    .line 166
    return v2

    .line 167
    :cond_17
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 168
    .line 169
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 170
    .line 171
    if-eq v1, v3, :cond_18

    .line 172
    .line 173
    return v2

    .line 174
    :cond_18
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 175
    .line 176
    iget p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 177
    .line 178
    if-eq p0, p1, :cond_19

    .line 179
    .line 180
    return v2

    .line 181
    :cond_19
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingTrajDrivingDirection()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingTrajLatestMove()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingTrajNumberPoints()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP1PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP1PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP2PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP2PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP3PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP3PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP4PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP4PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP5PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP5PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP6PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP6PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP7PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP7PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP8PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP8PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP9PosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajP9PosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajVehicleAngle()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajVehiclePosX()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 2
    .line 3
    return p0
.end method

.method public final getParkingTrajVehiclePosY()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

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
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 27
    .line 28
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 33
    .line 34
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 39
    .line 40
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 45
    .line 46
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 51
    .line 52
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 57
    .line 58
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 63
    .line 64
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 69
    .line 70
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 75
    .line 76
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 81
    .line 82
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 87
    .line 88
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 93
    .line 94
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 99
    .line 100
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 105
    .line 106
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 111
    .line 112
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 117
    .line 118
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 123
    .line 124
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 129
    .line 130
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 135
    .line 136
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 141
    .line 142
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 147
    .line 148
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    add-int/2addr p0, v0

    .line 153
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_NUMBER_POINTS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_LATEST_MOVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 30
    .line 31
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 32
    .line 33
    .line 34
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 35
    .line 36
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 39
    .line 40
    .line 41
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 42
    .line 43
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 44
    .line 45
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 46
    .line 47
    .line 48
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 49
    .line 50
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_VEHICLE_ANGLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 51
    .line 52
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 53
    .line 54
    .line 55
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 56
    .line 57
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P1_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 58
    .line 59
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 60
    .line 61
    .line 62
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 63
    .line 64
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P1_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 65
    .line 66
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 67
    .line 68
    .line 69
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 70
    .line 71
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P2_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 72
    .line 73
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 74
    .line 75
    .line 76
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 77
    .line 78
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P2_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 79
    .line 80
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 81
    .line 82
    .line 83
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 84
    .line 85
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P3_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 86
    .line 87
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 88
    .line 89
    .line 90
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 91
    .line 92
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P3_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 93
    .line 94
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 95
    .line 96
    .line 97
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 98
    .line 99
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P4_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 100
    .line 101
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 102
    .line 103
    .line 104
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 105
    .line 106
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P4_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 107
    .line 108
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 109
    .line 110
    .line 111
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 112
    .line 113
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P5_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 114
    .line 115
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 116
    .line 117
    .line 118
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 119
    .line 120
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P5_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 121
    .line 122
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 123
    .line 124
    .line 125
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 126
    .line 127
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P6_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 128
    .line 129
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 130
    .line 131
    .line 132
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 133
    .line 134
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P6_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 135
    .line 136
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 137
    .line 138
    .line 139
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 140
    .line 141
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P7_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 142
    .line 143
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 144
    .line 145
    .line 146
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 147
    .line 148
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P7_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 149
    .line 150
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 151
    .line 152
    .line 153
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 154
    .line 155
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P8_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 156
    .line 157
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 158
    .line 159
    .line 160
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 161
    .line 162
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P8_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 163
    .line 164
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 165
    .line 166
    .line 167
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 168
    .line 169
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P9_POS_X:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 170
    .line 171
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 172
    .line 173
    .line 174
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 175
    .line 176
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->PARKING_TRAJ_P9_POS_Y:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 177
    .line 178
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 179
    .line 180
    .line 181
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajNumberPoints:I

    .line 4
    .line 5
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajLatestMove:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;

    .line 6
    .line 7
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajDrivingDirection:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 8
    .line 9
    iget v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosX:I

    .line 10
    .line 11
    iget v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehiclePosY:I

    .line 12
    .line 13
    iget v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajVehicleAngle:I

    .line 14
    .line 15
    iget v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosX:I

    .line 16
    .line 17
    iget v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP1PosY:I

    .line 18
    .line 19
    iget v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosX:I

    .line 20
    .line 21
    iget v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP2PosY:I

    .line 22
    .line 23
    iget v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosX:I

    .line 24
    .line 25
    iget v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP3PosY:I

    .line 26
    .line 27
    iget v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosX:I

    .line 28
    .line 29
    iget v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP4PosY:I

    .line 30
    .line 31
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosX:I

    .line 32
    .line 33
    move/from16 v16, v15

    .line 34
    .line 35
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP5PosY:I

    .line 36
    .line 37
    move/from16 v17, v15

    .line 38
    .line 39
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosX:I

    .line 40
    .line 41
    move/from16 v18, v15

    .line 42
    .line 43
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP6PosY:I

    .line 44
    .line 45
    move/from16 v19, v15

    .line 46
    .line 47
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosX:I

    .line 48
    .line 49
    move/from16 v20, v15

    .line 50
    .line 51
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP7PosY:I

    .line 52
    .line 53
    move/from16 v21, v15

    .line 54
    .line 55
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosX:I

    .line 56
    .line 57
    move/from16 v22, v15

    .line 58
    .line 59
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP8PosY:I

    .line 60
    .line 61
    move/from16 v23, v15

    .line 62
    .line 63
    iget v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosX:I

    .line 64
    .line 65
    iget v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;->parkingTrajP9PosY:I

    .line 66
    .line 67
    move/from16 p0, v0

    .line 68
    .line 69
    new-instance v0, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    move/from16 v24, v15

    .line 72
    .line 73
    const-string v15, "C2PNormalPrioTrajectoryInfoMLB(parkingTrajNumberPoints="

    .line 74
    .line 75
    invoke-direct {v0, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", parkingTrajLatestMove="

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v1, ", parkingTrajDrivingDirection="

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", parkingTrajVehiclePosX="

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", parkingTrajVehiclePosY="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    const-string v1, ", parkingTrajVehicleAngle="

    .line 111
    .line 112
    const-string v2, ", parkingTrajP1PosX="

    .line 113
    .line 114
    invoke-static {v0, v5, v1, v6, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string v1, ", parkingTrajP1PosY="

    .line 118
    .line 119
    const-string v2, ", parkingTrajP2PosX="

    .line 120
    .line 121
    invoke-static {v0, v7, v1, v8, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 122
    .line 123
    .line 124
    const-string v1, ", parkingTrajP2PosY="

    .line 125
    .line 126
    const-string v2, ", parkingTrajP3PosX="

    .line 127
    .line 128
    invoke-static {v0, v9, v1, v10, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 129
    .line 130
    .line 131
    const-string v1, ", parkingTrajP3PosY="

    .line 132
    .line 133
    const-string v2, ", parkingTrajP4PosX="

    .line 134
    .line 135
    invoke-static {v0, v11, v1, v12, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 136
    .line 137
    .line 138
    const-string v1, ", parkingTrajP4PosY="

    .line 139
    .line 140
    const-string v2, ", parkingTrajP5PosX="

    .line 141
    .line 142
    invoke-static {v0, v13, v1, v14, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const-string v1, ", parkingTrajP5PosY="

    .line 146
    .line 147
    const-string v2, ", parkingTrajP6PosX="

    .line 148
    .line 149
    move/from16 v3, v16

    .line 150
    .line 151
    move/from16 v4, v17

    .line 152
    .line 153
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 154
    .line 155
    .line 156
    const-string v1, ", parkingTrajP6PosY="

    .line 157
    .line 158
    const-string v2, ", parkingTrajP7PosX="

    .line 159
    .line 160
    move/from16 v3, v18

    .line 161
    .line 162
    move/from16 v4, v19

    .line 163
    .line 164
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 165
    .line 166
    .line 167
    const-string v1, ", parkingTrajP7PosY="

    .line 168
    .line 169
    const-string v2, ", parkingTrajP8PosX="

    .line 170
    .line 171
    move/from16 v3, v20

    .line 172
    .line 173
    move/from16 v4, v21

    .line 174
    .line 175
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 176
    .line 177
    .line 178
    const-string v1, ", parkingTrajP8PosY="

    .line 179
    .line 180
    const-string v2, ", parkingTrajP9PosX="

    .line 181
    .line 182
    move/from16 v3, v22

    .line 183
    .line 184
    move/from16 v4, v23

    .line 185
    .line 186
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 187
    .line 188
    .line 189
    move/from16 v1, v24

    .line 190
    .line 191
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    const-string v1, ", parkingTrajP9PosY="

    .line 195
    .line 196
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    move/from16 v1, p0

    .line 200
    .line 201
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    const-string v1, ")"

    .line 205
    .line 206
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    return-object v0
.end method
