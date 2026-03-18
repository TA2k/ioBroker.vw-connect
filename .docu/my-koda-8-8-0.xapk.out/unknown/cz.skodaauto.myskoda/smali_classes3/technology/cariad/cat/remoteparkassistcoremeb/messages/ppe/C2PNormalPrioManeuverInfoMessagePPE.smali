.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0080\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u001d\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u000f\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 S2\u00020\u0001:\u0001SB\u0089\u0001\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\u000b\u0012\u0008\u0008\u0002\u0010\u000c\u001a\u00020\r\u0012\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u000f\u0012\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u0011\u0012\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u0013\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u0015\u0012\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u0017\u0012\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u0019\u0012\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u001b\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0008\u0010<\u001a\u00020=H\u0016J\t\u0010>\u001a\u00020\u0003H\u00c6\u0003J\t\u0010?\u001a\u00020\u0005H\u00c6\u0003J\t\u0010@\u001a\u00020\u0007H\u00c6\u0003J\t\u0010A\u001a\u00020\tH\u00c6\u0003J\t\u0010B\u001a\u00020\u000bH\u00c6\u0003J\t\u0010C\u001a\u00020\rH\u00c6\u0003J\t\u0010D\u001a\u00020\u000fH\u00c6\u0003J\t\u0010E\u001a\u00020\u0011H\u00c6\u0003J\t\u0010F\u001a\u00020\u0013H\u00c6\u0003J\t\u0010G\u001a\u00020\u0015H\u00c6\u0003J\t\u0010H\u001a\u00020\u0017H\u00c6\u0003J\t\u0010I\u001a\u00020\u0019H\u00c6\u0003J\t\u0010J\u001a\u00020\u001bH\u00c6\u0003J\u008b\u0001\u0010K\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000b2\u0008\u0008\u0002\u0010\u000c\u001a\u00020\r2\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u000f2\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u00112\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u00132\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u00152\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u00172\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u00192\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u001bH\u00c6\u0001J\u0013\u0010L\u001a\u00020M2\u0008\u0010N\u001a\u0004\u0018\u00010OH\u00d6\u0003J\t\u0010P\u001a\u00020\u0019H\u00d6\u0001J\t\u0010Q\u001a\u00020RH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001e\u0010\u001fR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008 \u0010!R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\"\u0010#R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008$\u0010%R\u0011\u0010\n\u001a\u00020\u000b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008&\u0010\'R\u0011\u0010\u000c\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008(\u0010)R\u0011\u0010\u000e\u001a\u00020\u000f\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008*\u0010+R\u0011\u0010\u0010\u001a\u00020\u0011\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008,\u0010-R\u0011\u0010\u0012\u001a\u00020\u0013\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008.\u0010/R\u0011\u0010\u0014\u001a\u00020\u0015\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00080\u00101R\u0011\u0010\u0016\u001a\u00020\u0017\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00082\u00103R\u0011\u0010\u0018\u001a\u00020\u0019\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00084\u00105R\u0011\u0010\u001a\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u00086\u00107R\u0014\u00108\u001a\u000209X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008:\u0010;\u00a8\u0006T"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "parkingManeuverDirectionSideStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;",
        "parkingManeuverType",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;",
        "customDriveAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;",
        "parkingManeuverDirectionSideAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;",
        "parkingManeuverTypeAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;",
        "parkingReversibleAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;",
        "standStillStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;",
        "driveReadinessRequestMode",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;",
        "keyStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;",
        "obstacleDetectedStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;",
        "remoteFunctionStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;",
        "progressBar",
        "",
        "degradationStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;)V",
        "getParkingManeuverDirectionSideStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;",
        "getParkingManeuverType",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;",
        "getCustomDriveAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;",
        "getParkingManeuverDirectionSideAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;",
        "getParkingManeuverTypeAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;",
        "getParkingReversibleAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;",
        "getStandStillStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;",
        "getDriveReadinessRequestMode",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;",
        "getKeyStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;",
        "getObstacleDetectedStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;",
        "getRemoteFunctionStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;",
        "getProgressBar",
        "()I",
        "getDegradationStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;",
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
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;

.field private static final SM_CUSTOM_DRIVE_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DEGRADATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_DRIVE_READINESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_KEY_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_MANEUVER_TYPE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_MANEUVER_TYPE_POSSIBLE_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_MANEUVER_TYPE_POSSIBLE_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_MANEUVER_TYPE_POSSIBLE_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_MANEUVER_TYPE_POSSIBLE_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_MANEUVER_TYPE_POSSIBLE_TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_PROGRESS_BAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_REVERSING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_STANDSTILL_REQUEST_P_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_STANDSTILL_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_STANDSTILL_VMM_STATUS_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_STANDSTILL_VMM_STATUS_P:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final SM_ST_ACV_REMOTE_FUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

.field private final driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

.field private final keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

.field private final obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

.field private final parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

.field private final parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

.field private final parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

.field private final parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

.field private final parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

.field private final progressBar:I

.field private final remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

.field private final standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;

    .line 8
    .line 9
    const/16 v0, 0x22

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->messageID:B

    .line 12
    .line 13
    const-wide v1, 0x5250400201000000L    # 3.232607119361011E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->address:J

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    sput-byte v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->priority:B

    .line 22
    .line 23
    const/4 v2, 0x7

    .line 24
    sput v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->byteLength:I

    .line 25
    .line 26
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v5, 0x5

    .line 30
    invoke-direct {v3, v4, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 31
    .line 32
    .line 33
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    const/4 v4, 0x3

    .line 38
    invoke-direct {v3, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 39
    .line 40
    .line 41
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 42
    .line 43
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 44
    .line 45
    const/16 v5, 0x8

    .line 46
    .line 47
    const/4 v6, 0x1

    .line 48
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 49
    .line 50
    .line 51
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_CUSTOM_DRIVE_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 52
    .line 53
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 54
    .line 55
    const/16 v5, 0x9

    .line 56
    .line 57
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 58
    .line 59
    .line 60
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 61
    .line 62
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 63
    .line 64
    const/16 v5, 0xa

    .line 65
    .line 66
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 67
    .line 68
    .line 69
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 70
    .line 71
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 72
    .line 73
    const/16 v5, 0xb

    .line 74
    .line 75
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 76
    .line 77
    .line 78
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 79
    .line 80
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    const/16 v5, 0xc

    .line 83
    .line 84
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 85
    .line 86
    .line 87
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 88
    .line 89
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 90
    .line 91
    const/16 v5, 0xd

    .line 92
    .line 93
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 94
    .line 95
    .line 96
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 97
    .line 98
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 99
    .line 100
    const/16 v5, 0xe

    .line 101
    .line 102
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 103
    .line 104
    .line 105
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 106
    .line 107
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 108
    .line 109
    const/16 v5, 0xf

    .line 110
    .line 111
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 112
    .line 113
    .line 114
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 115
    .line 116
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 117
    .line 118
    const/16 v5, 0x10

    .line 119
    .line 120
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 121
    .line 122
    .line 123
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 124
    .line 125
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 126
    .line 127
    const/16 v5, 0x11

    .line 128
    .line 129
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 130
    .line 131
    .line 132
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 133
    .line 134
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 135
    .line 136
    const/16 v5, 0x12

    .line 137
    .line 138
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 139
    .line 140
    .line 141
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 142
    .line 143
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 144
    .line 145
    const/16 v5, 0x13

    .line 146
    .line 147
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 148
    .line 149
    .line 150
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 151
    .line 152
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 153
    .line 154
    const/16 v5, 0x14

    .line 155
    .line 156
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 157
    .line 158
    .line 159
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 160
    .line 161
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 162
    .line 163
    const/16 v5, 0x15

    .line 164
    .line 165
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 166
    .line 167
    .line 168
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 169
    .line 170
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 171
    .line 172
    const/16 v5, 0x16

    .line 173
    .line 174
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 175
    .line 176
    .line 177
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 178
    .line 179
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 180
    .line 181
    const/16 v5, 0x17

    .line 182
    .line 183
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 184
    .line 185
    .line 186
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 187
    .line 188
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 189
    .line 190
    const/16 v5, 0x18

    .line 191
    .line 192
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 193
    .line 194
    .line 195
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 196
    .line 197
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 198
    .line 199
    const/16 v5, 0x19

    .line 200
    .line 201
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 202
    .line 203
    .line 204
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 205
    .line 206
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 207
    .line 208
    const/16 v5, 0x1a

    .line 209
    .line 210
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 211
    .line 212
    .line 213
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 214
    .line 215
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 216
    .line 217
    const/16 v5, 0x1b

    .line 218
    .line 219
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 220
    .line 221
    .line 222
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 223
    .line 224
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 225
    .line 226
    const/16 v5, 0x1c

    .line 227
    .line 228
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 229
    .line 230
    .line 231
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 232
    .line 233
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 234
    .line 235
    const/16 v5, 0x1d

    .line 236
    .line 237
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 238
    .line 239
    .line 240
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 241
    .line 242
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 243
    .line 244
    const/16 v5, 0x1e

    .line 245
    .line 246
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 247
    .line 248
    .line 249
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 250
    .line 251
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 252
    .line 253
    const/16 v5, 0x1f

    .line 254
    .line 255
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 256
    .line 257
    .line 258
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 259
    .line 260
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 261
    .line 262
    const/16 v5, 0x20

    .line 263
    .line 264
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 265
    .line 266
    .line 267
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_REVERSING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 268
    .line 269
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 270
    .line 271
    const/16 v5, 0x21

    .line 272
    .line 273
    invoke-direct {v3, v5, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 274
    .line 275
    .line 276
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 277
    .line 278
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 279
    .line 280
    invoke-direct {v3, v0, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 281
    .line 282
    .line 283
    sput-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_REQUEST_P_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 284
    .line 285
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 286
    .line 287
    const/16 v3, 0x23

    .line 288
    .line 289
    invoke-direct {v0, v3, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 290
    .line 291
    .line 292
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_VMM_STATUS_P:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 293
    .line 294
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 295
    .line 296
    const/16 v3, 0x24

    .line 297
    .line 298
    invoke-direct {v0, v3, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 299
    .line 300
    .line 301
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_VMM_STATUS_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 302
    .line 303
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 304
    .line 305
    const/16 v3, 0x25

    .line 306
    .line 307
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 308
    .line 309
    .line 310
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DRIVE_READINESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 311
    .line 312
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 313
    .line 314
    const/16 v3, 0x27

    .line 315
    .line 316
    invoke-direct {v0, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 317
    .line 318
    .line 319
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_KEY_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 320
    .line 321
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 322
    .line 323
    const/16 v3, 0x2a

    .line 324
    .line 325
    invoke-direct {v0, v3, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 326
    .line 327
    .line 328
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 329
    .line 330
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 331
    .line 332
    const/16 v3, 0x2b

    .line 333
    .line 334
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 335
    .line 336
    .line 337
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_ST_ACV_REMOTE_FUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 338
    .line 339
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 340
    .line 341
    const/16 v1, 0x2d

    .line 342
    .line 343
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 344
    .line 345
    .line 346
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_PROGRESS_BAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 347
    .line 348
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 349
    .line 350
    const/16 v1, 0x34

    .line 351
    .line 352
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 353
    .line 354
    .line 355
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DEGRADATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 356
    .line 357
    return-void
.end method

.method public constructor <init>()V
    .locals 16

    .line 1
    const/16 v14, 0x1fff

    const/4 v15, 0x0

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

    move-object/from16 v0, p0

    invoke-direct/range {v0 .. v15}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;)V
    .locals 1

    const-string v0, "parkingManeuverDirectionSideStatus"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingManeuverType"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "customDriveAvailability"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingManeuverDirectionSideAvailability"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingManeuverTypeAvailability"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingReversibleAvailability"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "standStillStatus"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "driveReadinessRequestMode"

    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "keyStatus"

    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "obstacleDetectedStatus"

    invoke-static {p10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "remoteFunctionStatus"

    invoke-static {p11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "degradationStatus"

    invoke-static {p13, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 4
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 6
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 7
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 8
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 9
    iput-object p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 10
    iput-object p8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 11
    iput-object p9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 12
    iput-object p10, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 13
    iput-object p11, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 14
    iput p12, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 15
    iput-object p13, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 16
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;ILkotlin/jvm/internal/g;)V
    .locals 26

    move/from16 v0, p14

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 17
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    goto :goto_0

    :cond_0
    move-object/from16 v1, p1

    :goto_0
    and-int/lit8 v2, v0, 0x2

    if-eqz v2, :cond_1

    .line 18
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    goto :goto_1

    :cond_1
    move-object/from16 v2, p2

    :goto_1
    and-int/lit8 v3, v0, 0x4

    if-eqz v3, :cond_2

    .line 19
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;->NOT_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    goto :goto_2

    :cond_2
    move-object/from16 v3, p3

    :goto_2
    and-int/lit8 v4, v0, 0x8

    if-eqz v4, :cond_3

    .line 20
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    const v24, 0x3ffff

    const/16 v25, 0x0

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

    invoke-direct/range {v5 .. v25}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;-><init>(ZZZZZZZZZZZZZZZZZZILkotlin/jvm/internal/g;)V

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v4, v0, 0x10

    if-eqz v4, :cond_4

    .line 21
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    const/16 v12, 0x1f

    const/4 v13, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-direct/range {v6 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;-><init>(ZZZZZILkotlin/jvm/internal/g;)V

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v4, v0, 0x20

    if-eqz v4, :cond_5

    .line 22
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;->NOT_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    goto :goto_5

    :cond_5
    move-object/from16 v4, p6

    :goto_5
    and-int/lit8 v7, v0, 0x40

    if-eqz v7, :cond_6

    .line 23
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    const/16 v8, 0xf

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-object/from16 p1, v7

    move/from16 p6, v8

    move-object/from16 p7, v9

    move/from16 p2, v10

    move/from16 p3, v11

    move/from16 p4, v12

    move/from16 p5, v13

    invoke-direct/range {p1 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;-><init>(ZZZZILkotlin/jvm/internal/g;)V

    goto :goto_6

    :cond_6
    move-object/from16 v7, p7

    :goto_6
    and-int/lit16 v8, v0, 0x80

    if-eqz v8, :cond_7

    .line 24
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    goto :goto_7

    :cond_7
    move-object/from16 v8, p8

    :goto_7
    and-int/lit16 v9, v0, 0x100

    if-eqz v9, :cond_8

    .line 25
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    goto :goto_8

    :cond_8
    move-object/from16 v9, p9

    :goto_8
    and-int/lit16 v10, v0, 0x200

    if-eqz v10, :cond_9

    .line 26
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;->NOT_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    goto :goto_9

    :cond_9
    move-object/from16 v10, p10

    :goto_9
    and-int/lit16 v11, v0, 0x400

    if-eqz v11, :cond_a

    .line 27
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;->NO_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    goto :goto_a

    :cond_a
    move-object/from16 v11, p11

    :goto_a
    and-int/lit16 v12, v0, 0x800

    if-eqz v12, :cond_b

    const/16 v12, 0x7f

    goto :goto_b

    :cond_b
    move/from16 v12, p12

    :goto_b
    and-int/lit16 v0, v0, 0x1000

    if-eqz v0, :cond_c

    .line 28
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;->NONE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    move-object/from16 p14, v0

    :goto_c
    move-object/from16 p1, p0

    move-object/from16 p2, v1

    move-object/from16 p3, v2

    move-object/from16 p4, v3

    move-object/from16 p7, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move-object/from16 p8, v7

    move-object/from16 p9, v8

    move-object/from16 p10, v9

    move-object/from16 p11, v10

    move-object/from16 p12, v11

    move/from16 p13, v12

    goto :goto_d

    :cond_c
    move-object/from16 p14, p13

    goto :goto_c

    .line 29
    :goto_d
    invoke-direct/range {p1 .. p14}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getSM_CUSTOM_DRIVE_POSSIBLE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_CUSTOM_DRIVE_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DEGRADATION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DEGRADATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_ACTIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_DRIVE_READINESS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DRIVE_READINESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_KEY_STATUS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_KEY_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_MANEUVER_TYPE_ACTIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_MANEUVER_TYPE_POSSIBLE_BASIC$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_MANEUVER_TYPE_POSSIBLE_GARAGE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_MANEUVER_TYPE_POSSIBLE_PARALLEL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_MANEUVER_TYPE_POSSIBLE_PERPENDICULAR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_MANEUVER_TYPE_POSSIBLE_TPA$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_OBSTACLE_DETECTED$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_PROGRESS_BAR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_PROGRESS_BAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_REVERSING_POSSIBLE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_REVERSING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_STANDSTILL_REQUEST_P_EPB$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_REQUEST_P_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_STANDSTILL_STANDSTILL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_STANDSTILL_VMM_STATUS_EPB$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_VMM_STATUS_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_STANDSTILL_VMM_STATUS_P$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_VMM_STATUS_P:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSM_ST_ACV_REMOTE_FUNCTION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_ST_ACV_REMOTE_FUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;
    .locals 12

    .line 1
    move/from16 v0, p14

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    :cond_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    goto :goto_0

    :cond_1
    move-object v1, p2

    :goto_0
    and-int/lit8 v2, v0, 0x4

    if-eqz v2, :cond_2

    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    goto :goto_1

    :cond_2
    move-object v2, p3

    :goto_1
    and-int/lit8 v3, v0, 0x8

    if-eqz v3, :cond_3

    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    goto :goto_2

    :cond_3
    move-object/from16 v3, p4

    :goto_2
    and-int/lit8 v4, v0, 0x10

    if-eqz v4, :cond_4

    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    goto :goto_3

    :cond_4
    move-object/from16 v4, p5

    :goto_3
    and-int/lit8 v5, v0, 0x20

    if-eqz v5, :cond_5

    iget-object v5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    goto :goto_4

    :cond_5
    move-object/from16 v5, p6

    :goto_4
    and-int/lit8 v6, v0, 0x40

    if-eqz v6, :cond_6

    iget-object v6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    goto :goto_5

    :cond_6
    move-object/from16 v6, p7

    :goto_5
    and-int/lit16 v7, v0, 0x80

    if-eqz v7, :cond_7

    iget-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    goto :goto_6

    :cond_7
    move-object/from16 v7, p8

    :goto_6
    and-int/lit16 v8, v0, 0x100

    if-eqz v8, :cond_8

    iget-object v8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    goto :goto_7

    :cond_8
    move-object/from16 v8, p9

    :goto_7
    and-int/lit16 v9, v0, 0x200

    if-eqz v9, :cond_9

    iget-object v9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    goto :goto_8

    :cond_9
    move-object/from16 v9, p10

    :goto_8
    and-int/lit16 v10, v0, 0x400

    if-eqz v10, :cond_a

    iget-object v10, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    goto :goto_9

    :cond_a
    move-object/from16 v10, p11

    :goto_9
    and-int/lit16 v11, v0, 0x800

    if-eqz v11, :cond_b

    iget v11, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    goto :goto_a

    :cond_b
    move/from16 v11, p12

    :goto_a
    and-int/lit16 v0, v0, 0x1000

    if-eqz v0, :cond_c

    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    move-object/from16 p15, v0

    :goto_b
    move-object p2, p0

    move-object p3, p1

    move-object/from16 p4, v1

    move-object/from16 p5, v2

    move-object/from16 p6, v3

    move-object/from16 p7, v4

    move-object/from16 p8, v5

    move-object/from16 p9, v6

    move-object/from16 p10, v7

    move-object/from16 p11, v8

    move-object/from16 p12, v9

    move-object/from16 p13, v10

    move/from16 p14, v11

    goto :goto_c

    :cond_c
    move-object/from16 p15, p13

    goto :goto_b

    :goto_c
    invoke-virtual/range {p2 .. p15}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 2
    .line 3
    return p0
.end method

.method public final component13()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;
    .locals 14

    .line 1
    const-string p0, "parkingManeuverDirectionSideStatus"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "parkingManeuverType"

    .line 7
    .line 8
    move-object/from16 v2, p2

    .line 9
    .line 10
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "customDriveAvailability"

    .line 14
    .line 15
    move-object/from16 v3, p3

    .line 16
    .line 17
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string p0, "parkingManeuverDirectionSideAvailability"

    .line 21
    .line 22
    move-object/from16 v4, p4

    .line 23
    .line 24
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string p0, "parkingManeuverTypeAvailability"

    .line 28
    .line 29
    move-object/from16 v5, p5

    .line 30
    .line 31
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string p0, "parkingReversibleAvailability"

    .line 35
    .line 36
    move-object/from16 v6, p6

    .line 37
    .line 38
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string p0, "standStillStatus"

    .line 42
    .line 43
    move-object/from16 v7, p7

    .line 44
    .line 45
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string p0, "driveReadinessRequestMode"

    .line 49
    .line 50
    move-object/from16 v8, p8

    .line 51
    .line 52
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    const-string p0, "keyStatus"

    .line 56
    .line 57
    move-object/from16 v9, p9

    .line 58
    .line 59
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    const-string p0, "obstacleDetectedStatus"

    .line 63
    .line 64
    move-object/from16 v10, p10

    .line 65
    .line 66
    invoke-static {v10, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    const-string p0, "remoteFunctionStatus"

    .line 70
    .line 71
    move-object/from16 v11, p11

    .line 72
    .line 73
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const-string p0, "degradationStatus"

    .line 77
    .line 78
    move-object/from16 v13, p13

    .line 79
    .line 80
    invoke-static {v13, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 84
    .line 85
    move-object v1, p1

    .line 86
    move/from16 v12, p12

    .line 87
    .line 88
    invoke-direct/range {v0 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;)V

    .line 89
    .line 90
    .line 91
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 21
    .line 22
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 28
    .line 29
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 35
    .line 36
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 37
    .line 38
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-nez v1, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 46
    .line 47
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 48
    .line 49
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 57
    .line 58
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 59
    .line 60
    if-eq v1, v3, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 64
    .line 65
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 75
    .line 76
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 77
    .line 78
    if-eq v1, v3, :cond_9

    .line 79
    .line 80
    return v2

    .line 81
    :cond_9
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 82
    .line 83
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 84
    .line 85
    if-eq v1, v3, :cond_a

    .line 86
    .line 87
    return v2

    .line 88
    :cond_a
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 89
    .line 90
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 91
    .line 92
    if-eq v1, v3, :cond_b

    .line 93
    .line 94
    return v2

    .line 95
    :cond_b
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 96
    .line 97
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 98
    .line 99
    if-eq v1, v3, :cond_c

    .line 100
    .line 101
    return v2

    .line 102
    :cond_c
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 103
    .line 104
    iget v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 105
    .line 106
    if-eq v1, v3, :cond_d

    .line 107
    .line 108
    return v2

    .line 109
    :cond_d
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 110
    .line 111
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 112
    .line 113
    if-eq p0, p1, :cond_e

    .line 114
    .line 115
    return v2

    .line 116
    :cond_e
    return v0
.end method

.method public final getCustomDriveAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDegradationStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDriveReadinessRequestMode()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getKeyStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getObstacleDetectedStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuverDirectionSideAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuverType()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuverTypeAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingReversibleAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getProgressBar()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 2
    .line 3
    return p0
.end method

.method public final getRemoteFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStandStillStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

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
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 27
    .line 28
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 35
    .line 36
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    add-int/2addr v0, v2

    .line 41
    mul-int/2addr v0, v1

    .line 42
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    add-int/2addr v2, v0

    .line 49
    mul-int/2addr v2, v1

    .line 50
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 51
    .line 52
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->hashCode()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    add-int/2addr v0, v2

    .line 57
    mul-int/2addr v0, v1

    .line 58
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    add-int/2addr v2, v0

    .line 65
    mul-int/2addr v2, v1

    .line 66
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    add-int/2addr v0, v2

    .line 73
    mul-int/2addr v0, v1

    .line 74
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    add-int/2addr v2, v0

    .line 81
    mul-int/2addr v2, v1

    .line 82
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 83
    .line 84
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    add-int/2addr v0, v2

    .line 89
    mul-int/2addr v0, v1

    .line 90
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 91
    .line 92
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    add-int/2addr p0, v0

    .line 103
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 12
    .line 13
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_CUSTOM_DRIVE_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 39
    .line 40
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isLeftForwardParkingOutAvailable()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 50
    .line 51
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isStraightForwardParkingOutAvailable()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 56
    .line 57
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 61
    .line 62
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isRightForwardParkingOutAvailable()Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 72
    .line 73
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isLeftBackwardParkingOutAvailable()Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 78
    .line 79
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 80
    .line 81
    .line 82
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 83
    .line 84
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isStraightBackwardParkingOutAvailable()Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 89
    .line 90
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 91
    .line 92
    .line 93
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 94
    .line 95
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isRightBackwardParkingOutAvailable()Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 100
    .line 101
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 102
    .line 103
    .line 104
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 105
    .line 106
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isLeftParallelParkingOutAvailable()Z

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 111
    .line 112
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 113
    .line 114
    .line 115
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 116
    .line 117
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isRightParallelParkingOutAvailable()Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 122
    .line 123
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 124
    .line 125
    .line 126
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 127
    .line 128
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isLeftForwardParkingInAvailable()Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 133
    .line 134
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 135
    .line 136
    .line 137
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 138
    .line 139
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isStraightForwardParkingInAvailable()Z

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 144
    .line 145
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 146
    .line 147
    .line 148
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 149
    .line 150
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isRightForwardParkingInAvailable()Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 155
    .line 156
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 157
    .line 158
    .line 159
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 160
    .line 161
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isLeftBackwardParkingInAvailable()Z

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 166
    .line 167
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 168
    .line 169
    .line 170
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 171
    .line 172
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isStraightBackwardParkingInAvailable()Z

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_STRAIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 177
    .line 178
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 179
    .line 180
    .line 181
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 182
    .line 183
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isRightBackwardParkingInAvailable()Z

    .line 184
    .line 185
    .line 186
    move-result v1

    .line 187
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 188
    .line 189
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 190
    .line 191
    .line 192
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 193
    .line 194
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isLeftParallelParkingInAvailable()Z

    .line 195
    .line 196
    .line 197
    move-result v1

    .line 198
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_LEFT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 199
    .line 200
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 201
    .line 202
    .line 203
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 204
    .line 205
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isRightParallelParkingInAvailable()Z

    .line 206
    .line 207
    .line 208
    move-result v1

    .line 209
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_RIGHT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 210
    .line 211
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 212
    .line 213
    .line 214
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 215
    .line 216
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isTrainedParkingOutAvailable()Z

    .line 217
    .line 218
    .line 219
    move-result v1

    .line 220
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 221
    .line 222
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 223
    .line 224
    .line 225
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 226
    .line 227
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;->isTrainedParkingInAvailable()Z

    .line 228
    .line 229
    .line 230
    move-result v1

    .line 231
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DIRECTION_SIDE_POSSIBLE_TRAINED_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 232
    .line 233
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 234
    .line 235
    .line 236
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 237
    .line 238
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;->isParallelManeuverAvailable()Z

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 243
    .line 244
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 245
    .line 246
    .line 247
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 248
    .line 249
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;->isPerpendicularManeuverAvailable()Z

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 254
    .line 255
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 256
    .line 257
    .line 258
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 259
    .line 260
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;->isGarageManeuverAvailable()Z

    .line 261
    .line 262
    .line 263
    move-result v1

    .line 264
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 265
    .line 266
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 267
    .line 268
    .line 269
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 270
    .line 271
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;->isBasicManeuverAvailable()Z

    .line 272
    .line 273
    .line 274
    move-result v1

    .line 275
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 276
    .line 277
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 278
    .line 279
    .line 280
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 281
    .line 282
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;->isTPAManeuverAvailable()Z

    .line 283
    .line 284
    .line 285
    move-result v1

    .line 286
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_MANEUVER_TYPE_POSSIBLE_TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 287
    .line 288
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 289
    .line 290
    .line 291
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 292
    .line 293
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 294
    .line 295
    .line 296
    move-result v1

    .line 297
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_REVERSING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 298
    .line 299
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 300
    .line 301
    .line 302
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 303
    .line 304
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->getStandStill()Z

    .line 305
    .line 306
    .line 307
    move-result v1

    .line 308
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 309
    .line 310
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 311
    .line 312
    .line 313
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 314
    .line 315
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->getRequest_P_EPB()Z

    .line 316
    .line 317
    .line 318
    move-result v1

    .line 319
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_REQUEST_P_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 320
    .line 321
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 322
    .line 323
    .line 324
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 325
    .line 326
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->getVmm_P()Z

    .line 327
    .line 328
    .line 329
    move-result v1

    .line 330
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_VMM_STATUS_P:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 331
    .line 332
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 333
    .line 334
    .line 335
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 336
    .line 337
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->getVmm_EPB()Z

    .line 338
    .line 339
    .line 340
    move-result v1

    .line 341
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_STANDSTILL_VMM_STATUS_EPB:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 342
    .line 343
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 344
    .line 345
    .line 346
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 347
    .line 348
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 349
    .line 350
    .line 351
    move-result v1

    .line 352
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DRIVE_READINESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 353
    .line 354
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 355
    .line 356
    .line 357
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 358
    .line 359
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 360
    .line 361
    .line 362
    move-result v1

    .line 363
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_KEY_STATUS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 364
    .line 365
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 366
    .line 367
    .line 368
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 369
    .line 370
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 371
    .line 372
    .line 373
    move-result v1

    .line 374
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 375
    .line 376
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 377
    .line 378
    .line 379
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 380
    .line 381
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 382
    .line 383
    .line 384
    move-result v1

    .line 385
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_ST_ACV_REMOTE_FUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 386
    .line 387
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 388
    .line 389
    .line 390
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 391
    .line 392
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_PROGRESS_BAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 393
    .line 394
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 395
    .line 396
    .line 397
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 398
    .line 399
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 400
    .line 401
    .line 402
    move-result p0

    .line 403
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->SM_DEGRADATION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 404
    .line 405
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 406
    .line 407
    .line 408
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 409
    .line 410
    .line 411
    move-result-object p0

    .line 412
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 14

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverType:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->customDriveAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/CustomDriveAvailabilityPPE;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverDirectionSideAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideAvailabilityPPE;

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingManeuverTypeAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypeAvailabilityPPE;

    .line 10
    .line 11
    iget-object v5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->parkingReversibleAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingReversibleAvailabilityPPE;

    .line 12
    .line 13
    iget-object v6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->standStillStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 14
    .line 15
    iget-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->driveReadinessRequestMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 16
    .line 17
    iget-object v8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->keyStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 18
    .line 19
    iget-object v9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->obstacleDetectedStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 20
    .line 21
    iget-object v10, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->remoteFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/RemoteFunctionStatusPPE;

    .line 22
    .line 23
    iget v11, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->progressBar:I

    .line 24
    .line 25
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->degradationStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DegradationStatusPPE;

    .line 26
    .line 27
    new-instance v12, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v13, "C2PNormalPrioManeuverInfoMessagePPE(parkingManeuverDirectionSideStatus="

    .line 30
    .line 31
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v0, ", parkingManeuverType="

    .line 38
    .line 39
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v12, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v0, ", customDriveAvailability="

    .line 46
    .line 47
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v12, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v0, ", parkingManeuverDirectionSideAvailability="

    .line 54
    .line 55
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v12, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v0, ", parkingManeuverTypeAvailability="

    .line 62
    .line 63
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v12, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v0, ", parkingReversibleAvailability="

    .line 70
    .line 71
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v12, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v0, ", standStillStatus="

    .line 78
    .line 79
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v12, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v0, ", driveReadinessRequestMode="

    .line 86
    .line 87
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v12, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v0, ", keyStatus="

    .line 94
    .line 95
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v12, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v0, ", obstacleDetectedStatus="

    .line 102
    .line 103
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v12, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v0, ", remoteFunctionStatus="

    .line 110
    .line 111
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v12, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v0, ", progressBar="

    .line 118
    .line 119
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v12, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    const-string v0, ", degradationStatus="

    .line 126
    .line 127
    invoke-virtual {v12, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v12, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string p0, ")"

    .line 134
    .line 135
    invoke-virtual {v12, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0
.end method
