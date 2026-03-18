.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\r\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0010\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u001e\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 T2\u00020\u0001:\u0001TB\u00d9\u0001\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\t\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\r\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u0011\u0012\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u0013\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u0015\u0012\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u0015\u0012\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u0015\u0012\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u0015\u0012\u0008\u0008\u0002\u0010\u0019\u001a\u00020\u0015\u0012\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u001b\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0008\u0010/\u001a\u000200H\u0016J\t\u00107\u001a\u00020\u0003H\u00c6\u0003J\t\u00108\u001a\u00020\u0003H\u00c6\u0003J\t\u00109\u001a\u00020\u0003H\u00c6\u0003J\t\u0010:\u001a\u00020\u0003H\u00c6\u0003J\t\u0010;\u001a\u00020\u0003H\u00c6\u0003J\t\u0010<\u001a\u00020\u0003H\u00c6\u0003J\t\u0010=\u001a\u00020\u0003H\u00c6\u0003J\t\u0010>\u001a\u00020\u0003H\u00c6\u0003J\t\u0010?\u001a\u00020\u0003H\u00c6\u0003J\t\u0010@\u001a\u00020\u0003H\u00c6\u0003J\t\u0010A\u001a\u00020\u0003H\u00c6\u0003J\t\u0010B\u001a\u00020\u0003H\u00c6\u0003J\t\u0010C\u001a\u00020\u0003H\u00c6\u0003J\t\u0010D\u001a\u00020\u0011H\u00c6\u0003J\t\u0010E\u001a\u00020\u0013H\u00c6\u0003J\t\u0010F\u001a\u00020\u0015H\u00c6\u0003J\t\u0010G\u001a\u00020\u0015H\u00c6\u0003J\t\u0010H\u001a\u00020\u0015H\u00c6\u0003J\t\u0010I\u001a\u00020\u0015H\u00c6\u0003J\t\u0010J\u001a\u00020\u0015H\u00c6\u0003J\t\u0010K\u001a\u00020\u001bH\u00c6\u0003J\u00db\u0001\u0010L\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0008\u001a\u00020\u00032\u0008\u0008\u0002\u0010\t\u001a\u00020\u00032\u0008\u0008\u0002\u0010\n\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000c\u001a\u00020\u00032\u0008\u0008\u0002\u0010\r\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u00112\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u00132\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u00152\u0008\u0008\u0002\u0010\u0016\u001a\u00020\u00152\u0008\u0008\u0002\u0010\u0017\u001a\u00020\u00152\u0008\u0008\u0002\u0010\u0018\u001a\u00020\u00152\u0008\u0008\u0002\u0010\u0019\u001a\u00020\u00152\u0008\u0008\u0002\u0010\u001a\u001a\u00020\u001bH\u00c6\u0001J\u0013\u0010M\u001a\u00020\u00032\u0008\u0010N\u001a\u0004\u0018\u00010OH\u00d6\u0003J\t\u0010P\u001a\u00020QH\u00d6\u0001J\t\u0010R\u001a\u00020SH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0002\u0010\u001eR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0004\u0010\u001eR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0005\u0010\u001eR\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u001eR\u0011\u0010\u0007\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0007\u0010\u001eR\u0011\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\u001eR\u0011\u0010\t\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\u001eR\u0011\u0010\n\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u001eR\u0011\u0010\u000b\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u001eR\u0011\u0010\u000c\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\u001eR\u0011\u0010\r\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u001eR\u0011\u0010\u000e\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\u001eR\u0011\u0010\u000f\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u001eR\u0011\u0010\u0010\u001a\u00020\u0011\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001f\u0010 R\u0011\u0010\u0012\u001a\u00020\u0013\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008!\u0010\"R\u0011\u0010\u0014\u001a\u00020\u0015\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008#\u0010$R\u0011\u0010\u0016\u001a\u00020\u0015\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008%\u0010$R\u0011\u0010\u0017\u001a\u00020\u0015\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008&\u0010$R\u0011\u0010\u0018\u001a\u00020\u0015\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\'\u0010$R\u0011\u0010\u0019\u001a\u00020\u0015\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008(\u0010$R\u0011\u0010\u001a\u001a\u00020\u001b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008)\u0010*R\u0014\u0010+\u001a\u00020,X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008-\u0010.R\u0014\u00101\u001a\u00020\u00038@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u00082\u0010\u001eR\u0014\u00103\u001a\u00020\u00038@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u00084\u0010\u001eR\u0014\u00105\u001a\u00020\u00038@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u00086\u0010\u001e\u00a8\u0006U"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "isCentralLockingInternalActive",
        "",
        "isCentralLockingExternalActive",
        "isDoorOpenDriverSideFront",
        "isDoorOpenPassengerSideFront",
        "isDoorOpenDriverSideRear",
        "isDoorOpenPassengerSideRear",
        "isTrunkOpen",
        "isBluetoothRequired",
        "isKeyAvailable",
        "isDoorOpen",
        "isTrailerDetected",
        "isSensorDirty",
        "isGearLevelCorrect",
        "activeRemoteSystem",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;",
        "activeControlElement",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;",
        "windowStatusDriverSideFront",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "windowStatusPassengerSideFront",
        "windowStatusDriverSideRear",
        "windowStatusPassengerSideRear",
        "sunroofOpeningPercentage",
        "sunroofMode",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;",
        "<init>",
        "(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;)V",
        "()Z",
        "getActiveRemoteSystem",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;",
        "getActiveControlElement",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;",
        "getWindowStatusDriverSideFront",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "getWindowStatusPassengerSideFront",
        "getWindowStatusDriverSideRear",
        "getWindowStatusPassengerSideRear",
        "getSunroofOpeningPercentage",
        "getSunroofMode",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "getDefinition",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;",
        "toBytes",
        "",
        "hasOpenWindows",
        "getHasOpenWindows$remoteparkassistcoremeb_release",
        "hasOpenDoorsOrFlaps",
        "getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release",
        "isVehicleLocked",
        "isVehicleLocked$remoteparkassistcoremeb_release",
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
        "copy",
        "equals",
        "other",
        "",
        "hashCode",
        "",
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
.field private static final BT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;

.field private static final FT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final HBFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final HFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final MD1_LAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_ACTIVE_CONTROL_ELEMENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_BT_REQUIRED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SM_ACTIVE_REMOTE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SM_DOORS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SM_GEAR_LEVEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SM_KEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SM_SENSOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SM_TRAILER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

.field private final activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isBluetoothRequired:Z

.field private final isCentralLockingExternalActive:Z

.field private final isCentralLockingInternalActive:Z

.field private final isDoorOpen:Z

.field private final isDoorOpenDriverSideFront:Z

.field private final isDoorOpenDriverSideRear:Z

.field private final isDoorOpenPassengerSideFront:Z

.field private final isDoorOpenPassengerSideRear:Z

.field private final isGearLevelCorrect:Z

.field private final isKeyAvailable:Z

.field private final isSensorDirty:Z

.field private final isTrailerDetected:Z

.field private final isTrunkOpen:Z

.field private final sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

.field private final sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

.field private final windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;

    .line 8
    .line 9
    const/16 v0, 0x23

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250410401000000L    # 3.23339025775819E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->address:J

    .line 19
    .line 20
    const/4 v0, 0x3

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->priority:B

    .line 22
    .line 23
    const/16 v1, 0x8

    .line 24
    .line 25
    sput v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->byteLength:I

    .line 26
    .line 27
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    const/4 v4, 0x1

    .line 31
    invoke-direct {v2, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 32
    .line 33
    .line 34
    sput-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 35
    .line 36
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 37
    .line 38
    invoke-direct {v2, v4, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 39
    .line 40
    .line 41
    sput-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 42
    .line 43
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 44
    .line 45
    const/4 v3, 0x2

    .line 46
    invoke-direct {v2, v3, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 47
    .line 48
    .line 49
    sput-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 52
    .line 53
    invoke-direct {v2, v0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 54
    .line 55
    .line 56
    sput-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 57
    .line 58
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 59
    .line 60
    const/4 v2, 0x4

    .line 61
    invoke-direct {v0, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 62
    .line 63
    .line 64
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 65
    .line 66
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 67
    .line 68
    const/4 v2, 0x5

    .line 69
    invoke-direct {v0, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 70
    .line 71
    .line 72
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 73
    .line 74
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 75
    .line 76
    const/4 v2, 0x6

    .line 77
    invoke-direct {v0, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 83
    .line 84
    const/4 v2, 0x7

    .line 85
    invoke-direct {v0, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 86
    .line 87
    .line 88
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_BT_REQUIRED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 89
    .line 90
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 91
    .line 92
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 93
    .line 94
    .line 95
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_KEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 96
    .line 97
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 98
    .line 99
    const/16 v5, 0x9

    .line 100
    .line 101
    invoke-direct {v0, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 102
    .line 103
    .line 104
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_DOORS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 105
    .line 106
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 107
    .line 108
    const/16 v5, 0xa

    .line 109
    .line 110
    invoke-direct {v0, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 111
    .line 112
    .line 113
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_TRAILER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 114
    .line 115
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 116
    .line 117
    const/16 v5, 0xb

    .line 118
    .line 119
    invoke-direct {v0, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 120
    .line 121
    .line 122
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_SENSOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 123
    .line 124
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 125
    .line 126
    const/16 v5, 0xc

    .line 127
    .line 128
    invoke-direct {v0, v5, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 129
    .line 130
    .line 131
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_GEAR_LEVEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 132
    .line 133
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 134
    .line 135
    const/16 v5, 0xd

    .line 136
    .line 137
    invoke-direct {v0, v5, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 138
    .line 139
    .line 140
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_ACTIVE_REMOTE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 141
    .line 142
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 143
    .line 144
    const/16 v5, 0xf

    .line 145
    .line 146
    invoke-direct {v0, v5, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 147
    .line 148
    .line 149
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_ACTIVE_CONTROL_ELEMENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 150
    .line 151
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 152
    .line 153
    const/16 v3, 0x11

    .line 154
    .line 155
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 156
    .line 157
    .line 158
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->BT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 159
    .line 160
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 161
    .line 162
    const/16 v3, 0x19

    .line 163
    .line 164
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 165
    .line 166
    .line 167
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->FT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 168
    .line 169
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 170
    .line 171
    const/16 v3, 0x21

    .line 172
    .line 173
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 174
    .line 175
    .line 176
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->HBFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 177
    .line 178
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 179
    .line 180
    const/16 v3, 0x29

    .line 181
    .line 182
    invoke-direct {v0, v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 183
    .line 184
    .line 185
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->HFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 186
    .line 187
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 188
    .line 189
    const/16 v1, 0x31

    .line 190
    .line 191
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 192
    .line 193
    .line 194
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 195
    .line 196
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 197
    .line 198
    const/16 v1, 0x38

    .line 199
    .line 200
    invoke-direct {v0, v1, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 201
    .line 202
    .line 203
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->MD1_LAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 204
    .line 205
    return-void
.end method

.method public constructor <init>()V
    .locals 24

    .line 1
    const v22, 0x1fffff

    const/16 v23, 0x0

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

    move-object/from16 v0, p0

    invoke-direct/range {v0 .. v23}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;-><init>(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;)V
    .locals 9

    move-object/from16 v0, p14

    move-object/from16 v1, p15

    move-object/from16 v2, p16

    move-object/from16 v3, p17

    move-object/from16 v4, p18

    move-object/from16 v5, p19

    move-object/from16 v6, p20

    move-object/from16 v7, p21

    const-string v8, "activeRemoteSystem"

    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "activeControlElement"

    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "windowStatusDriverSideFront"

    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "windowStatusPassengerSideFront"

    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "windowStatusDriverSideRear"

    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "windowStatusPassengerSideRear"

    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "sunroofOpeningPercentage"

    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "sunroofMode"

    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 4
    iput-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 5
    iput-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 6
    iput-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 7
    iput-boolean p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 8
    iput-boolean p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    move/from16 p1, p7

    .line 9
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    move/from16 p1, p8

    .line 10
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    move/from16 p1, p9

    .line 11
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    move/from16 p1, p10

    .line 12
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    move/from16 p1, p11

    .line 13
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    move/from16 p1, p12

    .line 14
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    move/from16 p1, p13

    .line 15
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 16
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 17
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 18
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 19
    iput-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 20
    iput-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 21
    iput-object v5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 22
    iput-object v6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 23
    iput-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 24
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;ILkotlin/jvm/internal/g;)V
    .locals 18

    move/from16 v0, p22

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    goto :goto_0

    :cond_0
    move/from16 v1, p1

    :goto_0
    and-int/lit8 v3, v0, 0x2

    if-eqz v3, :cond_1

    const/4 v3, 0x0

    goto :goto_1

    :cond_1
    move/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v0, 0x4

    if-eqz v4, :cond_2

    const/4 v4, 0x0

    goto :goto_2

    :cond_2
    move/from16 v4, p3

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

    .line 25
    sget-object v15, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    goto :goto_d

    :cond_d
    move-object/from16 v15, p14

    :goto_d
    and-int/lit16 v2, v0, 0x4000

    if-eqz v2, :cond_e

    .line 26
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v0, v16

    const/4 v0, 0x1

    if-eqz v16, :cond_f

    move/from16 v16, v1

    .line 27
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    move-object/from16 p2, v2

    move/from16 p1, v3

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-direct {v1, v3, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_f

    :cond_f
    move/from16 v16, v1

    move-object/from16 p2, v2

    move/from16 p1, v3

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object/from16 v1, p16

    :goto_f
    const/high16 v17, 0x10000

    and-int v17, p22, v17

    move-object/from16 p3, v1

    if-eqz v17, :cond_10

    .line 28
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v1, v3, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_10

    :cond_10
    move-object/from16 v1, p17

    :goto_10
    const/high16 v17, 0x20000

    and-int v17, p22, v17

    move-object/from16 p4, v1

    if-eqz v17, :cond_11

    .line 29
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v1, v3, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_11

    :cond_11
    move-object/from16 v1, p18

    :goto_11
    const/high16 v17, 0x40000

    and-int v17, p22, v17

    move-object/from16 p5, v1

    if-eqz v17, :cond_12

    .line 30
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v1, v3, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_12

    :cond_12
    move-object/from16 v1, p19

    :goto_12
    const/high16 v17, 0x80000

    and-int v17, p22, v17

    move-object/from16 p6, v1

    if-eqz v17, :cond_13

    .line 31
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    invoke-direct {v1, v3, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(IILkotlin/jvm/internal/g;)V

    goto :goto_13

    :cond_13
    move-object/from16 v1, p20

    :goto_13
    const/high16 v0, 0x100000

    and-int v0, p22, v0

    if-eqz v0, :cond_14

    .line 32
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;->Sliding:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    move-object/from16 p22, v0

    :goto_14
    move-object/from16 p16, p2

    move-object/from16 p17, p3

    move-object/from16 p18, p4

    move-object/from16 p19, p5

    move-object/from16 p20, p6

    move-object/from16 p21, v1

    move/from16 p4, v4

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

    move-object/from16 p15, v15

    move/from16 p2, v16

    move/from16 p3, p1

    move-object/from16 p1, p0

    goto :goto_15

    :cond_14
    move-object/from16 p22, p21

    goto :goto_14

    .line 33
    :goto_15
    invoke-direct/range {p1 .. p22}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;-><init>(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getBT_FH_OEFFNUNG$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->BT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getFT_FH_OEFFNUNG$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->FT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getHBFS_FH_OEFFNUNG$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->HBFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getHFS_FH_OEFFNUNG$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->HFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMD1_LAGE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->MD1_LAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMD1_POSITION$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPARKING_ACTIVE_CONTROL_ELEMENT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_ACTIVE_CONTROL_ELEMENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_BT_REQUIRED$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_BT_REQUIRED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SM_ACTIVE_REMOTE_SYSTEM$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_ACTIVE_REMOTE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SM_DOORS$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_DOORS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SM_GEAR_LEVEL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_GEAR_LEVEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SM_KEY$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_KEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SM_SENSOR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_SENSOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SM_TRAILER$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_TRAILER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getZV_BT_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_CENTRAL_LOCKING_EXTERNAL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_CENTRAL_LOCKING_INTERNAL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_FT_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_HBFS_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_HD_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getZV_HFS_OPEN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p22

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-boolean v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    goto :goto_0

    :cond_0
    move/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-boolean v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    goto :goto_1

    :cond_1
    move/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-boolean v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    goto :goto_2

    :cond_2
    move/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-boolean v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    goto :goto_3

    :cond_3
    move/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-boolean v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    goto :goto_4

    :cond_4
    move/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-boolean v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    goto :goto_5

    :cond_5
    move/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-boolean v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    goto :goto_6

    :cond_6
    move/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-boolean v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    goto :goto_7

    :cond_7
    move/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-boolean v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    goto :goto_8

    :cond_8
    move/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-boolean v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    goto :goto_9

    :cond_9
    move/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget-boolean v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    goto :goto_a

    :cond_a
    move/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-boolean v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    goto :goto_b

    :cond_b
    move/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget-boolean v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    goto :goto_d

    :cond_d
    move-object/from16 v15, p14

    :goto_d
    move/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_f

    :cond_f
    move-object/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p22, v16

    move-object/from16 p2, v1

    if-eqz v16, :cond_10

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_10

    :cond_10
    move-object/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p22, v16

    move-object/from16 p3, v1

    if-eqz v16, :cond_11

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_11

    :cond_11
    move-object/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p22, v16

    move-object/from16 p4, v1

    if-eqz v16, :cond_12

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_12

    :cond_12
    move-object/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p22, v16

    move-object/from16 p5, v1

    if-eqz v16, :cond_13

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    goto :goto_13

    :cond_13
    move-object/from16 v1, p20

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p22, v16

    if-eqz v16, :cond_14

    move-object/from16 p6, v1

    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    move-object/from16 p21, p6

    move-object/from16 p22, v1

    :goto_14
    move-object/from16 p17, p2

    move-object/from16 p18, p3

    move-object/from16 p19, p4

    move-object/from16 p20, p5

    move-object/from16 p16, v2

    move/from16 p3, v3

    move/from16 p4, v4

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

    move-object/from16 p15, v15

    move/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_15

    :cond_14
    move-object/from16 p22, p21

    move-object/from16 p21, v1

    goto :goto_14

    :goto_15
    invoke-virtual/range {p1 .. p22}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->copy(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component10()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component11()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component12()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component13()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component14()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component16()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component17()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component20()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component21()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component6()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component7()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component8()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component9()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;
    .locals 23

    .line 1
    const-string v0, "activeRemoteSystem"

    move-object/from16 v15, p14

    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "activeControlElement"

    move-object/from16 v1, p15

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideFront"

    move-object/from16 v2, p16

    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideFront"

    move-object/from16 v3, p17

    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusDriverSideRear"

    move-object/from16 v4, p18

    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowStatusPassengerSideRear"

    move-object/from16 v5, p19

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofOpeningPercentage"

    move-object/from16 v6, p20

    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "sunroofMode"

    move-object/from16 v7, p21

    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    move/from16 v8, p7

    move/from16 v9, p8

    move/from16 v10, p9

    move/from16 v11, p10

    move/from16 v12, p11

    move/from16 v13, p12

    move/from16 v14, p13

    move-object/from16 v16, p15

    move-object/from16 v17, v2

    move-object/from16 v18, v3

    move-object/from16 v19, v4

    move-object/from16 v20, v5

    move-object/from16 v21, v6

    move-object/from16 v22, v7

    move/from16 v2, p1

    move/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move/from16 v6, p5

    move/from16 v7, p6

    invoke-direct/range {v1 .. v22}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;-><init>(ZZZZZZZZZZZZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;)V

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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 42
    .line 43
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 44
    .line 45
    if-eq v1, v3, :cond_6

    .line 46
    .line 47
    return v2

    .line 48
    :cond_6
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_7

    .line 53
    .line 54
    return v2

    .line 55
    :cond_7
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 56
    .line 57
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 58
    .line 59
    if-eq v1, v3, :cond_8

    .line 60
    .line 61
    return v2

    .line 62
    :cond_8
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 63
    .line 64
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 65
    .line 66
    if-eq v1, v3, :cond_9

    .line 67
    .line 68
    return v2

    .line 69
    :cond_9
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 70
    .line 71
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 72
    .line 73
    if-eq v1, v3, :cond_a

    .line 74
    .line 75
    return v2

    .line 76
    :cond_a
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 77
    .line 78
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 79
    .line 80
    if-eq v1, v3, :cond_b

    .line 81
    .line 82
    return v2

    .line 83
    :cond_b
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 84
    .line 85
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 86
    .line 87
    if-eq v1, v3, :cond_c

    .line 88
    .line 89
    return v2

    .line 90
    :cond_c
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 91
    .line 92
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 93
    .line 94
    if-eq v1, v3, :cond_d

    .line 95
    .line 96
    return v2

    .line 97
    :cond_d
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 98
    .line 99
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 100
    .line 101
    if-eq v1, v3, :cond_e

    .line 102
    .line 103
    return v2

    .line 104
    :cond_e
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 105
    .line 106
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 107
    .line 108
    if-eq v1, v3, :cond_f

    .line 109
    .line 110
    return v2

    .line 111
    :cond_f
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 112
    .line 113
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 114
    .line 115
    if-eq v1, v3, :cond_10

    .line 116
    .line 117
    return v2

    .line 118
    :cond_10
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 119
    .line 120
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 121
    .line 122
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-nez v1, :cond_11

    .line 127
    .line 128
    return v2

    .line 129
    :cond_11
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 130
    .line 131
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 132
    .line 133
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-nez v1, :cond_12

    .line 138
    .line 139
    return v2

    .line 140
    :cond_12
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 141
    .line 142
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 143
    .line 144
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-nez v1, :cond_13

    .line 149
    .line 150
    return v2

    .line 151
    :cond_13
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 152
    .line 153
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 154
    .line 155
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    if-nez v1, :cond_14

    .line 160
    .line 161
    return v2

    .line 162
    :cond_14
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 163
    .line 164
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 165
    .line 166
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v1

    .line 170
    if-nez v1, :cond_15

    .line 171
    .line 172
    return v2

    .line 173
    :cond_15
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 174
    .line 175
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 176
    .line 177
    if-eq p0, p1, :cond_16

    .line 178
    .line 179
    return v2

    .line 180
    :cond_16
    return v0
.end method

.method public final getActiveControlElement()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getActiveRemoteSystem()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 29
    return p0
.end method

.method public final getHasOpenWindows$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 8
    .line 9
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 14
    .line 15
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 20
    .line 21
    instance-of v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 26
    .line 27
    instance-of p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    return p0

    .line 34
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 35
    return p0
.end method

.method public final getSunroofMode()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSunroofOpeningPercentage()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusDriverSideFront()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusDriverSideRear()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusPassengerSideFront()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowStatusPassengerSideRear()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 53
    .line 54
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 59
    .line 60
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 65
    .line 66
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 71
    .line 72
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 77
    .line 78
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 83
    .line 84
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    add-int/2addr v2, v0

    .line 89
    mul-int/2addr v2, v1

    .line 90
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    add-int/2addr v0, v2

    .line 97
    mul-int/2addr v0, v1

    .line 98
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 99
    .line 100
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    add-int/2addr v2, v0

    .line 105
    mul-int/2addr v2, v1

    .line 106
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    add-int/2addr v0, v2

    .line 113
    mul-int/2addr v0, v1

    .line 114
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 115
    .line 116
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    add-int/2addr v2, v0

    .line 121
    mul-int/2addr v2, v1

    .line 122
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 123
    .line 124
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    add-int/2addr v0, v2

    .line 129
    mul-int/2addr v0, v1

    .line 130
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 131
    .line 132
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    add-int/2addr v2, v0

    .line 137
    mul-int/2addr v2, v1

    .line 138
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 139
    .line 140
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    add-int/2addr p0, v2

    .line 145
    return p0
.end method

.method public final isBluetoothRequired()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isCentralLockingExternalActive()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isCentralLockingInternalActive()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpen()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenDriverSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenDriverSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenPassengerSideFront()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isDoorOpenPassengerSideRear()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isGearLevelCorrect()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isKeyAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isSensorDirty()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isTrailerDetected()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isTrunkOpen()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isVehicleLocked$remoteparkassistcoremeb_release()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    :cond_0
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_1
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_CENTRAL_LOCKING_INTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 8
    .line 9
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 13
    .line 14
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_CENTRAL_LOCKING_EXTERNAL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 17
    .line 18
    .line 19
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 20
    .line 21
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_FT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 22
    .line 23
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 24
    .line 25
    .line 26
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 27
    .line 28
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_BT_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 31
    .line 32
    .line 33
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 34
    .line 35
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 36
    .line 37
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 38
    .line 39
    .line 40
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 41
    .line 42
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HBFS_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 45
    .line 46
    .line 47
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 48
    .line 49
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->ZV_HD_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 52
    .line 53
    .line 54
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 55
    .line 56
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_BT_REQUIRED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 59
    .line 60
    .line 61
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 62
    .line 63
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_KEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 64
    .line 65
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 66
    .line 67
    .line 68
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 69
    .line 70
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_DOORS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 71
    .line 72
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 73
    .line 74
    .line 75
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 76
    .line 77
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_TRAILER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 78
    .line 79
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 80
    .line 81
    .line 82
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 83
    .line 84
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_SENSOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 85
    .line 86
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 87
    .line 88
    .line 89
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 90
    .line 91
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_GEAR_LEVEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 92
    .line 93
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_SM_ACTIVE_REMOTE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 103
    .line 104
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 108
    .line 109
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->PARKING_ACTIVE_CONTROL_ELEMENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 114
    .line 115
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 119
    .line 120
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->FT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 125
    .line 126
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 127
    .line 128
    .line 129
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 130
    .line 131
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->BT_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 136
    .line 137
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 138
    .line 139
    .line 140
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 141
    .line 142
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->HFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 147
    .line 148
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 149
    .line 150
    .line 151
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 152
    .line 153
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->HBFS_FH_OEFFNUNG:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 158
    .line 159
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 160
    .line 161
    .line 162
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 163
    .line 164
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;->getOriginalValue$remoteparkassistcoremeb_release()I

    .line 165
    .line 166
    .line 167
    move-result v1

    .line 168
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->MD1_POSITION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 169
    .line 170
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 171
    .line 172
    .line 173
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 174
    .line 175
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 176
    .line 177
    .line 178
    move-result p0

    .line 179
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->MD1_LAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 180
    .line 181
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 182
    .line 183
    .line 184
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingInternalActive:Z

    .line 4
    .line 5
    iget-boolean v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isCentralLockingExternalActive:Z

    .line 6
    .line 7
    iget-boolean v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideFront:Z

    .line 8
    .line 9
    iget-boolean v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideFront:Z

    .line 10
    .line 11
    iget-boolean v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenDriverSideRear:Z

    .line 12
    .line 13
    iget-boolean v6, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpenPassengerSideRear:Z

    .line 14
    .line 15
    iget-boolean v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrunkOpen:Z

    .line 16
    .line 17
    iget-boolean v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isBluetoothRequired:Z

    .line 18
    .line 19
    iget-boolean v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isKeyAvailable:Z

    .line 20
    .line 21
    iget-boolean v10, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isDoorOpen:Z

    .line 22
    .line 23
    iget-boolean v11, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isTrailerDetected:Z

    .line 24
    .line 25
    iget-boolean v12, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isSensorDirty:Z

    .line 26
    .line 27
    iget-boolean v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->isGearLevelCorrect:Z

    .line 28
    .line 29
    iget-object v14, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeRemoteSystem:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveRemoteSystemMEB;

    .line 30
    .line 31
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->activeControlElement:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ActiveControlElementMEB;

    .line 32
    .line 33
    move-object/from16 v16, v15

    .line 34
    .line 35
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 36
    .line 37
    move-object/from16 v17, v15

    .line 38
    .line 39
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideFront:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 40
    .line 41
    move-object/from16 v18, v15

    .line 42
    .line 43
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusDriverSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 44
    .line 45
    move-object/from16 v19, v15

    .line 46
    .line 47
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->windowStatusPassengerSideRear:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 48
    .line 49
    move-object/from16 v20, v15

    .line 50
    .line 51
    iget-object v15, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofOpeningPercentage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 52
    .line 53
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->sunroofMode:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/SunroofModeMEB;

    .line 54
    .line 55
    move-object/from16 p0, v0

    .line 56
    .line 57
    const-string v0, ", isCentralLockingExternalActive="

    .line 58
    .line 59
    move-object/from16 v21, v15

    .line 60
    .line 61
    const-string v15, ", isDoorOpenDriverSideFront="

    .line 62
    .line 63
    move-object/from16 v22, v14

    .line 64
    .line 65
    const-string v14, "C2PNormalPrioVehicleInfoMessageMEB(isCentralLockingInternalActive="

    .line 66
    .line 67
    invoke-static {v14, v0, v15, v1, v2}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    const-string v1, ", isDoorOpenPassengerSideFront="

    .line 72
    .line 73
    const-string v2, ", isDoorOpenDriverSideRear="

    .line 74
    .line 75
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v1, ", isDoorOpenPassengerSideRear="

    .line 79
    .line 80
    const-string v2, ", isTrunkOpen="

    .line 81
    .line 82
    invoke-static {v0, v5, v1, v6, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const-string v1, ", isBluetoothRequired="

    .line 86
    .line 87
    const-string v2, ", isKeyAvailable="

    .line 88
    .line 89
    invoke-static {v0, v7, v1, v8, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v1, ", isDoorOpen="

    .line 93
    .line 94
    const-string v2, ", isTrailerDetected="

    .line 95
    .line 96
    invoke-static {v0, v9, v1, v10, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 97
    .line 98
    .line 99
    const-string v1, ", isSensorDirty="

    .line 100
    .line 101
    const-string v2, ", isGearLevelCorrect="

    .line 102
    .line 103
    invoke-static {v0, v11, v1, v12, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v1, ", activeRemoteSystem="

    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    move-object/from16 v1, v22

    .line 115
    .line 116
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    const-string v1, ", activeControlElement="

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    move-object/from16 v1, v16

    .line 125
    .line 126
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    const-string v1, ", windowStatusDriverSideFront="

    .line 130
    .line 131
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    move-object/from16 v1, v17

    .line 135
    .line 136
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    const-string v1, ", windowStatusPassengerSideFront="

    .line 140
    .line 141
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    move-object/from16 v1, v18

    .line 145
    .line 146
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    const-string v1, ", windowStatusDriverSideRear="

    .line 150
    .line 151
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    move-object/from16 v1, v19

    .line 155
    .line 156
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    const-string v1, ", windowStatusPassengerSideRear="

    .line 160
    .line 161
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    move-object/from16 v1, v20

    .line 165
    .line 166
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    const-string v1, ", sunroofOpeningPercentage="

    .line 170
    .line 171
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    move-object/from16 v1, v21

    .line 175
    .line 176
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    const-string v1, ", sunroofMode="

    .line 180
    .line 181
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    move-object/from16 v1, p0

    .line 185
    .line 186
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    const-string v1, ")"

    .line 190
    .line 191
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    return-object v0
.end method
