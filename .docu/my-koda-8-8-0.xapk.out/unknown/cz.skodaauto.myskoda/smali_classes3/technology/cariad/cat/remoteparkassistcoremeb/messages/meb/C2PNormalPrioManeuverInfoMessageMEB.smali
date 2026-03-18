.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0016\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u000e\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u0000 B2\u00020\u0001:\u0001BBu\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\n\u001a\u00020\u000b\u0012\u0008\u0008\u0002\u0010\u000c\u001a\u00020\r\u0012\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u000f\u0012\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u0011\u0012\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u0013\u0012\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u0013\u0012\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u0013\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u0008\u0010-\u001a\u00020.H\u0016J\t\u0010/\u001a\u00020\u0003H\u00c6\u0003J\t\u00100\u001a\u00020\u0005H\u00c6\u0003J\t\u00101\u001a\u00020\u0007H\u00c6\u0003J\t\u00102\u001a\u00020\tH\u00c6\u0003J\t\u00103\u001a\u00020\u000bH\u00c6\u0003J\t\u00104\u001a\u00020\rH\u00c6\u0003J\t\u00105\u001a\u00020\u000fH\u00c6\u0003J\t\u00106\u001a\u00020\u0011H\u00c6\u0003J\t\u00107\u001a\u00020\u0013H\u00c6\u0003J\t\u00108\u001a\u00020\u0013H\u00c6\u0003J\t\u00109\u001a\u00020\u0013H\u00c6\u0003Jw\u0010:\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000b2\u0008\u0008\u0002\u0010\u000c\u001a\u00020\r2\u0008\u0008\u0002\u0010\u000e\u001a\u00020\u000f2\u0008\u0008\u0002\u0010\u0010\u001a\u00020\u00112\u0008\u0008\u0002\u0010\u0012\u001a\u00020\u00132\u0008\u0008\u0002\u0010\u0014\u001a\u00020\u00132\u0008\u0008\u0002\u0010\u0015\u001a\u00020\u0013H\u00c6\u0001J\u0013\u0010;\u001a\u00020\u00132\u0008\u0010<\u001a\u0004\u0018\u00010=H\u00d6\u0003J\t\u0010>\u001a\u00020?H\u00d6\u0001J\t\u0010@\u001a\u00020AH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0018\u0010\u0019R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001a\u0010\u001bR\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001c\u0010\u001dR\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u001e\u0010\u001fR\u0011\u0010\n\u001a\u00020\u000b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008 \u0010!R\u0011\u0010\u000c\u001a\u00020\r\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\"\u0010#R\u0011\u0010\u000e\u001a\u00020\u000f\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008$\u0010%R\u0011\u0010\u0010\u001a\u00020\u0011\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008&\u0010\'R\u0011\u0010\u0012\u001a\u00020\u0013\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0012\u0010(R\u0011\u0010\u0014\u001a\u00020\u0013\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0014\u0010(R\u0011\u0010\u0015\u001a\u00020\u0013\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010(R\u0014\u0010)\u001a\u00020*X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008+\u0010,\u00a8\u0006C"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "parkingSidesAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;",
        "parkingSideActiveStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;",
        "parkingScenariosAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;",
        "parkingScenarioActiveStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;",
        "parkingDirectionsAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;",
        "parkingDirectionActiveStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;",
        "parkingManeuversAvailability",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;",
        "parkingManeuverActiveStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;",
        "isParkingReversible",
        "",
        "isParkingReady",
        "isParkingStandstill",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZ)V",
        "getParkingSidesAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;",
        "getParkingSideActiveStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;",
        "getParkingScenariosAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;",
        "getParkingScenarioActiveStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;",
        "getParkingDirectionsAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;",
        "getParkingDirectionActiveStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;",
        "getParkingManeuversAvailability",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;",
        "getParkingManeuverActiveStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;",
        "()Z",
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
.field public static final Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;

.field private static final PARKING_DIRECTION_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_DIRECTION_BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_DIRECTION_FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_MANEUVER_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_MANEUVER_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_MANEUVER_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_READY_TO_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SCENARIO_TPA_OR_AAA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SIDE_LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SIDE_RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_SIDE_STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final PARKING_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

.field private static final address:J

.field private static final byteLength:I

.field private static final messageID:B

.field private static final priority:B

.field private static final requiresQueuing:Z


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

.field private final isParkingReady:Z

.field private final isParkingReversible:Z

.field private final isParkingStandstill:Z

.field private final parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

.field private final parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

.field private final parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

.field private final parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

.field private final parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

.field private final parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

.field private final parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

.field private final parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;

    .line 8
    .line 9
    const/16 v0, 0x22

    .line 10
    .line 11
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->messageID:B

    .line 12
    .line 13
    const-wide v0, 0x5250410201000000L    # 3.2333841869179016E88

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->address:J

    .line 19
    .line 20
    const/4 v0, 0x3

    .line 21
    sput-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->priority:B

    .line 22
    .line 23
    sput v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->byteLength:I

    .line 24
    .line 25
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const/4 v3, 0x1

    .line 29
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 33
    .line 34
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 35
    .line 36
    invoke-direct {v1, v3, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 37
    .line 38
    .line 39
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 40
    .line 41
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 42
    .line 43
    const/4 v2, 0x2

    .line 44
    invoke-direct {v1, v2, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 45
    .line 46
    .line 47
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 48
    .line 49
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 50
    .line 51
    invoke-direct {v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 52
    .line 53
    .line 54
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 55
    .line 56
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 57
    .line 58
    const/4 v4, 0x5

    .line 59
    invoke-direct {v1, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 60
    .line 61
    .line 62
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 63
    .line 64
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 65
    .line 66
    const/4 v4, 0x6

    .line 67
    invoke-direct {v1, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 68
    .line 69
    .line 70
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 71
    .line 72
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 73
    .line 74
    const/4 v4, 0x7

    .line 75
    invoke-direct {v1, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 76
    .line 77
    .line 78
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 79
    .line 80
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 81
    .line 82
    const/16 v4, 0x8

    .line 83
    .line 84
    invoke-direct {v1, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 85
    .line 86
    .line 87
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 88
    .line 89
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 90
    .line 91
    const/16 v4, 0x9

    .line 92
    .line 93
    invoke-direct {v1, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 94
    .line 95
    .line 96
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_TPA_OR_AAA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 97
    .line 98
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 99
    .line 100
    const/16 v4, 0xa

    .line 101
    .line 102
    invoke-direct {v1, v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 103
    .line 104
    .line 105
    sput-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 106
    .line 107
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 108
    .line 109
    const/16 v1, 0xd

    .line 110
    .line 111
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 112
    .line 113
    .line 114
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 115
    .line 116
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 117
    .line 118
    const/16 v1, 0xe

    .line 119
    .line 120
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 121
    .line 122
    .line 123
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 124
    .line 125
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 126
    .line 127
    const/16 v1, 0xf

    .line 128
    .line 129
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 130
    .line 131
    .line 132
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 133
    .line 134
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 135
    .line 136
    const/16 v1, 0x11

    .line 137
    .line 138
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 139
    .line 140
    .line 141
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 142
    .line 143
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 144
    .line 145
    const/16 v1, 0x12

    .line 146
    .line 147
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 148
    .line 149
    .line 150
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 151
    .line 152
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 153
    .line 154
    const/16 v1, 0x13

    .line 155
    .line 156
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 157
    .line 158
    .line 159
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 160
    .line 161
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 162
    .line 163
    const/16 v1, 0x15

    .line 164
    .line 165
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 166
    .line 167
    .line 168
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 169
    .line 170
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 171
    .line 172
    const/16 v1, 0x16

    .line 173
    .line 174
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 175
    .line 176
    .line 177
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_READY_TO_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 178
    .line 179
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 180
    .line 181
    const/16 v1, 0x17

    .line 182
    .line 183
    invoke-direct {v0, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;-><init>(II)V

    .line 184
    .line 185
    .line 186
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 187
    .line 188
    return-void
.end method

.method public constructor <init>()V
    .locals 14

    .line 1
    const/16 v12, 0x7ff

    const/4 v13, 0x0

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

    move-object v0, p0

    invoke-direct/range {v0 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZ)V
    .locals 1

    const-string v0, "parkingSidesAvailability"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingSideActiveStatus"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingScenariosAvailability"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingScenarioActiveStatus"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingDirectionsAvailability"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingDirectionActiveStatus"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingManeuversAvailability"

    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parkingManeuverActiveStatus"

    invoke-static {p8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 4
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 6
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 7
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 8
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 9
    iput-object p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 10
    iput-object p8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 11
    iput-boolean p9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 12
    iput-boolean p10, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 13
    iput-boolean p11, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 14
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;

    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILkotlin/jvm/internal/g;)V
    .locals 10

    move/from16 v0, p12

    and-int/lit8 v1, v0, 0x1

    if-eqz v1, :cond_0

    .line 15
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    const/4 v6, 0x7

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-direct/range {v2 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;-><init>(ZZZILkotlin/jvm/internal/g;)V

    move-object p1, v2

    :cond_0
    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_1

    .line 16
    sget-object p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    :cond_1
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_2

    .line 17
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    const/16 v8, 0x1f

    const/4 v9, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v2 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;-><init>(ZZZZZILkotlin/jvm/internal/g;)V

    move-object p3, v2

    :cond_2
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_3

    .line 18
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    goto :goto_0

    :cond_3
    move-object v1, p4

    :goto_0
    and-int/lit8 v2, v0, 0x10

    const/4 v3, 0x0

    const/4 v4, 0x3

    const/4 v5, 0x0

    if-eqz v2, :cond_4

    .line 19
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    invoke-direct {v2, v5, v5, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;-><init>(ZZILkotlin/jvm/internal/g;)V

    goto :goto_1

    :cond_4
    move-object v2, p5

    :goto_1
    and-int/lit8 v6, v0, 0x20

    if-eqz v6, :cond_5

    .line 20
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    goto :goto_2

    :cond_5
    move-object/from16 v6, p6

    :goto_2
    and-int/lit8 v7, v0, 0x40

    if-eqz v7, :cond_6

    .line 21
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    invoke-direct {v7, v5, v5, v4, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;-><init>(ZZILkotlin/jvm/internal/g;)V

    goto :goto_3

    :cond_6
    move-object/from16 v7, p7

    :goto_3
    and-int/lit16 v3, v0, 0x80

    if-eqz v3, :cond_7

    .line 22
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    goto :goto_4

    :cond_7
    move-object/from16 v3, p8

    :goto_4
    and-int/lit16 v4, v0, 0x100

    if-eqz v4, :cond_8

    move v4, v5

    goto :goto_5

    :cond_8
    move/from16 v4, p9

    :goto_5
    and-int/lit16 v8, v0, 0x200

    if-eqz v8, :cond_9

    move v8, v5

    goto :goto_6

    :cond_9
    move/from16 v8, p10

    :goto_6
    and-int/lit16 v0, v0, 0x400

    if-eqz v0, :cond_a

    move/from16 p12, v5

    :goto_7
    move-object p4, p3

    move-object p5, v1

    move-object/from16 p6, v2

    move-object/from16 p9, v3

    move/from16 p10, v4

    move-object/from16 p7, v6

    move-object/from16 p8, v7

    move/from16 p11, v8

    move-object p3, p2

    move-object p2, p1

    move-object p1, p0

    goto :goto_8

    :cond_a
    move/from16 p12, p11

    goto :goto_7

    .line 23
    :goto_8
    invoke-direct/range {p1 .. p12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZ)V

    return-void
.end method

.method public static final synthetic access$getAddress$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->address:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static final synthetic access$getByteLength$cp()I
    .locals 1

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->byteLength:I

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMessageID$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->messageID:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPARKING_DIRECTION_ACTIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_DIRECTION_BACKWARD$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_DIRECTION_FORWARD$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_MANEUVER_ACTIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_MANEUVER_PARKING_IN$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_MANEUVER_PARKING_OUT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_READY_TO_DRIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_READY_TO_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_REVERSIBLE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO_ACTIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO_BASIC$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO_GARAGE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO_PARALLEL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO_PERPENDICULAR$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SCENARIO_TPA_OR_AAA$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_TPA_OR_AAA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SIDE_ACTIVE$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SIDE_LEFT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SIDE_RIGHT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_SIDE_STRAIGHT$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPARKING_STANDSTILL$cp()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getPriority$cp()B
    .locals 1

    .line 1
    sget-byte v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->priority:B

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getRequiresQueuing$cp()Z
    .locals 1

    .line 1
    sget-boolean v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->requiresQueuing:Z

    .line 2
    .line 3
    return v0
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;
    .locals 0

    .line 1
    and-int/lit8 p13, p12, 0x1

    .line 2
    .line 3
    if-eqz p13, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p13, p12, 0x2

    .line 8
    .line 9
    if-eqz p13, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p13, p12, 0x4

    .line 14
    .line 15
    if-eqz p13, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p13, p12, 0x8

    .line 20
    .line 21
    if-eqz p13, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p13, p12, 0x10

    .line 26
    .line 27
    if-eqz p13, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p13, p12, 0x20

    .line 32
    .line 33
    if-eqz p13, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p13, p12, 0x40

    .line 38
    .line 39
    if-eqz p13, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p13, p12, 0x80

    .line 44
    .line 45
    if-eqz p13, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p13, p12, 0x100

    .line 50
    .line 51
    if-eqz p13, :cond_8

    .line 52
    .line 53
    iget-boolean p9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p13, p12, 0x200

    .line 56
    .line 57
    if-eqz p13, :cond_9

    .line 58
    .line 59
    iget-boolean p10, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 60
    .line 61
    :cond_9
    and-int/lit16 p12, p12, 0x400

    .line 62
    .line 63
    if-eqz p12, :cond_a

    .line 64
    .line 65
    iget-boolean p11, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 66
    .line 67
    :cond_a
    move p12, p10

    .line 68
    move p13, p11

    .line 69
    move-object p10, p8

    .line 70
    move p11, p9

    .line 71
    move-object p8, p6

    .line 72
    move-object p9, p7

    .line 73
    move-object p6, p4

    .line 74
    move-object p7, p5

    .line 75
    move-object p4, p2

    .line 76
    move-object p5, p3

    .line 77
    move-object p2, p0

    .line 78
    move-object p3, p1

    .line 79
    invoke-virtual/range {p2 .. p13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component11()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;
    .locals 12

    .line 1
    const-string p0, "parkingSidesAvailability"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "parkingSideActiveStatus"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "parkingScenariosAvailability"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "parkingScenarioActiveStatus"

    .line 17
    .line 18
    move-object/from16 v4, p4

    .line 19
    .line 20
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "parkingDirectionsAvailability"

    .line 24
    .line 25
    move-object/from16 v5, p5

    .line 26
    .line 27
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string p0, "parkingDirectionActiveStatus"

    .line 31
    .line 32
    move-object/from16 v6, p6

    .line 33
    .line 34
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string p0, "parkingManeuversAvailability"

    .line 38
    .line 39
    move-object/from16 v7, p7

    .line 40
    .line 41
    invoke-static {v7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const-string p0, "parkingManeuverActiveStatus"

    .line 45
    .line 46
    move-object/from16 v8, p8

    .line 47
    .line 48
    invoke-static {v8, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 52
    .line 53
    move-object v1, p1

    .line 54
    move-object v2, p2

    .line 55
    move-object v3, p3

    .line 56
    move/from16 v9, p9

    .line 57
    .line 58
    move/from16 v10, p10

    .line 59
    .line 60
    move/from16 v11, p11

    .line 61
    .line 62
    invoke-direct/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZ)V

    .line 63
    .line 64
    .line 65
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

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
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 25
    .line 26
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 32
    .line 33
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

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
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 43
    .line 44
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 45
    .line 46
    if-eq v1, v3, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 50
    .line 51
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 52
    .line 53
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_6

    .line 58
    .line 59
    return v2

    .line 60
    :cond_6
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 61
    .line 62
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 63
    .line 64
    if-eq v1, v3, :cond_7

    .line 65
    .line 66
    return v2

    .line 67
    :cond_7
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 68
    .line 69
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 70
    .line 71
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_8

    .line 76
    .line 77
    return v2

    .line 78
    :cond_8
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 79
    .line 80
    iget-object v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 81
    .line 82
    if-eq v1, v3, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 86
    .line 87
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 88
    .line 89
    if-eq v1, v3, :cond_a

    .line 90
    .line 91
    return v2

    .line 92
    :cond_a
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 93
    .line 94
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 95
    .line 96
    if-eq v1, v3, :cond_b

    .line 97
    .line 98
    return v2

    .line 99
    :cond_b
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 100
    .line 101
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 102
    .line 103
    if-eq p0, p1, :cond_c

    .line 104
    .line 105
    return v2

    .line 106
    :cond_c
    return v0
.end method

.method public getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingDirectionActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingDirectionsAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuverActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingManeuversAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingScenarioActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingScenariosAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingSideActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingSidesAvailability()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;->hashCode()I

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
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 19
    .line 20
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 35
    .line 36
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    add-int/2addr v0, v2

    .line 41
    mul-int/2addr v0, v1

    .line 42
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 51
    .line 52
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;->hashCode()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    add-int/2addr v0, v2

    .line 57
    mul-int/2addr v0, v1

    .line 58
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

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
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 67
    .line 68
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 73
    .line 74
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 79
    .line 80
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    add-int/2addr p0, v0

    .line 85
    return p0
.end method

.method public final isParkingReady()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isParkingReversible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isParkingStandstill()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 2
    .line 3
    return p0
.end method

.method public toBytes()[B
    .locals 3

    .line 1
    sget v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->byteLength:I

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 6
    .line 7
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;->isLeftAvailable()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 12
    .line 13
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 17
    .line 18
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;->isRightAvailable()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 28
    .line 29
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;->isStraightAvailable()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 34
    .line 35
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SIDE_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 45
    .line 46
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 50
    .line 51
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isParallelAvailable()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 56
    .line 57
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 61
    .line 62
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isPerpendicularAvailable()Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 72
    .line 73
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isGarageAvailable()Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 78
    .line 79
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 80
    .line 81
    .line 82
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 83
    .line 84
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isBasicAvailable()Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 89
    .line 90
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 91
    .line 92
    .line 93
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 94
    .line 95
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;->isTPAorAAAAvailable()Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_TPA_OR_AAA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 100
    .line 101
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 102
    .line 103
    .line 104
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 105
    .line 106
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_SCENARIO_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 111
    .line 112
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 113
    .line 114
    .line 115
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 116
    .line 117
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isForwardAvailable()Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 122
    .line 123
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 124
    .line 125
    .line 126
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 127
    .line 128
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;->isBackwardAvailable()Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 133
    .line 134
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 135
    .line 136
    .line 137
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 138
    .line 139
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_DIRECTION_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 144
    .line 145
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 146
    .line 147
    .line 148
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 149
    .line 150
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;->isParkingInAvailable()Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 155
    .line 156
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 157
    .line 158
    .line 159
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 160
    .line 161
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;->isParkingOutAvailable()Z

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 166
    .line 167
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 168
    .line 169
    .line 170
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 171
    .line 172
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_MANEUVER_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 177
    .line 178
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BILtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 179
    .line 180
    .line 181
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 182
    .line 183
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 184
    .line 185
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 186
    .line 187
    .line 188
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 189
    .line 190
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_READY_TO_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 191
    .line 192
    invoke-static {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 193
    .line 194
    .line 195
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 196
    .line 197
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->PARKING_STANDSTILL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;

    .line 198
    .line 199
    invoke-static {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->setValue-mbSTycY([BZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/BitPacket;)V

    .line 200
    .line 201
    .line 202
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/conversions/ByteArrayExtensionsKt;->toBytes-GBYM_sE([B)[B

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSidesAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingSideActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenariosAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingScenarioActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionsAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;

    .line 10
    .line 11
    iget-object v5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingDirectionActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 12
    .line 13
    iget-object v6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuversAvailability:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;

    .line 14
    .line 15
    iget-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->parkingManeuverActiveStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 16
    .line 17
    iget-boolean v8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible:Z

    .line 18
    .line 19
    iget-boolean v9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReady:Z

    .line 20
    .line 21
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingStandstill:Z

    .line 22
    .line 23
    new-instance v10, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v11, "C2PNormalPrioManeuverInfoMessageMEB(parkingSidesAvailability="

    .line 26
    .line 27
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v0, ", parkingSideActiveStatus="

    .line 34
    .line 35
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v10, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v0, ", parkingScenariosAvailability="

    .line 42
    .line 43
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v10, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v0, ", parkingScenarioActiveStatus="

    .line 50
    .line 51
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v0, ", parkingDirectionsAvailability="

    .line 58
    .line 59
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string v0, ", parkingDirectionActiveStatus="

    .line 66
    .line 67
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v10, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v0, ", parkingManeuversAvailability="

    .line 74
    .line 75
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v0, ", parkingManeuverActiveStatus="

    .line 82
    .line 83
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v10, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v0, ", isParkingReversible="

    .line 90
    .line 91
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v0, ", isParkingReady="

    .line 95
    .line 96
    const-string v1, ", isParkingStandstill="

    .line 97
    .line 98
    invoke-static {v10, v8, v0, v9, v1}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const-string v0, ")"

    .line 102
    .line 103
    invoke-static {v10, p0, v0}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0
.end method
