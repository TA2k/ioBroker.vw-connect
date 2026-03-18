.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk71/d;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0094\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\n\u0008\u0000\u0018\u00002\u00020\u0001B\'\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0008\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\u000cH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u000cH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u000eJ/\u0010\u0018\u001a\u00020\u000c2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u0017\u0010\u001c\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u00020\u001aH\u0002\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0017\u0010\u001f\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u00020\u001eH\u0002\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0017\u0010\u001f\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u00020!H\u0002\u00a2\u0006\u0004\u0008\u001f\u0010\"J\u0017\u0010%\u001a\u00020\u000c2\u0006\u0010$\u001a\u00020#H\u0002\u00a2\u0006\u0004\u0008%\u0010&J\u0017\u0010\'\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u00020\u001eH\u0002\u00a2\u0006\u0004\u0008\'\u0010 J\u0017\u0010(\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u00020\u001eH\u0002\u00a2\u0006\u0004\u0008(\u0010 J\u000f\u0010)\u001a\u00020\u000cH\u0002\u00a2\u0006\u0004\u0008)\u0010\u000eJ\u001f\u0010,\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u00020\u001e2\u0006\u0010+\u001a\u00020*H\u0002\u00a2\u0006\u0004\u0008,\u0010-J)\u00104\u001a\u00020\u000c2\n\u0008\u0002\u0010/\u001a\u0004\u0018\u00010.2\u000c\u00101\u001a\u0008\u0012\u0004\u0012\u00020\u000c00H\u0002\u00a2\u0006\u0004\u00082\u00103J\u000f\u00105\u001a\u00020\u000cH\u0002\u00a2\u0006\u0004\u00085\u0010\u000eJ\u0017\u00107\u001a\u00020\u000c2\u0006\u0010\u001b\u001a\u000206H\u0002\u00a2\u0006\u0004\u00087\u00108J\u000f\u00109\u001a\u00020\u000cH\u0002\u00a2\u0006\u0004\u00089\u0010\u000eJ\u0013\u0010<\u001a\u00020;*\u00020:H\u0002\u00a2\u0006\u0004\u0008<\u0010=R\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010>R\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010?R\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0007\u0010@R\u0014\u0010\t\u001a\u00020\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u0010AR\u0014\u0010B\u001a\u00020.8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008B\u0010CR\u0016\u0010E\u001a\u00020D8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008E\u0010FR\u0016\u0010G\u001a\u00020#8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008G\u0010HR\u0016\u0010I\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008I\u0010JR\u0016\u0010K\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008K\u0010JR\u0016\u0010L\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008L\u0010JR\u0014\u0010M\u001a\u00020.8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008M\u0010C\u00a8\u0006N"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;",
        "Lk71/d;",
        "Lk71/a;",
        "c2pListening",
        "Ln71/a;",
        "dispatcher",
        "Lo71/a;",
        "logger",
        "Ll71/a;",
        "debugConfig",
        "<init>",
        "(Lk71/a;Ln71/a;Lo71/a;Ll71/a;)V",
        "Llx0/b0;",
        "connect",
        "()V",
        "disconnect",
        "",
        "payload",
        "",
        "address",
        "",
        "priority",
        "",
        "requiresQueuing",
        "sendData",
        "([BJBZ)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;",
        "message",
        "reactToStaticInfoRequest",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;",
        "reactTo",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;",
        "newC2PNormalPrioManeuverMessage",
        "sendNormalPrioManeuverMessage",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;)V",
        "reactToTouchDiagnosis",
        "reactToEngineStart",
        "reactToScenarioSelection",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;",
        "functionStatus",
        "reactToDrive",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V",
        "Lmy0/c;",
        "delay",
        "Lkotlin/Function0;",
        "function",
        "dispatchToDemoThread-dnQKTGw",
        "(Lmy0/c;Lay0/a;)V",
        "dispatchToDemoThread",
        "sendDelayedC2PHighPrioCyclicMessage",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "send",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V",
        "resetCommunication",
        "Ll71/b;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;",
        "toParkingManeuverState",
        "(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;",
        "Lk71/a;",
        "Ln71/a;",
        "Lo71/a;",
        "Ll71/a;",
        "highPrioInterval",
        "J",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;",
        "c2pHighPrioMessage",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;",
        "c2PNormalPrioManeuverMessage",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;",
        "sendingCyclicMessages",
        "Z",
        "isTouchDiagnosisActionStarted",
        "isInitScenarioAlreadySent",
        "highPrioMessageSendInterval",
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


# instance fields
.field private c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

.field private c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

.field private final c2pListening:Lk71/a;

.field private final debugConfig:Ll71/a;

.field private final dispatcher:Ln71/a;

.field private final highPrioInterval:J

.field private final highPrioMessageSendInterval:J

.field private isInitScenarioAlreadySent:Z

.field private isTouchDiagnosisActionStarted:Z

.field private final logger:Lo71/a;

.field private sendingCyclicMessages:Z


# direct methods
.method public constructor <init>(Lk71/a;Ln71/a;Lo71/a;Ll71/a;)V
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    const-string v5, "c2pListening"

    .line 12
    .line 13
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v5, "dispatcher"

    .line 17
    .line 18
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v5, "logger"

    .line 22
    .line 23
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v5, "debugConfig"

    .line 27
    .line 28
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pListening:Lk71/a;

    .line 35
    .line 36
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 37
    .line 38
    iput-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->logger:Lo71/a;

    .line 39
    .line 40
    iput-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->debugConfig:Ll71/a;

    .line 41
    .line 42
    sget-wide v1, Ln81/b;->e:J

    .line 43
    .line 44
    iput-wide v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->highPrioInterval:J

    .line 45
    .line 46
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 47
    .line 48
    const/16 v13, 0x1ff

    .line 49
    .line 50
    const/4 v14, 0x0

    .line 51
    const/4 v4, 0x0

    .line 52
    const/4 v5, 0x0

    .line 53
    const/4 v6, 0x0

    .line 54
    const/4 v7, 0x0

    .line 55
    const/4 v8, 0x0

    .line 56
    const/4 v9, 0x0

    .line 57
    const/4 v10, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    const/4 v12, 0x0

    .line 60
    invoke-direct/range {v3 .. v14}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILkotlin/jvm/internal/g;)V

    .line 61
    .line 62
    .line 63
    iput-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 64
    .line 65
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 66
    .line 67
    const v26, 0x1fffff

    .line 68
    .line 69
    .line 70
    const/16 v27, 0x0

    .line 71
    .line 72
    const/4 v7, 0x0

    .line 73
    const/4 v11, 0x0

    .line 74
    const/4 v12, 0x0

    .line 75
    const/4 v13, 0x0

    .line 76
    const/4 v15, 0x0

    .line 77
    const/16 v16, 0x0

    .line 78
    .line 79
    const/16 v17, 0x0

    .line 80
    .line 81
    const/16 v18, 0x0

    .line 82
    .line 83
    const/16 v19, 0x0

    .line 84
    .line 85
    const/16 v20, 0x0

    .line 86
    .line 87
    const/16 v21, 0x0

    .line 88
    .line 89
    const/16 v22, 0x0

    .line 90
    .line 91
    const/16 v23, 0x0

    .line 92
    .line 93
    const/16 v24, 0x0

    .line 94
    .line 95
    const/16 v25, 0x0

    .line 96
    .line 97
    invoke-direct/range {v4 .. v27}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILkotlin/jvm/internal/g;)V

    .line 98
    .line 99
    .line 100
    iput-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 101
    .line 102
    sget v1, Lmy0/c;->g:I

    .line 103
    .line 104
    const/16 v1, 0x1e

    .line 105
    .line 106
    sget-object v2, Lmy0/e;->g:Lmy0/e;

    .line 107
    .line 108
    invoke-static {v1, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 109
    .line 110
    .line 111
    move-result-wide v1

    .line 112
    iput-wide v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->highPrioMessageSendInterval:J

    .line 113
    .line 114
    return-void
.end method

.method public static synthetic a([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendData$lambda$0$2([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToTouchDiagnosis$lambda$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->disconnect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 6

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->resetCommunication()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 5
    .line 6
    sget v1, Lmy0/c;->g:I

    .line 7
    .line 8
    sget-object v1, Lmy0/e;->g:Lmy0/e;

    .line 9
    .line 10
    const/16 v2, 0x1f4

    .line 11
    .line 12
    invoke-static {v2, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    new-instance v4, Lf81/e;

    .line 17
    .line 18
    const/4 v5, 0x5

    .line 19
    invoke-direct {v4, p0, v5}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v2, v3, v4}, Ljp/ca;->a(Ln71/a;JLay0/a;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 26
    .line 27
    const/16 v2, 0x3e8

    .line 28
    .line 29
    invoke-static {v2, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v1

    .line 33
    new-instance v3, Lf81/e;

    .line 34
    .line 35
    const/4 v4, 0x6

    .line 36
    invoke-direct {v3, p0, v4}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v1, v2, v3}, Ljp/ca;->a(Ln71/a;JLay0/a;)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0
.end method

.method private static final connect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pListening:Lk71/a;

    .line 2
    .line 3
    sget-object v0, Lk71/c;->d:Lk71/c;

    .line 4
    .line 5
    invoke-interface {p0, v0}, Lk71/a;->carChangedConnectionStatus(Lk71/c;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    return-object p0
.end method

.method private static final connect$lambda$0$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pListening:Lk71/a;

    .line 2
    .line 3
    sget-object v0, Lk71/c;->e:Lk71/c;

    .line 4
    .line 5
    invoke-interface {p0, v0}, Lk71/a;->carChangedConnectionStatus(Lk71/c;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    return-object p0
.end method

.method public static synthetic d(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;[B)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendData$lambda$0(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;[B)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 2
    .line 3
    sget v1, Lmy0/c;->g:I

    .line 4
    .line 5
    const/16 v1, 0x3e8

    .line 6
    .line 7
    sget-object v2, Lmy0/e;->g:Lmy0/e;

    .line 8
    .line 9
    invoke-static {v1, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    new-instance v3, Lf81/e;

    .line 14
    .line 15
    const/16 v4, 0x8

    .line 16
    .line 17
    invoke-direct {v3, p0, v4}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1, v2, v3}, Ljp/ca;->a(Ln71/a;JLay0/a;)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0
.end method

.method private static final disconnect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pListening:Lk71/a;

    .line 2
    .line 3
    sget-object v1, Lk71/c;->f:Lk71/c;

    .line 4
    .line 5
    invoke-interface {v0, v1}, Lk71/a;->carChangedConnectionStatus(Lk71/c;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->resetCommunication()V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method private final dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lmy0/c;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 4
    .line 5
    iget-wide v1, p1, Lmy0/c;->d:J

    .line 6
    .line 7
    invoke-static {v0, v1, v2, p2}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    return-void

    .line 15
    :cond_1
    :goto_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 16
    .line 17
    invoke-static {p0, p2}, Ln71/a;->a(Ln71/a;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public static synthetic dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x1

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static synthetic e(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToEngineStart$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendData$lambda$0$0([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendDelayedC2PHighPrioCyclicMessage$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendData$lambda$0$1([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToTouchDiagnosis$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactTo$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->send$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic m(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->connect$lambda$0$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic o(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->connect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;->CUSTOM_FINISH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    if-ne v0, v1, :cond_0

    .line 2
    sget p1, Lmy0/c;->g:I

    const/16 p1, 0x3e8

    sget-object v0, Lmy0/e;->g:Lmy0/e;

    invoke-static {p1, v0}, Lmy0/h;->s(ILmy0/e;)J

    move-result-wide v0

    .line 3
    new-instance p1, Lmy0/c;

    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 4
    new-instance v0, Lf81/e;

    const/4 v1, 0x4

    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    return-void

    .line 5
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->STARTING_UP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    if-ne v0, v1, :cond_1

    .line 6
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToTouchDiagnosis(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V

    return-void

    .line 7
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->ENGINE_READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    if-ne v0, v1, :cond_2

    .line 8
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToEngineStart(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V

    return-void

    .line 9
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    if-ne v0, v1, :cond_3

    .line 10
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->debugConfig:Ll71/a;

    .line 11
    iget-object v0, v0, Ll71/a;->a:Ll71/b;

    .line 12
    sget-object v2, Ll71/b;->e:Ll71/b;

    if-ne v0, v2, :cond_3

    .line 13
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isInitScenarioAlreadySent:Z

    if-nez v0, :cond_3

    .line 14
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToScenarioSelection()V

    return-void

    .line 15
    :cond_3
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    filled-new-array {v1, v0, v2}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    move-result-object v0

    .line 16
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    .line 17
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    .line 18
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    move-result-object v0

    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToDrive(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    :cond_4
    return-void
.end method

.method private final reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;)V
    .locals 25

    move-object/from16 v0, p0

    .line 19
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 20
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;->getParkingSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    move-result-object v2

    .line 21
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;->getParkingScenarioStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    move-result-object v3

    .line 22
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;->getParkingDirectionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    move-result-object v5

    const v23, 0x1ffff4

    const/16 v24, 0x0

    const/4 v4, 0x0

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

    .line 23
    invoke-static/range {v1 .. v24}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->copy-e-SI6bs$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    move-result-object v1

    .line 24
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendNormalPrioManeuverMessage(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;)V

    return-void
.end method

.method private static final reactTo$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->FINISHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 4
    .line 5
    const/16 v10, 0x1fe

    .line 6
    .line 7
    const/4 v11, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    const/4 v8, 0x0

    .line 15
    const/4 v9, 0x0

    .line 16
    invoke-static/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method private final reactToDrive(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 6
    .line 7
    if-ne v1, v2, :cond_0

    .line 8
    .line 9
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 14
    .line 15
    if-ne v3, v4, :cond_0

    .line 16
    .line 17
    iget-object v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 18
    .line 19
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 20
    .line 21
    const/16 v15, 0x1fe

    .line 22
    .line 23
    const/16 v16, 0x0

    .line 24
    .line 25
    const/4 v7, 0x0

    .line 26
    const/4 v8, 0x0

    .line 27
    const/4 v9, 0x0

    .line 28
    const/4 v10, 0x0

    .line 29
    const/4 v11, 0x0

    .line 30
    const/4 v12, 0x0

    .line 31
    const/4 v13, 0x0

    .line 32
    const/4 v14, 0x0

    .line 33
    invoke-static/range {v5 .. v16}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 41
    .line 42
    if-eq v1, v3, :cond_1

    .line 43
    .line 44
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 45
    .line 46
    if-ne v1, v3, :cond_2

    .line 47
    .line 48
    :cond_1
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;->DRIVE_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 53
    .line 54
    if-eq v1, v3, :cond_4

    .line 55
    .line 56
    :cond_2
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;->DRIVE_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/UserCommandStatusMLB;

    .line 61
    .line 62
    if-ne v1, v3, :cond_3

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_3
    return-void

    .line 66
    :cond_4
    :goto_0
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 67
    .line 68
    const/16 v11, 0x1fe

    .line 69
    .line 70
    const/4 v12, 0x0

    .line 71
    const/4 v3, 0x0

    .line 72
    const/4 v4, 0x0

    .line 73
    const/4 v5, 0x0

    .line 74
    const/4 v6, 0x0

    .line 75
    const/4 v7, 0x0

    .line 76
    const/4 v8, 0x0

    .line 77
    const/4 v9, 0x0

    .line 78
    const/4 v10, 0x0

    .line 79
    invoke-static/range {v1 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 84
    .line 85
    return-void
.end method

.method private final reactToEngineStart(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->isEngineStartRequested()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    sget p1, Lmy0/c;->g:I

    .line 8
    .line 9
    const/16 p1, 0x7d0

    .line 10
    .line 11
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 12
    .line 13
    invoke-static {p1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    new-instance p1, Lmy0/c;

    .line 18
    .line 19
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lf81/e;

    .line 23
    .line 24
    const/16 v1, 0x9

    .line 25
    .line 26
    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 27
    .line 28
    .line 29
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method private static final reactToEngineStart$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 4
    .line 5
    const/16 v10, 0x1fe

    .line 6
    .line 7
    const/4 v11, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    const/4 v8, 0x0

    .line 15
    const/4 v9, 0x0

    .line 16
    invoke-static/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method private final reactToScenarioSelection()V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 6
    .line 7
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 8
    .line 9
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 10
    .line 11
    const v23, 0x1ffff4

    .line 12
    .line 13
    .line 14
    const/16 v24, 0x0

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v7, 0x0

    .line 19
    const/4 v8, 0x0

    .line 20
    const/4 v9, 0x0

    .line 21
    const/4 v10, 0x0

    .line 22
    const/4 v11, 0x0

    .line 23
    const/4 v12, 0x0

    .line 24
    const/4 v13, 0x0

    .line 25
    const/4 v14, 0x0

    .line 26
    const/4 v15, 0x0

    .line 27
    const/16 v16, 0x0

    .line 28
    .line 29
    const/16 v17, 0x0

    .line 30
    .line 31
    const/16 v18, 0x0

    .line 32
    .line 33
    const/16 v19, 0x0

    .line 34
    .line 35
    const/16 v20, 0x0

    .line 36
    .line 37
    const/16 v21, 0x0

    .line 38
    .line 39
    const/16 v22, 0x0

    .line 40
    .line 41
    invoke-static/range {v1 .. v24}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->copy-e-SI6bs$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendNormalPrioManeuverMessage(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;)V

    .line 46
    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isInitScenarioAlreadySent:Z

    .line 50
    .line 51
    return-void
.end method

.method private final reactToStaticInfoRequest(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;)V
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Ll71/u;->d:Ll71/d;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    sget-object v1, Ll71/d;->c:Ll71/k;

    .line 9
    .line 10
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PStaticInfoResponseMessageMLB;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    int-to-byte v3, v1

    .line 17
    const/4 v4, 0x2

    .line 18
    int-to-byte v4, v4

    .line 19
    const/4 v8, 0x0

    .line 20
    int-to-byte v5, v8

    .line 21
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionResponseStatusMLB;->RUNNING:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionResponseStatusMLB;

    .line 22
    .line 23
    const/4 v7, 0x0

    .line 24
    invoke-direct/range {v2 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PStaticInfoResponseMessageMLB;-><init>(BBBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionResponseStatusMLB;Lkotlin/jvm/internal/g;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 28
    .line 29
    .line 30
    iget-object v9, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 31
    .line 32
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->getFunctionRequestStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;->START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 37
    .line 38
    if-ne v2, v3, :cond_0

    .line 39
    .line 40
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->STARTING_UP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 41
    .line 42
    :goto_0
    move-object v10, v2

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 45
    .line 46
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    goto :goto_0

    .line 51
    :goto_1
    sget-object v12, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 52
    .line 53
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->getFunctionRequestStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    if-ne v2, v3, :cond_1

    .line 58
    .line 59
    move v13, v1

    .line 60
    goto :goto_2

    .line 61
    :cond_1
    move v13, v8

    .line 62
    :goto_2
    const/16 v19, 0x1f2

    .line 63
    .line 64
    const/16 v20, 0x0

    .line 65
    .line 66
    const/4 v11, 0x0

    .line 67
    const/4 v14, 0x0

    .line 68
    const/4 v15, 0x0

    .line 69
    const/16 v16, 0x0

    .line 70
    .line 71
    const/16 v17, 0x0

    .line 72
    .line 73
    const/16 v18, 0x0

    .line 74
    .line 75
    invoke-static/range {v9 .. v20}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 80
    .line 81
    iput-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendingCyclicMessages:Z

    .line 82
    .line 83
    invoke-direct {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendDelayedC2PHighPrioCyclicMessage()V

    .line 84
    .line 85
    .line 86
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 87
    .line 88
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->debugConfig:Ll71/a;

    .line 89
    .line 90
    iget-object v1, v1, Ll71/a;->a:Ll71/b;

    .line 91
    .line 92
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->toParkingManeuverState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    const v25, 0x1ffffb

    .line 97
    .line 98
    .line 99
    const/16 v26, 0x0

    .line 100
    .line 101
    const/4 v4, 0x0

    .line 102
    const/4 v5, 0x0

    .line 103
    const/4 v7, 0x0

    .line 104
    const/4 v8, 0x0

    .line 105
    const/4 v9, 0x0

    .line 106
    const/4 v10, 0x0

    .line 107
    const/4 v11, 0x0

    .line 108
    const/4 v12, 0x0

    .line 109
    const/4 v13, 0x0

    .line 110
    const/16 v17, 0x0

    .line 111
    .line 112
    const/16 v18, 0x0

    .line 113
    .line 114
    const/16 v19, 0x0

    .line 115
    .line 116
    const/16 v20, 0x0

    .line 117
    .line 118
    const/16 v21, 0x0

    .line 119
    .line 120
    const/16 v22, 0x0

    .line 121
    .line 122
    const/16 v23, 0x0

    .line 123
    .line 124
    const/16 v24, 0x0

    .line 125
    .line 126
    invoke-static/range {v3 .. v26}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->copy-e-SI6bs$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 131
    .line 132
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 133
    .line 134
    .line 135
    return-void
.end method

.method private final reactToTouchDiagnosis(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getTouchDiagnosisResponseStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 11
    .line 12
    if-ne v0, v2, :cond_0

    .line 13
    .line 14
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getTouchDiagnosisResponseStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;->ACTION_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 26
    .line 27
    if-ne v0, v2, :cond_1

    .line 28
    .line 29
    const/4 p1, 0x1

    .line 30
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->getTouchDiagnosisResponseStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TouchDiagnosisResponseStatusMLB;

    .line 42
    .line 43
    if-ne p1, v0, :cond_2

    .line 44
    .line 45
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 46
    .line 47
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->highPrioMessageSendInterval:J

    .line 48
    .line 49
    const/4 p1, 0x2

    .line 50
    invoke-static {p1, v0, v1}, Lmy0/c;->l(IJ)J

    .line 51
    .line 52
    .line 53
    move-result-wide v0

    .line 54
    new-instance p1, Lmy0/c;

    .line 55
    .line 56
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lf81/e;

    .line 60
    .line 61
    const/4 v1, 0x0

    .line 62
    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 66
    .line 67
    .line 68
    const/16 p1, 0x3e8

    .line 69
    .line 70
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 71
    .line 72
    invoke-static {p1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 73
    .line 74
    .line 75
    move-result-wide v0

    .line 76
    new-instance p1, Lmy0/c;

    .line 77
    .line 78
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 79
    .line 80
    .line 81
    new-instance v0, Lf81/e;

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 85
    .line 86
    .line 87
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 88
    .line 89
    .line 90
    :cond_2
    return-void
.end method

.method private static final reactToTouchDiagnosis$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 2
    .line 3
    const/16 v10, 0x1f7

    .line 4
    .line 5
    const/4 v11, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v7, 0x0

    .line 13
    const/4 v8, 0x0

    .line 14
    const/4 v9, 0x0

    .line 15
    invoke-static/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method

.method private static final reactToTouchDiagnosis$lambda$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 12

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->ENGINE_READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 4
    .line 5
    const/16 v10, 0x1fe

    .line 6
    .line 7
    const/4 v11, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x0

    .line 14
    const/4 v8, 0x0

    .line 15
    const/4 v9, 0x0

    .line 16
    invoke-static/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method private final resetCommunication()V
    .locals 12

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 2
    .line 3
    const/16 v10, 0x1ff

    .line 4
    .line 5
    const/4 v11, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v7, 0x0

    .line 13
    const/4 v8, 0x0

    .line 14
    const/4 v9, 0x0

    .line 15
    invoke-direct/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILkotlin/jvm/internal/g;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isTouchDiagnosisActionStarted:Z

    .line 22
    .line 23
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendingCyclicMessages:Z

    .line 24
    .line 25
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->isInitScenarioAlreadySent:Z

    .line 26
    .line 27
    return-void
.end method

.method private final send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->logger:Lo71/a;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "send("

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v2, ")"

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-static {v0, v1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatcher:Ln71/a;

    .line 26
    .line 27
    new-instance v1, Ld90/w;

    .line 28
    .line 29
    const/16 v2, 0xf

    .line 30
    .line 31
    invoke-direct {v1, v2, p0, p1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-static {v0, v1}, Ln71/a;->b(Ln71/a;Lay0/a;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method private static final send$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)Llx0/b0;
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pListening:Lk71/a;

    .line 2
    .line 3
    invoke-interface {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->toBytes()[B

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;->getAddress()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    invoke-interface {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;->getPriority()B

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    invoke-interface {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;->getRequiresQueuing()Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    invoke-interface/range {v0 .. v5}, Lk71/a;->receivedMessageFromCar([BJBZ)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method

.method private static final sendData$lambda$0(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;[B)Llx0/b0;
    .locals 2

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;->getAddress()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    cmp-long v0, p0, v0

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget p0, Lmy0/c;->g:I

    .line 12
    .line 13
    const/16 p0, 0x1f4

    .line 14
    .line 15
    sget-object p1, Lmy0/e;->g:Lmy0/e;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lmy0/h;->s(ILmy0/e;)J

    .line 18
    .line 19
    .line 20
    move-result-wide p0

    .line 21
    new-instance v0, Lmy0/c;

    .line 22
    .line 23
    invoke-direct {v0, p0, p1}, Lmy0/c;-><init>(J)V

    .line 24
    .line 25
    .line 26
    new-instance p0, Lf81/f;

    .line 27
    .line 28
    const/4 p1, 0x0

    .line 29
    invoke-direct {p0, p3, p2, p1}, Lf81/f;-><init>([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p2, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;

    .line 37
    .line 38
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;->getAddress()J

    .line 39
    .line 40
    .line 41
    move-result-wide v0

    .line 42
    cmp-long v0, p0, v0

    .line 43
    .line 44
    if-nez v0, :cond_1

    .line 45
    .line 46
    iget-wide p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->highPrioInterval:J

    .line 47
    .line 48
    new-instance v0, Lmy0/c;

    .line 49
    .line 50
    invoke-direct {v0, p0, p1}, Lmy0/c;-><init>(J)V

    .line 51
    .line 52
    .line 53
    new-instance p0, Lf81/f;

    .line 54
    .line 55
    const/4 p1, 0x1

    .line 56
    invoke-direct {p0, p3, p2, p1}, Lf81/f;-><init>([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 57
    .line 58
    .line 59
    invoke-direct {p2, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB$Companion;

    .line 64
    .line 65
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB$Companion;->getAddress()J

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    cmp-long p0, p0, v0

    .line 70
    .line 71
    if-nez p0, :cond_2

    .line 72
    .line 73
    iget-wide p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->highPrioInterval:J

    .line 74
    .line 75
    new-instance v0, Lmy0/c;

    .line 76
    .line 77
    invoke-direct {v0, p0, p1}, Lmy0/c;-><init>(J)V

    .line 78
    .line 79
    .line 80
    new-instance p0, Lf81/f;

    .line 81
    .line 82
    const/4 p1, 0x2

    .line 83
    invoke-direct {p0, p3, p2, p1}, Lf81/f;-><init>([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 84
    .line 85
    .line 86
    invoke-direct {p2, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 87
    .line 88
    .line 89
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    return-object p0
.end method

.method private static final sendData$lambda$0$0([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactToStaticInfoRequest(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method private static final sendData$lambda$0$1([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CHighPrioMessageMLB;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method private static final sendData$lambda$0$2([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/P2CNormalPrioMessageMLB;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method private final sendDelayedC2PHighPrioCyclicMessage()V
    .locals 3

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->highPrioInterval:J

    .line 2
    .line 3
    new-instance v2, Lmy0/c;

    .line 4
    .line 5
    invoke-direct {v2, v0, v1}, Lmy0/c;-><init>(J)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lf81/e;

    .line 9
    .line 10
    const/4 v1, 0x7

    .line 11
    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v2, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method private static final sendDelayedC2PHighPrioCyclicMessage$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;)Llx0/b0;
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageMLB;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->sendDelayedC2PHighPrioCyclicMessage()V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private final sendNormalPrioManeuverMessage(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 10
    .line 11
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method private final toParkingManeuverState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_3

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    if-eq p0, p1, :cond_2

    .line 9
    .line 10
    const/4 p1, 0x2

    .line 11
    if-eq p0, p1, :cond_1

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    if-eq p0, p1, :cond_2

    .line 15
    .line 16
    const/4 p1, 0x4

    .line 17
    if-ne p0, p1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    :goto_0
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->PULLOUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->PARKING:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_3
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 33
    .line 34
    return-object p0
.end method


# virtual methods
.method public connect()V
    .locals 3

    .line 1
    new-instance v0, Lf81/e;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-static {p0, v2, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public disconnect()V
    .locals 3

    .line 1
    new-instance v0, Lf81/e;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, p0, v1}, Lf81/e;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-static {p0, v2, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public sendData([BJBZ)V
    .locals 6

    .line 1
    const-string p4, "payload"

    .line 2
    .line 3
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lf81/b;

    .line 7
    .line 8
    const/4 v5, 0x1

    .line 9
    move-object v3, p0

    .line 10
    move-object v4, p1

    .line 11
    move-wide v1, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Lf81/b;-><init>(JLk71/d;[BI)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    const/4 p1, 0x0

    .line 17
    invoke-static {v3, p1, v0, p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
