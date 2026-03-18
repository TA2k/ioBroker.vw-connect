.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk71/d;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00aa\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u0000\u0018\u00002\u00020\u0001B\'\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0008\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\u000cH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u000cH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u000eJ/\u0010\u0018\u001a\u00020\u000c2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J)\u0010 \u001a\u00020\u000c2\n\u0008\u0002\u0010\u001b\u001a\u0004\u0018\u00010\u001a2\u000c\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\u001cH\u0002\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u0017\u0010#\u001a\u00020\u000c2\u0006\u0010\"\u001a\u00020!H\u0002\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010\'\u001a\u00020\u000c2\u0006\u0010&\u001a\u00020%H\u0002\u00a2\u0006\u0004\u0008\'\u0010(J\u0017\u0010\'\u001a\u00020\u000c2\u0006\u0010&\u001a\u00020)H\u0002\u00a2\u0006\u0004\u0008\'\u0010*J\u0017\u0010-\u001a\u00020\u000c2\u0006\u0010,\u001a\u00020+H\u0002\u00a2\u0006\u0004\u0008-\u0010.J\u0017\u00100\u001a\u00020\u000c2\u0006\u0010/\u001a\u00020\u0016H\u0002\u00a2\u0006\u0004\u00080\u00101J\u000f\u00102\u001a\u00020\u000cH\u0002\u00a2\u0006\u0004\u00082\u0010\u000eJ\u001f\u00107\u001a\u00020\u000c2\u0006\u00104\u001a\u0002032\u0006\u00106\u001a\u000205H\u0002\u00a2\u0006\u0004\u00087\u00108J\u0017\u0010:\u001a\u00020\u000c2\u0006\u0010&\u001a\u000209H\u0002\u00a2\u0006\u0004\u0008:\u0010;J\u000f\u0010<\u001a\u00020\u000cH\u0002\u00a2\u0006\u0004\u0008<\u0010\u000eJ\u0013\u0010?\u001a\u00020>*\u00020=H\u0002\u00a2\u0006\u0004\u0008?\u0010@J\u0013\u0010B\u001a\u00020A*\u00020=H\u0002\u00a2\u0006\u0004\u0008B\u0010CR\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010DR\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010ER\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0007\u0010FR\u0014\u0010\t\u001a\u00020\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u0010GR\u0014\u0010H\u001a\u00020\u001a8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008H\u0010IR\u0016\u0010K\u001a\u00020J8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008K\u0010LR\u0016\u0010N\u001a\u00020M8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008N\u0010OR\u0016\u0010P\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008P\u0010QR\u0016\u0010R\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008R\u0010QR\u0016\u0010S\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008S\u0010Q\u00a8\u0006T"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;",
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
        "Lmy0/c;",
        "delay",
        "Lkotlin/Function0;",
        "function",
        "dispatchToDemoThread-dnQKTGw",
        "(Lmy0/c;Lay0/a;)V",
        "dispatchToDemoThread",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;",
        "functionRequestStatus",
        "reactToStaticInfoRequest",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;",
        "message",
        "reactTo",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;",
        "touchDiagnosisResponseStatus",
        "reactToTouchDiagnosis",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;)V",
        "isEngineStartRequested",
        "reactToEngineStart",
        "(Z)V",
        "reactToScenarioSelection",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;",
        "userCommandStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;",
        "functionStatus",
        "reactToDrive",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;",
        "send",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V",
        "resetCommunication",
        "Ll71/b;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;",
        "toFunctionAvailabilityState",
        "(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;",
        "toParkingManeuverActiveState",
        "(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;",
        "Lk71/a;",
        "Ln71/a;",
        "Lo71/a;",
        "Ll71/a;",
        "highPrioInterval",
        "J",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;",
        "c2pHighPrioMessage",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;",
        "c2PNormalPrioManeuverMessage",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;",
        "isTouchDiagnosisActionStarted",
        "Z",
        "isTouchDiagnosisFinished",
        "isInitScenarioAlreadySent",
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
.field private c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

.field private c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

.field private final c2pListening:Lk71/a;

.field private final debugConfig:Ll71/a;

.field private final dispatcher:Ln71/a;

.field private final highPrioInterval:J

.field private isInitScenarioAlreadySent:Z

.field private isTouchDiagnosisActionStarted:Z

.field private isTouchDiagnosisFinished:Z

.field private final logger:Lo71/a;


# direct methods
.method public constructor <init>(Lk71/a;Ln71/a;Lo71/a;Ll71/a;)V
    .locals 18

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
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pListening:Lk71/a;

    .line 35
    .line 36
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

    .line 37
    .line 38
    iput-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->logger:Lo71/a;

    .line 39
    .line 40
    iput-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->debugConfig:Ll71/a;

    .line 41
    .line 42
    sget-wide v1, Li81/b;->c:J

    .line 43
    .line 44
    iput-wide v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->highPrioInterval:J

    .line 45
    .line 46
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 47
    .line 48
    const/16 v11, 0x7f

    .line 49
    .line 50
    const/4 v12, 0x0

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
    invoke-direct/range {v3 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILkotlin/jvm/internal/g;)V

    .line 59
    .line 60
    .line 61
    iput-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 62
    .line 63
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 64
    .line 65
    const/16 v16, 0x7ff

    .line 66
    .line 67
    const/16 v17, 0x0

    .line 68
    .line 69
    const/4 v6, 0x0

    .line 70
    const/4 v11, 0x0

    .line 71
    const/4 v13, 0x0

    .line 72
    const/4 v14, 0x0

    .line 73
    const/4 v15, 0x0

    .line 74
    invoke-direct/range {v4 .. v17}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILkotlin/jvm/internal/g;)V

    .line 75
    .line 76
    .line 77
    iput-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 78
    .line 79
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToStaticInfoRequest$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->sendData$lambda$0$2([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->disconnect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 6

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->resetCommunication()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

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
    new-instance v4, Lf81/a;

    .line 17
    .line 18
    const/4 v5, 0x1

    .line 19
    invoke-direct {v4, p0, v5}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v2, v3, v4}, Ljp/ca;->a(Ln71/a;JLay0/a;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

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
    new-instance v3, Lf81/a;

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    invoke-direct {v3, p0, v4}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

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

.method private static final connect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pListening:Lk71/a;

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

.method private static final connect$lambda$0$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pListening:Lk71/a;

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

.method public static synthetic d(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToEngineStart$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

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
    new-instance v3, Lf81/a;

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    invoke-direct {v3, p0, v4}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0, v1, v2, v3}, Ljp/ca;->a(Ln71/a;JLay0/a;)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method private static final disconnect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pListening:Lk71/a;

    .line 2
    .line 3
    sget-object v1, Lk71/c;->f:Lk71/c;

    .line 4
    .line 5
    invoke-interface {v0, v1}, Lk71/a;->carChangedConnectionStatus(Lk71/c;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lf81/a;

    .line 9
    .line 10
    const/4 v1, 0x6

    .line 11
    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-static {p0, v2, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method

.method private static final disconnect$lambda$0$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->resetCommunication()V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

    .line 16
    .line 17
    invoke-static {p0, p2}, Ln71/a;->a(Ln71/a;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public static synthetic dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V
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
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static synthetic e(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactTo$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->sendData$lambda$0$0([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToTouchDiagnosis$lambda$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->connect$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->disconnect$lambda$0$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->connect$lambda$0$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->sendData$lambda$0$1([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic m(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToTouchDiagnosis$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic o(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;[B)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->sendData$lambda$0(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;[B)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic p(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->CUSTOM_FINISH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

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
    new-instance v0, Lf81/a;

    const/16 v1, 0x9

    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    return-void

    .line 5
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->STARTING_UP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    if-ne v0, v1, :cond_1

    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchDiagnosisResponseStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    move-result-object p1

    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToTouchDiagnosis(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;)V

    return-void

    .line 7
    :cond_1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->ENGINE_READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->ENGINE_START_REQUESTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    filled-new-array {v0, v1}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v0

    .line 8
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    .line 9
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 10
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->isEngineStartRequested()Z

    move-result p1

    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToEngineStart(Z)V

    return-void

    .line 11
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    if-ne v0, v1, :cond_3

    .line 12
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->debugConfig:Ll71/a;

    .line 13
    iget-object v0, v0, Ll71/a;->a:Ll71/b;

    .line 14
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->toFunctionAvailabilityState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    move-result-object v0

    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    if-ne v0, v2, :cond_3

    .line 15
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isInitScenarioAlreadySent:Z

    if-nez v0, :cond_3

    .line 16
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToScenarioSelection()V

    return-void

    .line 17
    :cond_3
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    filled-new-array {v1, v0, v2}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v0

    .line 18
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    .line 19
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    .line 20
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    move-result-object p1

    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    move-result-object v0

    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToDrive(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;)V

    :cond_4
    return-void
.end method

.method private final reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;)V
    .locals 14

    .line 21
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 22
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->getParkingSideActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    move-result-object v2

    .line 23
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->getParkingScenarioActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    move-result-object v4

    .line 24
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->getParkingDirectionActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    move-result-object v6

    const/16 v12, 0x7d5

    const/4 v13, 0x0

    const/4 v1, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    .line 25
    invoke-static/range {v0 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    move-result-object p1

    .line 26
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 27
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    :cond_0
    return-void
.end method

.method private static final reactTo$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->FINISHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 4
    .line 5
    const/16 v8, 0x7e

    .line 6
    .line 7
    const/4 v9, 0x0

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
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method

.method private final reactToDrive(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;)V
    .locals 12

    .line 1
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 2
    .line 3
    if-ne p2, v1, :cond_0

    .line 4
    .line 5
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 6
    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 10
    .line 11
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 12
    .line 13
    const/16 v10, 0x7e

    .line 14
    .line 15
    const/4 v11, 0x0

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v7, 0x0

    .line 20
    const/4 v8, 0x0

    .line 21
    const/4 v9, 0x0

    .line 22
    invoke-static/range {v2 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 31
    .line 32
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 33
    .line 34
    filled-new-array {v0, v2}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    if-eqz p2, :cond_1

    .line 47
    .line 48
    sget-object p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->DRIVE_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 49
    .line 50
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->DRIVE_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 51
    .line 52
    filled-new-array {p2, v0}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-static {p2}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    if-eqz p1, :cond_1

    .line 65
    .line 66
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 67
    .line 68
    const/16 v8, 0x7e

    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    const/4 v2, 0x0

    .line 72
    const/4 v3, 0x0

    .line 73
    const/4 v4, 0x0

    .line 74
    const/4 v5, 0x0

    .line 75
    const/4 v6, 0x0

    .line 76
    const/4 v7, 0x0

    .line 77
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 82
    .line 83
    .line 84
    :cond_1
    return-void
.end method

.method private final reactToEngineStart(Z)V
    .locals 10

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 4
    .line 5
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->ENGINE_START_REQUESTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 6
    .line 7
    const/16 v8, 0x7e

    .line 8
    .line 9
    const/4 v9, 0x0

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v5, 0x0

    .line 14
    const/4 v6, 0x0

    .line 15
    const/4 v7, 0x0

    .line 16
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 25
    .line 26
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->ENGINE_START_REQUESTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 31
    .line 32
    if-ne p1, v0, :cond_1

    .line 33
    .line 34
    sget p1, Lmy0/c;->g:I

    .line 35
    .line 36
    const/16 p1, 0x7d0

    .line 37
    .line 38
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 39
    .line 40
    invoke-static {p1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    new-instance p1, Lmy0/c;

    .line 45
    .line 46
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 47
    .line 48
    .line 49
    new-instance v0, Lf81/a;

    .line 50
    .line 51
    const/4 v1, 0x7

    .line 52
    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 53
    .line 54
    .line 55
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    return-void
.end method

.method private static final reactToEngineStart$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 4
    .line 5
    const/16 v8, 0x7e

    .line 6
    .line 7
    const/4 v9, 0x0

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
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method

.method private final reactToScenarioSelection()V
    .locals 14

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 2
    .line 3
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 4
    .line 5
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 6
    .line 7
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 8
    .line 9
    const/16 v12, 0x7d5

    .line 10
    .line 11
    const/4 v13, 0x0

    .line 12
    const/4 v1, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    const/4 v5, 0x0

    .line 15
    const/4 v7, 0x0

    .line 16
    const/4 v8, 0x0

    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x0

    .line 19
    const/4 v11, 0x0

    .line 20
    invoke-static/range {v0 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 25
    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isInitScenarioAlreadySent:Z

    .line 29
    .line 30
    return-void
.end method

.method private final reactToStaticInfoRequest(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)V
    .locals 8

    .line 1
    sget-object v0, Ll71/u;->d:Ll71/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object v0, Ll71/d;->d:Ll71/f;

    .line 7
    .line 8
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    int-to-byte v2, v0

    .line 15
    const/4 v0, 0x0

    .line 16
    int-to-byte v4, v0

    .line 17
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionResponseStatusMEB;->RUNNING:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionResponseStatusMEB;

    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->debugConfig:Ll71/a;

    .line 20
    .line 21
    iget-object v0, v0, Ll71/a;->a:Ll71/b;

    .line 22
    .line 23
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->toFunctionAvailabilityState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    const/4 v7, 0x0

    .line 28
    move v3, v2

    .line 29
    invoke-direct/range {v1 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;-><init>(BBBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionResponseStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Lkotlin/jvm/internal/g;)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 33
    .line 34
    .line 35
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->highPrioInterval:J

    .line 36
    .line 37
    new-instance v2, Lmy0/c;

    .line 38
    .line 39
    invoke-direct {v2, v0, v1}, Lmy0/c;-><init>(J)V

    .line 40
    .line 41
    .line 42
    new-instance v0, Ld90/w;

    .line 43
    .line 44
    const/16 v1, 0xe

    .line 45
    .line 46
    invoke-direct {v0, v1, p0, p1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    invoke-direct {p0, v2, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method private static final reactToStaticInfoRequest$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)Llx0/b0;
    .locals 14

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;->START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 4
    .line 5
    if-ne p1, v1, :cond_0

    .line 6
    .line 7
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->STARTING_UP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    :goto_0
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

    .line 15
    .line 16
    if-ne p1, v1, :cond_1

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const/4 p1, 0x0

    .line 21
    :goto_1
    const/16 v8, 0x78

    .line 22
    .line 23
    const/4 v9, 0x0

    .line 24
    const/4 v4, 0x0

    .line 25
    const/4 v5, 0x0

    .line 26
    const/4 v6, 0x0

    .line 27
    const/4 v7, 0x0

    .line 28
    move-object v1, v2

    .line 29
    move-object v2, v3

    .line 30
    move v3, p1

    .line 31
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 39
    .line 40
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->debugConfig:Ll71/a;

    .line 41
    .line 42
    iget-object p1, p1, Ll71/a;->a:Ll71/b;

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->toParkingManeuverActiveState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    const/16 v12, 0x77f

    .line 49
    .line 50
    const/4 v13, 0x0

    .line 51
    const/4 v1, 0x0

    .line 52
    const/4 v2, 0x0

    .line 53
    const/4 v3, 0x0

    .line 54
    const/4 v9, 0x0

    .line 55
    const/4 v10, 0x0

    .line 56
    const/4 v11, 0x0

    .line 57
    invoke-static/range {v0 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSidesAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenariosAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionsAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuversAvailabilityMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 62
    .line 63
    .line 64
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0
.end method

.method private final reactToTouchDiagnosis(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;)V
    .locals 12

    .line 1
    sget-object v0, Lf81/d;->a:[I

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_4

    .line 12
    .line 13
    const/4 v3, 0x2

    .line 14
    if-eq v0, v3, :cond_3

    .line 15
    .line 16
    const/4 v4, 0x3

    .line 17
    if-eq v0, v4, :cond_1

    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    if-ne v0, v1, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->logger:Lo71/a;

    .line 23
    .line 24
    new-instance v0, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v1, "reactToTouchDiagnosis("

    .line 27
    .line 28
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string p1, ") unexpected TouchDiagnosisResponse!"

    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_0
    new-instance p0, La8/r0;

    .line 48
    .line 49
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_1
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisActionStarted:Z

    .line 54
    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisFinished:Z

    .line 58
    .line 59
    if-nez p1, :cond_2

    .line 60
    .line 61
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisActionStarted:Z

    .line 62
    .line 63
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisFinished:Z

    .line 64
    .line 65
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->highPrioInterval:J

    .line 66
    .line 67
    invoke-static {v3, v0, v1}, Lmy0/c;->l(IJ)J

    .line 68
    .line 69
    .line 70
    move-result-wide v0

    .line 71
    new-instance p1, Lmy0/c;

    .line 72
    .line 73
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Lf81/a;

    .line 77
    .line 78
    const/4 v1, 0x4

    .line 79
    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 80
    .line 81
    .line 82
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 83
    .line 84
    .line 85
    const/16 p1, 0x3e8

    .line 86
    .line 87
    sget-object v0, Lmy0/e;->g:Lmy0/e;

    .line 88
    .line 89
    invoke-static {p1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 90
    .line 91
    .line 92
    move-result-wide v0

    .line 93
    new-instance p1, Lmy0/c;

    .line 94
    .line 95
    invoke-direct {p1, v0, v1}, Lmy0/c;-><init>(J)V

    .line 96
    .line 97
    .line 98
    new-instance v0, Lf81/a;

    .line 99
    .line 100
    const/4 v1, 0x5

    .line 101
    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 102
    .line 103
    .line 104
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 105
    .line 106
    .line 107
    :cond_2
    return-void

    .line 108
    :cond_3
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisActionStarted:Z

    .line 109
    .line 110
    return-void

    .line 111
    :cond_4
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisActionStarted:Z

    .line 112
    .line 113
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisFinished:Z

    .line 114
    .line 115
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 116
    .line 117
    const/16 v10, 0x7b

    .line 118
    .line 119
    const/4 v11, 0x0

    .line 120
    const/4 v3, 0x0

    .line 121
    const/4 v4, 0x0

    .line 122
    const/4 v5, 0x1

    .line 123
    const/4 v6, 0x0

    .line 124
    const/4 v7, 0x0

    .line 125
    const/4 v8, 0x0

    .line 126
    const/4 v9, 0x0

    .line 127
    invoke-static/range {v2 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 132
    .line 133
    .line 134
    return-void
.end method

.method private static final reactToTouchDiagnosis$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    const/16 v8, 0x7b

    .line 4
    .line 5
    const/4 v9, 0x0

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
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method

.method private static final reactToTouchDiagnosis$lambda$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->ENGINE_READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 4
    .line 5
    const/16 v8, 0x7e

    .line 6
    .line 7
    const/4 v9, 0x0

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
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0
.end method

.method private final resetCommunication()V
    .locals 10

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    const/16 v8, 0x7f

    .line 4
    .line 5
    const/4 v9, 0x0

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
    invoke-direct/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/DDAStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;ILkotlin/jvm/internal/g;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisActionStarted:Z

    .line 20
    .line 21
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isTouchDiagnosisFinished:Z

    .line 22
    .line 23
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->isInitScenarioAlreadySent:Z

    .line 24
    .line 25
    return-void
.end method

.method private final send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)V
    .locals 3

    .line 1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 7
    .line 8
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pHighPrioMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    move-object v0, p1

    .line 16
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 17
    .line 18
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2PNormalPrioManeuverMessage:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 19
    .line 20
    :cond_1
    :goto_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->logger:Lo71/a;

    .line 21
    .line 22
    new-instance v1, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v2, "send("

    .line 25
    .line 26
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v2, ")"

    .line 33
    .line 34
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static {v0, v1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatcher:Ln71/a;

    .line 45
    .line 46
    new-instance v1, Ld90/w;

    .line 47
    .line 48
    const/16 v2, 0xd

    .line 49
    .line 50
    invoke-direct {v1, v2, p0, p1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-static {v0, v1}, Ln71/a;->b(Ln71/a;Lay0/a;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method private static final send$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PMessage;)Llx0/b0;
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->c2pListening:Lk71/a;

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

.method private static final sendData$lambda$0(JLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;[B)Llx0/b0;
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
    new-instance p0, Lf81/c;

    .line 27
    .line 28
    const/4 p1, 0x0

    .line 29
    invoke-direct {p0, p3, p2, p1}, Lf81/c;-><init>([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p2, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;

    .line 37
    .line 38
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;->getAddress()J

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
    iget-wide p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->highPrioInterval:J

    .line 47
    .line 48
    new-instance v0, Lmy0/c;

    .line 49
    .line 50
    invoke-direct {v0, p0, p1}, Lmy0/c;-><init>(J)V

    .line 51
    .line 52
    .line 53
    new-instance p0, Lf81/c;

    .line 54
    .line 55
    const/4 p1, 0x1

    .line 56
    invoke-direct {p0, p3, p2, p1}, Lf81/c;-><init>([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 57
    .line 58
    .line 59
    invoke-direct {p2, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB$Companion;

    .line 64
    .line 65
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB$Companion;->getAddress()J

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
    iget-wide p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->highPrioInterval:J

    .line 74
    .line 75
    new-instance v0, Lmy0/c;

    .line 76
    .line 77
    invoke-direct {v0, p0, p1}, Lmy0/c;-><init>(J)V

    .line 78
    .line 79
    .line 80
    new-instance p0, Lf81/c;

    .line 81
    .line 82
    const/4 p1, 0x2

    .line 83
    invoke-direct {p0, p3, p2, p1}, Lf81/c;-><init>([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 84
    .line 85
    .line 86
    invoke-direct {p2, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw(Lmy0/c;Lay0/a;)V

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

.method private static final sendData$lambda$0$0([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
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
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->getFunctionRequestStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactToStaticInfoRequest(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0
.end method

.method private static final sendData$lambda$0$1([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method private static final sendData$lambda$0$2([BLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;)Llx0/b0;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->reactTo(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method private final toFunctionAvailabilityState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;
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
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_3
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 33
    .line 34
    return-object p0
.end method

.method private final toParkingManeuverActiveState(Ll71/b;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;
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
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_3
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 33
    .line 34
    return-object p0
.end method


# virtual methods
.method public connect()V
    .locals 3

    .line 1
    new-instance v0, Lf81/a;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-static {p0, v2, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public disconnect()V
    .locals 3

    .line 1
    new-instance v0, Lf81/a;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, p0, v1}, Lf81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-static {p0, v2, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

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
    const/4 v5, 0x0

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
    invoke-static {v3, p1, v0, p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;->dispatchToDemoThread-dnQKTGw$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;Lmy0/c;Lay0/a;ILjava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method
