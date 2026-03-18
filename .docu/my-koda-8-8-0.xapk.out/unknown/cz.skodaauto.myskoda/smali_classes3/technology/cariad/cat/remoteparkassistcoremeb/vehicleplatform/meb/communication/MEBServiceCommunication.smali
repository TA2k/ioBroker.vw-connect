.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00a8\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0012\n\u0002\u0008\u0004\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u000b\u0008\u0000\u0018\u00002\u00020\u0001BK\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u000c\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u0006\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0006\u0010\u000c\u001a\u00020\u000b\u0012\u0006\u0010\u000e\u001a\u00020\r\u0012\u000c\u0010\u0011\u001a\u0008\u0012\u0004\u0012\u00020\u00100\u000f\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u0010H\u0002\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u001f\u0010\u001a\u001a\u00020\u00102\u0006\u0010\u0017\u001a\u00020\u00162\u0006\u0010\u0019\u001a\u00020\u0018H\u0002\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ\u000f\u0010\u001c\u001a\u00020\u0010H\u0002\u00a2\u0006\u0004\u0008\u001c\u0010\u0015J\u0019\u0010\u001f\u001a\u00020\u00102\u0008\u0008\u0002\u0010\u001e\u001a\u00020\u001dH\u0002\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0017\u0010#\u001a\u00020\u00102\u0006\u0010\"\u001a\u00020!H\u0002\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010&\u001a\u00020\u00102\u0006\u0010\"\u001a\u00020%H\u0002\u00a2\u0006\u0004\u0008&\u0010\'J\u0017\u0010)\u001a\u00020\u00102\u0006\u0010(\u001a\u00020!H\u0002\u00a2\u0006\u0004\u0008)\u0010$J\u0017\u0010,\u001a\u00020\u00102\u0006\u0010+\u001a\u00020*H\u0002\u00a2\u0006\u0004\u0008,\u0010-J\u0017\u0010.\u001a\u00020\u00102\u0006\u0010(\u001a\u00020!H\u0002\u00a2\u0006\u0004\u0008.\u0010$J/\u00104\u001a\u00020\u00102\u0006\u0010+\u001a\u00020*2\u0006\u00100\u001a\u00020/2\u0006\u00102\u001a\u0002012\u0006\u00103\u001a\u00020\u001dH\u0014\u00a2\u0006\u0004\u00084\u00105J\u0017\u00108\u001a\u00020\u00102\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u00088\u00109J\u0017\u0010:\u001a\u00020\u00102\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u0008:\u00109J\u0017\u0010;\u001a\u00020\u00102\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u0008;\u00109J\u0017\u0010<\u001a\u00020\u00102\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u0008<\u00109J\u0017\u0010>\u001a\u00020\u00102\u0006\u0010=\u001a\u00020\u001dH\u0014\u00a2\u0006\u0004\u0008>\u0010 J\u0017\u0010?\u001a\u00020\u00102\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u0008?\u00109J\u0017\u0010@\u001a\u00020\u00102\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u0008@\u00109J\u0017\u0010C\u001a\u00020\u00102\u0006\u0010B\u001a\u00020AH\u0016\u00a2\u0006\u0004\u0008C\u0010DJ\u000f\u0010E\u001a\u00020\u0010H\u0016\u00a2\u0006\u0004\u0008E\u0010\u0015R\u0014\u0010\u000c\u001a\u00020\u000b8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000c\u0010FR\u0014\u0010\u000e\u001a\u00020\r8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000e\u0010GR\u001a\u0010I\u001a\u00020H8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008I\u0010J\u001a\u0004\u0008K\u0010LR$\u0010O\u001a\u00020M2\u0006\u0010N\u001a\u00020M8\u0000@BX\u0080\u000e\u00a2\u0006\u000c\n\u0004\u0008O\u0010P\u001a\u0004\u0008Q\u0010RR\u0016\u0010T\u001a\u00020S8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008T\u0010UR\u0016\u0010V\u001a\u00020\u001d8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008V\u0010WR\u0016\u0010X\u001a\u00020\u001d8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008X\u0010WR$\u0010Z\u001a\u00020Y2\u0006\u0010N\u001a\u00020Y8\u0002@BX\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008Z\u0010[\"\u0004\u0008\\\u0010]R\u0014\u0010^\u001a\u00020\u001d8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008^\u0010WR\u0016\u0010_\u001a\u00020\u001d8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008_\u0010WR\u0016\u0010`\u001a\u00020S8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008`\u0010UR\u0014\u0010c\u001a\u00020!8BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008a\u0010b\u00a8\u0006d"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "Lr71/a;",
        "latestServiceCommunicationData",
        "Lk71/d;",
        "p2CCommunicating",
        "",
        "Ll71/u;",
        "enabledVehiclePlatforms",
        "Ll71/a;",
        "debugConfig",
        "Ln71/a;",
        "dispatcher",
        "Lo71/a;",
        "logger",
        "Lkotlin/Function0;",
        "Llx0/b0;",
        "onReconnect",
        "<init>",
        "(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/a;)V",
        "resetTouchDiagnosisResponseStateDelayed",
        "()V",
        "Ls71/l;",
        "screen",
        "Ls71/p;",
        "userAction",
        "sendStopIfNeeded",
        "(Ls71/l;Ls71/p;)V",
        "startCyclicP2CHighPrioMessageIfNotAlreadyStarted",
        "",
        "shouldSendImmediately",
        "sendDelayedP2CHighPrioMessage",
        "(Z)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;",
        "message",
        "updateCurrent",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;",
        "updateAndSend",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V",
        "p2cHighPrioMessage",
        "log",
        "",
        "payload",
        "handleC2PHighPrioMessageMEB",
        "([B)V",
        "logInvalidTouches",
        "",
        "address",
        "",
        "priority",
        "requiresQueuing",
        "onC2PMessageReceived",
        "([BJBZ)V",
        "Lt71/a;",
        "status",
        "userActionDidChange",
        "(Lt71/a;)V",
        "sideEffectTriggered",
        "touchPositionDidChange",
        "screenDidChange",
        "isFull",
        "onSendWindowIsFullChanged",
        "lifecycleDidChange",
        "safetyInstructionDidChange",
        "Lk71/c;",
        "connectionStatus",
        "onConnectionStateChanged",
        "(Lk71/c;)V",
        "resetMessages",
        "Ln71/a;",
        "Lo71/a;",
        "Lmy0/c;",
        "highPrioInterval",
        "J",
        "getHighPrioInterval-UwyO8pc",
        "()J",
        "Li81/c;",
        "value",
        "messages",
        "Li81/c;",
        "getMessages$remoteparkassistcoremeb_release",
        "()Li81/c;",
        "Lpy0/a;",
        "latestAliveCounter",
        "Lpy0/a;",
        "isSendingCyclicMessagesActive",
        "Z",
        "shouldBlockSendingDueToMultiTouch",
        "Li81/a;",
        "latestCarDataMEB",
        "Li81/a;",
        "setLatestCarDataMEB",
        "(Li81/a;)V",
        "shouldBlockSendingDuringFullSendWindow",
        "isSendWindowFull",
        "aliveCounter",
        "getCurrentP2CHighPrioMessageMEB",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;",
        "currentP2CHighPrioMessageMEB",
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
.field private aliveCounter:Lpy0/a;

.field private final dispatcher:Ln71/a;

.field private final highPrioInterval:J

.field private isSendWindowFull:Z

.field private isSendingCyclicMessagesActive:Z

.field private latestAliveCounter:Lpy0/a;

.field private latestCarDataMEB:Li81/a;

.field private final logger:Lo71/a;

.field private messages:Li81/c;

.field private shouldBlockSendingDueToMultiTouch:Z

.field private final shouldBlockSendingDuringFullSendWindow:Z


# direct methods
.method public constructor <init>(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lr71/a;",
            "Lk71/d;",
            "Ljava/util/Set<",
            "+",
            "Ll71/u;",
            ">;",
            "Ll71/a;",
            "Ln71/a;",
            "Lo71/a;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "latestServiceCommunicationData"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "p2CCommunicating"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "enabledVehiclePlatforms"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "debugConfig"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "dispatcher"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v0, "logger"

    .line 27
    .line 28
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v0, "onReconnect"

    .line 32
    .line 33
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-direct/range {p0 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;-><init>(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/a;)V

    .line 37
    .line 38
    .line 39
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->dispatcher:Ln71/a;

    .line 40
    .line 41
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 42
    .line 43
    sget-wide p1, Li81/b;->c:J

    .line 44
    .line 45
    iput-wide p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->highPrioInterval:J

    .line 46
    .line 47
    new-instance p1, Li81/c;

    .line 48
    .line 49
    invoke-direct {p1}, Li81/c;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 53
    .line 54
    const/4 p1, -0x1

    .line 55
    invoke-static {p1}, Ljp/ee;->a(I)Lpy0/a;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 60
    .line 61
    new-instance p1, Li81/a;

    .line 62
    .line 63
    invoke-direct {p1}, Li81/a;-><init>()V

    .line 64
    .line 65
    .line 66
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 67
    .line 68
    iget-boolean p1, p4, Ll71/a;->b:Z

    .line 69
    .line 70
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDuringFullSendWindow:Z

    .line 71
    .line 72
    const/4 p1, 0x0

    .line 73
    invoke-static {p1}, Ljp/ee;->a(I)Lpy0/a;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->aliveCounter:Lpy0/a;

    .line 78
    .line 79
    return-void
.end method

.method public static synthetic g(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->sendDelayedP2CHighPrioMessage$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 2
    .line 3
    iget-object p0, p0, Li81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 4
    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->sendDelayedP2CHighPrioMessage$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final handleC2PHighPrioMessageMEB([B)V
    .locals 8

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 4
    .line 5
    .line 6
    move-result-object v3

    .line 7
    if-nez v3, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 10
    .line 11
    array-length p1, p1

    .line 12
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB$Companion;->getByteLength()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const-string v1, " != expected size("

    .line 17
    .line 18
    const-string v2, "))"

    .line 19
    .line 20
    const-string v3, "Could not create C2PHighPrioMessageMEB! Payload size("

    .line 21
    .line 22
    invoke-static {p1, v0, v3, v1, v2}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 31
    .line 32
    iget-object p1, p1, Li81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 33
    .line 34
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->toBytes()[B

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->toBytes()[B

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-static {p1, v0}, Ljava/util/Arrays;->equals([B[B)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-nez p1, :cond_1

    .line 47
    .line 48
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 49
    .line 50
    new-instance v0, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v1, "Received: "

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-static {p1, v0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 68
    .line 69
    const/4 v6, 0x0

    .line 70
    const/16 v7, 0x17

    .line 71
    .line 72
    const/4 v2, 0x0

    .line 73
    move-object v5, v3

    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-static/range {v1 .. v7}, Li81/c;->a(Li81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;I)Li81/c;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_1
    move-object v5, v3

    .line 84
    :goto_0
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 85
    .line 86
    const/4 v6, 0x0

    .line 87
    const/16 v7, 0x3d

    .line 88
    .line 89
    const/4 v2, 0x0

    .line 90
    const/4 v4, 0x0

    .line 91
    move-object v3, v5

    .line 92
    const/4 v5, 0x0

    .line 93
    invoke-static/range {v1 .. v7}, Li81/a;->a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 98
    .line 99
    .line 100
    return-void
.end method

.method public static synthetic i(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->resetTouchDiagnosisResponseStateDelayed$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final log(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V
    .locals 13

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getAliveCounter()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 6
    .line 7
    iget v1, v1, Lpy0/a;->a:I

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v1, 0x0

    .line 14
    :goto_0
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 15
    .line 16
    iput v0, v2, Lpy0/a;->a:I

    .line 17
    .line 18
    const/16 v10, 0x3e

    .line 19
    .line 20
    const/4 v11, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v8, 0x0

    .line 26
    const/4 v9, 0x0

    .line 27
    move-object v3, p1

    .line 28
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->toBytes()[B

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 37
    .line 38
    iget-object v4, v0, Li81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 39
    .line 40
    const/16 v11, 0x3e

    .line 41
    .line 42
    const/4 v12, 0x0

    .line 43
    const/4 v5, 0x0

    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v9, 0x0

    .line 46
    const/4 v10, 0x0

    .line 47
    invoke-static/range {v4 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->toBytes()[B

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const-string v2, "Send: "

    .line 56
    .line 57
    if-eqz v1, :cond_1

    .line 58
    .line 59
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 60
    .line 61
    new-instance p1, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v0, " (alive counter is stuck)"

    .line 70
    .line 71
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :cond_1
    invoke-static {v0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-nez p1, :cond_2

    .line 87
    .line 88
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 89
    .line 90
    new-instance p1, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    return-void

    .line 106
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 107
    .line 108
    new-instance p1, Ljava/lang/StringBuilder;

    .line 109
    .line 110
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-static {p0, p1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    return-void
.end method

.method private final logInvalidTouches(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->DRIVE_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x0

    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->DRIVE_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 16
    .line 17
    if-ne v0, v1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v0, v3

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    :goto_0
    move v0, v2

    .line 23
    :goto_1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->isEngineStartRequested()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchPositionY()I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    const/16 v5, 0x1f

    .line 32
    .line 33
    if-ne v4, v5, :cond_2

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    move v4, v2

    .line 38
    goto :goto_2

    .line 39
    :cond_2
    move v4, v3

    .line 40
    :goto_2
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchPositionY()I

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    if-ne v6, v5, :cond_3

    .line 45
    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    move v6, v2

    .line 49
    goto :goto_3

    .line 50
    :cond_3
    move v6, v3

    .line 51
    :goto_3
    if-eqz v0, :cond_5

    .line 52
    .line 53
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchPositionY()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eq v0, v5, :cond_5

    .line 58
    .line 59
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchPositionY()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    const/16 v7, 0x19

    .line 64
    .line 65
    if-gt v7, v0, :cond_4

    .line 66
    .line 67
    const/16 v7, 0x1e

    .line 68
    .line 69
    if-gt v0, v7, :cond_4

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_4
    move v0, v2

    .line 73
    goto :goto_5

    .line 74
    :cond_5
    :goto_4
    move v0, v3

    .line 75
    :goto_5
    if-eqz v1, :cond_6

    .line 76
    .line 77
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchPositionY()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eq v1, v5, :cond_6

    .line 82
    .line 83
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getTouchPositionY()I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    const/16 v5, 0x13

    .line 88
    .line 89
    if-gt v5, v1, :cond_7

    .line 90
    .line 91
    const/16 v5, 0x18

    .line 92
    .line 93
    if-gt v1, v5, :cond_7

    .line 94
    .line 95
    :cond_6
    move v2, v3

    .line 96
    :cond_7
    if-nez v4, :cond_9

    .line 97
    .line 98
    if-nez v6, :cond_9

    .line 99
    .line 100
    if-nez v0, :cond_9

    .line 101
    .line 102
    if-eqz v2, :cond_8

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_8
    return-void

    .line 106
    :cond_9
    :goto_6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 107
    .line 108
    new-instance v0, Ljava/lang/StringBuilder;

    .line 109
    .line 110
    const-string v1, "Invalid touch detected -> Send: "

    .line 111
    .line 112
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    return-void
.end method

.method private final resetTouchDiagnosisResponseStateDelayed()V
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->dispatcher:Ln71/a;

    .line 2
    .line 3
    sget-wide v1, Li81/b;->c:J

    .line 4
    .line 5
    const/4 v3, 0x3

    .line 6
    invoke-static {v3, v1, v2}, Lmy0/c;->l(IJ)J

    .line 7
    .line 8
    .line 9
    move-result-wide v1

    .line 10
    new-instance v3, Lh81/a;

    .line 11
    .line 12
    const/4 v4, 0x1

    .line 13
    invoke-direct {v3, p0, v4}, Lh81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1, v2, v3}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method private static final resetTouchDiagnosisResponseStateDelayed$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;
    .locals 9

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 6
    .line 7
    const/16 v7, 0x1f

    .line 8
    .line 9
    const/4 v8, 0x0

    .line 10
    const/4 v1, 0x0

    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    const/4 v4, 0x0

    .line 14
    const/4 v5, 0x0

    .line 15
    invoke-static/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method

.method private final sendDelayedP2CHighPrioMessage(Z)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    sget p1, Lmy0/c;->g:I

    .line 9
    .line 10
    sget-object p1, Lmy0/e;->g:Lmy0/e;

    .line 11
    .line 12
    invoke-static {v0, p1}, Lmy0/h;->s(ILmy0/e;)J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getHighPrioInterval-UwyO8pc()J

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    :goto_0
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->dispatcher:Ln71/a;

    .line 22
    .line 23
    new-instance v3, Lh81/a;

    .line 24
    .line 25
    invoke-direct {v3, p0, v0}, Lh81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {p1, v1, v2, v3}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public static synthetic sendDelayedP2CHighPrioMessage$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;ZILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->sendDelayedP2CHighPrioMessage(Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method private static final sendDelayedP2CHighPrioMessage$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;
    .locals 10

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDuringFullSendWindow:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->isSendWindowFull:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    :cond_0
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->aliveCounter:Lpy0/a;

    .line 14
    .line 15
    iget v2, v0, Lpy0/a;->a:I

    .line 16
    .line 17
    const/16 v8, 0x3e

    .line 18
    .line 19
    const/4 v9, 0x0

    .line 20
    const/4 v3, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->dispatcher:Ln71/a;

    .line 33
    .line 34
    new-instance v1, Lh81/a;

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    invoke-direct {v1, p0, v2}, Lh81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0, v1}, Ln71/a;->d(Ln71/a;Lay0/a;)Ln71/b;

    .line 41
    .line 42
    .line 43
    :cond_1
    const/4 v0, 0x1

    .line 44
    const/4 v1, 0x0

    .line 45
    const/4 v2, 0x0

    .line 46
    invoke-static {p0, v2, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->sendDelayedP2CHighPrioMessage$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;ZILjava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0
.end method

.method private static final sendDelayedP2CHighPrioMessage$lambda$0$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;)Llx0/b0;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->aliveCounter:Lpy0/a;

    .line 2
    .line 3
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->getAliveCounter()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    add-int/lit8 p0, p0, 0x1

    .line 12
    .line 13
    rem-int/lit8 p0, p0, 0x10

    .line 14
    .line 15
    xor-int/lit8 v1, p0, 0x10

    .line 16
    .line 17
    neg-int v2, p0

    .line 18
    or-int/2addr v2, p0

    .line 19
    and-int/2addr v1, v2

    .line 20
    shr-int/lit8 v1, v1, 0x1f

    .line 21
    .line 22
    and-int/lit8 v1, v1, 0x10

    .line 23
    .line 24
    add-int/2addr p0, v1

    .line 25
    iput p0, v0, Lpy0/a;->a:I

    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0
.end method

.method private final sendStopIfNeeded(Ls71/l;Ls71/p;)V
    .locals 9

    .line 1
    sget-object v0, Ls71/l;->g:Ls71/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    sget-object v3, Ls71/l;->j:Ls71/l;

    .line 11
    .line 12
    if-ne p1, v3, :cond_1

    .line 13
    .line 14
    sget-object v3, Ls71/p;->e:Ls71/p;

    .line 15
    .line 16
    if-ne p2, v3, :cond_1

    .line 17
    .line 18
    move v1, v2

    .line 19
    :cond_1
    if-nez v0, :cond_2

    .line 20
    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    iget-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    new-instance v0, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v1, "screenChanged("

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string p1, ") => isEngineStartRequested = false [CheckInvalidTouches]"

    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-static {p2, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 56
    .line 57
    const/16 v7, 0x39

    .line 58
    .line 59
    const/4 v8, 0x0

    .line 60
    const/4 v1, 0x0

    .line 61
    const/4 v3, 0x0

    .line 62
    const/4 v4, 0x0

    .line 63
    const/4 v5, 0x0

    .line 64
    const/4 v6, 0x0

    .line 65
    invoke-static/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 70
    .line 71
    .line 72
    :cond_2
    return-void
.end method

.method private final setLatestCarDataMEB(Li81/a;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 10
    .line 11
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getDelegate$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->carStatusChanged(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method private final startCyclicP2CHighPrioMessageIfNotAlreadyStarted()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getHighPrioInterval-UwyO8pc()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v1, v2}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    new-instance v2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v3, "startCyclicP2CHighPrioMessageIfNotAlreadyStarted() highPrioInterval: "

    .line 18
    .line 19
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-static {v0, v1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x1

    .line 33
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 34
    .line 35
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->sendDelayedP2CHighPrioMessage(Z)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 40
    .line 41
    const-string v0, "High prio cyclic sending is already started."

    .line 42
    .line 43
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method private final updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V
    .locals 9

    .line 1
    invoke-interface {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;->getAddress()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;

    .line 10
    .line 11
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;->getAddress()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    cmp-long v2, v0, v2

    .line 16
    .line 17
    const-string v3, "Send: "

    .line 18
    .line 19
    if-eqz v2, :cond_2

    .line 20
    .line 21
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CVehicleDataRequestMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CVehicleDataRequestMessageMEB$Companion;

    .line 22
    .line 23
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CVehicleDataRequestMessageMEB$Companion;->getAddress()J

    .line 24
    .line 25
    .line 26
    move-result-wide v4

    .line 27
    cmp-long v2, v0, v4

    .line 28
    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB$Companion;

    .line 33
    .line 34
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB$Companion;->getAddress()J

    .line 35
    .line 36
    .line 37
    move-result-wide v4

    .line 38
    cmp-long v2, v0, v4

    .line 39
    .line 40
    if-nez v2, :cond_1

    .line 41
    .line 42
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 43
    .line 44
    new-instance v1, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-static {v0, v1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 60
    .line 61
    move-object v5, p1

    .line 62
    check-cast v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 63
    .line 64
    const/4 v7, 0x0

    .line 65
    const/16 v8, 0x1b

    .line 66
    .line 67
    const/4 v3, 0x0

    .line 68
    const/4 v4, 0x0

    .line 69
    const/4 v6, 0x0

    .line 70
    invoke-static/range {v2 .. v8}, Li81/c;->a(Li81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;I)Li81/c;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;

    .line 78
    .line 79
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB$Companion;->getAddress()J

    .line 80
    .line 81
    .line 82
    move-result-wide v2

    .line 83
    cmp-long v0, v0, v2

    .line 84
    .line 85
    if-nez v0, :cond_3

    .line 86
    .line 87
    move-object v2, p1

    .line 88
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 89
    .line 90
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->log(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 91
    .line 92
    .line 93
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 94
    .line 95
    const/4 v6, 0x0

    .line 96
    const/16 v7, 0x1c

    .line 97
    .line 98
    const/4 v4, 0x0

    .line 99
    const/4 v5, 0x0

    .line 100
    move-object v3, v2

    .line 101
    invoke-static/range {v1 .. v7}, Li81/c;->a(Li81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;I)Li81/c;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 106
    .line 107
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logInvalidTouches(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_2
    :goto_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 112
    .line 113
    new-instance v1, Ljava/lang/StringBuilder;

    .line 114
    .line 115
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    invoke-static {v0, v1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    :cond_3
    :goto_1
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 129
    .line 130
    .line 131
    return-void
.end method

.method private final updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V
    .locals 7

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x1e

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v1, p1

    .line 10
    invoke-static/range {v0 .. v6}, Li81/c;->a(Li81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;I)Li81/c;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public getHighPrioInterval-UwyO8pc()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->highPrioInterval:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getMessages$remoteparkassistcoremeb_release()Li81/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public lifecycleDidChange(Lt71/a;)V
    .locals 10

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ln71/c;->f:Ln71/c;

    .line 7
    .line 8
    sget-object v1, Ln71/c;->g:Ln71/c;

    .line 9
    .line 10
    filled-new-array {v0, v1}, [Ln71/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, p1, Lt71/a;->a:Ln71/c;

    .line 19
    .line 20
    invoke-interface {v0, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 31
    .line 32
    const/16 v8, 0x3d

    .line 33
    .line 34
    const/4 v9, 0x0

    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v4, 0x0

    .line 37
    const/4 v5, 0x0

    .line 38
    const/4 v6, 0x0

    .line 39
    const/4 v7, 0x0

    .line 40
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 45
    .line 46
    .line 47
    :cond_0
    invoke-super {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->lifecycleDidChange(Lt71/a;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public onC2PMessageReceived([BJBZ)V
    .locals 10

    .line 1
    const-string p4, "payload"

    .line 2
    .line 3
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB$Companion;

    .line 7
    .line 8
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB$Companion;->getAddress()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    cmp-long p5, p2, v0

    .line 13
    .line 14
    const-string v0, "Received: "

    .line 15
    .line 16
    const-string v1, "))"

    .line 17
    .line 18
    const-string v2, " != expected size("

    .line 19
    .line 20
    if-nez p5, :cond_1

    .line 21
    .line 22
    invoke-virtual {p4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    if-nez p2, :cond_0

    .line 27
    .line 28
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 29
    .line 30
    array-length p1, p1

    .line 31
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB$Companion;->getByteLength()I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    const-string p3, "Could not create C2PStaticInfoResponseMessageMEB! Payload size("

    .line 36
    .line 37
    invoke-static {p1, p2, p3, v2, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 46
    .line 47
    new-instance p3, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p3

    .line 59
    invoke-static {p1, p3}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getLatestCarDataRPA()Ll71/v;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;->getMajorVersion-w2LRezQ()B

    .line 67
    .line 68
    .line 69
    move-result p3

    .line 70
    and-int/lit16 p3, p3, 0xff

    .line 71
    .line 72
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;->getMinorVersion-w2LRezQ()B

    .line 73
    .line 74
    .line 75
    move-result p4

    .line 76
    and-int/lit16 p4, p4, 0xff

    .line 77
    .line 78
    invoke-virtual {p0, p3, p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->determinePiloPaVersion(II)Ll71/u;

    .line 79
    .line 80
    .line 81
    move-result-object p3

    .line 82
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    const-string p1, "piloPaVersion"

    .line 86
    .line 87
    invoke-static {p3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    new-instance p1, Ll71/v;

    .line 91
    .line 92
    invoke-direct {p1, p3}, Ll71/v;-><init>(Ll71/u;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestCarDataRPA(Ll71/v;)V

    .line 96
    .line 97
    .line 98
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 99
    .line 100
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PStaticInfoResponseMessageMEB;->getFunctionAvailabilityStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    const/4 v5, 0x0

    .line 105
    const/16 v6, 0x3e

    .line 106
    .line 107
    const/4 v2, 0x0

    .line 108
    const/4 v3, 0x0

    .line 109
    const/4 v4, 0x0

    .line 110
    invoke-static/range {v0 .. v6}, Li81/a;->a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 115
    .line 116
    .line 117
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->startCyclicP2CHighPrioMessageIfNotAlreadyStarted()V

    .line 118
    .line 119
    .line 120
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CVehicleDataRequestMessageMEB;

    .line 121
    .line 122
    const/4 p2, 0x1

    .line 123
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CVehicleDataRequestMessageMEB;-><init>(Z)V

    .line 124
    .line 125
    .line 126
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 127
    .line 128
    .line 129
    return-void

    .line 130
    :cond_1
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB$Companion;

    .line 131
    .line 132
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB$Companion;->getAddress()J

    .line 133
    .line 134
    .line 135
    move-result-wide p4

    .line 136
    cmp-long p4, p2, p4

    .line 137
    .line 138
    if-nez p4, :cond_2

    .line 139
    .line 140
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->handleC2PHighPrioMessageMEB([B)V

    .line 141
    .line 142
    .line 143
    return-void

    .line 144
    :cond_2
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;

    .line 145
    .line 146
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;->getAddress()J

    .line 147
    .line 148
    .line 149
    move-result-wide v3

    .line 150
    cmp-long p5, p2, v3

    .line 151
    .line 152
    if-nez p5, :cond_4

    .line 153
    .line 154
    invoke-virtual {p4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 155
    .line 156
    .line 157
    move-result-object v6

    .line 158
    if-nez v6, :cond_3

    .line 159
    .line 160
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 161
    .line 162
    array-length p1, p1

    .line 163
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB$Companion;->getByteLength()I

    .line 164
    .line 165
    .line 166
    move-result p2

    .line 167
    const-string p3, "Could not create C2PNormalPrioManeuverInfoMessageMEB! Payload size("

    .line 168
    .line 169
    invoke-static {p1, p2, p3, v2, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :cond_3
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 178
    .line 179
    new-instance p2, Ljava/lang/StringBuilder;

    .line 180
    .line 181
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p2

    .line 191
    invoke-static {p1, p2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 195
    .line 196
    const/4 v7, 0x0

    .line 197
    const/16 v9, 0xf

    .line 198
    .line 199
    const/4 v4, 0x0

    .line 200
    const/4 v5, 0x0

    .line 201
    move-object v8, v6

    .line 202
    const/4 v6, 0x0

    .line 203
    invoke-static/range {v3 .. v9}, Li81/c;->a(Li81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;I)Li81/c;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 208
    .line 209
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 210
    .line 211
    move-object v6, v8

    .line 212
    const/4 v8, 0x0

    .line 213
    const/16 v9, 0x3b

    .line 214
    .line 215
    invoke-static/range {v3 .. v9}, Li81/a;->a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;

    .line 216
    .line 217
    .line 218
    move-result-object p1

    .line 219
    move-object v8, v6

    .line 220
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 221
    .line 222
    .line 223
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 224
    .line 225
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 226
    .line 227
    invoke-virtual {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->getParkingScenarioActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    invoke-virtual {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->getParkingSideActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    invoke-virtual {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->getParkingDirectionActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    invoke-virtual {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->getParkingManeuverActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 240
    .line 241
    .line 242
    move-result-object v4

    .line 243
    const/16 v6, 0x10

    .line 244
    .line 245
    const/4 v5, 0x0

    .line 246
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 247
    .line 248
    .line 249
    move-result-object p1

    .line 250
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 251
    .line 252
    .line 253
    return-void

    .line 254
    :cond_4
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;

    .line 255
    .line 256
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;->getAddress()J

    .line 257
    .line 258
    .line 259
    move-result-wide v3

    .line 260
    cmp-long p5, p2, v3

    .line 261
    .line 262
    if-nez p5, :cond_6

    .line 263
    .line 264
    invoke-virtual {p4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;

    .line 265
    .line 266
    .line 267
    move-result-object v7

    .line 268
    if-nez v7, :cond_5

    .line 269
    .line 270
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 271
    .line 272
    array-length p1, p1

    .line 273
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB$Companion;->getByteLength()I

    .line 274
    .line 275
    .line 276
    move-result p2

    .line 277
    const-string p3, "Could not create C2PNormalPrioVehicleInfoMessageMEB! Payload size("

    .line 278
    .line 279
    invoke-static {p1, p2, p3, v2, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object p1

    .line 283
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    return-void

    .line 287
    :cond_5
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 288
    .line 289
    new-instance p2, Ljava/lang/StringBuilder;

    .line 290
    .line 291
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {p2, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 295
    .line 296
    .line 297
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object p2

    .line 301
    invoke-static {p1, p2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 305
    .line 306
    const/4 v8, 0x0

    .line 307
    const/16 v9, 0x37

    .line 308
    .line 309
    const/4 v4, 0x0

    .line 310
    const/4 v5, 0x0

    .line 311
    const/4 v6, 0x0

    .line 312
    invoke-static/range {v3 .. v9}, Li81/a;->a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;

    .line 313
    .line 314
    .line 315
    move-result-object p1

    .line 316
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 317
    .line 318
    .line 319
    return-void

    .line 320
    :cond_6
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryMetadataMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryMetadataMEB$Companion;

    .line 321
    .line 322
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryMetadataMEB$Companion;->getAddress()J

    .line 323
    .line 324
    .line 325
    move-result-wide v3

    .line 326
    cmp-long p5, p2, v3

    .line 327
    .line 328
    if-nez p5, :cond_8

    .line 329
    .line 330
    invoke-virtual {p4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryMetadataMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryMetadataMEB;

    .line 331
    .line 332
    .line 333
    move-result-object p2

    .line 334
    if-nez p2, :cond_7

    .line 335
    .line 336
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 337
    .line 338
    array-length p1, p1

    .line 339
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryMetadataMEB$Companion;->getByteLength()I

    .line 340
    .line 341
    .line 342
    move-result p2

    .line 343
    const-string p3, "Could not create C2PNormalPrioTrajectoryMetadataMEB! Payload size("

    .line 344
    .line 345
    invoke-static {p1, p2, p3, v2, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object p1

    .line 349
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    return-void

    .line 353
    :cond_7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 354
    .line 355
    new-instance p1, Ljava/lang/StringBuilder;

    .line 356
    .line 357
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 361
    .line 362
    .line 363
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object p1

    .line 367
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    return-void

    .line 371
    :cond_8
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryInfoMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryInfoMEB$Companion;

    .line 372
    .line 373
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryInfoMEB$Companion;->getAddress()J

    .line 374
    .line 375
    .line 376
    move-result-wide v3

    .line 377
    cmp-long p5, p2, v3

    .line 378
    .line 379
    if-nez p5, :cond_a

    .line 380
    .line 381
    invoke-virtual {p4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryInfoMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryInfoMEB;

    .line 382
    .line 383
    .line 384
    move-result-object p2

    .line 385
    if-nez p2, :cond_9

    .line 386
    .line 387
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 388
    .line 389
    array-length p1, p1

    .line 390
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioTrajectoryInfoMEB$Companion;->getByteLength()I

    .line 391
    .line 392
    .line 393
    move-result p2

    .line 394
    const-string p3, "Could not create C2PNormalPrioTrajectoryInfoMEB! Payload size("

    .line 395
    .line 396
    invoke-static {p1, p2, p3, v2, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object p1

    .line 400
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    return-void

    .line 404
    :cond_9
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 405
    .line 406
    new-instance p1, Ljava/lang/StringBuilder;

    .line 407
    .line 408
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 412
    .line 413
    .line 414
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 415
    .line 416
    .line 417
    move-result-object p1

    .line 418
    invoke-static {p0, p1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    return-void

    .line 422
    :cond_a
    sget-object p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;

    .line 423
    .line 424
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;->getAddress()J

    .line 425
    .line 426
    .line 427
    move-result-wide v3

    .line 428
    cmp-long p2, p2, v3

    .line 429
    .line 430
    if-nez p2, :cond_c

    .line 431
    .line 432
    invoke-virtual {p4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 433
    .line 434
    .line 435
    move-result-object v8

    .line 436
    if-nez v8, :cond_b

    .line 437
    .line 438
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 439
    .line 440
    array-length p1, p1

    .line 441
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB$Companion;->getByteLength()I

    .line 442
    .line 443
    .line 444
    move-result p2

    .line 445
    const-string p3, "Could not create C2PVehicleDataResponseMessageMEB! Payload size("

    .line 446
    .line 447
    invoke-static {p1, p2, p3, v2, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object p1

    .line 451
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 452
    .line 453
    .line 454
    return-void

    .line 455
    :cond_b
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 456
    .line 457
    new-instance p2, Ljava/lang/StringBuilder;

    .line 458
    .line 459
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    invoke-virtual {p2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 463
    .line 464
    .line 465
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 466
    .line 467
    .line 468
    move-result-object p2

    .line 469
    invoke-static {p1, p2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 473
    .line 474
    const/4 v7, 0x0

    .line 475
    const/16 v9, 0x2f

    .line 476
    .line 477
    const/4 v4, 0x0

    .line 478
    const/4 v5, 0x0

    .line 479
    const/4 v6, 0x0

    .line 480
    invoke-static/range {v3 .. v9}, Li81/a;->a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;

    .line 481
    .line 482
    .line 483
    move-result-object p1

    .line 484
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 485
    .line 486
    .line 487
    :cond_c
    return-void
.end method

.method public onConnectionStateChanged(Lk71/c;)V
    .locals 7

    .line 1
    const-string v0, "connectionStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_3

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p1, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p1, v0, :cond_0

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance p0, La8/r0;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getLatestReceivedServiceCommunicationMessages()Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    check-cast p1, Ljava/lang/Iterable;

    .line 33
    .line 34
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Lr71/b;

    .line 49
    .line 50
    iget-object v2, v0, Lr71/b;->a:[B

    .line 51
    .line 52
    iget-wide v3, v0, Lr71/b;->b:J

    .line 53
    .line 54
    iget-byte v5, v0, Lr71/b;->c:B

    .line 55
    .line 56
    iget-boolean v6, v0, Lr71/b;->d:Z

    .line 57
    .line 58
    move-object v1, p0

    .line 59
    invoke-virtual/range {v1 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->receivedMessageFromCar([BJBZ)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    move-object v1, p0

    .line 64
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 65
    .line 66
    invoke-virtual {v1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestReceivedServiceCommunicationMessages(Ljava/util/List;)V

    .line 67
    .line 68
    .line 69
    :cond_3
    return-void
.end method

.method public onSendWindowIsFullChanged(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->isSendWindowFull:Z

    .line 2
    .line 3
    return-void
.end method

.method public resetMessages()V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    iput v1, v0, Lpy0/a;->a:I

    .line 5
    .line 6
    new-instance v0, Li81/c;

    .line 7
    .line 8
    invoke-direct {v0}, Li81/c;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 12
    .line 13
    new-instance v0, Li81/a;

    .line 14
    .line 15
    invoke-direct {v0}, Li81/a;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public safetyInstructionDidChange(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getDelegate$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-interface {v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->safetyInstructionChanged(Lt71/a;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getDelegate$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 22
    .line 23
    invoke-interface {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->carStatusChanged(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    :cond_1
    return-void
.end method

.method public screenDidChange(Lt71/a;)V
    .locals 10

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->screenDidChange(Lt71/a;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p1, Lt71/a;->b:Ls71/q;

    .line 10
    .line 11
    instance-of v1, v0, Ls71/p;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object v1, p1, Lt71/a;->e:Ls71/l;

    .line 16
    .line 17
    const-string v2, "null cannot be cast to non-null type technology.cariad.cat.remoteparkassistcoremeb.core.common.signal.UserAction"

    .line 18
    .line 19
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    check-cast v0, Ls71/p;

    .line 23
    .line 24
    invoke-direct {p0, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->sendStopIfNeeded(Ls71/l;Ls71/p;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-object p1, p1, Lt71/a;->e:Ls71/l;

    .line 28
    .line 29
    sget-object v0, Ls71/l;->e:Ls71/l;

    .line 30
    .line 31
    if-ne p1, v0, :cond_1

    .line 32
    .line 33
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 38
    .line 39
    const/16 v8, 0x1f

    .line 40
    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v2, 0x0

    .line 43
    const/4 v3, 0x0

    .line 44
    const/4 v4, 0x0

    .line 45
    const/4 v5, 0x0

    .line 46
    const/4 v6, 0x0

    .line 47
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 60
    .line 61
    const/16 v7, 0x1f

    .line 62
    .line 63
    const/4 v8, 0x0

    .line 64
    const/4 v1, 0x0

    .line 65
    const/4 v2, 0x0

    .line 66
    const/4 v3, 0x0

    .line 67
    const/4 v4, 0x0

    .line 68
    const/4 v5, 0x0

    .line 69
    invoke-static/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 74
    .line 75
    .line 76
    return-void
.end method

.method public sideEffectTriggered(Lt71/a;)V
    .locals 10

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->sideEffectTriggered(Lt71/a;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p1, Lt71/a;->c:Ls71/m;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const-string v1, ") => isEngineStartRequested = false [CheckInvalidTouches]"

    .line 16
    .line 17
    const-string v2, "sideEffectTriggered("

    .line 18
    .line 19
    packed-switch v0, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    new-instance p0, La8/r0;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :pswitch_0
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 29
    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 33
    .line 34
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 35
    .line 36
    new-instance v1, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p1, ") => isEngineStartRequested = true [CheckInvalidTouches]"

    .line 45
    .line 46
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    const/16 v8, 0x3b

    .line 61
    .line 62
    const/4 v9, 0x0

    .line 63
    const/4 v2, 0x0

    .line 64
    const/4 v3, 0x0

    .line 65
    const/4 v4, 0x1

    .line 66
    const/4 v5, 0x0

    .line 67
    const/4 v6, 0x0

    .line 68
    const/4 v7, 0x0

    .line 69
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 78
    .line 79
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 80
    .line 81
    new-instance v0, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string p1, ") => isEngineStartRequested could not be set due to MultiTouchDetected [CheckInvalidTouches]"

    .line 90
    .line 91
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->latestCarDataMEB:Li81/a;

    .line 103
    .line 104
    sget-object p1, Ll71/c;->d:Ll71/c;

    .line 105
    .line 106
    const/16 v6, 0x1f

    .line 107
    .line 108
    const/4 v1, 0x0

    .line 109
    const/4 v2, 0x0

    .line 110
    const/4 v3, 0x0

    .line 111
    const/4 v4, 0x0

    .line 112
    const/4 v5, 0x0

    .line 113
    invoke-static/range {v0 .. v6}, Li81/a;->a(Li81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioVehicleInfoMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;I)Li81/a;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->setLatestCarDataMEB(Li81/a;)V

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 122
    .line 123
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 124
    .line 125
    new-instance v3, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 148
    .line 149
    const/16 v8, 0x39

    .line 150
    .line 151
    const/4 v9, 0x0

    .line 152
    const/4 v2, 0x0

    .line 153
    const/4 v4, 0x0

    .line 154
    const/4 v5, 0x0

    .line 155
    const/4 v6, 0x0

    .line 156
    const/4 v7, 0x0

    .line 157
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->stopFunctionAndDisconnectDelayed()V

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :pswitch_3
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 169
    .line 170
    const/4 v0, 0x0

    .line 171
    const/4 v1, 0x2

    .line 172
    invoke-static {p0, p1, v0, v1}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 173
    .line 174
    .line 175
    return-void

    .line 176
    :pswitch_4
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 177
    .line 178
    iget-object p1, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 179
    .line 180
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->isWindowCommandCloseActive()Z

    .line 181
    .line 182
    .line 183
    move-result p1

    .line 184
    if-eqz p1, :cond_1

    .line 185
    .line 186
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 187
    .line 188
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 189
    .line 190
    const/16 v6, 0xf

    .line 191
    .line 192
    const/4 v7, 0x0

    .line 193
    const/4 v1, 0x0

    .line 194
    const/4 v2, 0x0

    .line 195
    const/4 v3, 0x0

    .line 196
    const/4 v4, 0x0

    .line 197
    const/4 v5, 0x0

    .line 198
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 203
    .line 204
    .line 205
    return-void

    .line 206
    :pswitch_5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 207
    .line 208
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 209
    .line 210
    new-instance v3, Ljava/lang/StringBuilder;

    .line 211
    .line 212
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object p1

    .line 225
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 233
    .line 234
    const/16 v8, 0x39

    .line 235
    .line 236
    const/4 v9, 0x0

    .line 237
    const/4 v2, 0x0

    .line 238
    const/4 v4, 0x0

    .line 239
    const/4 v5, 0x0

    .line 240
    const/4 v6, 0x0

    .line 241
    const/4 v7, 0x0

    .line 242
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 243
    .line 244
    .line 245
    move-result-object p1

    .line 246
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 247
    .line 248
    .line 249
    return-void

    .line 250
    :pswitch_6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 251
    .line 252
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 253
    .line 254
    new-instance v3, Ljava/lang/StringBuilder;

    .line 255
    .line 256
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object p1

    .line 269
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    const/16 v8, 0x3b

    .line 277
    .line 278
    const/4 v9, 0x0

    .line 279
    const/4 v2, 0x0

    .line 280
    const/4 v3, 0x0

    .line 281
    const/4 v4, 0x0

    .line 282
    const/4 v5, 0x0

    .line 283
    const/4 v6, 0x0

    .line 284
    const/4 v7, 0x0

    .line 285
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 286
    .line 287
    .line 288
    move-result-object p1

    .line 289
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 290
    .line 291
    .line 292
    :cond_1
    :pswitch_7
    return-void

    .line 293
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_7
        :pswitch_1
        :pswitch_0
        :pswitch_7
    .end packed-switch
.end method

.method public touchPositionDidChange(Lt71/a;)V
    .locals 10

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->touchPositionDidChange(Lt71/a;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object p1, p1, Lt71/a;->d:Lu71/b;

    .line 14
    .line 15
    iget v5, p1, Lu71/b;->a:I

    .line 16
    .line 17
    iget v6, p1, Lu71/b;->b:I

    .line 18
    .line 19
    const/16 v8, 0x27

    .line 20
    .line 21
    const/4 v9, 0x0

    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x0

    .line 25
    const/4 v7, 0x0

    .line 26
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public userActionDidChange(Lt71/a;)V
    .locals 12

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->userActionDidChange(Lt71/a;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p1, Lt71/a;->b:Ls71/q;

    .line 10
    .line 11
    sget-object v0, Ls71/p;->g:Ls71/p;

    .line 12
    .line 13
    if-ne p1, v0, :cond_0

    .line 14
    .line 15
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->ACTION_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 20
    .line 21
    const/16 v8, 0x1f

    .line 22
    .line 23
    const/4 v9, 0x0

    .line 24
    const/4 v2, 0x0

    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v4, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x0

    .line 29
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    sget-object v0, Ls71/p;->i:Ls71/p;

    .line 38
    .line 39
    if-ne p1, v0, :cond_1

    .line 40
    .line 41
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 46
    .line 47
    const/16 v8, 0x1f

    .line 48
    .line 49
    const/4 v9, 0x0

    .line 50
    const/4 v2, 0x0

    .line 51
    const/4 v3, 0x0

    .line 52
    const/4 v4, 0x0

    .line 53
    const/4 v5, 0x0

    .line 54
    const/4 v6, 0x0

    .line 55
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 60
    .line 61
    .line 62
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->resetTouchDiagnosisResponseStateDelayed()V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    sget-object v0, Ls71/p;->h:Ls71/p;

    .line 67
    .line 68
    if-ne p1, v0, :cond_2

    .line 69
    .line 70
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 75
    .line 76
    const/16 v8, 0x1f

    .line 77
    .line 78
    const/4 v9, 0x0

    .line 79
    const/4 v2, 0x0

    .line 80
    const/4 v3, 0x0

    .line 81
    const/4 v4, 0x0

    .line 82
    const/4 v5, 0x0

    .line 83
    const/4 v6, 0x0

    .line 84
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_2
    sget-object v0, Ls71/p;->j:Ls71/p;

    .line 93
    .line 94
    if-ne p1, v0, :cond_3

    .line 95
    .line 96
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 97
    .line 98
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 99
    .line 100
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 101
    .line 102
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 103
    .line 104
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 105
    .line 106
    const/16 v6, 0x18

    .line 107
    .line 108
    const/4 v7, 0x0

    .line 109
    const/4 v4, 0x0

    .line 110
    const/4 v5, 0x0

    .line 111
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 116
    .line 117
    .line 118
    return-void

    .line 119
    :cond_3
    sget-object v0, Ls71/p;->k:Ls71/p;

    .line 120
    .line 121
    if-ne p1, v0, :cond_4

    .line 122
    .line 123
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 124
    .line 125
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 126
    .line 127
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 128
    .line 129
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 130
    .line 131
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 132
    .line 133
    const/16 v6, 0x18

    .line 134
    .line 135
    const/4 v7, 0x0

    .line 136
    const/4 v4, 0x0

    .line 137
    const/4 v5, 0x0

    .line 138
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 143
    .line 144
    .line 145
    return-void

    .line 146
    :cond_4
    sget-object v0, Ls71/p;->l:Ls71/p;

    .line 147
    .line 148
    if-ne p1, v0, :cond_5

    .line 149
    .line 150
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 151
    .line 152
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 153
    .line 154
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 155
    .line 156
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 157
    .line 158
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 159
    .line 160
    const/16 v6, 0x18

    .line 161
    .line 162
    const/4 v7, 0x0

    .line 163
    const/4 v4, 0x0

    .line 164
    const/4 v5, 0x0

    .line 165
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 170
    .line 171
    .line 172
    return-void

    .line 173
    :cond_5
    sget-object v0, Ls71/p;->m:Ls71/p;

    .line 174
    .line 175
    if-ne p1, v0, :cond_6

    .line 176
    .line 177
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 178
    .line 179
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 180
    .line 181
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 182
    .line 183
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 184
    .line 185
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 186
    .line 187
    const/16 v6, 0x18

    .line 188
    .line 189
    const/4 v7, 0x0

    .line 190
    const/4 v4, 0x0

    .line 191
    const/4 v5, 0x0

    .line 192
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 197
    .line 198
    .line 199
    return-void

    .line 200
    :cond_6
    sget-object v0, Ls71/p;->w:Ls71/p;

    .line 201
    .line 202
    const-string v1, ") => UserCommandState could not be set due to MultiTouchDetected [CheckInvalidTouches]"

    .line 203
    .line 204
    const-string v2, "userActionDidChange("

    .line 205
    .line 206
    if-eq p1, v0, :cond_13

    .line 207
    .line 208
    sget-object v0, Ls71/p;->n:Ls71/p;

    .line 209
    .line 210
    if-ne p1, v0, :cond_7

    .line 211
    .line 212
    goto/16 :goto_1

    .line 213
    .line 214
    :cond_7
    sget-object v0, Ls71/p;->u:Ls71/p;

    .line 215
    .line 216
    if-ne p1, v0, :cond_9

    .line 217
    .line 218
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 219
    .line 220
    if-nez v0, :cond_8

    .line 221
    .line 222
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->DRIVE_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 227
    .line 228
    const/16 v10, 0x3d

    .line 229
    .line 230
    const/4 v11, 0x0

    .line 231
    const/4 v4, 0x0

    .line 232
    const/4 v6, 0x0

    .line 233
    const/4 v7, 0x0

    .line 234
    const/4 v8, 0x0

    .line 235
    const/4 v9, 0x0

    .line 236
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 241
    .line 242
    .line 243
    return-void

    .line 244
    :cond_8
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 245
    .line 246
    new-instance v0, Ljava/lang/StringBuilder;

    .line 247
    .line 248
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 252
    .line 253
    .line 254
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object p1

    .line 261
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    return-void

    .line 265
    :cond_9
    sget-object v0, Ls71/p;->v:Ls71/p;

    .line 266
    .line 267
    if-eq p1, v0, :cond_12

    .line 268
    .line 269
    sget-object v0, Ls71/p;->x:Ls71/p;

    .line 270
    .line 271
    if-eq p1, v0, :cond_12

    .line 272
    .line 273
    sget-object v0, Ls71/p;->o:Ls71/p;

    .line 274
    .line 275
    if-ne p1, v0, :cond_a

    .line 276
    .line 277
    goto/16 :goto_0

    .line 278
    .line 279
    :cond_a
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 280
    .line 281
    if-ne p1, v0, :cond_b

    .line 282
    .line 283
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 288
    .line 289
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 290
    .line 291
    const/16 v10, 0x19

    .line 292
    .line 293
    const/4 v11, 0x0

    .line 294
    const/4 v4, 0x0

    .line 295
    const/4 v6, 0x0

    .line 296
    const/4 v7, 0x0

    .line 297
    const/4 v8, 0x0

    .line 298
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 299
    .line 300
    .line 301
    move-result-object p1

    .line 302
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 303
    .line 304
    .line 305
    const/4 p1, 0x1

    .line 306
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 307
    .line 308
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->resetTouchDiagnosisResponseStateDelayed()V

    .line 309
    .line 310
    .line 311
    return-void

    .line 312
    :cond_b
    sget-object v0, Ls71/p;->F:Ls71/p;

    .line 313
    .line 314
    if-ne p1, v0, :cond_c

    .line 315
    .line 316
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 317
    .line 318
    .line 319
    move-result-object v3

    .line 320
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;

    .line 321
    .line 322
    const/16 v10, 0x1f

    .line 323
    .line 324
    const/4 v11, 0x0

    .line 325
    const/4 v4, 0x0

    .line 326
    const/4 v5, 0x0

    .line 327
    const/4 v6, 0x0

    .line 328
    const/4 v7, 0x0

    .line 329
    const/4 v8, 0x0

    .line 330
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 331
    .line 332
    .line 333
    move-result-object p1

    .line 334
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 335
    .line 336
    .line 337
    const/4 p1, 0x0

    .line 338
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 339
    .line 340
    return-void

    .line 341
    :cond_c
    sget-object v0, Ls71/p;->e:Ls71/p;

    .line 342
    .line 343
    if-ne p1, v0, :cond_d

    .line 344
    .line 345
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 346
    .line 347
    .line 348
    move-result-object v3

    .line 349
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->CUSTOM_FINISH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 350
    .line 351
    const/16 v10, 0x3d

    .line 352
    .line 353
    const/4 v11, 0x0

    .line 354
    const/4 v4, 0x0

    .line 355
    const/4 v6, 0x0

    .line 356
    const/4 v7, 0x0

    .line 357
    const/4 v8, 0x0

    .line 358
    const/4 v9, 0x0

    .line 359
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 360
    .line 361
    .line 362
    move-result-object p1

    .line 363
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 364
    .line 365
    .line 366
    return-void

    .line 367
    :cond_d
    sget-object v0, Ls71/p;->z:Ls71/p;

    .line 368
    .line 369
    if-ne p1, v0, :cond_e

    .line 370
    .line 371
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 372
    .line 373
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 374
    .line 375
    const/16 v6, 0xf

    .line 376
    .line 377
    const/4 v7, 0x0

    .line 378
    const/4 v1, 0x0

    .line 379
    const/4 v2, 0x0

    .line 380
    const/4 v3, 0x0

    .line 381
    const/4 v4, 0x0

    .line 382
    const/4 v5, 0x1

    .line 383
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 384
    .line 385
    .line 386
    move-result-object p1

    .line 387
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 388
    .line 389
    .line 390
    return-void

    .line 391
    :cond_e
    sget-object v0, Ls71/p;->A:Ls71/p;

    .line 392
    .line 393
    if-ne p1, v0, :cond_f

    .line 394
    .line 395
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->messages:Li81/c;

    .line 396
    .line 397
    iget-object v0, p1, Li81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 398
    .line 399
    const/16 v6, 0xf

    .line 400
    .line 401
    const/4 v7, 0x0

    .line 402
    const/4 v1, 0x0

    .line 403
    const/4 v2, 0x0

    .line 404
    const/4 v3, 0x0

    .line 405
    const/4 v4, 0x0

    .line 406
    const/4 v5, 0x0

    .line 407
    invoke-static/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CNormalPrioMessageMEB;

    .line 408
    .line 409
    .line 410
    move-result-object p1

    .line 411
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 412
    .line 413
    .line 414
    return-void

    .line 415
    :cond_f
    sget-object v0, Ls71/p;->C:Ls71/p;

    .line 416
    .line 417
    if-ne p1, v0, :cond_10

    .line 418
    .line 419
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 420
    .line 421
    new-instance v1, Ljava/lang/StringBuilder;

    .line 422
    .line 423
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 424
    .line 425
    .line 426
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 427
    .line 428
    .line 429
    const-string p1, ") => isEngineStartRequested = false [CheckInvalidTouches]"

    .line 430
    .line 431
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 432
    .line 433
    .line 434
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 435
    .line 436
    .line 437
    move-result-object p1

    .line 438
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 439
    .line 440
    .line 441
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 442
    .line 443
    .line 444
    move-result-object v1

    .line 445
    const/16 v8, 0x3b

    .line 446
    .line 447
    const/4 v9, 0x0

    .line 448
    const/4 v2, 0x0

    .line 449
    const/4 v3, 0x0

    .line 450
    const/4 v4, 0x0

    .line 451
    const/4 v5, 0x0

    .line 452
    const/4 v6, 0x0

    .line 453
    const/4 v7, 0x0

    .line 454
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 455
    .line 456
    .line 457
    move-result-object p1

    .line 458
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 459
    .line 460
    .line 461
    return-void

    .line 462
    :cond_10
    sget-object p0, Ls71/p;->B:Ls71/p;

    .line 463
    .line 464
    if-eq p1, p0, :cond_11

    .line 465
    .line 466
    sget-object p0, Ls71/p;->D:Ls71/p;

    .line 467
    .line 468
    if-eq p1, p0, :cond_11

    .line 469
    .line 470
    sget-object p0, Ls71/p;->f:Ls71/p;

    .line 471
    .line 472
    if-eq p1, p0, :cond_11

    .line 473
    .line 474
    sget-object p0, Ls71/p;->d:Ls71/p;

    .line 475
    .line 476
    if-eq p1, p0, :cond_11

    .line 477
    .line 478
    sget-object p0, Ls71/p;->y:Ls71/p;

    .line 479
    .line 480
    if-eq p1, p0, :cond_11

    .line 481
    .line 482
    sget-object p0, Ls71/p;->t:Ls71/p;

    .line 483
    .line 484
    if-eq p1, p0, :cond_11

    .line 485
    .line 486
    sget-object p0, Ls71/p;->p:Ls71/p;

    .line 487
    .line 488
    if-eq p1, p0, :cond_11

    .line 489
    .line 490
    sget-object p0, Ls71/p;->d:Ls71/p;

    .line 491
    .line 492
    :cond_11
    return-void

    .line 493
    :cond_12
    :goto_0
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 494
    .line 495
    .line 496
    move-result-object v0

    .line 497
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 498
    .line 499
    const/16 v7, 0x3d

    .line 500
    .line 501
    const/4 v8, 0x0

    .line 502
    const/4 v1, 0x0

    .line 503
    const/4 v3, 0x0

    .line 504
    const/4 v4, 0x0

    .line 505
    const/4 v5, 0x0

    .line 506
    const/4 v6, 0x0

    .line 507
    invoke-static/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 508
    .line 509
    .line 510
    move-result-object p1

    .line 511
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 512
    .line 513
    .line 514
    return-void

    .line 515
    :cond_13
    :goto_1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 516
    .line 517
    if-nez v0, :cond_14

    .line 518
    .line 519
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->getCurrentP2CHighPrioMessageMEB()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 520
    .line 521
    .line 522
    move-result-object v3

    .line 523
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;->DRIVE_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;

    .line 524
    .line 525
    const/16 v10, 0x3d

    .line 526
    .line 527
    const/4 v11, 0x0

    .line 528
    const/4 v4, 0x0

    .line 529
    const/4 v6, 0x0

    .line 530
    const/4 v7, 0x0

    .line 531
    const/4 v8, 0x0

    .line 532
    const/4 v9, 0x0

    .line 533
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/UserCommandStatusMEB;ZIILtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/TouchDiagnosisResponseStatusMEB;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;

    .line 534
    .line 535
    .line 536
    move-result-object p1

    .line 537
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->updateCurrent(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/P2CHighPrioMessageMEB;)V

    .line 538
    .line 539
    .line 540
    return-void

    .line 541
    :cond_14
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;->logger:Lo71/a;

    .line 542
    .line 543
    new-instance v0, Ljava/lang/StringBuilder;

    .line 544
    .line 545
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 546
    .line 547
    .line 548
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 549
    .line 550
    .line 551
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 552
    .line 553
    .line 554
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 555
    .line 556
    .line 557
    move-result-object p1

    .line 558
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 559
    .line 560
    .line 561
    return-void
.end method
