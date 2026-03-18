.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00e0\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0014\u0008\u0000\u0018\u00002\u00020\u0001BK\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u000c\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u0006\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0006\u0010\u000c\u001a\u00020\u000b\u0012\u0006\u0010\u000e\u001a\u00020\r\u0012\u000c\u0010\u0011\u001a\u0008\u0012\u0004\u0012\u00020\u00100\u000f\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J/\u0010\u001c\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0017\u001a\u00020\u00162\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001b\u001a\u00020\u001aH\u0014\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0017\u0010 \u001a\u00020\u00102\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008 \u0010!J\u0017\u0010\"\u001a\u00020\u00102\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008\"\u0010!J\u0017\u0010#\u001a\u00020\u00102\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008#\u0010!J\u0017\u0010$\u001a\u00020\u00102\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008$\u0010!J\u0017\u0010&\u001a\u00020\u00102\u0006\u0010%\u001a\u00020\u001aH\u0014\u00a2\u0006\u0004\u0008&\u0010\'J\u0017\u0010(\u001a\u00020\u00102\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008(\u0010!J\u0017\u0010-\u001a\u00020\u00102\u0006\u0010*\u001a\u00020)H\u0000\u00a2\u0006\u0004\u0008+\u0010,J\u0017\u00100\u001a\u00020\u00102\u0006\u0010/\u001a\u00020.H\u0016\u00a2\u0006\u0004\u00080\u00101J\u000f\u00102\u001a\u00020\u0010H\u0016\u00a2\u0006\u0004\u00082\u00103J\u0017\u00106\u001a\u00020\u00102\u0006\u00105\u001a\u000204H\u0002\u00a2\u0006\u0004\u00086\u00107J\u000f\u00108\u001a\u00020\u0010H\u0002\u00a2\u0006\u0004\u00088\u00103J\u0017\u0010:\u001a\u00020\u00102\u0006\u00109\u001a\u00020\u001aH\u0002\u00a2\u0006\u0004\u0008:\u0010\'J\u000f\u0010;\u001a\u00020\u0010H\u0002\u00a2\u0006\u0004\u0008;\u00103J\u0017\u0010>\u001a\u00020=2\u0006\u0010*\u001a\u00020<H\u0002\u00a2\u0006\u0004\u0008>\u0010?J\u000f\u0010A\u001a\u00020@H\u0002\u00a2\u0006\u0004\u0008A\u0010BJ\u0017\u0010E\u001a\u00020@2\u0006\u0010D\u001a\u00020CH\u0002\u00a2\u0006\u0004\u0008E\u0010FJ\u001f\u0010I\u001a\u00020\u001a2\u0006\u0010G\u001a\u00020C2\u0006\u0010H\u001a\u00020CH\u0002\u00a2\u0006\u0004\u0008I\u0010JJ\u0017\u0010L\u001a\u00020\u00102\u0006\u0010*\u001a\u00020KH\u0002\u00a2\u0006\u0004\u0008L\u0010MJ\u0017\u0010O\u001a\u00020\u00102\u0006\u0010*\u001a\u00020NH\u0002\u00a2\u0006\u0004\u0008O\u0010PJ\u0017\u0010R\u001a\u00020\u00102\u0006\u0010Q\u001a\u00020)H\u0002\u00a2\u0006\u0004\u0008R\u0010,J\u001f\u0010T\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010S\u001a\u00020\u0007H\u0002\u00a2\u0006\u0004\u0008T\u0010UJ\u0017\u0010W\u001a\u00020\u00102\u0006\u0010*\u001a\u00020VH\u0002\u00a2\u0006\u0004\u0008W\u0010XJ\u0017\u0010Y\u001a\u00020\u00102\u0006\u0010*\u001a\u00020<H\u0002\u00a2\u0006\u0004\u0008Y\u0010ZJ\u0017\u0010]\u001a\u00020\u00102\u0006\u0010\\\u001a\u00020[H\u0002\u00a2\u0006\u0004\u0008]\u0010^J\u0013\u0010`\u001a\u00020_*\u00020_H\u0002\u00a2\u0006\u0004\u0008`\u0010aJ\u0017\u0010b\u001a\u00020\u00102\u0006\u0010*\u001a\u00020<H\u0002\u00a2\u0006\u0004\u0008b\u0010ZJ\u0017\u0010c\u001a\u00020\u00102\u0006\u0010Q\u001a\u00020)H\u0002\u00a2\u0006\u0004\u0008c\u0010,J\'\u0010i\u001a\u00020\u001a2\u0006\u0010e\u001a\u00020d2\u0006\u0010g\u001a\u00020f2\u0006\u0010h\u001a\u00020NH\u0002\u00a2\u0006\u0004\u0008i\u0010jR\u0014\u0010\u000c\u001a\u00020\u000b8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000c\u0010kR\u0014\u0010\u000e\u001a\u00020\r8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000e\u0010lR\u001a\u0010n\u001a\u00020m8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008n\u0010o\u001a\u0004\u0008p\u0010qR$\u0010t\u001a\u00020r2\u0006\u0010s\u001a\u00020r8\u0000@BX\u0080\u000e\u00a2\u0006\u000c\n\u0004\u0008t\u0010u\u001a\u0004\u0008v\u0010wR\u001a\u0010y\u001a\u00020x8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008y\u0010z\u001a\u0004\u0008{\u0010|R\u0016\u0010}\u001a\u00020\u001a8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008}\u0010~R\u0016\u0010\u007f\u001a\u00020\u001a8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u007f\u0010~R\u0016\u0010\u0080\u0001\u001a\u00020x8\u0002X\u0082\u0004\u00a2\u0006\u0007\n\u0005\u0008\u0080\u0001\u0010zR\u0018\u0010\u0081\u0001\u001a\u00020x8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0007\n\u0005\u0008\u0081\u0001\u0010zR\u0018\u0010\u0082\u0001\u001a\u00020\u001a8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0007\n\u0005\u0008\u0082\u0001\u0010~R\u0019\u0010\u0083\u0001\u001a\u00020C8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u0083\u0001\u0010\u0084\u0001R)\u0010\u0085\u0001\u001a\u00020=2\u0006\u0010s\u001a\u00020=8\u0002@BX\u0082\u000e\u00a2\u0006\u0010\n\u0006\u0008\u0085\u0001\u0010\u0086\u0001\"\u0006\u0008\u0087\u0001\u0010\u0088\u0001R\u0017\u0010\u008b\u0001\u001a\u00020)8BX\u0082\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u0089\u0001\u0010\u008a\u0001\u00a8\u0006\u008c\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "Ll71/a;",
        "debugConfig",
        "Lk71/d;",
        "p2CCommunicating",
        "",
        "Ll71/u;",
        "enabledVehiclePlatforms",
        "Lr71/a;",
        "latestServiceCommunicationData",
        "Lo71/a;",
        "logger",
        "Ln71/a;",
        "dispatcher",
        "Lkotlin/Function0;",
        "Llx0/b0;",
        "onReconnect",
        "<init>",
        "(Ll71/a;Lk71/d;Ljava/util/Set;Lr71/a;Lo71/a;Ln71/a;Lay0/a;)V",
        "",
        "payload",
        "",
        "address",
        "",
        "priority",
        "",
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
        "(Z)V",
        "lifecycleDidChange",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;",
        "message",
        "updateCurrent$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V",
        "updateCurrent",
        "Lk71/c;",
        "connectionStatus",
        "onConnectionStateChanged",
        "(Lk71/c;)V",
        "resetMessages",
        "()V",
        "Ls71/l;",
        "screen",
        "sendStopIfNeeded",
        "(Ls71/l;)V",
        "startCyclicP2CHighPrioMessageIfNotAlreadyStarted",
        "shouldSendImmediately",
        "sendDelayedP2CHighPrioMessage",
        "setBadConnectionIfNeeded",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;",
        "Lu81/a;",
        "setBadConnection",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)Lu81/a;",
        "Ln71/b;",
        "incrementP2CAliveCounterPPE",
        "()Ln71/b;",
        "",
        "latestC2PAliveCounter",
        "incrementP2CAliveAcknowledgePPE",
        "(I)Ln71/b;",
        "newC2PAliveAcknowledge",
        "existingP2CAliveCounter",
        "isCounterDifferenceValid",
        "(II)Z",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;",
        "updateAndSend",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;",
        "requestNewScenario",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V",
        "p2cHighPrioMessage",
        "log",
        "piloPaVersion",
        "handleC2PHighPrioMessagePPE",
        "([BLl71/u;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;",
        "handleC2PNormalPrioManeuverInfoMessagePPE",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;)V",
        "updateUserCommandToStopOnFinishedIfNeeded",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;",
        "c2prTPAParkingSpaceInfoPPE",
        "addOrReplaceNewParkingSpaceInfoMessageOnLatestCarData",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;",
        "filteredStoppingReasonsDuringPaused",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;",
        "resetEngineStartRequestedIfNeeded",
        "logInvalidTouches",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;",
        "parkingManeuverDirectionSideStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;",
        "parkingManeuverType",
        "latestSentP2CNormalPrio",
        "didManeuverInformationChangedFromLastSentMessage",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)Z",
        "Lo71/a;",
        "Ln71/a;",
        "Lmy0/c;",
        "highPrioInterval",
        "J",
        "getHighPrioInterval-UwyO8pc",
        "()J",
        "Lu81/c;",
        "value",
        "messages",
        "Lu81/c;",
        "getMessages$remoteparkassistcoremeb_release",
        "()Lu81/c;",
        "Lpy0/a;",
        "aliveCounter",
        "Lpy0/a;",
        "getAliveCounter$remoteparkassistcoremeb_release",
        "()Lpy0/a;",
        "isSendingCyclicMessagesActive",
        "Z",
        "shouldBlockSendingDueToMultiTouch",
        "aliveAcknowledge",
        "latestAliveCounter",
        "canSendNormalPrioMessages",
        "subsequentAliveCounterStuckCount",
        "I",
        "latestCarDataPPE",
        "Lu81/a;",
        "setLatestCarDataPPE",
        "(Lu81/a;)V",
        "getCurrentP2CHighPrioMessagePPE",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;",
        "currentP2CHighPrioMessagePPE",
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
.field private final aliveAcknowledge:Lpy0/a;

.field private final aliveCounter:Lpy0/a;

.field private canSendNormalPrioMessages:Z

.field private final dispatcher:Ln71/a;

.field private final highPrioInterval:J

.field private isSendingCyclicMessagesActive:Z

.field private latestAliveCounter:Lpy0/a;

.field private latestCarDataPPE:Lu81/a;

.field private final logger:Lo71/a;

.field private messages:Lu81/c;

.field private shouldBlockSendingDueToMultiTouch:Z

.field private subsequentAliveCounterStuckCount:I


# direct methods
.method public constructor <init>(Ll71/a;Lk71/d;Ljava/util/Set;Lr71/a;Lo71/a;Ln71/a;Lay0/a;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ll71/a;",
            "Lk71/d;",
            "Ljava/util/Set<",
            "+",
            "Ll71/u;",
            ">;",
            "Lr71/a;",
            "Lo71/a;",
            "Ln71/a;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "debugConfig"

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
    const-string v0, "latestServiceCommunicationData"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "logger"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v0, "dispatcher"

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
    move-object v1, p4

    .line 37
    move-object p4, p1

    .line 38
    move-object p1, v1

    .line 39
    move-object v1, p6

    .line 40
    move-object p6, p5

    .line 41
    move-object p5, v1

    .line 42
    invoke-direct/range {p0 .. p7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;-><init>(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 46
    .line 47
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->dispatcher:Ln71/a;

    .line 48
    .line 49
    sget-wide p1, Lu81/b;->d:J

    .line 50
    .line 51
    iput-wide p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->highPrioInterval:J

    .line 52
    .line 53
    new-instance p1, Lu81/c;

    .line 54
    .line 55
    invoke-direct {p1}, Lu81/c;-><init>()V

    .line 56
    .line 57
    .line 58
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 59
    .line 60
    const/4 p1, 0x0

    .line 61
    invoke-static {p1}, Ljp/ee;->a(I)Lpy0/a;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 66
    .line 67
    invoke-static {p1}, Ljp/ee;->a(I)Lpy0/a;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveAcknowledge:Lpy0/a;

    .line 72
    .line 73
    const/4 p1, -0x1

    .line 74
    invoke-static {p1}, Ljp/ee;->a(I)Lpy0/a;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 79
    .line 80
    const/4 p1, 0x1

    .line 81
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->canSendNormalPrioMessages:Z

    .line 82
    .line 83
    new-instance p1, Lu81/a;

    .line 84
    .line 85
    invoke-direct {p1}, Lu81/a;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 89
    .line 90
    return-void
.end method

.method private final addOrReplaceNewParkingSpaceInfoMessageOnLatestCarData(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;)V
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 2
    .line 3
    iget-object v0, v0, Lu81/a;->f:Ljava/util/Set;

    .line 4
    .line 5
    check-cast v0, Ljava/lang/Iterable;

    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    move-object v3, v2

    .line 27
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 28
    .line 29
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->getParkingSlotId()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->getParkingSlotId()I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-ne v3, v4, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-static {v0, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 53
    .line 54
    const/4 v9, 0x0

    .line 55
    const/16 v10, 0xdf

    .line 56
    .line 57
    const/4 v2, 0x0

    .line 58
    const/4 v3, 0x0

    .line 59
    const/4 v4, 0x0

    .line 60
    const/4 v5, 0x0

    .line 61
    const/4 v6, 0x0

    .line 62
    const/4 v8, 0x0

    .line 63
    invoke-static/range {v1 .. v10}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 68
    .line 69
    .line 70
    return-void
.end method

.method private final didManeuverInformationChangedFromLastSentMessage(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)Z
    .locals 0

    .line 1
    invoke-virtual {p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-ne p1, p0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->getParkingManeuverType()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eq p2, p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method private final filteredStoppingReasonsDuringPaused(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;
    .locals 1

    .line 1
    sget-object p0, Lt81/b;->a:[I

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    aget p0, p0, v0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p0, v0, :cond_0

    .line 14
    .line 15
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    return-object p1
.end method

.method public static synthetic g(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 2
    .line 3
    iget-object p0, p0, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 4
    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->sendDelayedP2CHighPrioMessage$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final handleC2PHighPrioMessagePPE([BLl71/u;)V
    .locals 20

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
    instance-of v3, v2, Ll71/p;

    .line 8
    .line 9
    if-nez v3, :cond_3

    .line 10
    .line 11
    instance-of v3, v2, Ll71/q;

    .line 12
    .line 13
    if-nez v3, :cond_3

    .line 14
    .line 15
    instance-of v3, v2, Ll71/r;

    .line 16
    .line 17
    if-nez v3, :cond_3

    .line 18
    .line 19
    instance-of v3, v2, Ll71/s;

    .line 20
    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    goto :goto_2

    .line 24
    :cond_0
    sget-object v3, Ll71/i;->e:Ll71/i;

    .line 25
    .line 26
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-nez v3, :cond_2

    .line 31
    .line 32
    sget-object v3, Ll71/j;->e:Ll71/j;

    .line 33
    .line 34
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-nez v3, :cond_2

    .line 39
    .line 40
    sget-object v3, Ll71/k;->e:Ll71/k;

    .line 41
    .line 42
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-nez v3, :cond_2

    .line 47
    .line 48
    sget-object v3, Ll71/f;->e:Ll71/f;

    .line 49
    .line 50
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-nez v3, :cond_2

    .line 55
    .line 56
    sget-object v3, Ll71/m;->e:Ll71/m;

    .line 57
    .line 58
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    if-nez v3, :cond_2

    .line 63
    .line 64
    instance-of v2, v2, Ll71/n;

    .line 65
    .line 66
    if-eqz v2, :cond_1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    new-instance v0, La8/r0;

    .line 70
    .line 71
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 72
    .line 73
    .line 74
    throw v0

    .line 75
    :cond_2
    :goto_0
    const/4 v2, 0x0

    .line 76
    :goto_1
    move-object v3, v2

    .line 77
    goto :goto_3

    .line 78
    :cond_3
    :goto_2
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

    .line 79
    .line 80
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    goto :goto_1

    .line 85
    :goto_3
    if-nez v3, :cond_4

    .line 86
    .line 87
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 88
    .line 89
    array-length v1, v1

    .line 90
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

    .line 91
    .line 92
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;->getByteLength()I

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    const-string v3, " != expected size("

    .line 97
    .line 98
    const-string v4, "))"

    .line 99
    .line 100
    const-string v5, "Could not create C2PHighPrioMessagePPE! Payload size("

    .line 101
    .line 102
    invoke-static {v1, v2, v5, v3, v4}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    return-void

    .line 110
    :cond_4
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 111
    .line 112
    iget-object v1, v1, Lu81/c;->f:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 113
    .line 114
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->toBytes()[B

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->toBytes()[B

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-static {v1, v2}, Ljava/util/Arrays;->equals([B[B)Z

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    if-nez v1, :cond_5

    .line 127
    .line 128
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 129
    .line 130
    new-instance v2, Ljava/lang/StringBuilder;

    .line 131
    .line 132
    const-string v4, "Received: "

    .line 133
    .line 134
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    move-object v4, v3

    .line 148
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 149
    .line 150
    const/4 v12, 0x0

    .line 151
    const/16 v13, 0x3df

    .line 152
    .line 153
    move-object v9, v4

    .line 154
    const/4 v4, 0x0

    .line 155
    const/4 v5, 0x0

    .line 156
    const/4 v6, 0x0

    .line 157
    const/4 v7, 0x0

    .line 158
    const/4 v8, 0x0

    .line 159
    const/4 v10, 0x0

    .line 160
    const/4 v11, 0x0

    .line 161
    invoke-static/range {v3 .. v13}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    move-object v4, v9

    .line 166
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_5
    move-object v4, v3

    .line 170
    :goto_4
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getAliveAcknowledge()I

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    invoke-direct {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getAliveCounter()I

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->isCounterDifferenceValid(II)Z

    .line 183
    .line 184
    .line 185
    move-result v1

    .line 186
    if-nez v1, :cond_6

    .line 187
    .line 188
    invoke-direct {v0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setBadConnection(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)Lu81/a;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    goto :goto_5

    .line 193
    :cond_6
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 198
    .line 199
    if-ne v1, v2, :cond_7

    .line 200
    .line 201
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->filteredStoppingReasonsDuringPaused(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 206
    .line 207
    .line 208
    move-result-object v9

    .line 209
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 210
    .line 211
    const/16 v10, 0x1f

    .line 212
    .line 213
    const/4 v11, 0x0

    .line 214
    move-object v3, v4

    .line 215
    const/4 v4, 0x0

    .line 216
    const/4 v5, 0x0

    .line 217
    const/4 v6, 0x0

    .line 218
    const/4 v7, 0x0

    .line 219
    const/4 v8, 0x0

    .line 220
    invoke-static/range {v3 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 221
    .line 222
    .line 223
    move-result-object v11

    .line 224
    move-object v4, v3

    .line 225
    const/16 v18, 0x0

    .line 226
    .line 227
    const/16 v19, 0xfe

    .line 228
    .line 229
    const/4 v12, 0x0

    .line 230
    const/4 v13, 0x0

    .line 231
    const/4 v14, 0x0

    .line 232
    const/4 v15, 0x0

    .line 233
    const/16 v16, 0x0

    .line 234
    .line 235
    const/16 v17, 0x0

    .line 236
    .line 237
    move-object v10, v1

    .line 238
    invoke-static/range {v10 .. v19}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    goto :goto_5

    .line 243
    :cond_7
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 244
    .line 245
    const/4 v11, 0x0

    .line 246
    const/16 v12, 0xfe

    .line 247
    .line 248
    const/4 v5, 0x0

    .line 249
    const/4 v6, 0x0

    .line 250
    const/4 v7, 0x0

    .line 251
    const/4 v8, 0x0

    .line 252
    const/4 v9, 0x0

    .line 253
    const/4 v10, 0x0

    .line 254
    invoke-static/range {v3 .. v12}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    :goto_5
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 259
    .line 260
    .line 261
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 262
    .line 263
    iget-object v1, v1, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 264
    .line 265
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getAliveCounter()I

    .line 266
    .line 267
    .line 268
    move-result v1

    .line 269
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->incrementP2CAliveAcknowledgePPE(I)Ln71/b;

    .line 270
    .line 271
    .line 272
    invoke-direct {v0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->resetEngineStartRequestedIfNeeded(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)V

    .line 273
    .line 274
    .line 275
    invoke-direct {v0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateUserCommandToStopOnFinishedIfNeeded(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)V

    .line 276
    .line 277
    .line 278
    return-void
.end method

.method private final handleC2PNormalPrioManeuverInfoMessagePPE(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;)V
    .locals 13

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 2
    .line 3
    iget-object v0, v0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 4
    .line 5
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverType()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :goto_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 25
    .line 26
    iget-object v2, v2, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 27
    .line 28
    invoke-direct {p0, v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->didManeuverInformationChangedFromLastSentMessage(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 33
    .line 34
    const/4 v10, 0x0

    .line 35
    const/16 v12, 0x2ff

    .line 36
    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v6, 0x0

    .line 41
    const/4 v7, 0x0

    .line 42
    const/4 v8, 0x0

    .line 43
    const/4 v9, 0x0

    .line 44
    move-object v11, p1

    .line 45
    invoke-static/range {v2 .. v12}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    move-object v4, v11

    .line 50
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 51
    .line 52
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 53
    .line 54
    const/16 v11, 0xfd

    .line 55
    .line 56
    invoke-static/range {v2 .. v11}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 61
    .line 62
    .line 63
    if-nez v1, :cond_1

    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 67
    .line 68
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 69
    .line 70
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {p1, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method

.method public static synthetic i(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->incrementP2CAliveAcknowledgePPE$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final incrementP2CAliveAcknowledgePPE(I)Ln71/b;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->dispatcher:Ln71/a;

    .line 2
    .line 3
    new-instance v1, Lba0/h;

    .line 4
    .line 5
    const/16 v2, 0x8

    .line 6
    .line 7
    invoke-direct {v1, p0, p1, v2}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 8
    .line 9
    .line 10
    const-wide/16 p0, 0x0

    .line 11
    .line 12
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToMainThread(JLay0/a;)Ln71/b;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method private static final incrementP2CAliveAcknowledgePPE$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)Llx0/b0;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveAcknowledge:Lpy0/a;

    .line 2
    .line 3
    add-int/lit8 p1, p1, 0x1

    .line 4
    .line 5
    rem-int/lit16 p1, p1, 0xff

    .line 6
    .line 7
    xor-int/lit16 v0, p1, 0xff

    .line 8
    .line 9
    neg-int v1, p1

    .line 10
    or-int/2addr v1, p1

    .line 11
    and-int/2addr v0, v1

    .line 12
    shr-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    and-int/lit16 v0, v0, 0xff

    .line 15
    .line 16
    add-int/2addr p1, v0

    .line 17
    iput p1, p0, Lpy0/a;->a:I

    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method

.method private final incrementP2CAliveCounterPPE()Ln71/b;
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->dispatcher:Ln71/a;

    .line 2
    .line 3
    new-instance v1, Lt81/a;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, v2}, Lt81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)V

    .line 7
    .line 8
    .line 9
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    invoke-interface {v0, v2, v3, v1}, Ln71/a;->dispatchToMainThread(JLay0/a;)Ln71/b;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final incrementP2CAliveCounterPPE$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 2
    .line 3
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getAliveCounter()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    add-int/lit8 p0, p0, 0x1

    .line 12
    .line 13
    rem-int/lit16 p0, p0, 0xff

    .line 14
    .line 15
    xor-int/lit16 v1, p0, 0xff

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
    and-int/lit16 v1, v1, 0xff

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

.method private final isCounterDifferenceValid(II)Z
    .locals 5

    .line 1
    sub-int v0, p1, p2

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    rsub-int v1, v0, 0xff

    .line 8
    .line 9
    if-le v0, v1, :cond_0

    .line 10
    .line 11
    move v0, v1

    .line 12
    :cond_0
    const/16 v1, 0xa

    .line 13
    .line 14
    if-le v0, v1, :cond_1

    .line 15
    .line 16
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 17
    .line 18
    const-string v2, " is to big. AliveCounter: "

    .line 19
    .line 20
    const-string v3, " AliveAcknowledge: "

    .line 21
    .line 22
    const-string v4, "Bad Connection: Counter difference "

    .line 23
    .line 24
    invoke-static {v0, p2, v4, v2, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    if-gt v0, v1, :cond_2

    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    return p0

    .line 42
    :cond_2
    const/4 p0, 0x0

    .line 43
    return p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->incrementP2CAliveCounterPPE$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final log(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V
    .locals 12

    .line 1
    const/16 v8, 0x7e

    .line 2
    .line 3
    const/4 v9, 0x0

    .line 4
    const/4 v1, 0x0

    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v7, 0x0

    .line 11
    move-object v0, p1

    .line 12
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->toBytes()[B

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 21
    .line 22
    iget-object v2, v1, Lu81/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 23
    .line 24
    const/16 v10, 0x7e

    .line 25
    .line 26
    const/4 v11, 0x0

    .line 27
    const/4 v6, 0x0

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v8, 0x0

    .line 30
    invoke-static/range {v2 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->toBytes()[B

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    iget v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->subsequentAliveCounterStuckCount:I

    .line 39
    .line 40
    const-string v3, "Send: "

    .line 41
    .line 42
    if-lez v2, :cond_0

    .line 43
    .line 44
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 45
    .line 46
    new-instance p1, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v0, " (alive counter is stuck)"

    .line 55
    .line 56
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_0
    invoke-static {v1, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-nez p1, :cond_1

    .line 72
    .line 73
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 74
    .line 75
    new-instance p1, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    return-void

    .line 91
    :cond_1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 92
    .line 93
    new-instance p1, Ljava/lang/StringBuilder;

    .line 94
    .line 95
    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-static {p0, p1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    return-void
.end method

.method private final logInvalidTouches(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->DRIVE_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x0

    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->DRIVE_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->isEngineStartRequested()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getTouchPositionY()I

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getTouchPositionY()I

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getTouchPositionY()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eq v0, v5, :cond_5

    .line 58
    .line 59
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getTouchPositionY()I

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
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getTouchPositionY()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eq v1, v5, :cond_6

    .line 82
    .line 83
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getTouchPositionY()I

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

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

.method private final requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V
    .locals 4

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->canSendNormalPrioMessages:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 8
    .line 9
    const-string v0, "requestNewScenario(): pause sending P2CNormalPrioMessagePPE messages for 1 second"

    .line 10
    .line 11
    invoke-static {p1, v0}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->dispatcher:Ln71/a;

    .line 15
    .line 16
    sget-wide v0, Lu81/b;->b:J

    .line 17
    .line 18
    new-instance v2, Lt81/a;

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    invoke-direct {v2, p0, v3}, Lt81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1, v0, v1, v2}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method private static final requestNewScenario$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 2
    .line 3
    const-string v1, "requestNewScenario(): resume sending P2CNormalPrioMessagePPE messages"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->canSendNormalPrioMessages:Z

    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 12
    .line 13
    iget-object v0, v0, Lu81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 14
    .line 15
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->handleC2PNormalPrioManeuverInfoMessagePPE(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;)V

    .line 16
    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method

.method private final resetEngineStartRequestedIfNeeded(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)V
    .locals 11

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ENGINE_START_REQUESTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 6
    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 10
    .line 11
    const-string v0, "functionState is ENGINE_START_REQUESTED => isEngineStartRequested = false"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const/16 v9, 0x77

    .line 21
    .line 22
    const/4 v10, 0x0

    .line 23
    const/4 v2, 0x0

    .line 24
    const/4 v3, 0x0

    .line 25
    const/4 v4, 0x0

    .line 26
    const/4 v5, 0x0

    .line 27
    const/4 v6, 0x0

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v8, 0x0

    .line 30
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method private final sendDelayedP2CHighPrioMessage(Z)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    sget p1, Lmy0/c;->g:I

    .line 8
    .line 9
    const-wide/16 v0, 0x0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getHighPrioInterval-UwyO8pc()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    :goto_0
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->dispatcher:Ln71/a;

    .line 17
    .line 18
    new-instance v2, Lt81/a;

    .line 19
    .line 20
    const/4 v3, 0x2

    .line 21
    invoke-direct {v2, p0, v3}, Lt81/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1, v0, v1, v2}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 25
    .line 26
    .line 27
    :cond_1
    return-void
.end method

.method private static final sendDelayedP2CHighPrioMessage$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;)Llx0/b0;
    .locals 12

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setBadConnectionIfNeeded()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 5
    .line 6
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 7
    .line 8
    iget v1, v1, Lpy0/a;->a:I

    .line 9
    .line 10
    iput v1, v0, Lpy0/a;->a:I

    .line 11
    .line 12
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveAcknowledge:Lpy0/a;

    .line 17
    .line 18
    iget v4, v0, Lpy0/a;->a:I

    .line 19
    .line 20
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 21
    .line 22
    iget v3, v0, Lpy0/a;->a:I

    .line 23
    .line 24
    const/16 v10, 0x7c

    .line 25
    .line 26
    const/4 v11, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x0

    .line 29
    const/4 v7, 0x0

    .line 30
    const/4 v8, 0x0

    .line 31
    const/4 v9, 0x0

    .line 32
    invoke-static/range {v2 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 37
    .line 38
    .line 39
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->incrementP2CAliveCounterPPE()Ln71/b;

    .line 40
    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->sendDelayedP2CHighPrioMessage(Z)V

    .line 44
    .line 45
    .line 46
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0
.end method

.method private final sendStopIfNeeded(Ls71/l;)V
    .locals 11

    .line 1
    sget-object v0, Ls71/l;->g:Ls71/l;

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 10
    .line 11
    const/16 v9, 0x57

    .line 12
    .line 13
    const/4 v10, 0x0

    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v8, 0x0

    .line 20
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method private final setBadConnection(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)Lu81/a;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 2
    .line 3
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ABORTED_RESUMING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 4
    .line 5
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->RECEPTION_OBSTRUCTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 6
    .line 7
    const/16 v8, 0x1b

    .line 8
    .line 9
    const/4 v9, 0x0

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v6, 0x0

    .line 14
    move-object v1, p1

    .line 15
    invoke-static/range {v1 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;IILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleAreaPPE;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const/4 v8, 0x0

    .line 20
    const/16 v9, 0xfe

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    const/4 v7, 0x0

    .line 27
    invoke-static/range {v0 .. v9}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 35
    .line 36
    return-object p0
.end method

.method private final setBadConnectionIfNeeded()V
    .locals 7

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 2
    .line 3
    iget-object v0, v0, Lu81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 6
    .line 7
    iget v1, v1, Lpy0/a;->a:I

    .line 8
    .line 9
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 10
    .line 11
    iget v2, v2, Lpy0/a;->a:I

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    const/4 v4, 0x1

    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->subsequentAliveCounterStuckCount:I

    .line 18
    .line 19
    add-int/2addr v1, v4

    .line 20
    iput v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->subsequentAliveCounterStuckCount:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iput v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->subsequentAliveCounterStuckCount:I

    .line 24
    .line 25
    :goto_0
    iget v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->subsequentAliveCounterStuckCount:I

    .line 26
    .line 27
    const/16 v2, 0xa

    .line 28
    .line 29
    if-lt v1, v2, :cond_1

    .line 30
    .line 31
    move v3, v4

    .line 32
    :cond_1
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getAliveAcknowledge()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 37
    .line 38
    iget v2, v2, Lpy0/a;->a:I

    .line 39
    .line 40
    invoke-direct {p0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->isCounterDifferenceValid(II)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v3, :cond_2

    .line 45
    .line 46
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 47
    .line 48
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 49
    .line 50
    iget v4, v4, Lpy0/a;->a:I

    .line 51
    .line 52
    new-instance v5, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v6, "Bad Connection due to alive counter is stuck for >= 10 times.. Current AliveCounter "

    .line 55
    .line 56
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-static {v2, v4}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    :cond_2
    if-nez v3, :cond_4

    .line 70
    .line 71
    if-nez v1, :cond_3

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_3
    return-void

    .line 75
    :cond_4
    :goto_1
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setBadConnection(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)Lu81/a;

    .line 76
    .line 77
    .line 78
    return-void
.end method

.method private final setLatestCarDataPPE(Lu81/a;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

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
    .locals 5

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->isSendingCyclicMessagesActive:Z

    .line 7
    .line 8
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 9
    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getHighPrioInterval-UwyO8pc()J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    invoke-static {v2, v3}, Lmy0/c;->o(J)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    new-instance v3, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v4, "startCyclicP2CHighPrioMessageIfNotAlreadyStarted() highPrioInterval: "

    .line 21
    .line 22
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->sendDelayedP2CHighPrioMessage(Z)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

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
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageImplementation;->getDefinition()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-interface {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/MessageDefinition;->getAddress()J

    .line 10
    .line 11
    .line 12
    move-result-wide v2

    .line 13
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;

    .line 14
    .line 15
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage$Companion;->getAddress()J

    .line 16
    .line 17
    .line 18
    move-result-wide v4

    .line 19
    cmp-long v4, v2, v4

    .line 20
    .line 21
    const-string v5, "Send: "

    .line 22
    .line 23
    if-eqz v4, :cond_5

    .line 24
    .line 25
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;

    .line 26
    .line 27
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;->getAddress()J

    .line 28
    .line 29
    .line 30
    move-result-wide v6

    .line 31
    cmp-long v6, v2, v6

    .line 32
    .line 33
    if-nez v6, :cond_0

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_0
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE$Companion;

    .line 38
    .line 39
    invoke-virtual {v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE$Companion;->getAddress()J

    .line 40
    .line 41
    .line 42
    move-result-wide v6

    .line 43
    cmp-long v6, v2, v6

    .line 44
    .line 45
    if-nez v6, :cond_2

    .line 46
    .line 47
    iget-boolean v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->canSendNormalPrioMessages:Z

    .line 48
    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 52
    .line 53
    new-instance v3, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-static {v2, v3}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 69
    .line 70
    move-object v7, v1

    .line 71
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 72
    .line 73
    const/4 v13, 0x0

    .line 74
    const/16 v14, 0x3fb

    .line 75
    .line 76
    const/4 v5, 0x0

    .line 77
    const/4 v6, 0x0

    .line 78
    const/4 v8, 0x0

    .line 79
    const/4 v9, 0x0

    .line 80
    const/4 v10, 0x0

    .line 81
    const/4 v11, 0x0

    .line 82
    const/4 v12, 0x0

    .line 83
    invoke-static/range {v4 .. v14}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 88
    .line 89
    goto/16 :goto_1

    .line 90
    .line 91
    :cond_1
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 92
    .line 93
    const-string v1, "Send: P2CNormalPrioMessagePPE paused until SCENARIO_CONFIRMATION_DELAY_THRESHOLD"

    .line 94
    .line 95
    invoke-static {v0, v1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :cond_2
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE$Companion;

    .line 100
    .line 101
    invoke-virtual {v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE$Companion;->getAddress()J

    .line 102
    .line 103
    .line 104
    move-result-wide v6

    .line 105
    cmp-long v6, v2, v6

    .line 106
    .line 107
    if-nez v6, :cond_3

    .line 108
    .line 109
    move-object v8, v1

    .line 110
    check-cast v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 111
    .line 112
    invoke-direct {v0, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->log(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 113
    .line 114
    .line 115
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 116
    .line 117
    const/16 v16, 0x0

    .line 118
    .line 119
    const/16 v17, 0x3fc

    .line 120
    .line 121
    const/4 v10, 0x0

    .line 122
    const/4 v11, 0x0

    .line 123
    const/4 v12, 0x0

    .line 124
    const/4 v13, 0x0

    .line 125
    const/4 v14, 0x0

    .line 126
    const/4 v15, 0x0

    .line 127
    move-object v9, v8

    .line 128
    invoke-static/range {v7 .. v17}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 133
    .line 134
    invoke-direct {v0, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logInvalidTouches(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_3
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;

    .line 139
    .line 140
    invoke-virtual {v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE$Companion;->getAddress()J

    .line 141
    .line 142
    .line 143
    move-result-wide v6

    .line 144
    cmp-long v6, v2, v6

    .line 145
    .line 146
    if-nez v6, :cond_4

    .line 147
    .line 148
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 149
    .line 150
    new-instance v3, Ljava/lang/StringBuilder;

    .line 151
    .line 152
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    invoke-static {v2, v3}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 166
    .line 167
    move-object v8, v1

    .line 168
    check-cast v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 169
    .line 170
    const/4 v13, 0x0

    .line 171
    const/16 v14, 0x3f7

    .line 172
    .line 173
    const/4 v5, 0x0

    .line 174
    const/4 v6, 0x0

    .line 175
    const/4 v7, 0x0

    .line 176
    const/4 v9, 0x0

    .line 177
    const/4 v10, 0x0

    .line 178
    const/4 v11, 0x0

    .line 179
    const/4 v12, 0x0

    .line 180
    invoke-static/range {v4 .. v14}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_4
    invoke-virtual {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE$Companion;->getAddress()J

    .line 188
    .line 189
    .line 190
    move-result-wide v6

    .line 191
    cmp-long v2, v2, v6

    .line 192
    .line 193
    if-nez v2, :cond_6

    .line 194
    .line 195
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 196
    .line 197
    new-instance v3, Ljava/lang/StringBuilder;

    .line 198
    .line 199
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    invoke-static {v2, v3}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 213
    .line 214
    move-object v9, v1

    .line 215
    check-cast v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 216
    .line 217
    const/4 v13, 0x0

    .line 218
    const/16 v14, 0x3ef

    .line 219
    .line 220
    const/4 v5, 0x0

    .line 221
    const/4 v6, 0x0

    .line 222
    const/4 v7, 0x0

    .line 223
    const/4 v8, 0x0

    .line 224
    const/4 v10, 0x0

    .line 225
    const/4 v11, 0x0

    .line 226
    const/4 v12, 0x0

    .line 227
    invoke-static/range {v4 .. v14}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 232
    .line 233
    goto :goto_1

    .line 234
    :cond_5
    :goto_0
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 235
    .line 236
    new-instance v3, Ljava/lang/StringBuilder;

    .line 237
    .line 238
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    invoke-static {v2, v3}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    :cond_6
    :goto_1
    invoke-virtual/range {p0 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 252
    .line 253
    .line 254
    return-void
.end method

.method private final updateUserCommandToStopOnFinishedIfNeeded(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;)V
    .locals 11

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->FINISHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->CLAMP_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->NOT_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 26
    .line 27
    iget-object p1, p1, Lu81/c;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 28
    .line 29
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->getUserCommandStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->CUSTOM_FINISH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 34
    .line 35
    if-ne p1, v0, :cond_0

    .line 36
    .line 37
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 42
    .line 43
    const/16 v9, 0x5f

    .line 44
    .line 45
    const/4 v10, 0x0

    .line 46
    const/4 v2, 0x0

    .line 47
    const/4 v3, 0x0

    .line 48
    const/4 v4, 0x0

    .line 49
    const/4 v5, 0x0

    .line 50
    const/4 v6, 0x0

    .line 51
    const/4 v8, 0x0

    .line 52
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 57
    .line 58
    .line 59
    :cond_0
    return-void
.end method


# virtual methods
.method public final getAliveCounter$remoteparkassistcoremeb_release()Lpy0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->aliveCounter:Lpy0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public getHighPrioInterval-UwyO8pc()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->highPrioInterval:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getMessages$remoteparkassistcoremeb_release()Lu81/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public lifecycleDidChange(Lt71/a;)V
    .locals 11

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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 31
    .line 32
    const/16 v9, 0x5f

    .line 33
    .line 34
    const/4 v10, 0x0

    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v8, 0x0

    .line 41
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 46
    .line 47
    .line 48
    :cond_0
    invoke-super {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->lifecycleDidChange(Lt71/a;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method

.method public onC2PMessageReceived([BJBZ)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "payload"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;

    .line 11
    .line 12
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;->getAddress()J

    .line 13
    .line 14
    .line 15
    move-result-wide v3

    .line 16
    cmp-long v3, p2, v3

    .line 17
    .line 18
    const-string v4, " != expected size("

    .line 19
    .line 20
    const-string v5, "Received: "

    .line 21
    .line 22
    const-string v6, "))"

    .line 23
    .line 24
    if-nez v3, :cond_1

    .line 25
    .line 26
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 33
    .line 34
    array-length v1, v1

    .line 35
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE$Companion;->getByteLength()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    const-string v3, "Could not create C2PStaticInfoResponseMessagePPE! Payload size("

    .line 40
    .line 41
    invoke-static {v1, v2, v3, v4, v6}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 50
    .line 51
    new-instance v2, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getLatestCarDataRPA()Ll71/v;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->getMajorVersion-w2LRezQ()B

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    and-int/lit16 v2, v2, 0xff

    .line 75
    .line 76
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->getMinorVersion-w2LRezQ()B

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    and-int/lit16 v4, v4, 0xff

    .line 81
    .line 82
    invoke-virtual {v0, v2, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->determinePiloPaVersion(II)Ll71/u;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    const-string v1, "piloPaVersion"

    .line 90
    .line 91
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    new-instance v1, Ll71/v;

    .line 95
    .line 96
    invoke-direct {v1, v2}, Ll71/v;-><init>(Ll71/u;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestCarDataRPA(Ll71/v;)V

    .line 100
    .line 101
    .line 102
    iget-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 103
    .line 104
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PStaticInfoResponseMessagePPE;->getFunctionResponseStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;

    .line 105
    .line 106
    .line 107
    move-result-object v12

    .line 108
    const/16 v13, 0x7f

    .line 109
    .line 110
    const/4 v5, 0x0

    .line 111
    const/4 v6, 0x0

    .line 112
    const/4 v7, 0x0

    .line 113
    const/4 v8, 0x0

    .line 114
    const/4 v9, 0x0

    .line 115
    const/4 v10, 0x0

    .line 116
    const/4 v11, 0x0

    .line 117
    invoke-static/range {v4 .. v13}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 122
    .line 123
    .line 124
    invoke-direct {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->startCyclicP2CHighPrioMessageIfNotAlreadyStarted()V

    .line 125
    .line 126
    .line 127
    return-void

    .line 128
    :cond_1
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;

    .line 129
    .line 130
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE$Companion;->getAddress()J

    .line 131
    .line 132
    .line 133
    move-result-wide v2

    .line 134
    cmp-long v2, p2, v2

    .line 135
    .line 136
    if-nez v2, :cond_2

    .line 137
    .line 138
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getReceivedPiloPaVersion$remoteparkassistcoremeb_release()Ll71/u;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->handleC2PHighPrioMessagePPE([BLl71/u;)V

    .line 143
    .line 144
    .line 145
    return-void

    .line 146
    :cond_2
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;

    .line 147
    .line 148
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;->getAddress()J

    .line 149
    .line 150
    .line 151
    move-result-wide v7

    .line 152
    cmp-long v3, p2, v7

    .line 153
    .line 154
    if-nez v3, :cond_4

    .line 155
    .line 156
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    if-nez v3, :cond_3

    .line 161
    .line 162
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 163
    .line 164
    array-length v1, v1

    .line 165
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE$Companion;->getByteLength()I

    .line 166
    .line 167
    .line 168
    move-result v2

    .line 169
    const-string v3, "Could not create C2PNormalPrioManeuverInfoMessagePPE! Payload size("

    .line 170
    .line 171
    invoke-static {v1, v2, v3, v4, v6}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    return-void

    .line 179
    :cond_3
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 180
    .line 181
    new-instance v2, Ljava/lang/StringBuilder;

    .line 182
    .line 183
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->handleC2PNormalPrioManeuverInfoMessagePPE(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;)V

    .line 197
    .line 198
    .line 199
    return-void

    .line 200
    :cond_4
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;

    .line 201
    .line 202
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;->getAddress()J

    .line 203
    .line 204
    .line 205
    move-result-wide v7

    .line 206
    cmp-long v3, p2, v7

    .line 207
    .line 208
    if-nez v3, :cond_6

    .line 209
    .line 210
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 211
    .line 212
    .line 213
    move-result-object v10

    .line 214
    if-nez v10, :cond_5

    .line 215
    .line 216
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 217
    .line 218
    array-length v1, v1

    .line 219
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE$Companion;->getByteLength()I

    .line 220
    .line 221
    .line 222
    move-result v2

    .line 223
    const-string v3, "Could not create C2PNormalPrioVehicleInfoMessagePPE! Payload size("

    .line 224
    .line 225
    invoke-static {v1, v2, v3, v4, v6}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    return-void

    .line 233
    :cond_5
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 234
    .line 235
    new-instance v2, Ljava/lang/StringBuilder;

    .line 236
    .line 237
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 251
    .line 252
    const/4 v15, 0x0

    .line 253
    const/16 v16, 0xfb

    .line 254
    .line 255
    const/4 v8, 0x0

    .line 256
    const/4 v9, 0x0

    .line 257
    const/4 v11, 0x0

    .line 258
    const/4 v12, 0x0

    .line 259
    const/4 v13, 0x0

    .line 260
    const/4 v14, 0x0

    .line 261
    invoke-static/range {v7 .. v16}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 262
    .line 263
    .line 264
    move-result-object v1

    .line 265
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 266
    .line 267
    .line 268
    return-void

    .line 269
    :cond_6
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE$Companion;

    .line 270
    .line 271
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE$Companion;->getAddress()J

    .line 272
    .line 273
    .line 274
    move-result-wide v7

    .line 275
    cmp-long v3, p2, v7

    .line 276
    .line 277
    if-nez v3, :cond_8

    .line 278
    .line 279
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;

    .line 280
    .line 281
    .line 282
    move-result-object v12

    .line 283
    if-nez v12, :cond_7

    .line 284
    .line 285
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 286
    .line 287
    array-length v1, v1

    .line 288
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE$Companion;->getByteLength()I

    .line 289
    .line 290
    .line 291
    move-result v2

    .line 292
    const-string v3, "Could not create C2PNormalPrioTrajectoryInfoPPE! Payload size("

    .line 293
    .line 294
    invoke-static {v1, v2, v3, v4, v6}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    return-void

    .line 302
    :cond_7
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 303
    .line 304
    new-instance v2, Ljava/lang/StringBuilder;

    .line 305
    .line 306
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 310
    .line 311
    .line 312
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v2

    .line 316
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 320
    .line 321
    const/16 v16, 0x0

    .line 322
    .line 323
    const/16 v17, 0x3bf

    .line 324
    .line 325
    const/4 v8, 0x0

    .line 326
    const/4 v9, 0x0

    .line 327
    const/4 v10, 0x0

    .line 328
    const/4 v11, 0x0

    .line 329
    move-object v14, v12

    .line 330
    const/4 v12, 0x0

    .line 331
    const/4 v13, 0x0

    .line 332
    const/4 v15, 0x0

    .line 333
    invoke-static/range {v7 .. v17}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 338
    .line 339
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 340
    .line 341
    const/16 v16, 0xef

    .line 342
    .line 343
    move-object v12, v14

    .line 344
    const/4 v14, 0x0

    .line 345
    invoke-static/range {v7 .. v16}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 350
    .line 351
    .line 352
    return-void

    .line 353
    :cond_8
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;

    .line 354
    .line 355
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;->getAddress()J

    .line 356
    .line 357
    .line 358
    move-result-wide v7

    .line 359
    cmp-long v3, p2, v7

    .line 360
    .line 361
    if-nez v3, :cond_a

    .line 362
    .line 363
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;

    .line 364
    .line 365
    .line 366
    move-result-object v11

    .line 367
    if-nez v11, :cond_9

    .line 368
    .line 369
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 370
    .line 371
    array-length v1, v1

    .line 372
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE$Companion;->getByteLength()I

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    const-string v3, "Could not create C2PNormalPrioTrajectoryMetadataPPE! Payload size("

    .line 377
    .line 378
    invoke-static {v1, v2, v3, v4, v6}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    return-void

    .line 386
    :cond_9
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 387
    .line 388
    new-instance v2, Ljava/lang/StringBuilder;

    .line 389
    .line 390
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 394
    .line 395
    .line 396
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object v2

    .line 400
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 404
    .line 405
    const/16 v16, 0x0

    .line 406
    .line 407
    const/16 v17, 0x37f

    .line 408
    .line 409
    const/4 v8, 0x0

    .line 410
    const/4 v9, 0x0

    .line 411
    const/4 v10, 0x0

    .line 412
    move-object v15, v11

    .line 413
    const/4 v11, 0x0

    .line 414
    const/4 v12, 0x0

    .line 415
    const/4 v13, 0x0

    .line 416
    const/4 v14, 0x0

    .line 417
    invoke-static/range {v7 .. v17}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 418
    .line 419
    .line 420
    move-result-object v1

    .line 421
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 422
    .line 423
    iget-object v7, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 424
    .line 425
    move-object v11, v15

    .line 426
    const/4 v15, 0x0

    .line 427
    const/16 v16, 0xf7

    .line 428
    .line 429
    invoke-static/range {v7 .. v16}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 430
    .line 431
    .line 432
    move-result-object v1

    .line 433
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 434
    .line 435
    .line 436
    return-void

    .line 437
    :cond_a
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;

    .line 438
    .line 439
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->getAddress()J

    .line 440
    .line 441
    .line 442
    move-result-wide v3

    .line 443
    cmp-long v3, p2, v3

    .line 444
    .line 445
    if-nez v3, :cond_c

    .line 446
    .line 447
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;

    .line 448
    .line 449
    .line 450
    move-result-object v3

    .line 451
    if-nez v3, :cond_b

    .line 452
    .line 453
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 454
    .line 455
    array-length v1, v1

    .line 456
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE$Companion;->getByteLength()I

    .line 457
    .line 458
    .line 459
    move-result v2

    .line 460
    const-string v3, "Could not create C2PrTPAParkingSpaceInfoPPE! Payload size("

    .line 461
    .line 462
    const-string v4, " is not in range(4.."

    .line 463
    .line 464
    invoke-static {v1, v2, v3, v4, v6}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 465
    .line 466
    .line 467
    move-result-object v1

    .line 468
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 469
    .line 470
    .line 471
    return-void

    .line 472
    :cond_b
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 473
    .line 474
    new-instance v2, Ljava/lang/StringBuilder;

    .line 475
    .line 476
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 477
    .line 478
    .line 479
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 480
    .line 481
    .line 482
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v2

    .line 486
    invoke-static {v1, v2}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 487
    .line 488
    .line 489
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->addOrReplaceNewParkingSpaceInfoMessageOnLatestCarData(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PrTPAParkingSpaceInfoPPE;)V

    .line 490
    .line 491
    .line 492
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
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->isSendingCyclicMessagesActive:Z

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
    return-void
.end method

.method public resetMessages()V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestAliveCounter:Lpy0/a;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    iput v1, v0, Lpy0/a;->a:I

    .line 5
    .line 6
    new-instance v0, Lu81/c;

    .line 7
    .line 8
    invoke-direct {v0}, Lu81/c;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 12
    .line 13
    new-instance v0, Lu81/a;

    .line 14
    .line 15
    invoke-direct {v0}, Lu81/a;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public screenDidChange(Lt71/a;)V
    .locals 11

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
    iget-object v0, p1, Lt71/a;->e:Ls71/l;

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->sendStopIfNeeded(Ls71/l;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p1, Lt71/a;->e:Ls71/l;

    .line 15
    .line 16
    sget-object v0, Ls71/l;->e:Ls71/l;

    .line 17
    .line 18
    if-ne p1, v0, :cond_0

    .line 19
    .line 20
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 25
    .line 26
    const/16 v9, 0x3f

    .line 27
    .line 28
    const/4 v10, 0x0

    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_0
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 48
    .line 49
    const/16 v8, 0x3f

    .line 50
    .line 51
    const/4 v9, 0x0

    .line 52
    const/4 v1, 0x0

    .line 53
    const/4 v2, 0x0

    .line 54
    const/4 v3, 0x0

    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v6, 0x0

    .line 58
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method

.method public sideEffectTriggered(Lt71/a;)V
    .locals 11

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
    const-string v1, "sideEffectTriggered("

    .line 16
    .line 17
    packed-switch v0, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    new-instance p0, La8/r0;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 27
    .line 28
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 29
    .line 30
    new-instance v2, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p1, ") => isEngineStartRequested = true [CheckInvalidTouches]"

    .line 39
    .line 40
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    const/16 v9, 0x77

    .line 55
    .line 56
    const/4 v10, 0x0

    .line 57
    const/4 v2, 0x0

    .line 58
    const/4 v3, 0x0

    .line 59
    const/4 v4, 0x0

    .line 60
    const/4 v5, 0x1

    .line 61
    const/4 v6, 0x0

    .line 62
    const/4 v7, 0x0

    .line 63
    const/4 v8, 0x0

    .line 64
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 73
    .line 74
    sget-object v7, Ll71/c;->e:Ll71/c;

    .line 75
    .line 76
    const/4 v8, 0x0

    .line 77
    const/16 v9, 0xbf

    .line 78
    .line 79
    const/4 v1, 0x0

    .line 80
    const/4 v2, 0x0

    .line 81
    const/4 v3, 0x0

    .line 82
    const/4 v4, 0x0

    .line 83
    const/4 v5, 0x0

    .line 84
    const/4 v6, 0x0

    .line 85
    invoke-static/range {v0 .. v9}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->latestCarDataPPE:Lu81/a;

    .line 94
    .line 95
    sget-object v7, Ll71/c;->d:Ll71/c;

    .line 96
    .line 97
    const/4 v8, 0x0

    .line 98
    const/16 v9, 0xbf

    .line 99
    .line 100
    const/4 v1, 0x0

    .line 101
    const/4 v2, 0x0

    .line 102
    const/4 v3, 0x0

    .line 103
    const/4 v4, 0x0

    .line 104
    const/4 v5, 0x0

    .line 105
    const/4 v6, 0x0

    .line 106
    invoke-static/range {v0 .. v9}, Lu81/a;->a(Lu81/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ljava/util/LinkedHashSet;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionResponseStatusPPE;I)Lu81/a;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->setLatestCarDataPPE(Lu81/a;)V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    :pswitch_3
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 119
    .line 120
    const/16 v8, 0x57

    .line 121
    .line 122
    const/4 v9, 0x0

    .line 123
    const/4 v1, 0x0

    .line 124
    const/4 v2, 0x0

    .line 125
    const/4 v3, 0x0

    .line 126
    const/4 v4, 0x0

    .line 127
    const/4 v5, 0x0

    .line 128
    const/4 v7, 0x0

    .line 129
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->stopFunctionAndDisconnectDelayed()V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :pswitch_4
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 141
    .line 142
    const/4 v0, 0x0

    .line 143
    const/4 v1, 0x2

    .line 144
    invoke-static {p0, p1, v0, v1}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 145
    .line 146
    .line 147
    return-void

    .line 148
    :pswitch_5
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 149
    .line 150
    iget-object p1, p1, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 151
    .line 152
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->isComfortClosingRequested()Z

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    if-eqz p1, :cond_0

    .line 157
    .line 158
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 159
    .line 160
    iget-object p1, p1, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 161
    .line 162
    const/4 v0, 0x0

    .line 163
    invoke-virtual {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->copy(Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 168
    .line 169
    .line 170
    return-void

    .line 171
    :pswitch_6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 176
    .line 177
    const/16 v8, 0x57

    .line 178
    .line 179
    const/4 v9, 0x0

    .line 180
    const/4 v1, 0x0

    .line 181
    const/4 v2, 0x0

    .line 182
    const/4 v3, 0x0

    .line 183
    const/4 v4, 0x0

    .line 184
    const/4 v5, 0x0

    .line 185
    const/4 v7, 0x0

    .line 186
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 187
    .line 188
    .line 189
    move-result-object p1

    .line 190
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 191
    .line 192
    .line 193
    return-void

    .line 194
    :pswitch_7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 195
    .line 196
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 197
    .line 198
    new-instance v2, Ljava/lang/StringBuilder;

    .line 199
    .line 200
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    const-string p1, ") => isEngineStartRequested = false [CheckInvalidTouches]"

    .line 207
    .line 208
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    const/16 v9, 0x77

    .line 223
    .line 224
    const/4 v10, 0x0

    .line 225
    const/4 v2, 0x0

    .line 226
    const/4 v3, 0x0

    .line 227
    const/4 v4, 0x0

    .line 228
    const/4 v5, 0x0

    .line 229
    const/4 v6, 0x0

    .line 230
    const/4 v7, 0x0

    .line 231
    const/4 v8, 0x0

    .line 232
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 237
    .line 238
    .line 239
    :cond_0
    :pswitch_8
    return-void

    .line 240
    nop

    .line 241
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_8
    .end packed-switch
.end method

.method public touchPositionDidChange(Lt71/a;)V
    .locals 11

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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object p1, p1, Lt71/a;->d:Lu71/b;

    .line 14
    .line 15
    iget v4, p1, Lu71/b;->a:I

    .line 16
    .line 17
    iget v6, p1, Lu71/b;->b:I

    .line 18
    .line 19
    const/16 v9, 0x6b

    .line 20
    .line 21
    const/4 v10, 0x0

    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v7, 0x0

    .line 26
    const/4 v8, 0x0

    .line 27
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V
    .locals 12

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 7
    .line 8
    const/4 v10, 0x0

    .line 9
    const/16 v11, 0x3fe

    .line 10
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
    const/4 v8, 0x0

    .line 17
    const/4 v9, 0x0

    .line 18
    move-object v2, p1

    .line 19
    invoke-static/range {v1 .. v11}, Lu81/c;->a(Lu81/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryInfoPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioTrajectoryMetadataPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;I)Lu81/c;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 24
    .line 25
    return-void
.end method

.method public userActionDidChange(Lt71/a;)V
    .locals 14

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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->ACTION_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 20
    .line 21
    const/16 v9, 0x3f

    .line 22
    .line 23
    const/4 v10, 0x0

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
    const/4 v7, 0x0

    .line 30
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    sget-object v0, Ls71/p;->i:Ls71/p;

    .line 39
    .line 40
    if-ne p1, v0, :cond_1

    .line 41
    .line 42
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 47
    .line 48
    const/16 v9, 0x3f

    .line 49
    .line 50
    const/4 v10, 0x0

    .line 51
    const/4 v2, 0x0

    .line 52
    const/4 v3, 0x0

    .line 53
    const/4 v4, 0x0

    .line 54
    const/4 v5, 0x0

    .line 55
    const/4 v6, 0x0

    .line 56
    const/4 v7, 0x0

    .line 57
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_1
    sget-object v0, Ls71/p;->h:Ls71/p;

    .line 66
    .line 67
    if-ne p1, v0, :cond_2

    .line 68
    .line 69
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 74
    .line 75
    const/16 v9, 0x3f

    .line 76
    .line 77
    const/4 v10, 0x0

    .line 78
    const/4 v2, 0x0

    .line 79
    const/4 v3, 0x0

    .line 80
    const/4 v4, 0x0

    .line 81
    const/4 v5, 0x0

    .line 82
    const/4 v6, 0x0

    .line 83
    const/4 v7, 0x0

    .line 84
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_2
    sget-object v0, Ls71/p;->t:Ls71/p;

    .line 93
    .line 94
    if-ne p1, v0, :cond_3

    .line 95
    .line 96
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 97
    .line 98
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 99
    .line 100
    sget-object v0, Ls71/j;->d:Ls71/j;

    .line 101
    .line 102
    sget-object v1, Ls71/g;->d:Ls71/g;

    .line 103
    .line 104
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 105
    .line 106
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :cond_3
    sget-object v0, Ls71/p;->j:Ls71/p;

    .line 119
    .line 120
    if-ne p1, v0, :cond_4

    .line 121
    .line 122
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 123
    .line 124
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 125
    .line 126
    sget-object v0, Ls71/j;->g:Ls71/j;

    .line 127
    .line 128
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 129
    .line 130
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 131
    .line 132
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 141
    .line 142
    .line 143
    return-void

    .line 144
    :cond_4
    sget-object v0, Ls71/p;->k:Ls71/p;

    .line 145
    .line 146
    if-ne p1, v0, :cond_5

    .line 147
    .line 148
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 149
    .line 150
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 151
    .line 152
    sget-object v0, Ls71/j;->g:Ls71/j;

    .line 153
    .line 154
    sget-object v1, Ls71/g;->f:Ls71/g;

    .line 155
    .line 156
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 157
    .line 158
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 167
    .line 168
    .line 169
    return-void

    .line 170
    :cond_5
    sget-object v0, Ls71/p;->l:Ls71/p;

    .line 171
    .line 172
    if-ne p1, v0, :cond_6

    .line 173
    .line 174
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 175
    .line 176
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 177
    .line 178
    sget-object v0, Ls71/j;->e:Ls71/j;

    .line 179
    .line 180
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 181
    .line 182
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 183
    .line 184
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 193
    .line 194
    .line 195
    return-void

    .line 196
    :cond_6
    sget-object v0, Ls71/p;->m:Ls71/p;

    .line 197
    .line 198
    if-ne p1, v0, :cond_7

    .line 199
    .line 200
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 201
    .line 202
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 203
    .line 204
    sget-object v0, Ls71/j;->f:Ls71/j;

    .line 205
    .line 206
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 207
    .line 208
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 209
    .line 210
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 215
    .line 216
    .line 217
    move-result-object p1

    .line 218
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 219
    .line 220
    .line 221
    return-void

    .line 222
    :cond_7
    sget-object v0, Ls71/p;->p:Ls71/p;

    .line 223
    .line 224
    if-ne p1, v0, :cond_8

    .line 225
    .line 226
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 227
    .line 228
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 229
    .line 230
    sget-object v0, Ls71/j;->e:Ls71/j;

    .line 231
    .line 232
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 233
    .line 234
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 235
    .line 236
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 245
    .line 246
    .line 247
    return-void

    .line 248
    :cond_8
    sget-object v0, Ls71/p;->q:Ls71/p;

    .line 249
    .line 250
    if-ne p1, v0, :cond_9

    .line 251
    .line 252
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 253
    .line 254
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 255
    .line 256
    sget-object v0, Ls71/j;->f:Ls71/j;

    .line 257
    .line 258
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 259
    .line 260
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 261
    .line 262
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 267
    .line 268
    .line 269
    move-result-object p1

    .line 270
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 271
    .line 272
    .line 273
    return-void

    .line 274
    :cond_9
    sget-object v0, Ls71/p;->r:Ls71/p;

    .line 275
    .line 276
    if-ne p1, v0, :cond_a

    .line 277
    .line 278
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 279
    .line 280
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 281
    .line 282
    sget-object v0, Ls71/j;->e:Ls71/j;

    .line 283
    .line 284
    sget-object v1, Ls71/g;->f:Ls71/g;

    .line 285
    .line 286
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 287
    .line 288
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 293
    .line 294
    .line 295
    move-result-object p1

    .line 296
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 297
    .line 298
    .line 299
    return-void

    .line 300
    :cond_a
    sget-object v0, Ls71/p;->s:Ls71/p;

    .line 301
    .line 302
    if-ne p1, v0, :cond_b

    .line 303
    .line 304
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 305
    .line 306
    iget-object p1, p1, Lu81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 307
    .line 308
    sget-object v0, Ls71/j;->f:Ls71/j;

    .line 309
    .line 310
    sget-object v1, Ls71/g;->f:Ls71/g;

    .line 311
    .line 312
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 313
    .line 314
    invoke-static {v0, v1, v2}, Lpm/a;->a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    invoke-virtual {p1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;->copy(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;

    .line 319
    .line 320
    .line 321
    move-result-object p1

    .line 322
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->requestNewScenario(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CNormalPrioMessagePPE;)V

    .line 323
    .line 324
    .line 325
    return-void

    .line 326
    :cond_b
    sget-object v0, Ls71/p;->w:Ls71/p;

    .line 327
    .line 328
    const-string v1, ") => userCommandStatus could not be set due to MultiTouchDetected [CheckInvalidTouches]"

    .line 329
    .line 330
    const-string v2, "userActionDidChange("

    .line 331
    .line 332
    if-eq p1, v0, :cond_19

    .line 333
    .line 334
    sget-object v0, Ls71/p;->n:Ls71/p;

    .line 335
    .line 336
    if-ne p1, v0, :cond_c

    .line 337
    .line 338
    goto/16 :goto_1

    .line 339
    .line 340
    :cond_c
    sget-object v0, Ls71/p;->u:Ls71/p;

    .line 341
    .line 342
    if-ne p1, v0, :cond_e

    .line 343
    .line 344
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 345
    .line 346
    if-nez v0, :cond_d

    .line 347
    .line 348
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 349
    .line 350
    .line 351
    move-result-object v3

    .line 352
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->DRIVE_2:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 353
    .line 354
    const/16 v11, 0x5f

    .line 355
    .line 356
    const/4 v12, 0x0

    .line 357
    const/4 v4, 0x0

    .line 358
    const/4 v5, 0x0

    .line 359
    const/4 v6, 0x0

    .line 360
    const/4 v7, 0x0

    .line 361
    const/4 v8, 0x0

    .line 362
    const/4 v10, 0x0

    .line 363
    invoke-static/range {v3 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 364
    .line 365
    .line 366
    move-result-object p1

    .line 367
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 368
    .line 369
    .line 370
    return-void

    .line 371
    :cond_d
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 372
    .line 373
    new-instance v0, Ljava/lang/StringBuilder;

    .line 374
    .line 375
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 379
    .line 380
    .line 381
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 382
    .line 383
    .line 384
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 385
    .line 386
    .line 387
    move-result-object p1

    .line 388
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    return-void

    .line 392
    :cond_e
    sget-object v0, Ls71/p;->o:Ls71/p;

    .line 393
    .line 394
    if-eq p1, v0, :cond_18

    .line 395
    .line 396
    sget-object v0, Ls71/p;->v:Ls71/p;

    .line 397
    .line 398
    if-eq p1, v0, :cond_18

    .line 399
    .line 400
    sget-object v0, Ls71/p;->x:Ls71/p;

    .line 401
    .line 402
    if-ne p1, v0, :cond_f

    .line 403
    .line 404
    goto/16 :goto_0

    .line 405
    .line 406
    :cond_f
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 407
    .line 408
    const/4 v1, 0x1

    .line 409
    if-ne p1, v0, :cond_10

    .line 410
    .line 411
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 412
    .line 413
    .line 414
    move-result-object v3

    .line 415
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 416
    .line 417
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 418
    .line 419
    const/16 v11, 0x17

    .line 420
    .line 421
    const/4 v12, 0x0

    .line 422
    const/4 v4, 0x0

    .line 423
    const/4 v5, 0x0

    .line 424
    const/4 v6, 0x0

    .line 425
    const/4 v7, 0x0

    .line 426
    const/4 v8, 0x0

    .line 427
    invoke-static/range {v3 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 428
    .line 429
    .line 430
    move-result-object p1

    .line 431
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 432
    .line 433
    .line 434
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 435
    .line 436
    return-void

    .line 437
    :cond_10
    sget-object v0, Ls71/p;->F:Ls71/p;

    .line 438
    .line 439
    const/4 v3, 0x0

    .line 440
    if-ne p1, v0, :cond_11

    .line 441
    .line 442
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 443
    .line 444
    .line 445
    move-result-object v4

    .line 446
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;->ACTION_NOT_STARTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;

    .line 447
    .line 448
    const/16 v12, 0x3f

    .line 449
    .line 450
    const/4 v13, 0x0

    .line 451
    const/4 v5, 0x0

    .line 452
    const/4 v6, 0x0

    .line 453
    const/4 v7, 0x0

    .line 454
    const/4 v8, 0x0

    .line 455
    const/4 v9, 0x0

    .line 456
    const/4 v10, 0x0

    .line 457
    invoke-static/range {v4 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 458
    .line 459
    .line 460
    move-result-object p1

    .line 461
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 462
    .line 463
    .line 464
    iput-boolean v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 465
    .line 466
    return-void

    .line 467
    :cond_11
    sget-object v0, Ls71/p;->e:Ls71/p;

    .line 468
    .line 469
    if-ne p1, v0, :cond_12

    .line 470
    .line 471
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 472
    .line 473
    .line 474
    move-result-object v4

    .line 475
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->CUSTOM_FINISH:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 476
    .line 477
    const/16 v12, 0x5f

    .line 478
    .line 479
    const/4 v13, 0x0

    .line 480
    const/4 v5, 0x0

    .line 481
    const/4 v6, 0x0

    .line 482
    const/4 v7, 0x0

    .line 483
    const/4 v8, 0x0

    .line 484
    const/4 v9, 0x0

    .line 485
    const/4 v11, 0x0

    .line 486
    invoke-static/range {v4 .. v13}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 487
    .line 488
    .line 489
    move-result-object p1

    .line 490
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 491
    .line 492
    .line 493
    return-void

    .line 494
    :cond_12
    sget-object v0, Ls71/p;->C:Ls71/p;

    .line 495
    .line 496
    if-ne p1, v0, :cond_13

    .line 497
    .line 498
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 499
    .line 500
    new-instance v1, Ljava/lang/StringBuilder;

    .line 501
    .line 502
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 506
    .line 507
    .line 508
    const-string p1, ") => isEngineStartRequested = false [CheckInvalidTouches]"

    .line 509
    .line 510
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 511
    .line 512
    .line 513
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 514
    .line 515
    .line 516
    move-result-object p1

    .line 517
    invoke-static {v0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 521
    .line 522
    .line 523
    move-result-object v1

    .line 524
    const/16 v9, 0x77

    .line 525
    .line 526
    const/4 v10, 0x0

    .line 527
    const/4 v2, 0x0

    .line 528
    const/4 v3, 0x0

    .line 529
    const/4 v4, 0x0

    .line 530
    const/4 v5, 0x0

    .line 531
    const/4 v6, 0x0

    .line 532
    const/4 v7, 0x0

    .line 533
    const/4 v8, 0x0

    .line 534
    invoke-static/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 535
    .line 536
    .line 537
    move-result-object p1

    .line 538
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 539
    .line 540
    .line 541
    return-void

    .line 542
    :cond_13
    sget-object v0, Ls71/p;->z:Ls71/p;

    .line 543
    .line 544
    if-ne p1, v0, :cond_14

    .line 545
    .line 546
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 547
    .line 548
    iget-object p1, p1, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 549
    .line 550
    invoke-virtual {p1, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->copy(Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 551
    .line 552
    .line 553
    move-result-object p1

    .line 554
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 555
    .line 556
    .line 557
    return-void

    .line 558
    :cond_14
    sget-object v0, Ls71/p;->A:Ls71/p;

    .line 559
    .line 560
    if-ne p1, v0, :cond_15

    .line 561
    .line 562
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->messages:Lu81/c;

    .line 563
    .line 564
    iget-object p1, p1, Lu81/c;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 565
    .line 566
    invoke-virtual {p1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;->copy(Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CComfortCmdsMessagePPE;

    .line 567
    .line 568
    .line 569
    move-result-object p1

    .line 570
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 571
    .line 572
    .line 573
    return-void

    .line 574
    :cond_15
    instance-of v0, p1, Ls71/r;

    .line 575
    .line 576
    if-eqz v0, :cond_16

    .line 577
    .line 578
    check-cast p1, Ls71/r;

    .line 579
    .line 580
    iget-object p1, p1, Ls71/r;->d:Ll71/y;

    .line 581
    .line 582
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;

    .line 583
    .line 584
    iget p1, p1, Ll71/y;->b:I

    .line 585
    .line 586
    invoke-direct {v0, p1, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CrTPAParkingSlotSelectionMessagePPE;-><init>(IZ)V

    .line 587
    .line 588
    .line 589
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateAndSend(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 590
    .line 591
    .line 592
    return-void

    .line 593
    :cond_16
    sget-object p0, Ls71/p;->B:Ls71/p;

    .line 594
    .line 595
    if-eq p1, p0, :cond_17

    .line 596
    .line 597
    sget-object p0, Ls71/p;->D:Ls71/p;

    .line 598
    .line 599
    if-eq p1, p0, :cond_17

    .line 600
    .line 601
    sget-object p0, Ls71/p;->d:Ls71/p;

    .line 602
    .line 603
    :cond_17
    return-void

    .line 604
    :cond_18
    :goto_0
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 605
    .line 606
    .line 607
    move-result-object v0

    .line 608
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 609
    .line 610
    const/16 v8, 0x5f

    .line 611
    .line 612
    const/4 v9, 0x0

    .line 613
    const/4 v1, 0x0

    .line 614
    const/4 v2, 0x0

    .line 615
    const/4 v3, 0x0

    .line 616
    const/4 v4, 0x0

    .line 617
    const/4 v5, 0x0

    .line 618
    const/4 v7, 0x0

    .line 619
    invoke-static/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 620
    .line 621
    .line 622
    move-result-object p1

    .line 623
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 624
    .line 625
    .line 626
    return-void

    .line 627
    :cond_19
    :goto_1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->shouldBlockSendingDueToMultiTouch:Z

    .line 628
    .line 629
    if-nez v0, :cond_1a

    .line 630
    .line 631
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->getCurrentP2CHighPrioMessagePPE()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 632
    .line 633
    .line 634
    move-result-object v3

    .line 635
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;->DRIVE_1:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;

    .line 636
    .line 637
    const/16 v11, 0x5f

    .line 638
    .line 639
    const/4 v12, 0x0

    .line 640
    const/4 v4, 0x0

    .line 641
    const/4 v5, 0x0

    .line 642
    const/4 v6, 0x0

    .line 643
    const/4 v7, 0x0

    .line 644
    const/4 v8, 0x0

    .line 645
    const/4 v10, 0x0

    .line 646
    invoke-static/range {v3 .. v12}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;->copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;IIIZILtechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/UserCommandStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TouchDiagnosisResponseStatusPPE;ILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;

    .line 647
    .line 648
    .line 649
    move-result-object p1

    .line 650
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->updateCurrent$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/P2CHighPrioMessagePPE;)V

    .line 651
    .line 652
    .line 653
    return-void

    .line 654
    :cond_1a
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->logger:Lo71/a;

    .line 655
    .line 656
    new-instance v0, Ljava/lang/StringBuilder;

    .line 657
    .line 658
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 659
    .line 660
    .line 661
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 662
    .line 663
    .line 664
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 665
    .line 666
    .line 667
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 668
    .line 669
    .line 670
    move-result-object p1

    .line 671
    invoke-static {p0, p1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 672
    .line 673
    .line 674
    return-void
.end method
