.class public abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lq71/a;
.implements Lk71/a;
.implements Lt71/b;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00d8\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0007\n\u0002\u0010\u0008\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u000b\u0008 \u0018\u0000 \u0094\u00012\u00020\u00012\u00020\u00022\u00020\u0003:\u0003[\u0095\u0001BK\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u000c\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\t0\u0008\u0012\u0006\u0010\u000c\u001a\u00020\u000b\u0012\u0006\u0010\u000e\u001a\u00020\r\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\u000c\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u00120\u0011\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0017\u0010\u0018\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u0017\u0010\u001a\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u001a\u0010\u0019J\u0017\u0010\u001b\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u0019J\u0017\u0010\u001c\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u001c\u0010\u0019J\u0017\u0010\u001d\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u001d\u0010\u0019J\u0017\u0010\u001e\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020\u0016H\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u0019J\u000f\u0010\u001f\u001a\u00020\u0012H&\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0017\u0010#\u001a\u00020\u00122\u0006\u0010\"\u001a\u00020!H&\u00a2\u0006\u0004\u0008#\u0010$J/\u0010-\u001a\u00020\u00122\u0006\u0010&\u001a\u00020%2\u0006\u0010(\u001a\u00020\'2\u0006\u0010*\u001a\u00020)2\u0006\u0010,\u001a\u00020+H$\u00a2\u0006\u0004\u0008-\u0010.J\u0017\u00100\u001a\u00020\u00122\u0006\u0010/\u001a\u00020+H$\u00a2\u0006\u0004\u00080\u00101J/\u00102\u001a\u00020\u00122\u0006\u0010&\u001a\u00020%2\u0006\u0010(\u001a\u00020\'2\u0006\u0010*\u001a\u00020)2\u0006\u0010,\u001a\u00020+H\u0016\u00a2\u0006\u0004\u00082\u0010.J\u0017\u00105\u001a\u00020\u00122\u0006\u00104\u001a\u000203H\u0016\u00a2\u0006\u0004\u00085\u00106J\u0017\u00107\u001a\u00020\u00122\u0006\u0010\"\u001a\u00020!H\u0016\u00a2\u0006\u0004\u00087\u0010$J\u0017\u00109\u001a\u00020\u00122\u0006\u00108\u001a\u00020+H\u0016\u00a2\u0006\u0004\u00089\u00101J\u001f\u0010>\u001a\u00020\u00122\u0006\u0010;\u001a\u00020:2\u0006\u0010=\u001a\u00020<H\u0016\u00a2\u0006\u0004\u0008>\u0010?J\u0017\u0010A\u001a\u00020\u00122\u0006\u0010\u0017\u001a\u00020@H\u0016\u00a2\u0006\u0004\u0008A\u0010BJ\u000f\u0010C\u001a\u00020\u0012H\u0016\u00a2\u0006\u0004\u0008C\u0010 J\'\u0010E\u001a\u00020\u00122\u0006\u0010;\u001a\u00020:2\u000e\u0010D\u001a\n\u0012\u0004\u0012\u00020\u0012\u0018\u00010\u0011H\u0016\u00a2\u0006\u0004\u0008E\u0010FJ\u000f\u0010G\u001a\u00020\u0012H\u0004\u00a2\u0006\u0004\u0008G\u0010 J\u0017\u0010J\u001a\u00020\u00122\u0006\u0010I\u001a\u00020HH\u0004\u00a2\u0006\u0004\u0008J\u0010KJ\u001f\u0010N\u001a\u00020\t2\u0006\u0010L\u001a\u0002032\u0006\u0010M\u001a\u000203H\u0004\u00a2\u0006\u0004\u0008N\u0010OJ\u001f\u0010#\u001a\u00020\u00122\u0006\u0010Q\u001a\u00020P2\u0006\u0010R\u001a\u00020PH\u0002\u00a2\u0006\u0004\u0008#\u0010SJ\u000f\u0010T\u001a\u00020\u0012H\u0002\u00a2\u0006\u0004\u0008T\u0010 J\u001f\u0010U\u001a\u00020\u00122\u0006\u0010&\u001a\u00020%2\u0006\u0010(\u001a\u00020\'H\u0002\u00a2\u0006\u0004\u0008U\u0010VJ\u000f\u0010W\u001a\u00020\u0012H\u0002\u00a2\u0006\u0004\u0008W\u0010 J\u000f\u0010X\u001a\u00020\u0012H\u0002\u00a2\u0006\u0004\u0008X\u0010 J\u0017\u0010Y\u001a\u00020\u00122\u0006\u0010;\u001a\u00020:H\u0002\u00a2\u0006\u0004\u0008Y\u0010ZJ1\u0010E\u001a\u00020\u00122\u0006\u0010\\\u001a\u00020[2\u0006\u0010;\u001a\u00020:2\u0010\u0008\u0002\u0010D\u001a\n\u0012\u0004\u0012\u00020\u0012\u0018\u00010\u0011H\u0002\u00a2\u0006\u0004\u0008E\u0010]J\u001f\u0010^\u001a\u00020\t2\u0006\u0010L\u001a\u0002032\u0006\u0010M\u001a\u000203H\u0002\u00a2\u0006\u0004\u0008^\u0010OJ\u000f\u0010_\u001a\u00020\u0012H\u0002\u00a2\u0006\u0004\u0008_\u0010 J\u0013\u0010a\u001a\u00020\t*\u00020`H\u0002\u00a2\u0006\u0004\u0008a\u0010bR\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0007\u0010cR\u001a\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\t0\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\n\u0010dR\u0014\u0010\u000c\u001a\u00020\u000b8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000c\u0010eR\u0014\u0010\u000e\u001a\u00020\r8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000e\u0010fR\u0014\u0010\u0010\u001a\u00020\u000f8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0010\u0010gR\u001a\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u00120\u00118\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0013\u0010hR$\u0010j\u001a\u00020@2\u0006\u0010i\u001a\u00020@8\u0002@BX\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008j\u0010k\"\u0004\u0008l\u0010BR*\u0010n\u001a\u00020m2\u0006\u0010i\u001a\u00020m8\u0004@DX\u0084\u000e\u00a2\u0006\u0012\n\u0004\u0008n\u0010o\u001a\u0004\u0008p\u0010q\"\u0004\u0008r\u0010sR$\u0010t\u001a\u00020P2\u0006\u0010i\u001a\u00020P8\u0002@BX\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008t\u0010u\"\u0004\u0008v\u0010wR(\u0010z\u001a\u0008\u0012\u0004\u0012\u00020y0x8\u0004@\u0004X\u0084\u000e\u00a2\u0006\u0012\n\u0004\u0008z\u0010{\u001a\u0004\u0008|\u0010}\"\u0004\u0008~\u0010\u007fR7\u0010\u0081\u0001\u001a\u0005\u0018\u00010\u0080\u00012\t\u0010i\u001a\u0005\u0018\u00010\u0080\u00018\u0000@@X\u0080\u000e\u00a2\u0006\u0018\n\u0006\u0008\u0081\u0001\u0010\u0082\u0001\u001a\u0006\u0008\u0083\u0001\u0010\u0084\u0001\"\u0006\u0008\u0085\u0001\u0010\u0086\u0001R\u0017\u0010\\\u001a\u00020[8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0007\n\u0005\u0008\\\u0010\u0087\u0001R\u001c\u0010\u0089\u0001\u001a\u0005\u0018\u00010\u0088\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u0089\u0001\u0010\u008a\u0001R\u0018\u0010\u008e\u0001\u001a\u00030\u008b\u00018&X\u00a6\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u008c\u0001\u0010\u008d\u0001R\u0017\u0010\u0091\u0001\u001a\u00020\t8@X\u0080\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u008f\u0001\u0010\u0090\u0001R\u0016\u0010\u0005\u001a\u00020\u00048@X\u0080\u0004\u00a2\u0006\u0008\u001a\u0006\u0008\u0092\u0001\u0010\u0093\u0001\u00a8\u0006\u0096\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "Lq71/a;",
        "Lk71/a;",
        "Lt71/b;",
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
        "Lt71/a;",
        "status",
        "userActionDidChange",
        "(Lt71/a;)V",
        "lifecycleDidChange",
        "sideEffectTriggered",
        "safetyInstructionDidChange",
        "touchPositionDidChange",
        "screenDidChange",
        "resetMessages",
        "()V",
        "Lk71/c;",
        "connectionStatus",
        "onConnectionStateChanged",
        "(Lk71/c;)V",
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
        "isFull",
        "onSendWindowIsFullChanged",
        "(Z)V",
        "receivedMessageFromCar",
        "",
        "car2PhoneMode",
        "receivedAdvertisementFromCar",
        "(I)V",
        "carChangedConnectionStatus",
        "isConnectionAllowed",
        "carChangedConnectionAllowanceStatus",
        "Lt71/c;",
        "connectionErrorStatus",
        "",
        "connectionErrorDescription",
        "carDidDetectConnectionError",
        "(Lt71/c;Ljava/lang/String;)V",
        "Lt71/f;",
        "sendWindowStatusChanged",
        "(Lt71/f;)V",
        "connect",
        "onDisconnectCalled",
        "disconnect",
        "(Lt71/c;Lay0/a;)V",
        "stopFunctionAndDisconnectDelayed",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;",
        "message",
        "send",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V",
        "c2pStaticInfoResponseMessageMajor",
        "c2pStaticInfoResponseMessageMinor",
        "determinePiloPaVersion",
        "(II)Ll71/u;",
        "Lk71/b;",
        "previousConnectionData",
        "newConnectionData",
        "(Lk71/b;Lk71/b;)V",
        "reconnect",
        "checkReceivedPiloPaVersion",
        "([BJ)V",
        "sendStartFunction",
        "sendStopFunction",
        "disconnectIfConnectionLost",
        "(Lt71/c;)V",
        "Lp71/c;",
        "disconnectType",
        "(Lp71/c;Lt71/c;Lay0/a;)V",
        "createPiloPaVersion",
        "resetConnectionErrorStatus",
        "Ll71/b;",
        "toPiloPaVersion",
        "(Ll71/b;)Ll71/u;",
        "Lk71/d;",
        "Ljava/util/Set;",
        "Ll71/a;",
        "Ln71/a;",
        "Lo71/a;",
        "Lay0/a;",
        "value",
        "latestSendWindowStatus",
        "Lt71/f;",
        "setLatestSendWindowStatus",
        "Ll71/v;",
        "latestCarDataRPA",
        "Ll71/v;",
        "getLatestCarDataRPA",
        "()Ll71/v;",
        "setLatestCarDataRPA",
        "(Ll71/v;)V",
        "latestConnectionData",
        "Lk71/b;",
        "setLatestConnectionData",
        "(Lk71/b;)V",
        "",
        "Lr71/b;",
        "latestReceivedServiceCommunicationMessages",
        "Ljava/util/List;",
        "getLatestReceivedServiceCommunicationMessages",
        "()Ljava/util/List;",
        "setLatestReceivedServiceCommunicationMessages",
        "(Ljava/util/List;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;",
        "delegate",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;",
        "getDelegate$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;",
        "setDelegate$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V",
        "Lp71/c;",
        "Ln71/b;",
        "backgroundDisconnectCancellable",
        "Ln71/b;",
        "Lmy0/c;",
        "getHighPrioInterval-UwyO8pc",
        "()J",
        "highPrioInterval",
        "getReceivedPiloPaVersion$remoteparkassistcoremeb_release",
        "()Ll71/u;",
        "receivedPiloPaVersion",
        "getLatestServiceCommunicationData$remoteparkassistcoremeb_release",
        "()Lr71/a;",
        "Companion",
        "p71/b",
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
.field public static final Companion:Lp71/b;

.field private static final DISCONNECT_DELAY:J


# instance fields
.field private backgroundDisconnectCancellable:Ln71/b;

.field private final debugConfig:Ll71/a;

.field private delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

.field private disconnectType:Lp71/c;

.field private final dispatcher:Ln71/a;

.field private final enabledVehiclePlatforms:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ll71/u;",
            ">;"
        }
    .end annotation
.end field

.field private latestCarDataRPA:Ll71/v;

.field private latestConnectionData:Lk71/b;

.field private latestReceivedServiceCommunicationMessages:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lr71/b;",
            ">;"
        }
    .end annotation
.end field

.field private latestSendWindowStatus:Lt71/f;

.field private final logger:Lo71/a;

.field private final onReconnect:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field

.field private final p2CCommunicating:Lk71/d;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lp71/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->Companion:Lp71/b;

    .line 7
    .line 8
    sget v0, Lmy0/c;->g:I

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 12
    .line 13
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    sput-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->DISCONNECT_DELAY:J

    .line 18
    .line 19
    return-void
.end method

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
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->p2CCommunicating:Lk71/d;

    .line 40
    .line 41
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 42
    .line 43
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->debugConfig:Ll71/a;

    .line 44
    .line 45
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->dispatcher:Ln71/a;

    .line 46
    .line 47
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 48
    .line 49
    iput-object p7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onReconnect:Lay0/a;

    .line 50
    .line 51
    iget-object p2, p1, Lr71/a;->c:Lt71/f;

    .line 52
    .line 53
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestSendWindowStatus:Lt71/f;

    .line 54
    .line 55
    iget-object p2, p1, Lr71/a;->b:Ll71/v;

    .line 56
    .line 57
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    .line 58
    .line 59
    iget-object p2, p1, Lr71/a;->a:Lk71/b;

    .line 60
    .line 61
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 62
    .line 63
    iget-object p1, p1, Lr71/a;->d:Ljava/util/List;

    .line 64
    .line 65
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestReceivedServiceCommunicationMessages:Ljava/util/List;

    .line 66
    .line 67
    sget-object p1, Lp71/c;->d:Lp71/c;

    .line 68
    .line 69
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnectType:Lp71/c;

    .line 70
    .line 71
    return-void
.end method

.method public static final synthetic access$getDISCONNECT_DELAY$cp()J
    .locals 2

    .line 1
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->DISCONNECT_DELAY:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->stopFunctionAndDisconnectDelayed$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final checkReceivedPiloPaVersion([BJ)V
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort$Companion;->getAddress()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    cmp-long v1, p2, v1

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    const-wide v1, 0x5250400001000000L    # 3.232601048520723E88

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    cmp-long p2, p2, v1

    .line 17
    .line 18
    if-nez p2, :cond_2

    .line 19
    .line 20
    :cond_0
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort$Companion;->create([B)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    if-nez p2, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 27
    .line 28
    array-length p1, p1

    .line 29
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort$Companion;->getByteLength()I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    const-string p3, " != expected size("

    .line 34
    .line 35
    const-string v0, "))"

    .line 36
    .line 37
    const-string v1, "Could not create C2PStaticInfoResponseMessageShort! Payload size("

    .line 38
    .line 39
    invoke-static {p1, p2, v1, p3, v0}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

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
    :cond_1
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;->getMajorVersion-w2LRezQ()B

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    and-int/lit16 p1, p1, 0xff

    .line 52
    .line 53
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;->getMinorVersion-w2LRezQ()B

    .line 54
    .line 55
    .line 56
    move-result p3

    .line 57
    and-int/lit16 p3, p3, 0xff

    .line 58
    .line 59
    invoke-virtual {p0, p1, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->determinePiloPaVersion(II)Ll71/u;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    instance-of p1, p1, Ll71/n;

    .line 64
    .line 65
    if-eqz p1, :cond_2

    .line 66
    .line 67
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$UnsupportedRpaVersionError;

    .line 68
    .line 69
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;->getMajorVersion-w2LRezQ()B

    .line 70
    .line 71
    .line 72
    move-result p3

    .line 73
    invoke-static {p3}, Llx0/s;->a(B)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;->getMinorVersion-w2LRezQ()B

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    invoke-static {v0}, Llx0/s;->a(B)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/C2PStaticInfoResponseMessageShort;->getPatchVersion-w2LRezQ()B

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    invoke-static {p2}, Llx0/s;->a(B)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    new-instance v1, Ljava/lang/StringBuilder;

    .line 94
    .line 95
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string p3, "."

    .line 102
    .line 103
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p2

    .line 119
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$UnsupportedRpaVersionError;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const/4 p2, 0x0

    .line 123
    const/4 p3, 0x2

    .line 124
    invoke-static {p0, p1, p2, p3}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 125
    .line 126
    .line 127
    :cond_2
    return-void
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->p2CCommunicating:Lk71/d;

    .line 2
    .line 3
    invoke-interface {p0}, Lk71/d;->connect()V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private final createPiloPaVersion(II)Ll71/u;
    .locals 6

    .line 1
    sget-object v0, Ll71/u;->d:Ll71/d;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const-string v0, "enabledVehiclePlatforms"

    .line 9
    .line 10
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    if-ne p1, v0, :cond_0

    .line 15
    .line 16
    if-ne p2, v0, :cond_0

    .line 17
    .line 18
    sget-object v0, Ll71/f;->e:Ll71/f;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v2, 0x1

    .line 22
    if-ne p1, v2, :cond_1

    .line 23
    .line 24
    if-nez p2, :cond_1

    .line 25
    .line 26
    sget-object v0, Ll71/i;->e:Ll71/i;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    if-ne p1, v2, :cond_2

    .line 30
    .line 31
    if-ne p2, v2, :cond_2

    .line 32
    .line 33
    sget-object v0, Ll71/j;->e:Ll71/j;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    if-ne p1, v2, :cond_3

    .line 37
    .line 38
    if-ne p2, v0, :cond_3

    .line 39
    .line 40
    sget-object v0, Ll71/k;->e:Ll71/k;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_3
    const/4 v3, 0x3

    .line 44
    if-ne p1, v3, :cond_4

    .line 45
    .line 46
    if-nez p2, :cond_4

    .line 47
    .line 48
    sget-object v0, Ll71/p;->e:Ll71/p;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_4
    if-ne p1, v3, :cond_5

    .line 52
    .line 53
    if-ne p2, v2, :cond_5

    .line 54
    .line 55
    sget-object v0, Ll71/q;->e:Ll71/q;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_5
    if-ne p1, v3, :cond_6

    .line 59
    .line 60
    if-ne p2, v0, :cond_6

    .line 61
    .line 62
    sget-object v0, Ll71/r;->e:Ll71/r;

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_6
    const/4 v0, 0x4

    .line 66
    if-ne p1, v0, :cond_7

    .line 67
    .line 68
    if-nez p2, :cond_7

    .line 69
    .line 70
    sget-object v0, Ll71/s;->e:Ll71/s;

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_7
    new-instance v0, Ll71/n;

    .line 74
    .line 75
    invoke-direct {v0, p1, p2}, Ll71/n;-><init>(II)V

    .line 76
    .line 77
    .line 78
    :goto_0
    invoke-interface {v1, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_8

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_8
    new-instance v0, Ll71/n;

    .line 86
    .line 87
    invoke-direct {v0, p1, p2}, Ll71/n;-><init>(II)V

    .line 88
    .line 89
    .line 90
    :goto_1
    instance-of v1, v0, Ll71/n;

    .line 91
    .line 92
    const-string v2, ", received => "

    .line 93
    .line 94
    const-string v3, ") enabledVehiclePlatforms: "

    .line 95
    .line 96
    const-string v4, "."

    .line 97
    .line 98
    const-string v5, "createPiloPaVersion(): DDA version ("

    .line 99
    .line 100
    if-eqz v1, :cond_9

    .line 101
    .line 102
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 103
    .line 104
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 105
    .line 106
    invoke-static {p1, p2, v5, v4, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-static {v1, p0}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    return-object v0

    .line 127
    :cond_9
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 128
    .line 129
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 130
    .line 131
    invoke-static {p1, p2, v5, v4, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    invoke-static {v1, p0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    return-object v0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Lay0/a;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Lay0/a;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final disconnect(Lp71/c;Lt71/c;Lay0/a;)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lp71/c;",
            "Lt71/c;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnectType:Lp71/c;

    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 5
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 6
    sget-object v3, Lk71/c;->f:Lk71/c;

    const-string v1, ", "

    const-string v2, "RPA terminates connection ("

    if-eq v0, v3, :cond_0

    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, ")..."

    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 8
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    const/4 v4, 0x0

    const/4 v6, 0x5

    const/4 v2, 0x0

    move-object v5, p2

    invoke-static/range {v1 .. v6}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    move-result-object p1

    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 9
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->dispatcher:Ln71/a;

    new-instance p2, Lo51/c;

    const/16 v0, 0x9

    invoke-direct {p2, v0, p0, p3}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-static {p1, p2}, Ln71/a;->b(Ln71/a;Lay0/a;)V

    return-void

    :cond_0
    move-object v5, p2

    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, "). Already "

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p0, p1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    if-eqz p3, :cond_1

    .line 11
    invoke-interface {p3}, Lay0/a;->invoke()Ljava/lang/Object;

    :cond_1
    return-void
.end method

.method public static synthetic disconnect$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Lp71/c;Lt71/c;Lay0/a;ILjava/lang/Object;)V
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x4

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p3, 0x0

    .line 8
    :cond_0
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnect(Lp71/c;Lt71/c;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    const-string p1, "Super calls with default arguments not supported in this target, function: disconnect"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method private static final disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Lay0/a;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->p2CCommunicating:Lk71/d;

    .line 2
    .line 3
    invoke-interface {p0}, Lk71/d;->disconnect()V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method private final disconnectIfConnectionLost(Lt71/c;)V
    .locals 2

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;

    .line 10
    .line 11
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    return-void

    .line 19
    :cond_1
    :goto_0
    const/4 v0, 0x2

    .line 20
    const/4 v1, 0x0

    .line 21
    invoke-static {p0, p1, v1, v0}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public static synthetic e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->send$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->lifecycleDidChange$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final lifecycleDidChange$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$BackgroundActivityError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$BackgroundActivityError;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-static {p0, v0, v2, v1}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 6
    .line 7
    .line 8
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->backgroundDisconnectCancellable:Ln71/b;

    .line 9
    .line 10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0
.end method

.method private final onConnectionStateChanged(Lk71/b;Lk71/b;)V
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    .line 2
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v1

    .line 3
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ".onConnectionStateChanged(previousConnectionData: "

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", newConnectionData: "

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 4
    iget-object v0, p2, Lk71/b;->b:Lk71/c;

    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_6

    const/4 v1, 0x1

    if-eq v0, v1, :cond_4

    const/4 v2, 0x2

    if-ne v0, v2, :cond_3

    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnectType:Lp71/c;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_2

    if-eq v0, v1, :cond_0

    if-ne v0, v2, :cond_1

    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onReconnect:Lay0/a;

    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    :cond_0
    move-object v0, p2

    goto :goto_0

    .line 8
    :cond_1
    new-instance p0, La8/r0;

    .line 9
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 10
    throw p0

    .line 11
    :cond_2
    iget-object p1, p1, Lk71/b;->b:Lk71/c;

    .line 12
    sget-object v0, Lk71/c;->f:Lk71/c;

    if-eq p1, v0, :cond_0

    .line 13
    iget-object p1, p2, Lk71/b;->d:Lt71/c;

    .line 14
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    .line 15
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$UnknownError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$UnknownError;

    const/4 v5, 0x7

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v0, p2

    .line 16
    invoke-static/range {v0 .. v5}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    move-result-object p1

    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    goto :goto_0

    .line 17
    :cond_3
    new-instance p0, La8/r0;

    .line 18
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 19
    throw p0

    :cond_4
    move-object v0, p2

    .line 20
    iget-object p1, p1, Lk71/b;->b:Lk71/c;

    .line 21
    sget-object p2, Lk71/c;->e:Lk71/c;

    if-eq p1, p2, :cond_5

    .line 22
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->sendStartFunction()V

    goto :goto_0

    .line 23
    :cond_5
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getReceivedPiloPaVersion$remoteparkassistcoremeb_release()Ll71/u;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    const-string p1, "piloPaVersion"

    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ll71/v;

    invoke-direct {p1, p2}, Ll71/v;-><init>(Ll71/u;)V

    .line 25
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestCarDataRPA(Ll71/v;)V

    goto :goto_0

    :cond_6
    move-object v0, p2

    .line 26
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->resetMessages()V

    .line 27
    :goto_0
    iget-object p1, v0, Lk71/b;->b:Lk71/c;

    .line 28
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onConnectionStateChanged(Lk71/c;)V

    .line 29
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    if-eqz p0, :cond_7

    invoke-interface {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->connectionStatusChanged(Lk71/b;)V

    :cond_7
    return-void
.end method

.method private final reconnect()V
    .locals 6

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->resetConnectionErrorStatus()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 5
    .line 6
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    if-ne v0, v1, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onReconnect:Lay0/a;

    .line 21
    .line 22
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    new-instance p0, La8/r0;

    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    sget-object v1, Lp71/c;->f:Lp71/c;

    .line 33
    .line 34
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 35
    .line 36
    const/4 v4, 0x4

    .line 37
    const/4 v5, 0x0

    .line 38
    const/4 v3, 0x0

    .line 39
    move-object v0, p0

    .line 40
    invoke-static/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnect$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Lp71/c;Lt71/c;Lay0/a;ILjava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method private final resetConnectionErrorStatus()V
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 2
    .line 3
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 4
    .line 5
    const/4 v5, 0x7

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-static/range {v0 .. v5}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method private static final send$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)Llx0/b0;
    .locals 6

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->p2CCommunicating:Lk71/d;

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
    invoke-interface/range {v0 .. v5}, Lk71/d;->sendData([BJBZ)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method

.method private final sendStartFunction()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 8
    .line 9
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v2, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ".sendStartFunction()"

    .line 26
    .line 27
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;->START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 41
    .line 42
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;-><init>(ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method private final sendStopFunction()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 8
    .line 9
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v2, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ".sendStopFunction()"

    .line 26
    .line 27
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;->STOP:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;

    .line 41
    .line 42
    invoke-direct {v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CStaticInfoRequestMessage;-><init>(ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/FunctionRequestStatus;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method private final setLatestConnectionData(Lk71/b;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 4
    .line 5
    invoke-direct {p0, v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onConnectionStateChanged(Lk71/b;Lk71/b;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private final setLatestSendWindowStatus(Lt71/f;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestSendWindowStatus:Lt71/f;

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestSendWindowStatus:Lt71/f;

    .line 6
    .line 7
    sget-object v0, Lt71/f;->e:Lt71/f;

    .line 8
    .line 9
    if-ne p1, v0, :cond_0

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    :goto_0
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onSendWindowIsFullChanged(Z)V

    .line 15
    .line 16
    .line 17
    :cond_1
    return-void
.end method

.method private static final stopFunctionAndDisconnectDelayed$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)Llx0/b0;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    invoke-static {p0, v0, v1, v2}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    return-object p0
.end method

.method private final toPiloPaVersion(Ll71/b;)Ll71/u;
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
    if-eq p0, p1, :cond_2

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    if-eq p0, p1, :cond_1

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
    sget-object p0, Ll71/u;->d:Ll71/d;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    sget-object p0, Ll71/d;->d:Ll71/f;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    sget-object p0, Ll71/u;->d:Ll71/d;

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    sget-object p0, Ll71/d;->c:Ll71/k;

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_3
    sget-object p0, Ll71/m;->e:Ll71/m;

    .line 43
    .line 44
    return-object p0
.end method


# virtual methods
.method public carChangedConnectionAllowanceStatus(Z)V
    .locals 8

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "carChangedConnectionAllowanceStatus("

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

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
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    const/16 v7, 0xe

    .line 29
    .line 30
    const/4 v4, 0x0

    .line 31
    const/4 v5, 0x0

    .line 32
    move v3, p1

    .line 33
    invoke-static/range {v2 .. v7}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public carChangedConnectionStatus(Lk71/c;)V
    .locals 8

    .line 1
    const-string v0, "connectionStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "carChangedConnectionState("

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v2, ")"

    .line 19
    .line 20
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    const/16 v7, 0xd

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    const/4 v5, 0x0

    .line 37
    move-object v4, p1

    .line 38
    invoke-static/range {v2 .. v7}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V
    .locals 7

    .line 1
    const-string v0, "connectionErrorStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "connectionErrorDescription"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 12
    .line 13
    new-instance v1, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v2, "carDidDetectConnectionError("

    .line 16
    .line 17
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v2, ", "

    .line 24
    .line 25
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string p2, ")"

    .line 32
    .line 33
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    invoke-static {v0, p2}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 44
    .line 45
    const/4 v4, 0x0

    .line 46
    const/4 v6, 0x7

    .line 47
    const/4 v2, 0x0

    .line 48
    const/4 v3, 0x0

    .line 49
    move-object v5, p1

    .line 50
    invoke-static/range {v1 .. v6}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 55
    .line 56
    .line 57
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 58
    .line 59
    iget-object p1, p1, Lk71/b;->d:Lt71/c;

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnectIfConnectionLost(Lt71/c;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public connect()V
    .locals 7

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 2
    .line 3
    iget-object v0, v0, Lk71/b;->c:Ls71/b;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 17
    .line 18
    iget-boolean v1, v0, Lk71/b;->a:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 23
    .line 24
    sget-object v3, Lk71/c;->d:Lk71/c;

    .line 25
    .line 26
    if-eq v0, v3, :cond_1

    .line 27
    .line 28
    sget-object v1, Lk71/c;->e:Lk71/c;

    .line 29
    .line 30
    if-eq v0, v1, :cond_1

    .line 31
    .line 32
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 33
    .line 34
    const-string v1, "RPA starts connecting..."

    .line 35
    .line 36
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sget-object v0, Lp71/c;->d:Lp71/c;

    .line 40
    .line 41
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnectType:Lp71/c;

    .line 42
    .line 43
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 44
    .line 45
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 46
    .line 47
    const/4 v6, 0x5

    .line 48
    const/4 v2, 0x0

    .line 49
    const/4 v4, 0x0

    .line 50
    invoke-static/range {v1 .. v6}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->dispatcher:Ln71/a;

    .line 58
    .line 59
    new-instance v1, Lp71/a;

    .line 60
    .line 61
    const/4 v2, 0x2

    .line 62
    invoke-direct {v1, p0, v2}, Lp71/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;I)V

    .line 63
    .line 64
    .line 65
    invoke-static {v0, v1}, Ln71/a;->b(Ln71/a;Lay0/a;)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_1
    :goto_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 70
    .line 71
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 72
    .line 73
    iget-object v1, p0, Lk71/b;->b:Lk71/c;

    .line 74
    .line 75
    iget-boolean v2, p0, Lk71/b;->a:Z

    .line 76
    .line 77
    iget-object p0, p0, Lk71/b;->c:Ls71/b;

    .line 78
    .line 79
    new-instance v3, Ljava/lang/StringBuilder;

    .line 80
    .line 81
    const-string v4, "connect() is called, but connection status is: "

    .line 82
    .line 83
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v1, ", connection allowance status is: "

    .line 90
    .line 91
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", car advertisement mode is: "

    .line 98
    .line 99
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string p0, "!"

    .line 106
    .line 107
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    invoke-static {v0, p0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    return-void
.end method

.method public final determinePiloPaVersion(II)Ll71/u;
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->debugConfig:Ll71/a;

    .line 2
    .line 3
    iget-object v1, v0, Ll71/a;->c:Ll71/u;

    .line 4
    .line 5
    iget-object v0, v0, Ll71/a;->a:Ll71/b;

    .line 6
    .line 7
    sget-object v2, Ll71/m;->e:Ll71/m;

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    sget-object v3, Ll71/b;->d:Ll71/b;

    .line 14
    .line 15
    if-eq v0, v3, :cond_0

    .line 16
    .line 17
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->toPiloPaVersion(Ll71/b;)Ll71/u;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    if-nez v2, :cond_1

    .line 23
    .line 24
    return-object v1

    .line 25
    :cond_1
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->createPiloPaVersion(II)Ll71/u;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public disconnect(Lt71/c;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lt71/c;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "connectionErrorStatus"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    sget-object v0, Lp71/c;->e:Lp71/c;

    .line 2
    invoke-direct {p0, v0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnect(Lp71/c;Lt71/c;Lay0/a;)V

    return-void
.end method

.method public final getDelegate$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract getHighPrioInterval-UwyO8pc()J
.end method

.method public final getLatestCarDataRPA()Ll71/v;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLatestReceivedServiceCommunicationMessages()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lr71/b;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestReceivedServiceCommunicationMessages:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLatestServiceCommunicationData$remoteparkassistcoremeb_release()Lr71/a;
    .locals 4

    .line 1
    new-instance v0, Lr71/a;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestSendWindowStatus:Lt71/f;

    .line 8
    .line 9
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestReceivedServiceCommunicationMessages:Ljava/util/List;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Lr71/a;-><init>(Lk71/b;Ll71/v;Lt71/f;Ljava/util/List;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public final getReceivedPiloPaVersion$remoteparkassistcoremeb_release()Ll71/u;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    .line 2
    .line 3
    iget-object p0, p0, Ll71/v;->a:Ll71/u;

    .line 4
    .line 5
    return-object p0
.end method

.method public lifecycleDidChange(Lt71/a;)V
    .locals 4

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v2, p1, Lt71/a;->a:Ln71/c;

    .line 23
    .line 24
    new-instance v3, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, ".lifecycleDidChange("

    .line 33
    .line 34
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ")"

    .line 41
    .line 42
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object v0, p1, Lt71/a;->a:Ln71/c;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    const/4 v1, 0x1

    .line 61
    if-eq v0, v1, :cond_3

    .line 62
    .line 63
    const/4 v1, 0x2

    .line 64
    if-eq v0, v1, :cond_1

    .line 65
    .line 66
    const/4 v1, 0x3

    .line 67
    if-eq v0, v1, :cond_1

    .line 68
    .line 69
    const/4 p1, 0x4

    .line 70
    if-ne v0, p1, :cond_0

    .line 71
    .line 72
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->stopFunctionAndDisconnectDelayed()V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_0
    new-instance p0, La8/r0;

    .line 77
    .line 78
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_1
    iget-object p1, p1, Lt71/a;->e:Ls71/l;

    .line 83
    .line 84
    sget-object v0, Ls71/l;->j:Ls71/l;

    .line 85
    .line 86
    if-eq p1, v0, :cond_4

    .line 87
    .line 88
    sget-object v0, Ls71/l;->k:Ls71/l;

    .line 89
    .line 90
    if-ne p1, v0, :cond_2

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 94
    .line 95
    iget-object p1, p1, Lk71/b;->b:Lk71/c;

    .line 96
    .line 97
    sget-object v0, Lk71/c;->e:Lk71/c;

    .line 98
    .line 99
    if-ne p1, v0, :cond_4

    .line 100
    .line 101
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->backgroundDisconnectCancellable:Ln71/b;

    .line 102
    .line 103
    if-nez p1, :cond_4

    .line 104
    .line 105
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->dispatcher:Ln71/a;

    .line 106
    .line 107
    sget-wide v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->DISCONNECT_DELAY:J

    .line 108
    .line 109
    new-instance v2, Lp71/a;

    .line 110
    .line 111
    const/4 v3, 0x1

    .line 112
    invoke-direct {v2, p0, v3}, Lp71/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;I)V

    .line 113
    .line 114
    .line 115
    invoke-static {p1, v0, v1, v2}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->backgroundDisconnectCancellable:Ln71/b;

    .line 120
    .line 121
    return-void

    .line 122
    :cond_3
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->backgroundDisconnectCancellable:Ln71/b;

    .line 123
    .line 124
    if-eqz p1, :cond_4

    .line 125
    .line 126
    iget-object p1, p1, Ln71/b;->a:Lay0/a;

    .line 127
    .line 128
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    const/4 p1, 0x0

    .line 132
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->backgroundDisconnectCancellable:Ln71/b;

    .line 133
    .line 134
    :cond_4
    :goto_0
    return-void
.end method

.method public abstract onC2PMessageReceived([BJBZ)V
.end method

.method public abstract onConnectionStateChanged(Lk71/c;)V
.end method

.method public abstract onSendWindowIsFullChanged(Z)V
.end method

.method public receivedAdvertisementFromCar(I)V
    .locals 6

    .line 1
    invoke-static {p1}, Lkp/p7;->d(I)Ls71/b;

    .line 2
    .line 3
    .line 4
    move-result-object v3

    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 6
    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "receivedAdvertisementFromCar(car2PhoneMode: "

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p1, "): "

    .line 18
    .line 19
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-static {v0, p1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    const/16 v5, 0xb

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    const/4 v2, 0x0

    .line 39
    invoke-static/range {v0 .. v5}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestConnectionData(Lk71/b;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    const/4 v0, 0x2

    .line 51
    if-eqz p1, :cond_3

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    if-eq p1, v1, :cond_1

    .line 55
    .line 56
    if-eq p1, v0, :cond_1

    .line 57
    .line 58
    const/4 v0, 0x3

    .line 59
    if-eq p1, v0, :cond_1

    .line 60
    .line 61
    const/4 p0, 0x4

    .line 62
    if-ne p1, p0, :cond_0

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    new-instance p0, La8/r0;

    .line 66
    .line 67
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 72
    .line 73
    iget-object p1, p1, Lk71/b;->d:Lt71/c;

    .line 74
    .line 75
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$PlayProtectionError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$PlayProtectionError;

    .line 76
    .line 77
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-eqz p1, :cond_2

    .line 82
    .line 83
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->resetConnectionErrorStatus()V

    .line 84
    .line 85
    .line 86
    :cond_2
    :goto_0
    return-void

    .line 87
    :cond_3
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$PlayProtectionError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$PlayProtectionError;

    .line 88
    .line 89
    const/4 v1, 0x0

    .line 90
    invoke-static {p0, p1, v1, v0}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 91
    .line 92
    .line 93
    return-void
.end method

.method public receivedMessageFromCar([BJBZ)V
    .locals 2

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 7
    .line 8
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 9
    .line 10
    sget-object v1, Lp71/d;->a:[I

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    aget v0, v1, v0

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    if-ne v0, v1, :cond_0

    .line 20
    .line 21
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->checkReceivedPiloPaVersion([BJ)V

    .line 22
    .line 23
    .line 24
    invoke-virtual/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onC2PMessageReceived([BJBZ)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    iget-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 29
    .line 30
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 31
    .line 32
    new-instance p3, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string p4, "Not a valid connection state: "

    .line 35
    .line 36
    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, ". Ignore C2PMessage with payload: "

    .line 43
    .line 44
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-static {p2, p0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method

.method public abstract resetMessages()V
.end method

.method public safetyInstructionDidChange(Lt71/a;)V
    .locals 2

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iget-object p1, p1, Lt71/a;->f:Lt71/e;

    .line 23
    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p0, ".safetyInstructionDidChange("

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string p0, ")"

    .line 41
    .line 42
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {v0, p0}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public screenDidChange(Lt71/a;)V
    .locals 2

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iget-object p1, p1, Lt71/a;->e:Ls71/l;

    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance v1, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string p0, ".screenDidChange("

    .line 37
    .line 38
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p0, ")"

    .line 45
    .line 46
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-static {v0, p0}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final send(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)V
    .locals 3

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 7
    .line 8
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 9
    .line 10
    sget-object v1, Lk71/c;->e:Lk71/c;

    .line 11
    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 15
    .line 16
    new-instance v0, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v1, "No connection! Send message failed: "

    .line 19
    .line 20
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->dispatcher:Ln71/a;

    .line 35
    .line 36
    new-instance v1, Lo51/c;

    .line 37
    .line 38
    const/16 v2, 0x8

    .line 39
    .line 40
    invoke-direct {v1, v2, p0, p1}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0, v1}, Ln71/a;->b(Ln71/a;Lay0/a;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public sendWindowStatusChanged(Lt71/f;)V
    .locals 3

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "sendWindowStatusChanged("

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v2, ") [ACC]"

    .line 19
    .line 20
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-static {v0, v1}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setLatestSendWindowStatus(Lt71/f;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final setDelegate$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V
    .locals 1

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestConnectionData:Lk71/b;

    .line 6
    .line 7
    invoke-interface {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->connectionStatusChanged(Lk71/b;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    .line 13
    .line 14
    invoke-interface {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->carStatusChanged(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    :cond_1
    return-void
.end method

.method public final setLatestCarDataRPA(Ll71/v;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestCarDataRPA:Ll71/v;

    .line 7
    .line 8
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;->carStatusChanged(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public final setLatestReceivedServiceCommunicationMessages(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lr71/b;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->latestReceivedServiceCommunicationMessages:Ljava/util/List;

    .line 7
    .line 8
    return-void
.end method

.method public sideEffectTriggered(Lt71/a;)V
    .locals 2

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iget-object p1, p1, Lt71/a;->c:Ls71/m;

    .line 23
    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p0, ".sideEffectTriggered("

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string p0, ")"

    .line 41
    .line 42
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {v0, p0}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public final stopFunctionAndDisconnectDelayed()V
    .locals 5

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->sendStopFunction()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->dispatcher:Ln71/a;

    .line 5
    .line 6
    sget v1, Lmy0/c;->g:I

    .line 7
    .line 8
    const/16 v1, 0x3c

    .line 9
    .line 10
    sget-object v2, Lmy0/e;->g:Lmy0/e;

    .line 11
    .line 12
    invoke-static {v1, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    new-instance v3, Lp71/a;

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-direct {v3, p0, v4}, Lp71/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v1, v2, v3}, Ljp/ca;->b(Ln71/a;JLay0/a;)Ln71/b;

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public touchPositionDidChange(Lt71/a;)V
    .locals 2

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    iget-object p1, p1, Lt71/a;->d:Lu71/b;

    .line 23
    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p0, ".touchPositionDidChange("

    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string p0, ")"

    .line 41
    .line 42
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {v0, p0}, Lo71/a;->c(Lo71/a;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public userActionDidChange(Lt71/a;)V
    .locals 4

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->logger:Lo71/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v2, p1, Lt71/a;->b:Ls71/q;

    .line 23
    .line 24
    new-instance v3, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, ".userActionDidChange("

    .line 33
    .line 34
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ")"

    .line 41
    .line 42
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-static {v0, v1}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object p1, p1, Lt71/a;->b:Ls71/q;

    .line 53
    .line 54
    sget-object v0, Ls71/p;->D:Ls71/p;

    .line 55
    .line 56
    if-ne p1, v0, :cond_0

    .line 57
    .line 58
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->reconnect()V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_0
    sget-object v0, Ls71/p;->f:Ls71/p;

    .line 63
    .line 64
    if-ne p1, v0, :cond_1

    .line 65
    .line 66
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->stopFunctionAndDisconnectDelayed()V

    .line 67
    .line 68
    .line 69
    :cond_1
    return-void
.end method
