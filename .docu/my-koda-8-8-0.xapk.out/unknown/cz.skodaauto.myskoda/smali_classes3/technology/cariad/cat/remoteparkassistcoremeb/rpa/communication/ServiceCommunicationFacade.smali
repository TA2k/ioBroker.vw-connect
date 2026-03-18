.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk71/a;
.implements Lq71/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00c8\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u000b\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u0002:\u0001gBE\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u0012\u000c\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\t\u0012\u0006\u0010\r\u001a\u00020\u000c\u0012\u000c\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000e\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J/\u0010\u001b\u001a\u00020\u000f2\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u001a\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u0017\u0010\u001f\u001a\u00020\u000f2\u0006\u0010\u001e\u001a\u00020\u001dH\u0016\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0017\u0010#\u001a\u00020\u000f2\u0006\u0010\"\u001a\u00020!H\u0016\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010&\u001a\u00020\u000f2\u0006\u0010%\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u001f\u0010,\u001a\u00020\u000f2\u0006\u0010)\u001a\u00020(2\u0006\u0010+\u001a\u00020*H\u0016\u00a2\u0006\u0004\u0008,\u0010-J\u0017\u00100\u001a\u00020\u000f2\u0006\u0010/\u001a\u00020.H\u0016\u00a2\u0006\u0004\u00080\u00101J\u000f\u00102\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u00082\u00103J\'\u00105\u001a\u00020\u000f2\u0006\u0010)\u001a\u00020(2\u000e\u00104\u001a\n\u0012\u0004\u0012\u00020\u000f\u0018\u00010\u000eH\u0016\u00a2\u0006\u0004\u00085\u00106J\u0017\u00108\u001a\u00020\u000f2\u0006\u00107\u001a\u00020\nH\u0002\u00a2\u0006\u0004\u00088\u00109J\u001f\u0010=\u001a\u00020\u00032\u0006\u0010;\u001a\u00020:2\u0006\u0010<\u001a\u00020\u0003H\u0002\u00a2\u0006\u0004\u0008=\u0010>J\u001f\u0010C\u001a\u00020B2\u0006\u0010?\u001a\u00020\n2\u0006\u0010A\u001a\u00020@H\u0002\u00a2\u0006\u0004\u0008C\u0010DJ\u001f\u0010F\u001a\u00020E2\u0006\u0010A\u001a\u00020@2\u0006\u0010\u0004\u001a\u00020\u0003H\u0002\u00a2\u0006\u0004\u0008F\u0010GJ\u001f\u0010I\u001a\u00020H2\u0006\u0010A\u001a\u00020@2\u0006\u0010\u0004\u001a\u00020\u0003H\u0002\u00a2\u0006\u0004\u0008I\u0010JJ\u001f\u0010L\u001a\u00020K2\u0006\u0010A\u001a\u00020@2\u0006\u0010\u0004\u001a\u00020\u0003H\u0002\u00a2\u0006\u0004\u0008L\u0010MJ\u001f\u0010O\u001a\u00020N2\u0006\u0010A\u001a\u00020@2\u0006\u0010\u0004\u001a\u00020\u0003H\u0002\u00a2\u0006\u0004\u0008O\u0010PR\u0014\u0010\u0008\u001a\u00020\u00078\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0008\u0010QR\u001a\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\t8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000b\u0010RR\u0014\u0010\r\u001a\u00020\u000c8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\r\u0010SR\u001a\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u000f0\u000e8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0010\u0010TR.\u0010W\u001a\u0004\u0018\u00010U2\u0008\u0010V\u001a\u0004\u0018\u00010U8\u0000@@X\u0080\u000e\u00a2\u0006\u0012\n\u0004\u0008W\u0010X\u001a\u0004\u0008Y\u0010Z\"\u0004\u0008[\u0010\\R\u001a\u0010]\u001a\u00020\u00038\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008]\u0010^\u001a\u0004\u0008_\u0010`R*\u0010a\u001a\u00020B2\u0006\u0010V\u001a\u00020B8\u0000@BX\u0080\u000e\u00a2\u0006\u0012\n\u0004\u0008a\u0010b\u001a\u0004\u0008c\u0010d\"\u0004\u0008e\u0010fR\u0014\u0010h\u001a\u00020g8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008h\u0010iR\u001a\u0010k\u001a\u00020j8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008k\u0010l\u001a\u0004\u0008m\u0010n\u00a8\u0006o"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;",
        "Lk71/a;",
        "Lq71/a;",
        "Lk71/d;",
        "p2CCommunicating",
        "Lk71/b;",
        "latestConnectionData",
        "Ll71/w;",
        "dependencies",
        "",
        "Ll71/u;",
        "enabledVehiclePlatforms",
        "Ll71/a;",
        "debugConfig",
        "Lkotlin/Function0;",
        "Llx0/b0;",
        "onReconnect",
        "<init>",
        "(Lk71/d;Lk71/b;Ll71/w;Ljava/util/Set;Ll71/a;Lay0/a;)V",
        "",
        "payload",
        "",
        "address",
        "",
        "priority",
        "",
        "requiresQueuing",
        "receivedMessageFromCar",
        "([BJBZ)V",
        "",
        "car2PhoneMode",
        "receivedAdvertisementFromCar",
        "(I)V",
        "Lk71/c;",
        "connectionStatus",
        "carChangedConnectionStatus",
        "(Lk71/c;)V",
        "isConnectionAllowed",
        "carChangedConnectionAllowanceStatus",
        "(Z)V",
        "Lt71/c;",
        "connectionErrorStatus",
        "",
        "connectionErrorDescription",
        "carDidDetectConnectionError",
        "(Lt71/c;Ljava/lang/String;)V",
        "Lt71/f;",
        "status",
        "sendWindowStatusChanged",
        "(Lt71/f;)V",
        "connect",
        "()V",
        "onDisconnectCalled",
        "disconnect",
        "(Lt71/c;Lay0/a;)V",
        "determinedPiloPaVersion",
        "onReceivedPiloPaVersion",
        "(Ll71/u;)V",
        "Ll71/b;",
        "demoMode",
        "realP2CCommunicating",
        "determineP2CCommunicating",
        "(Ll71/b;Lk71/d;)Lk71/d;",
        "targetPiloPaVersion",
        "Lr71/a;",
        "latestServiceCommunicationData",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "createServiceCommunication",
        "(Ll71/u;Lr71/a;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;",
        "createMEBServiceCommunication",
        "(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/communication/MLBServiceCommunication;",
        "createMLBServiceCommunication",
        "(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/communication/MLBServiceCommunication;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;",
        "createPPEServiceCommunication",
        "(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;",
        "createUnknownServiceCommunication",
        "(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;",
        "Ll71/w;",
        "Ljava/util/Set;",
        "Ll71/a;",
        "Lay0/a;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;",
        "value",
        "delegate",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;",
        "getDelegate$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;",
        "setDelegate$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V",
        "concreteP2CCommunicating",
        "Lk71/d;",
        "getConcreteP2CCommunicating$remoteparkassistcoremeb_release",
        "()Lk71/d;",
        "serviceCommunication",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "getServiceCommunication$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "setServiceCommunication",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)V",
        "Ly71/b;",
        "appStatusDelegateFacade",
        "Ly71/b;",
        "Lt71/b;",
        "appStatusDelegate",
        "Lt71/b;",
        "getAppStatusDelegate$remoteparkassistcoremeb_release",
        "()Lt71/b;",
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
.field private final appStatusDelegate:Lt71/b;

.field private final appStatusDelegateFacade:Ly71/b;

.field private final concreteP2CCommunicating:Lk71/d;

.field private final debugConfig:Ll71/a;

.field private delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

.field private final dependencies:Ll71/w;

.field private final enabledVehiclePlatforms:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ll71/u;",
            ">;"
        }
    .end annotation
.end field

.field private final onReconnect:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field

.field private serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;


# direct methods
.method public constructor <init>(Lk71/d;Lk71/b;Ll71/w;Ljava/util/Set;Ll71/a;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lk71/d;",
            "Lk71/b;",
            "Ll71/w;",
            "Ljava/util/Set<",
            "+",
            "Ll71/u;",
            ">;",
            "Ll71/a;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "p2CCommunicating"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "dependencies"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "enabledVehiclePlatforms"

    .line 12
    .line 13
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "debugConfig"

    .line 17
    .line 18
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "onReconnect"

    .line 22
    .line 23
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 30
    .line 31
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 32
    .line 33
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 34
    .line 35
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->onReconnect:Lay0/a;

    .line 36
    .line 37
    iget-object p3, p5, Ll71/a;->a:Ll71/b;

    .line 38
    .line 39
    invoke-direct {p0, p3, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->determineP2CCommunicating(Ll71/b;Lk71/d;)Lk71/d;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->concreteP2CCommunicating:Lk71/d;

    .line 44
    .line 45
    new-instance p3, Lr71/a;

    .line 46
    .line 47
    if-nez p2, :cond_0

    .line 48
    .line 49
    sget-object p2, Ls71/b;->h:Ls71/b;

    .line 50
    .line 51
    sget-object p4, Lk71/c;->f:Lk71/c;

    .line 52
    .line 53
    sget-object p5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 54
    .line 55
    new-instance p6, Lk71/b;

    .line 56
    .line 57
    const/4 v0, 0x0

    .line 58
    invoke-direct {p6, v0, p4, p2, p5}, Lk71/b;-><init>(ZLk71/c;Ls71/b;Lt71/c;)V

    .line 59
    .line 60
    .line 61
    move-object p2, p6

    .line 62
    :cond_0
    new-instance p4, Ll71/v;

    .line 63
    .line 64
    sget-object p5, Ll71/m;->e:Ll71/m;

    .line 65
    .line 66
    invoke-direct {p4, p5}, Ll71/v;-><init>(Ll71/u;)V

    .line 67
    .line 68
    .line 69
    sget-object p5, Lt71/f;->d:Lt71/f;

    .line 70
    .line 71
    sget-object p6, Lmx0/s;->d:Lmx0/s;

    .line 72
    .line 73
    invoke-direct {p3, p2, p4, p5, p6}, Lr71/a;-><init>(Lk71/b;Ll71/v;Lt71/f;Ljava/util/List;)V

    .line 74
    .line 75
    .line 76
    invoke-direct {p0, p3, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->createUnknownServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 81
    .line 82
    new-instance p2, Ly71/b;

    .line 83
    .line 84
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 85
    .line 86
    .line 87
    iput-object p1, p2, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 88
    .line 89
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->appStatusDelegateFacade:Ly71/b;

    .line 90
    .line 91
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->appStatusDelegate:Lt71/b;

    .line 92
    .line 93
    return-void
.end method

.method public static final synthetic access$onReceivedPiloPaVersion(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Ll71/u;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->onReceivedPiloPaVersion(Ll71/u;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/f;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->sendWindowStatusChanged$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/f;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final carChangedConnectionAllowanceStatus$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Z)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->carChangedConnectionAllowanceStatus(Z)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final carChangedConnectionStatus$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lk71/c;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->carChangedConnectionStatus(Lk71/c;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final carDidDetectConnectionError$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Ljava/lang/String;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->connect()V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private final createMEBServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;
    .locals 8

    .line 1
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 2
    .line 3
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 6
    .line 7
    iget-object v6, v0, Ll71/w;->b:Lu61/b;

    .line 8
    .line 9
    iget-object v5, v0, Ll71/w;->a:Ln71/a;

    .line 10
    .line 11
    iget-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->onReconnect:Lay0/a;

    .line 12
    .line 13
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;

    .line 14
    .line 15
    move-object v1, p1

    .line 16
    move-object v2, p2

    .line 17
    invoke-direct/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;-><init>(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method private final createMLBServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/communication/MLBServiceCommunication;
    .locals 8

    .line 1
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 2
    .line 3
    iget-object v4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 6
    .line 7
    iget-object v6, v0, Ll71/w;->b:Lu61/b;

    .line 8
    .line 9
    iget-object v5, v0, Ll71/w;->a:Ln71/a;

    .line 10
    .line 11
    iget-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->onReconnect:Lay0/a;

    .line 12
    .line 13
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/communication/MLBServiceCommunication;

    .line 14
    .line 15
    move-object v1, p1

    .line 16
    move-object v2, p2

    .line 17
    invoke-direct/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/communication/MLBServiceCommunication;-><init>(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method private final createPPEServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;
    .locals 8

    .line 1
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 6
    .line 7
    iget-object v5, v0, Ll71/w;->b:Lu61/b;

    .line 8
    .line 9
    iget-object v6, v0, Ll71/w;->a:Ln71/a;

    .line 10
    .line 11
    iget-object v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->onReconnect:Lay0/a;

    .line 12
    .line 13
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;

    .line 14
    .line 15
    move-object v4, p1

    .line 16
    move-object v2, p2

    .line 17
    invoke-direct/range {v0 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;-><init>(Ll71/a;Lk71/d;Ljava/util/Set;Lr71/a;Lo71/a;Ln71/a;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method private final createServiceCommunication(Ll71/u;Lr71/a;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;
    .locals 3

    .line 1
    instance-of v0, p1, Ll71/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->concreteP2CCommunicating:Lk71/d;

    .line 6
    .line 7
    invoke-direct {p0, p2, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->createMEBServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/communication/MEBServiceCommunication;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    instance-of v0, p1, Ll71/l;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->concreteP2CCommunicating:Lk71/d;

    .line 17
    .line 18
    invoke-direct {p0, p2, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->createMLBServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/communication/MLBServiceCommunication;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    instance-of v0, p1, Ll71/t;

    .line 24
    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->concreteP2CCommunicating:Lk71/d;

    .line 28
    .line 29
    invoke-direct {p0, p2, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->createPPEServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 35
    .line 36
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 37
    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v2, "createServiceCommunication("

    .line 41
    .line 42
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string p1, "): UnknownServiceCommunication"

    .line 49
    .line 50
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-static {v0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->concreteP2CCommunicating:Lk71/d;

    .line 61
    .line 62
    invoke-direct {p0, p2, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->createUnknownServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method

.method private final createUnknownServiceCommunication(Lr71/a;Lk71/d;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;
    .locals 12

    .line 1
    iget-object v8, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 2
    .line 3
    iget-object v9, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 6
    .line 7
    iget-object v10, v0, Ll71/w;->b:Lu61/b;

    .line 8
    .line 9
    iget-object v11, v0, Ll71/w;->a:Ln71/a;

    .line 10
    .line 11
    new-instance v0, Ly21/d;

    .line 12
    .line 13
    const/4 v6, 0x0

    .line 14
    const/4 v7, 0x5

    .line 15
    const/4 v1, 0x1

    .line 16
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 17
    .line 18
    const-string v4, "onReceivedPiloPaVersion"

    .line 19
    .line 20
    const-string v5, "onReceivedPiloPaVersion(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/data/PiloPaVersion;)V"

    .line 21
    .line 22
    move-object v2, p0

    .line 23
    invoke-direct/range {v0 .. v7}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->onReconnect:Lay0/a;

    .line 27
    .line 28
    move-object v7, v0

    .line 29
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;

    .line 30
    .line 31
    move-object v2, p2

    .line 32
    move-object v3, v8

    .line 33
    move-object v4, v9

    .line 34
    move-object v6, v10

    .line 35
    move-object v5, v11

    .line 36
    move-object v8, v1

    .line 37
    move-object v1, p1

    .line 38
    invoke-direct/range {v0 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/UnknownPiloPaVersionServiceCommunication;-><init>(Lr71/a;Lk71/d;Ljava/util/Set;Ll71/a;Ln71/a;Lo71/a;Lay0/k;Lay0/a;)V

    .line 39
    .line 40
    .line 41
    return-object v0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->receivedAdvertisementFromCar$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final determineP2CCommunicating(Ll71/b;Lk71/d;)Lk71/d;
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_3

    .line 6
    .line 7
    const/4 p2, 0x1

    .line 8
    if-eq p1, p2, :cond_2

    .line 9
    .line 10
    const/4 p2, 0x2

    .line 11
    if-eq p1, p2, :cond_2

    .line 12
    .line 13
    const/4 p2, 0x3

    .line 14
    if-eq p1, p2, :cond_1

    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    if-ne p1, p2, :cond_0

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
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;

    .line 27
    .line 28
    iget-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 29
    .line 30
    iget-object v0, p2, Ll71/w;->a:Ln71/a;

    .line 31
    .line 32
    iget-object p2, p2, Ll71/w;->b:Lu61/b;

    .line 33
    .line 34
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 35
    .line 36
    invoke-direct {p1, p0, v0, p2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMEB;-><init>(Lk71/a;Ln71/a;Lo71/a;Ll71/a;)V

    .line 37
    .line 38
    .line 39
    return-object p1

    .line 40
    :cond_2
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;

    .line 41
    .line 42
    iget-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 43
    .line 44
    iget-object v0, p2, Ll71/w;->a:Ln71/a;

    .line 45
    .line 46
    iget-object p2, p2, Ll71/w;->b:Lu61/b;

    .line 47
    .line 48
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->debugConfig:Ll71/a;

    .line 49
    .line 50
    invoke-direct {p1, p0, v0, p2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/demo/DemoC2PCommunicationMLB;-><init>(Lk71/a;Ln71/a;Lo71/a;Ll71/a;)V

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    :cond_3
    return-object p2
.end method

.method private static final disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Lay0/a;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->disconnect(Lt71/c;Lay0/a;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->carChangedConnectionAllowanceStatus$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Z)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Lay0/a;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Lay0/a;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lk71/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->carChangedConnectionStatus$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lk71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Ljava/lang/String;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->carDidDetectConnectionError$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Ljava/lang/String;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;[BJBZ)Llx0/b0;
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->receivedMessageFromCar$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;[BJBZ)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final onReceivedPiloPaVersion(Ll71/u;)V
    .locals 1

    .line 1
    instance-of v0, p1, Ll71/m;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    instance-of v0, p1, Ll71/n;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 10
    .line 11
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getLatestServiceCommunicationData$remoteparkassistcoremeb_release()Lr71/a;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->createServiceCommunication(Ll71/u;Lr71/a;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->setServiceCommunication(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 23
    .line 24
    iget-object p1, v0, Lr71/a;->a:Lk71/b;

    .line 25
    .line 26
    iget-object p1, p1, Lk71/b;->b:Lk71/c;

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->onConnectionStateChanged(Lk71/c;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    return-void
.end method

.method private static final receivedAdvertisementFromCar$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;I)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->receivedAdvertisementFromCar(I)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final receivedMessageFromCar$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;[BJBZ)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->receivedMessageFromCar([BJBZ)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final sendWindowStatusChanged$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/f;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->sendWindowStatusChanged(Lt71/f;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private final setServiceCommunication(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;)V
    .locals 1

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setDelegate$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->appStatusDelegateFacade:Ly71/b;

    .line 9
    .line 10
    iput-object p1, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public carChangedConnectionAllowanceStatus(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 4
    .line 5
    new-instance v1, Lc/d;

    .line 6
    .line 7
    const/16 v2, 0x11

    .line 8
    .line 9
    invoke-direct {v1, p0, p1, v2}, Lc/d;-><init>(Ljava/lang/Object;ZI)V

    .line 10
    .line 11
    .line 12
    const-wide/16 p0, 0x0

    .line 13
    .line 14
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public carChangedConnectionStatus(Lk71/c;)V
    .locals 3

    .line 1
    const-string v0, "connectionStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 7
    .line 8
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 9
    .line 10
    new-instance v1, Lvu/d;

    .line 11
    .line 12
    const/16 v2, 0x1b

    .line 13
    .line 14
    invoke-direct {v1, v2, p0, p1}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 p0, 0x0

    .line 18
    .line 19
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V
    .locals 3

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 12
    .line 13
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 14
    .line 15
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 16
    .line 17
    const/16 v2, 0xe

    .line 18
    .line 19
    invoke-direct {v1, p0, p1, p2, v2}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    const-wide/16 p0, 0x0

    .line 23
    .line 24
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public connect()V
    .locals 4

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 4
    .line 5
    new-instance v1, Ly1/i;

    .line 6
    .line 7
    const/4 v2, 0x5

    .line 8
    invoke-direct {v1, p0, v2}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    const-wide/16 v2, 0x0

    .line 12
    .line 13
    invoke-interface {v0, v2, v3, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public disconnect(Lt71/c;Lay0/a;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lt71/c;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "connectionErrorStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 7
    .line 8
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 9
    .line 10
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 11
    .line 12
    const/16 v2, 0xf

    .line 13
    .line 14
    invoke-direct {v1, p0, p1, p2, v2}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    const-wide/16 p0, 0x0

    .line 18
    .line 19
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final getAppStatusDelegate$remoteparkassistcoremeb_release()Lt71/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->appStatusDelegate:Lt71/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConcreteP2CCommunicating$remoteparkassistcoremeb_release()Lk71/d;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->concreteP2CCommunicating:Lk71/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDelegate$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getServiceCommunication$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    return-object p0
.end method

.method public receivedAdvertisementFromCar(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 4
    .line 5
    new-instance v1, Lba0/h;

    .line 6
    .line 7
    const/16 v2, 0xd

    .line 8
    .line 9
    invoke-direct {v1, p0, p1, v2}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 10
    .line 11
    .line 12
    const-wide/16 p0, 0x0

    .line 13
    .line 14
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public receivedMessageFromCar([BJBZ)V
    .locals 8

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 7
    .line 8
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 9
    .line 10
    new-instance v1, Ly71/a;

    .line 11
    .line 12
    move-object v2, p0

    .line 13
    move-object v3, p1

    .line 14
    move-wide v4, p2

    .line 15
    move v6, p4

    .line 16
    move v7, p5

    .line 17
    invoke-direct/range {v1 .. v7}, Ly71/a;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;[BJBZ)V

    .line 18
    .line 19
    .line 20
    const-wide/16 p0, 0x0

    .line 21
    .line 22
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 23
    .line 24
    .line 25
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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->dependencies:Ll71/w;

    .line 7
    .line 8
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 9
    .line 10
    new-instance v1, Lvu/d;

    .line 11
    .line 12
    const/16 v2, 0x1c

    .line 13
    .line 14
    invoke-direct {v1, v2, p0, p1}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 p0, 0x0

    .line 18
    .line 19
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final setDelegate$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->delegate:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->serviceCommunication:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->setDelegate$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
