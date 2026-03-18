.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk71/a;
.implements Lc81/h;
.implements Lc81/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00ce\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0007\n\u0002\u0008\u0004\n\u0002\u0010\n\n\u0002\u0008\u0014\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B5\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0008\u0012\u000c\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\n\u0012\u0006\u0010\u000e\u001a\u00020\r\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J+\u0010\u0017\u001a\u0014\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\u00160\u00132\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0011H\u0002\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u000f\u0010\u001a\u001a\u00020\u0019H\u0002\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ\u0017\u0010\u001e\u001a\u00020\u00192\u0006\u0010\u001d\u001a\u00020\u001cH\u0002\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\u0019H\u0002\u00a2\u0006\u0004\u0008 \u0010\u001bJ%\u0010%\u001a\u00020\u00192\u0006\u0010\u001d\u001a\u00020\u001c2\u000c\u0010\"\u001a\u0008\u0012\u0004\u0012\u00020\u00190!H\u0000\u00a2\u0006\u0004\u0008#\u0010$J\u000f\u0010\'\u001a\u00020\u0019H\u0000\u00a2\u0006\u0004\u0008&\u0010\u001bJ/\u00100\u001a\u00020\u00192\u0006\u0010)\u001a\u00020(2\u0006\u0010+\u001a\u00020*2\u0006\u0010-\u001a\u00020,2\u0006\u0010/\u001a\u00020.H\u0016\u00a2\u0006\u0004\u00080\u00101J\u0017\u00104\u001a\u00020\u00192\u0006\u00103\u001a\u000202H\u0016\u00a2\u0006\u0004\u00084\u00105J\u0017\u00108\u001a\u00020\u00192\u0006\u00107\u001a\u000206H\u0016\u00a2\u0006\u0004\u00088\u00109J\u0017\u0010;\u001a\u00020\u00192\u0006\u0010:\u001a\u00020.H\u0016\u00a2\u0006\u0004\u0008;\u0010<J\u001f\u0010A\u001a\u00020\u00192\u0006\u0010>\u001a\u00020=2\u0006\u0010@\u001a\u00020?H\u0016\u00a2\u0006\u0004\u0008A\u0010BJ\u0017\u0010E\u001a\u00020\u00192\u0006\u0010D\u001a\u00020CH\u0016\u00a2\u0006\u0004\u0008E\u0010FJ\u0017\u0010I\u001a\u00020\u00192\u0006\u0010H\u001a\u00020GH\u0016\u00a2\u0006\u0004\u0008I\u0010JJ?\u0010S\u001a\u00020\u00192\u0006\u0010L\u001a\u00020K2\u0006\u0010M\u001a\u00020K2\u0006\u0010N\u001a\u00020K2\u0006\u0010O\u001a\u00020K2\u0006\u0010Q\u001a\u00020P2\u0006\u0010R\u001a\u00020.H\u0016\u00a2\u0006\u0004\u0008S\u0010TR\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010UR\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0007\u0010VR\u0014\u0010\t\u001a\u00020\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u0010WR\u001a\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\n8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000c\u0010XR\u0014\u0010\u000e\u001a\u00020\r8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u000e\u0010YR$\u0010[\u001a\u00020\u00142\u0006\u0010Z\u001a\u00020\u00148\u0000@BX\u0080\u000e\u00a2\u0006\u000c\n\u0004\u0008[\u0010\\\u001a\u0004\u0008]\u0010^R$\u0010_\u001a\u00020\u00152\u0006\u0010Z\u001a\u00020\u00158\u0000@BX\u0080\u000e\u00a2\u0006\u000c\n\u0004\u0008_\u0010`\u001a\u0004\u0008a\u0010bR\u0016\u0010c\u001a\u00020\u00168\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008c\u0010dR\u0018\u0010f\u001a\u0004\u0018\u00010e8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008f\u0010gR\u0014\u0010k\u001a\u00020h8@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008i\u0010jR\u0014\u0010n\u001a\u00020\u00048@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008l\u0010m\u00a8\u0006o"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;",
        "Lk71/a;",
        "Lc81/h;",
        "Lc81/a;",
        "Lk71/d;",
        "p2CCommunicating",
        "Ll71/w;",
        "dependencies",
        "Ll71/z;",
        "trajectoryConfig",
        "",
        "Ll71/u;",
        "enabledVehiclePlatforms",
        "Ll71/a;",
        "debugConfig",
        "<init>",
        "(Lk71/d;Ll71/w;Ll71/z;Ljava/util/Set;Ll71/a;)V",
        "Lk71/b;",
        "latestConnectionData",
        "Llx0/r;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;",
        "Lc81/d;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;",
        "createInitSetup",
        "(Lk71/b;)Llx0/r;",
        "Llx0/b0;",
        "onReconnect",
        "()V",
        "Lc81/e;",
        "navigationDelegate",
        "onStart",
        "(Lc81/e;)V",
        "onStop",
        "Lkotlin/Function0;",
        "onFinish",
        "start$remoteparkassistcoremeb_release",
        "(Lc81/e;Lay0/a;)V",
        "start",
        "stop$remoteparkassistcoremeb_release",
        "stop",
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
        "Ln71/c;",
        "lifecycle",
        "lifecycleChanged",
        "(Ln71/c;)V",
        "",
        "xPositionPx",
        "yPositionPx",
        "deviceDisplayWidthPx",
        "deviceDisplayHeightPx",
        "",
        "multiTouchCount",
        "touchEnded",
        "touchPositionChanged",
        "(FFFFSZ)V",
        "Lk71/d;",
        "Ll71/w;",
        "Ll71/z;",
        "Ljava/util/Set;",
        "Ll71/a;",
        "value",
        "rpaStateMachine",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;",
        "getRpaStateMachine$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;",
        "navigationController",
        "Lc81/d;",
        "getNavigationController$remoteparkassistcoremeb_release",
        "()Lc81/d;",
        "serviceCommunicationFacade",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;",
        "Lc81/g;",
        "startArguments",
        "Lc81/g;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "getServiceCommunication$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;",
        "serviceCommunication",
        "getConcreteP2CCommunicating$remoteparkassistcoremeb_release",
        "()Lk71/d;",
        "concreteP2CCommunicating",
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
.field private final debugConfig:Ll71/a;

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

.field private navigationController:Lc81/d;

.field private final p2CCommunicating:Lk71/d;

.field private rpaStateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

.field private serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

.field private startArguments:Lc81/g;

.field private final trajectoryConfig:Ll71/z;


# direct methods
.method public constructor <init>(Lk71/d;Ll71/w;Ll71/z;Ljava/util/Set;Ll71/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lk71/d;",
            "Ll71/w;",
            "Ll71/z;",
            "Ljava/util/Set<",
            "+",
            "Ll71/u;",
            ">;",
            "Ll71/a;",
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
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "trajectoryConfig"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "enabledVehiclePlatforms"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "debugConfig"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->p2CCommunicating:Lk71/d;

    .line 30
    .line 31
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->dependencies:Ll71/w;

    .line 32
    .line 33
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->trajectoryConfig:Ll71/z;

    .line 34
    .line 35
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 36
    .line 37
    iput-object p5, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->debugConfig:Ll71/a;

    .line 38
    .line 39
    const/4 p1, 0x0

    .line 40
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->createInitSetup(Lk71/b;)Llx0/r;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iget-object p2, p1, Llx0/r;->d:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 47
    .line 48
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->rpaStateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 49
    .line 50
    iget-object p2, p1, Llx0/r;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p2, Lc81/d;

    .line 53
    .line 54
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 55
    .line 56
    iget-object p1, p1, Llx0/r;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 59
    .line 60
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 61
    .line 62
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->onStart$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$onReconnect(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->onReconnect()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->stop$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final createInitSetup(Lk71/b;)Llx0/r;
    .locals 17
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lk71/b;",
            ")",
            "Llx0/r;"
        }
    .end annotation

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-direct {v8, v0, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;ILkotlin/jvm/internal/g;)V

    .line 8
    .line 9
    .line 10
    new-instance v9, Lc81/d;

    .line 11
    .line 12
    iget-object v0, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->dependencies:Ll71/w;

    .line 13
    .line 14
    new-instance v1, Lb81/b;

    .line 15
    .line 16
    new-instance v3, Lb81/d;

    .line 17
    .line 18
    iget-object v4, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->trajectoryConfig:Ll71/z;

    .line 19
    .line 20
    invoke-direct {v3, v0, v4}, Lb81/d;-><init>(Ll71/w;Ll71/z;)V

    .line 21
    .line 22
    .line 23
    iget-object v4, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->dependencies:Ll71/w;

    .line 24
    .line 25
    invoke-direct {v1, v3, v4}, Lb81/b;-><init>(Lb81/d;Ll71/w;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {v9, v0, v8, v1}, Lc81/d;-><init>(Ll71/w;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;Lb81/b;)V

    .line 29
    .line 30
    .line 31
    iget-object v11, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->p2CCommunicating:Lk71/d;

    .line 32
    .line 33
    iget-object v13, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->dependencies:Ll71/w;

    .line 34
    .line 35
    iget-object v14, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->enabledVehiclePlatforms:Ljava/util/Set;

    .line 36
    .line 37
    iget-object v15, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->debugConfig:Ll71/a;

    .line 38
    .line 39
    new-instance v0, Lc3/g;

    .line 40
    .line 41
    const/4 v6, 0x0

    .line 42
    const/16 v7, 0x8

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 46
    .line 47
    const-string v4, "onReconnect"

    .line 48
    .line 49
    const-string v5, "onReconnect()V"

    .line 50
    .line 51
    invoke-direct/range {v0 .. v7}, Lc3/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 52
    .line 53
    .line 54
    new-instance v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 55
    .line 56
    move-object/from16 v12, p1

    .line 57
    .line 58
    move-object/from16 v16, v0

    .line 59
    .line 60
    invoke-direct/range {v10 .. v16}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;-><init>(Lk71/d;Lk71/b;Ll71/w;Ljava/util/Set;Ll71/a;Lay0/a;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v10, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->setDelegate$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/communication/ServiceCommunicationDelegate;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->getAppStatusDelegate$remoteparkassistcoremeb_release()Lt71/b;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iput-object v0, v9, Lc81/d;->d:Lt71/b;

    .line 71
    .line 72
    iget-object v1, v9, Lc81/d;->e:Lt71/a;

    .line 73
    .line 74
    if-eqz v1, :cond_0

    .line 75
    .line 76
    invoke-virtual {v1, v0}, Lt71/a;->b(Lt71/b;)V

    .line 77
    .line 78
    .line 79
    :cond_0
    new-instance v0, Llx0/r;

    .line 80
    .line 81
    invoke-direct {v0, v8, v9, v10}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    return-object v0
.end method

.method private final onReconnect()V
    .locals 7

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->dependencies:Ll71/w;

    .line 2
    .line 3
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 4
    .line 5
    const-string v1, "RPANavigationManager.onReconnect()"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->getServiceCommunication$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->getLatestServiceCommunicationData$remoteparkassistcoremeb_release()Lr71/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, v0, Lr71/a;->a:Lk71/b;

    .line 19
    .line 20
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 21
    .line 22
    const/4 v6, 0x7

    .line 23
    const/4 v2, 0x0

    .line 24
    const/4 v3, 0x0

    .line 25
    const/4 v4, 0x0

    .line 26
    invoke-static/range {v1 .. v6}, Lk71/b;->a(Lk71/b;ZLk71/c;Ls71/b;Lt71/c;I)Lk71/b;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->createInitSetup(Lk71/b;)Llx0/r;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    iget-object v1, v0, Llx0/r;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 37
    .line 38
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->rpaStateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 39
    .line 40
    iget-object v1, v0, Llx0/r;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lc81/d;

    .line 43
    .line 44
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 45
    .line 46
    iget-object v0, v0, Llx0/r;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 49
    .line 50
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 51
    .line 52
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->startArguments:Lc81/g;

    .line 53
    .line 54
    if-eqz v0, :cond_0

    .line 55
    .line 56
    iget-object v0, v0, Lc81/g;->b:Lc81/e;

    .line 57
    .line 58
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->onStart(Lc81/e;)V

    .line 59
    .line 60
    .line 61
    :cond_0
    return-void
.end method

.method private final onStart(Lc81/e;)V
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 2
    .line 3
    new-instance v1, Lc81/f;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v1, p0, v2}, Lc81/f;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    const-string v2, "navigationDelegate"

    .line 13
    .line 14
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v0, Lc81/d;->a:Ll71/w;

    .line 18
    .line 19
    iget-object v2, v2, Ll71/w;->a:Ln71/a;

    .line 20
    .line 21
    new-instance v3, Lc41/b;

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    invoke-direct {v3, v0, p1, v1, v4}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    const-wide/16 v0, 0x0

    .line 28
    .line 29
    invoke-interface {v2, v0, v1, v3}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->connect()V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method private static final onStart$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->stop$remoteparkassistcoremeb_release()V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method

.method private final onStop()V
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 2
    .line 3
    iget-object v1, v0, Lc81/d;->a:Ll71/w;

    .line 4
    .line 5
    iget-object v1, v1, Ll71/w;->a:Ln71/a;

    .line 6
    .line 7
    new-instance v2, La71/u;

    .line 8
    .line 9
    const/16 v3, 0x1b

    .line 10
    .line 11
    invoke-direct {v2, v0, v3}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    const-wide/16 v3, 0x0

    .line 15
    .line 16
    invoke-interface {v1, v3, v4, v2}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->startArguments:Lc81/g;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->startArguments:Lc81/g;

    .line 25
    .line 26
    iget-object v0, v0, Lc81/g;->a:Lay0/a;

    .line 27
    .line 28
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->dependencies:Ll71/w;

    .line 32
    .line 33
    iget-object p0, p0, Ll71/w;->a:Ln71/a;

    .line 34
    .line 35
    invoke-interface {p0}, Ln71/a;->cancelAllDispatchJobs()V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method private static final stop$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->onStop()V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method


# virtual methods
.method public carChangedConnectionAllowanceStatus(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->carChangedConnectionAllowanceStatus(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public carChangedConnectionStatus(Lk71/c;)V
    .locals 1

    .line 1
    const-string v0, "connectionStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->carChangedConnectionStatus(Lk71/c;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V
    .locals 1

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final getConcreteP2CCommunicating$remoteparkassistcoremeb_release()Lk71/d;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->getConcreteP2CCommunicating$remoteparkassistcoremeb_release()Lk71/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getNavigationController$remoteparkassistcoremeb_release()Lc81/d;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRpaStateMachine$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->rpaStateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getServiceCommunication$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->getServiceCommunication$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public lifecycleChanged(Ln71/c;)V
    .locals 1

    .line 1
    const-string v0, "lifecycle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lc81/d;->lifecycleChanged(Ln71/c;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public receivedAdvertisementFromCar(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->receivedAdvertisementFromCar(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public receivedMessageFromCar([BJBZ)V
    .locals 1

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 7
    .line 8
    invoke-virtual/range {p0 .. p5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->receivedMessageFromCar([BJBZ)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public sendWindowStatusChanged(Lt71/f;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->sendWindowStatusChanged(Lt71/f;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final start$remoteparkassistcoremeb_release(Lc81/e;Lay0/a;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lc81/e;",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "navigationDelegate"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onFinish"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lc81/g;

    .line 12
    .line 13
    invoke-direct {v0, p1, p2}, Lc81/g;-><init>(Lc81/e;Lay0/a;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->startArguments:Lc81/g;

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->onStart(Lc81/e;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final stop$remoteparkassistcoremeb_release()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->serviceCommunicationFacade:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 2
    .line 3
    new-instance v1, Lc81/f;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, v2}, Lc81/f;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;I)V

    .line 7
    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-static {v0, v2, v1, p0}, Lq71/a;->a(Lq71/a;Lt71/c;Lc81/f;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public touchPositionChanged(FFFFSZ)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->navigationController:Lc81/d;

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p6}, Lc81/d;->touchPositionChanged(FFFFSZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
