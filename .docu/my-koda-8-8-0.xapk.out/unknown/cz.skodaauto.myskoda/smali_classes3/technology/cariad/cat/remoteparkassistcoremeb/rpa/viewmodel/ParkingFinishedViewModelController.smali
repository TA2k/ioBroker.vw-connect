.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;
.super Le81/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le81/q;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0090\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u001a\u0018\u00002\u00020\u00012\u00020\u0002B\u0011\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u000c\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\u0007H\u0010\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0017\u0010\u0010\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\rH\u0010\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u0017\u0010\u0014\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\u0011H\u0010\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u0017\u0010\u0019\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u0015H\u0010\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u000f\u0010\u001d\u001a\u00020\u001aH\u0010\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u001f\u0010\"\u001a\u00020\t2\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010!\u001a\u00020 H\u0016\u00a2\u0006\u0004\u0008\"\u0010#J\u0017\u0010$\u001a\u00020\t2\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008$\u0010%J\u000f\u0010&\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u000f\u0010(\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008(\u0010\'J\u000f\u0010)\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008)\u0010\'J\u000f\u0010*\u001a\u00020\tH\u0002\u00a2\u0006\u0004\u0008*\u0010\'R\u001a\u0010,\u001a\u00020+8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008,\u0010-\u001a\u0004\u0008.\u0010/R(\u00103\u001a\u0010\u0012\u000c\u0012\n\u0012\u0006\u0008\u0001\u0012\u00020201008\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u00083\u00104\u001a\u0004\u00085\u00106R \u00108\u001a\u0008\u0012\u0004\u0012\u000207008\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u00088\u00104\u001a\u0004\u00089\u00106R\u001a\u0010;\u001a\u0008\u0012\u0004\u0012\u00020\u001e0:8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008;\u0010<R*\u0010?\u001a\u00020=2\u0006\u0010>\u001a\u00020=8\u0016@PX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008?\u0010@\u001a\u0004\u0008A\u0010B\"\u0004\u0008C\u0010DR*\u0010E\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@PX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008E\u0010F\u001a\u0004\u0008E\u0010G\"\u0004\u0008H\u0010IR.\u0010K\u001a\u0004\u0018\u00010J2\u0008\u0010>\u001a\u0004\u0018\u00010J8\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008K\u0010L\u001a\u0004\u0008M\u0010N\"\u0004\u0008O\u0010PR*\u0010Q\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008Q\u0010F\u001a\u0004\u0008Q\u0010G\"\u0004\u0008R\u0010IR*\u0010S\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008S\u0010F\u001a\u0004\u0008S\u0010G\"\u0004\u0008T\u0010IR*\u0010U\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008U\u0010F\u001a\u0004\u0008U\u0010G\"\u0004\u0008V\u0010IR.\u0010W\u001a\u0004\u0018\u00010 2\u0008\u0010>\u001a\u0004\u0018\u00010 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008W\u0010X\u001a\u0004\u0008W\u0010Y\"\u0004\u0008Z\u0010[R*\u0010]\u001a\u00020\\2\u0006\u0010>\u001a\u00020\\8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008]\u0010^\u001a\u0004\u0008_\u0010`\"\u0004\u0008a\u0010bR.\u0010c\u001a\u0004\u0018\u00010 2\u0008\u0010>\u001a\u0004\u0018\u00010 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008c\u0010X\u001a\u0004\u0008c\u0010Y\"\u0004\u0008d\u0010[R.\u0010e\u001a\u0004\u0018\u00010 2\u0008\u0010>\u001a\u0004\u0018\u00010 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008e\u0010X\u001a\u0004\u0008e\u0010Y\"\u0004\u0008f\u0010[R*\u0010g\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008g\u0010F\u001a\u0004\u0008g\u0010G\"\u0004\u0008h\u0010IR*\u0010i\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008i\u0010F\u001a\u0004\u0008i\u0010G\"\u0004\u0008j\u0010IR*\u0010k\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008k\u0010F\u001a\u0004\u0008k\u0010G\"\u0004\u0008l\u0010IR*\u0010m\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008m\u0010F\u001a\u0004\u0008m\u0010G\"\u0004\u0008n\u0010IR0\u0010o\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@RX\u0097\u000e\u00a2\u0006\u0018\n\u0004\u0008o\u0010F\u0012\u0004\u0008q\u0010\'\u001a\u0004\u0008o\u0010G\"\u0004\u0008p\u0010IR*\u0010r\u001a\u00020 2\u0006\u0010>\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008r\u0010F\u001a\u0004\u0008s\u0010G\"\u0004\u0008t\u0010IR\u0014\u0010u\u001a\u00020 8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008u\u0010G\u00a8\u0006v"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;",
        "Le81/x;",
        "Le81/q;",
        "Ll71/w;",
        "dependencies",
        "<init>",
        "(Ll71/w;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;",
        "newState",
        "Llx0/b0;",
        "updateMEB$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V",
        "updateMEB",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;",
        "updateMLB$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V",
        "updateMLB",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;",
        "updatePPE$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;)V",
        "updatePPE",
        "Ll71/x;",
        "values",
        "onStateValuesChange$remoteparkassistcoremeb_release",
        "(Ll71/x;)V",
        "onStateValuesChange",
        "Le81/t;",
        "toRPAViewModel$remoteparkassistcoremeb_release",
        "()Le81/t;",
        "toRPAViewModel",
        "Lz71/g;",
        "parkingFinishedObserver",
        "",
        "notifyOnRegister",
        "addObserver",
        "(Lz71/g;Z)V",
        "removeObserver",
        "(Lz71/g;)V",
        "startCloseWindows",
        "()V",
        "stopCloseWindows",
        "onAppear",
        "updateIsParkingFinishedWithoutWarnings",
        "Ls71/l;",
        "representingScreen",
        "Ls71/l;",
        "getRepresentingScreen",
        "()Ls71/l;",
        "",
        "Lhy0/d;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "supportedScreenStates",
        "Ljava/util/Set;",
        "getSupportedScreenStates$remoteparkassistcoremeb_release",
        "()Ljava/util/Set;",
        "Ls71/p;",
        "supportedUserActions",
        "getSupportedUserActions$remoteparkassistcoremeb_release",
        "Ln71/d;",
        "observing",
        "Ln71/d;",
        "Ls71/h;",
        "value",
        "activeParkingManeuver",
        "Ls71/h;",
        "getActiveParkingManeuver",
        "()Ls71/h;",
        "setActiveParkingManeuver$remoteparkassistcoremeb_release",
        "(Ls71/h;)V",
        "isTargetPositionReached",
        "Z",
        "()Z",
        "setTargetPositionReached$remoteparkassistcoremeb_release",
        "(Z)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;",
        "error",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;",
        "getError",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;",
        "setError",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V",
        "isSafeLockActive",
        "setSafeLockActive",
        "isChargerUnlocking",
        "setChargerUnlocking",
        "isSunroofAvailable",
        "setSunroofAvailable",
        "isEngineTurnedOff",
        "Ljava/lang/Boolean;",
        "()Ljava/lang/Boolean;",
        "setEngineTurnedOff",
        "(Ljava/lang/Boolean;)V",
        "Lz71/f;",
        "doorsAndFlapsStatus",
        "Lz71/f;",
        "getDoorsAndFlapsStatus",
        "()Lz71/f;",
        "setDoorsAndFlapsStatus",
        "(Lz71/f;)V",
        "isHandbrakeActive",
        "setHandbrakeActive",
        "isHavingOpenWindows",
        "setHavingOpenWindows",
        "isCloseWindowsEnabled",
        "setCloseWindowsEnabled",
        "isClosingWindows",
        "setClosingWindows",
        "isAwaitingFinished",
        "setAwaitingFinished",
        "isParkingFinishedWithoutWarnings",
        "setParkingFinishedWithoutWarnings",
        "isParkingProcessActive",
        "setParkingProcessActive",
        "isParkingProcessActive$annotations",
        "hasUserTakenOverVehicle",
        "getHasUserTakenOverVehicle",
        "setHasUserTakenOverVehicle",
        "isClosingWindowsSupported",
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
.field private activeParkingManeuver:Ls71/h;

.field private doorsAndFlapsStatus:Lz71/f;

.field private error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

.field private hasUserTakenOverVehicle:Z

.field private isAwaitingFinished:Z

.field private isChargerUnlocking:Z

.field private isCloseWindowsEnabled:Z

.field private isClosingWindows:Z

.field private isEngineTurnedOff:Ljava/lang/Boolean;

.field private isHandbrakeActive:Ljava/lang/Boolean;

.field private isHavingOpenWindows:Ljava/lang/Boolean;

.field private isParkingFinishedWithoutWarnings:Z

.field private isParkingProcessActive:Z

.field private isSafeLockActive:Z

.field private isSunroofAvailable:Z

.field private isTargetPositionReached:Z

.field private final observing:Ln71/d;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ln71/d;"
        }
    .end annotation
.end field

.field private final representingScreen:Ls71/l;

.field private final supportedScreenStates:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lhy0/d;",
            ">;"
        }
    .end annotation
.end field

.field private final supportedUserActions:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ls71/p;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ll71/w;)V
    .locals 5

    .line 1
    const-string v0, "dependencies"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1}, Le81/x;-><init>(Ll71/w;)V

    .line 7
    .line 8
    .line 9
    sget-object v0, Ls71/l;->j:Ls71/l;

    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->representingScreen:Ls71/l;

    .line 12
    .line 13
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 28
    .line 29
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const/4 v3, 0x3

    .line 34
    new-array v3, v3, [Lhy0/d;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    aput-object v1, v3, v4

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    aput-object v2, v3, v1

    .line 41
    .line 42
    const/4 v2, 0x2

    .line 43
    aput-object v0, v3, v2

    .line 44
    .line 45
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 50
    .line 51
    sget-object v0, Ls71/p;->y:Ls71/p;

    .line 52
    .line 53
    sget-object v2, Ls71/p;->z:Ls71/p;

    .line 54
    .line 55
    sget-object v3, Ls71/p;->A:Ls71/p;

    .line 56
    .line 57
    filled-new-array {v0, v2, v3}, [Ls71/p;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 66
    .line 67
    new-instance v0, Ln71/d;

    .line 68
    .line 69
    iget-object p1, p1, Ll71/w;->a:Ln71/a;

    .line 70
    .line 71
    invoke-direct {v0, p1}, Ln71/d;-><init>(Ln71/a;)V

    .line 72
    .line 73
    .line 74
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 75
    .line 76
    sget-object p1, Ls71/h;->d:Ls71/h;

    .line 77
    .line 78
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->activeParkingManeuver:Ls71/h;

    .line 79
    .line 80
    sget-object p1, Lz71/f;->d:Lz71/f;

    .line 81
    .line 82
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->doorsAndFlapsStatus:Lz71/f;

    .line 83
    .line 84
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingProcessActive:Z

    .line 85
    .line 86
    return-void
.end method

.method private static final _set_activeParkingManeuver_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getActiveParkingManeuver()Ls71/h;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedActiveParkingManeuverDidChange(Ls71/h;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_doorsAndFlapsStatus_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getDoorsAndFlapsStatus()Lz71/f;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedDoorsAndFlapsStatusDidChange(Lz71/f;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_hasUserTakenOverVehicle_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getHasUserTakenOverVehicle()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedHasUserTakenOverVehicleDidChange(Z)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isAwaitingFinished_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isAwaitingFinished()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsAwaitingFinishedDidChange(Z)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isChargerUnlocking_$lambda$0(ZLz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsChargerUnlockingDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isCloseWindowsEnabled_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled:Z

    .line 7
    .line 8
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsCloseWindowsEnabledDidChange(Z)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0
.end method

.method private static final _set_isClosingWindows_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isClosingWindows()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsClosingWindowsDidChange(Z)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isEngineTurnedOff_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff()Ljava/lang/Boolean;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsEngineTurnedOffDidChange(Ljava/lang/Boolean;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isHandbrakeActive_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive()Ljava/lang/Boolean;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsHandbrakeActiveDidChange(Ljava/lang/Boolean;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isHavingOpenWindows_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows()Ljava/lang/Boolean;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsHavingOpenWindowsDidChange(Ljava/lang/Boolean;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isParkingFinishedWithoutWarnings_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingFinishedWithoutWarnings()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsParkingFinishedWithoutWarningsDidChange(Z)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isParkingProcessActive_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingProcessActive()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsParkingProcessActiveDidChange(Z)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final _set_isSafeLockActive_$lambda$0(ZLz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsSafeLockActiveDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isSunroofAvailable_$lambda$0(ZLz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsSunroofAvailableDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isTargetPositionReached_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isTargetPositionReached()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsTargetPositionReachedDidChange(Z)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isParkingProcessActive_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_activeParkingManeuver_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isParkingFinishedWithoutWarnings_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isEngineTurnedOff_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isAwaitingFinished_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isClosingWindows_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isCloseWindowsEnabled_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic isParkingProcessActive$annotations()V
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic j(Lz71/g;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isChargerUnlocking_$lambda$0(ZLz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_hasUserTakenOverVehicle_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_doorsAndFlapsStatus_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic m(Lz71/g;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isSunroofAvailable_$lambda$0(ZLz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isTargetPositionReached_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic o(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic p(Lz71/g;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isSafeLockActive_$lambda$0(ZLz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic q(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isHandbrakeActive_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->_set_isHavingOpenWindows_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;Lz71/g;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private setAwaitingFinished(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isAwaitingFinished:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isAwaitingFinished:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method private setCloseWindowsEnabled(Z)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled:Z

    .line 9
    .line 10
    if-eq v0, p1, :cond_0

    .line 11
    .line 12
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled:Z

    .line 13
    .line 14
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 15
    .line 16
    new-instance v0, Le81/k;

    .line 17
    .line 18
    const/4 v1, 0x7

    .line 19
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method private setClosingWindows(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isClosingWindows:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isClosingWindows:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/16 v1, 0x8

    .line 12
    .line 13
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method private setDoorsAndFlapsStatus(Lz71/f;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->doorsAndFlapsStatus:Lz71/f;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->doorsAndFlapsStatus:Lz71/f;

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method private setEngineTurnedOff(Ljava/lang/Boolean;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff:Ljava/lang/Boolean;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff:Ljava/lang/Boolean;

    .line 10
    .line 11
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/k;

    .line 14
    .line 15
    const/16 v1, 0xa

    .line 16
    .line 17
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method private setHandbrakeActive(Ljava/lang/Boolean;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive:Ljava/lang/Boolean;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive:Ljava/lang/Boolean;

    .line 10
    .line 11
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/k;

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method private setHasUserTakenOverVehicle(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->hasUserTakenOverVehicle:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->hasUserTakenOverVehicle:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/16 v1, 0xb

    .line 12
    .line 13
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method private setHavingOpenWindows(Ljava/lang/Boolean;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows:Ljava/lang/Boolean;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows:Ljava/lang/Boolean;

    .line 10
    .line 11
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/k;

    .line 14
    .line 15
    const/4 v1, 0x5

    .line 16
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method private setParkingFinishedWithoutWarnings(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingFinishedWithoutWarnings:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingFinishedWithoutWarnings:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method private setParkingProcessActive(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingProcessActive:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingProcessActive:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/16 v1, 0x9

    .line 12
    .line 13
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method private final updateIsParkingFinishedWithoutWarnings()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getDoorsAndFlapsStatus()Lz71/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lz71/f;->g:Lz71/f;

    .line 6
    .line 7
    if-ne v0, v1, :cond_3

    .line 8
    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows()Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows()Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_3

    .line 26
    .line 27
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff()Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff()Ljava/lang/Boolean;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 38
    .line 39
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive()Ljava/lang/Boolean;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive()Ljava/lang/Boolean;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_3

    .line 62
    .line 63
    :cond_2
    const/4 v0, 0x1

    .line 64
    goto :goto_0

    .line 65
    :cond_3
    const/4 v0, 0x0

    .line 66
    :goto_0
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setParkingFinishedWithoutWarnings(Z)V

    .line 67
    .line 68
    .line 69
    return-void
.end method


# virtual methods
.method public addObserver(Lz71/g;Z)V
    .locals 1

    .line 1
    const-string v0, "parkingFinishedObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ln71/d;->a(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getActiveParkingManeuver()Ls71/h;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedActiveParkingManeuverDidChange(Ls71/h;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isTargetPositionReached()Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsTargetPositionReachedDidChange(Z)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff()Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsEngineTurnedOffDidChange(Ljava/lang/Boolean;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getDoorsAndFlapsStatus()Lz71/f;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedDoorsAndFlapsStatusDidChange(Lz71/f;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive()Ljava/lang/Boolean;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsHandbrakeActiveDidChange(Ljava/lang/Boolean;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows()Ljava/lang/Boolean;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsHavingOpenWindowsDidChange(Ljava/lang/Boolean;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isClosingWindowsSupported()Z

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsClosingWindowsSupportedDidChange(Z)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled()Z

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsCloseWindowsEnabledDidChange(Z)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isClosingWindows()Z

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsClosingWindowsDidChange(Z)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isAwaitingFinished()Z

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsAwaitingFinishedDidChange(Z)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingFinishedWithoutWarnings()Z

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsParkingFinishedWithoutWarningsDidChange(Z)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingProcessActive()Z

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsParkingProcessActiveDidChange(Z)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getHasUserTakenOverVehicle()Z

    .line 98
    .line 99
    .line 100
    move-result p2

    .line 101
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedHasUserTakenOverVehicleDidChange(Z)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSafeLockActive()Z

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsSafeLockActiveDidChange(Z)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isChargerUnlocking()Z

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    invoke-interface {p1, p2}, Lz71/g;->parkingFinishedIsChargerUnlockingDidChange(Z)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSunroofAvailable()Z

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    invoke-interface {p1, p0}, Lz71/g;->parkingFinishedIsSunroofAvailableDidChange(Z)V

    .line 130
    .line 131
    .line 132
    :cond_0
    return-void
.end method

.method public getActiveParkingManeuver()Ls71/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->activeParkingManeuver:Ls71/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDoorsAndFlapsStatus()Lz71/f;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->doorsAndFlapsStatus:Lz71/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

    .line 2
    .line 3
    return-object p0
.end method

.method public getHasUserTakenOverVehicle()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->hasUserTakenOverVehicle:Z

    .line 2
    .line 3
    return p0
.end method

.method public getRepresentingScreen()Ls71/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->representingScreen:Ls71/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSupportedScreenStates$remoteparkassistcoremeb_release()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lhy0/d;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ls71/p;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public isAwaitingFinished()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isAwaitingFinished:Z

    .line 2
    .line 3
    return p0
.end method

.method public isChargerUnlocking()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isChargerUnlocking:Z

    .line 2
    .line 3
    return p0
.end method

.method public isCloseWindowsEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isClosingWindows()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isClosingWindows:Z

    .line 2
    .line 3
    return p0
.end method

.method public isClosingWindowsSupported()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    return p0
.end method

.method public isEngineTurnedOff()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isEngineTurnedOff:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public isHandbrakeActive()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHandbrakeActive:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public isHavingOpenWindows()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isHavingOpenWindows:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public isParkingFinishedWithoutWarnings()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingFinishedWithoutWarnings:Z

    .line 2
    .line 3
    return p0
.end method

.method public isParkingProcessActive()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isParkingProcessActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public isSafeLockActive()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSafeLockActive:Z

    .line 2
    .line 3
    return p0
.end method

.method public isSunroofAvailable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSunroofAvailable:Z

    .line 2
    .line 3
    return p0
.end method

.method public isTargetPositionReached()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isTargetPositionReached:Z

    .line 2
    .line 3
    return p0
.end method

.method public onAppear()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->y:Ls71/p;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Le81/x;->onAppear()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public onStateValuesChange$remoteparkassistcoremeb_release(Ll71/x;)V
    .locals 4

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 7
    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 11
    .line 12
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 13
    .line 14
    iget-object v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 15
    .line 16
    iget-object v2, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setEngineTurnedOff(Ljava/lang/Boolean;)V

    .line 19
    .line 20
    .line 21
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    sget-object v0, Lz71/f;->e:Lz71/f;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    sget-object v0, Lz71/f;->f:Lz71/f;

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 42
    .line 43
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_2

    .line 48
    .line 49
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_2

    .line 54
    .line 55
    sget-object v0, Lz71/f;->g:Lz71/f;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    sget-object v0, Lz71/f;->d:Lz71/f;

    .line 59
    .line 60
    :goto_0
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setDoorsAndFlapsStatus(Lz71/f;)V

    .line 61
    .line 62
    .line 63
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 64
    .line 65
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHandbrakeActive(Ljava/lang/Boolean;)V

    .line 66
    .line 67
    .line 68
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->a:Ls71/h;

    .line 69
    .line 70
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setActiveParkingManeuver$remoteparkassistcoremeb_release(Ls71/h;)V

    .line 71
    .line 72
    .line 73
    iget-boolean v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 74
    .line 75
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setTargetPositionReached$remoteparkassistcoremeb_release(Z)V

    .line 76
    .line 77
    .line 78
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 81
    .line 82
    .line 83
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->updateIsParkingFinishedWithoutWarnings()V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 88
    .line 89
    if-eqz v0, :cond_7

    .line 90
    .line 91
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 92
    .line 93
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 94
    .line 95
    iget-object v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 96
    .line 97
    iget-object v2, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 98
    .line 99
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setEngineTurnedOff(Ljava/lang/Boolean;)V

    .line 100
    .line 101
    .line 102
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 103
    .line 104
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-eqz v3, :cond_4

    .line 109
    .line 110
    sget-object v0, Lz71/f;->e:Lz71/f;

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_4
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_5

    .line 118
    .line 119
    sget-object v0, Lz71/f;->f:Lz71/f;

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_5
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 123
    .line 124
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-eqz v1, :cond_6

    .line 129
    .line 130
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_6

    .line 135
    .line 136
    sget-object v0, Lz71/f;->g:Lz71/f;

    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_6
    sget-object v0, Lz71/f;->d:Lz71/f;

    .line 140
    .line 141
    :goto_1
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setDoorsAndFlapsStatus(Lz71/f;)V

    .line 142
    .line 143
    .line 144
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHandbrakeActive(Ljava/lang/Boolean;)V

    .line 147
    .line 148
    .line 149
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 152
    .line 153
    .line 154
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->a:Ls71/h;

    .line 155
    .line 156
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setActiveParkingManeuver$remoteparkassistcoremeb_release(Ls71/h;)V

    .line 157
    .line 158
    .line 159
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->b:Z

    .line 160
    .line 161
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setTargetPositionReached$remoteparkassistcoremeb_release(Z)V

    .line 162
    .line 163
    .line 164
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->updateIsParkingFinishedWithoutWarnings()V

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :cond_7
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 169
    .line 170
    if-eqz v0, :cond_c

    .line 171
    .line 172
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 173
    .line 174
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 175
    .line 176
    iget-object v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->b:Ljava/lang/Boolean;

    .line 177
    .line 178
    iget-object v2, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->a:Ljava/lang/Boolean;

    .line 179
    .line 180
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setEngineTurnedOff(Ljava/lang/Boolean;)V

    .line 181
    .line 182
    .line 183
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 184
    .line 185
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    if-eqz v3, :cond_8

    .line 190
    .line 191
    sget-object v0, Lz71/f;->e:Lz71/f;

    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_8
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v2

    .line 198
    if-eqz v2, :cond_9

    .line 199
    .line 200
    sget-object v0, Lz71/f;->f:Lz71/f;

    .line 201
    .line 202
    goto :goto_2

    .line 203
    :cond_9
    iget-boolean v2, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->h:Z

    .line 204
    .line 205
    if-eqz v2, :cond_a

    .line 206
    .line 207
    sget-object v0, Lz71/f;->d:Lz71/f;

    .line 208
    .line 209
    goto :goto_2

    .line 210
    :cond_a
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v1

    .line 216
    if-eqz v1, :cond_b

    .line 217
    .line 218
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v0

    .line 222
    if-eqz v0, :cond_b

    .line 223
    .line 224
    sget-object v0, Lz71/f;->g:Lz71/f;

    .line 225
    .line 226
    goto :goto_2

    .line 227
    :cond_b
    sget-object v0, Lz71/f;->d:Lz71/f;

    .line 228
    .line 229
    :goto_2
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setDoorsAndFlapsStatus(Lz71/f;)V

    .line 230
    .line 231
    .line 232
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 233
    .line 234
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHandbrakeActive(Ljava/lang/Boolean;)V

    .line 235
    .line 236
    .line 237
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 238
    .line 239
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 240
    .line 241
    .line 242
    iget-boolean v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->i:Z

    .line 243
    .line 244
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 245
    .line 246
    .line 247
    iget-boolean v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->l:Z

    .line 248
    .line 249
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setSafeLockActive(Z)V

    .line 250
    .line 251
    .line 252
    iget-boolean v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->j:Z

    .line 253
    .line 254
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setChargerUnlocking(Z)V

    .line 255
    .line 256
    .line 257
    iget-boolean v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->k:Z

    .line 258
    .line 259
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setSunroofAvailable(Z)V

    .line 260
    .line 261
    .line 262
    iget-object v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->f:Ls71/h;

    .line 263
    .line 264
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setActiveParkingManeuver$remoteparkassistcoremeb_release(Ls71/h;)V

    .line 265
    .line 266
    .line 267
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->g:Z

    .line 268
    .line 269
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setTargetPositionReached$remoteparkassistcoremeb_release(Z)V

    .line 270
    .line 271
    .line 272
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->updateIsParkingFinishedWithoutWarnings()V

    .line 273
    .line 274
    .line 275
    :cond_c
    return-void
.end method

.method public removeObserver(Lz71/g;)V
    .locals 1

    .line 1
    const-string v0, "parkingFinishedObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ln71/d;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setActiveParkingManeuver$remoteparkassistcoremeb_release(Ls71/h;)V
    .locals 2

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->activeParkingManeuver:Ls71/h;

    .line 7
    .line 8
    if-eq v0, p1, :cond_0

    .line 9
    .line 10
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->activeParkingManeuver:Ls71/h;

    .line 11
    .line 12
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 13
    .line 14
    new-instance v0, Le81/k;

    .line 15
    .line 16
    const/4 v1, 0x6

    .line 17
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public setChargerUnlocking(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isChargerUnlocking:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isChargerUnlocking:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0xb

    .line 12
    .line 13
    invoke-direct {v0, v1, p1}, Le81/b;-><init>(IZ)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, La2/e;

    .line 14
    .line 15
    const/16 v1, 0x1d

    .line 16
    .line 17
    invoke-direct {v0, p1, v1}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public setSafeLockActive(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSafeLockActive:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSafeLockActive:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0xa

    .line 12
    .line 13
    invoke-direct {v0, v1, p1}, Le81/b;-><init>(IZ)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public setSunroofAvailable(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSunroofAvailable:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isSunroofAvailable:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0xc

    .line 12
    .line 13
    invoke-direct {v0, v1, p1}, Le81/b;-><init>(IZ)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public setTargetPositionReached$remoteparkassistcoremeb_release(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isTargetPositionReached:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isTargetPositionReached:Z

    .line 6
    .line 7
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/k;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, p0, v1}, Le81/k;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v0}, Ln71/d;->b(Lay0/k;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public startCloseWindows()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->isCloseWindowsEnabled()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    new-instance v1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v2, "Cannot trigger startCloseWindows() - the functionality for closing windows is not enabled. isCloseWindowsEnabled = "

    .line 20
    .line 21
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {v0, p0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    sget-object v0, Ls71/p;->z:Ls71/p;

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public stopCloseWindows()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->A:Ls71/p;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public toRPAViewModel$remoteparkassistcoremeb_release()Le81/t;
    .locals 0

    .line 1
    return-object p0
.end method

.method public updateMEB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V
    .locals 3

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WaitingForFinish;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingNotPossible;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 27
    .line 28
    .line 29
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$WindowClosingPossible;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 41
    .line 42
    .line 43
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 44
    .line 45
    .line 46
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$ClosingWindows;

    .line 51
    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 55
    .line 56
    .line 57
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 58
    .line 59
    .line 60
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_3
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState$Timeout;

    .line 65
    .line 66
    if-eqz p1, :cond_4

    .line 67
    .line 68
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 69
    .line 70
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 71
    .line 72
    .line 73
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 74
    .line 75
    .line 76
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 77
    .line 78
    .line 79
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 80
    .line 81
    .line 82
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V

    .line 85
    .line 86
    .line 87
    :cond_4
    return-void
.end method

.method public updateMLB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V
    .locals 3

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingNotPossible;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 27
    .line 28
    .line 29
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 41
    .line 42
    .line 43
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 44
    .line 45
    .line 46
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$ClosingWindows;

    .line 51
    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 55
    .line 56
    .line 57
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 58
    .line 59
    .line 60
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_3
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Timeout;

    .line 65
    .line 66
    if-eqz p1, :cond_4

    .line 67
    .line 68
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 69
    .line 70
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 71
    .line 72
    .line 73
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 74
    .line 75
    .line 76
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 77
    .line 78
    .line 79
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 80
    .line 81
    .line 82
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V

    .line 85
    .line 86
    .line 87
    :cond_4
    return-void
.end method

.method public updatePPE$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;)V
    .locals 4

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 27
    .line 28
    .line 29
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 41
    .line 42
    .line 43
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 44
    .line 45
    .line 46
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$ClosingWindows;

    .line 51
    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 55
    .line 56
    .line 57
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 58
    .line 59
    .line 60
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$NotActive;

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    if-eqz v0, :cond_4

    .line 68
    .line 69
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 70
    .line 71
    .line 72
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 73
    .line 74
    .line 75
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 76
    .line 77
    .line 78
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 79
    .line 80
    .line 81
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHandbrakeActive(Ljava/lang/Boolean;)V

    .line 82
    .line 83
    .line 84
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setEngineTurnedOff(Ljava/lang/Boolean;)V

    .line 85
    .line 86
    .line 87
    sget-object p1, Lz71/f;->d:Lz71/f;

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setDoorsAndFlapsStatus(Lz71/f;)V

    .line 90
    .line 91
    .line 92
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setParkingFinishedWithoutWarnings(Z)V

    .line 93
    .line 94
    .line 95
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setParkingProcessActive(Z)V

    .line 96
    .line 97
    .line 98
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHasUserTakenOverVehicle(Z)V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    :cond_4
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Timeout;

    .line 103
    .line 104
    if-eqz p1, :cond_5

    .line 105
    .line 106
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setAwaitingFinished(Z)V

    .line 107
    .line 108
    .line 109
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setCloseWindowsEnabled(Z)V

    .line 110
    .line 111
    .line 112
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setClosingWindows(Z)V

    .line 113
    .line 114
    .line 115
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHavingOpenWindows(Ljava/lang/Boolean;)V

    .line 116
    .line 117
    .line 118
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setHandbrakeActive(Ljava/lang/Boolean;)V

    .line 119
    .line 120
    .line 121
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setEngineTurnedOff(Ljava/lang/Boolean;)V

    .line 122
    .line 123
    .line 124
    sget-object p1, Lz71/f;->d:Lz71/f;

    .line 125
    .line 126
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setDoorsAndFlapsStatus(Lz71/f;)V

    .line 127
    .line 128
    .line 129
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;

    .line 130
    .line 131
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;)V

    .line 132
    .line 133
    .line 134
    :cond_5
    return-void
.end method
