.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;
.super Le81/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le81/p;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0092\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0010\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u00012\u00020\u0002B\u0011\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J7\u0010\u0010\u001a\u00020\u000f2\u0008\u0010\u0008\u001a\u0004\u0018\u00010\u00072\u0008\u0010\n\u001a\u0004\u0018\u00010\t2\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u000b2\u0008\u0008\u0002\u0010\u000e\u001a\u00020\rH\u0002\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0017\u0010\u0017\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u0012H\u0010\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0017\u0010\u001b\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u0018H\u0010\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\u0017\u0010\u001f\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u001cH\u0010\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\u0017\u0010#\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020 H\u0010\u00a2\u0006\u0004\u0008!\u0010\"J\u000f\u0010\'\u001a\u00020$H\u0010\u00a2\u0006\u0004\u0008%\u0010&J\u000f\u0010(\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008(\u0010)J\u001f\u0010-\u001a\u00020\u00142\u0006\u0010+\u001a\u00020*2\u0006\u0010,\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008-\u0010.J\u0017\u0010/\u001a\u00020\u00142\u0006\u0010+\u001a\u00020*H\u0016\u00a2\u0006\u0004\u0008/\u00100R\u001a\u00102\u001a\u0008\u0012\u0004\u0012\u00020*018\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00082\u00103R\u001a\u00105\u001a\u0002048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00085\u00106\u001a\u0004\u00087\u00108R*\u0010:\u001a\u00020\r2\u0006\u00109\u001a\u00020\r8\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008:\u0010;\u001a\u0004\u0008:\u0010<\"\u0004\u0008=\u0010>R*\u0010?\u001a\u00020\u000f2\u0006\u00109\u001a\u00020\u000f8\u0016@VX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008?\u0010@\u001a\u0004\u0008A\u0010B\"\u0004\u0008C\u0010DR(\u0010H\u001a\u0010\u0012\u000c\u0012\n\u0012\u0006\u0008\u0001\u0012\u00020G0F0E8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008H\u0010I\u001a\u0004\u0008J\u0010KR \u0010M\u001a\u0008\u0012\u0004\u0012\u00020L0E8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008M\u0010I\u001a\u0004\u0008N\u0010K\u00a8\u0006O"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;",
        "Le81/x;",
        "Le81/p;",
        "Ll71/w;",
        "dependencies",
        "<init>",
        "(Ll71/w;)V",
        "Ls71/n;",
        "stoppingReason",
        "Ll71/c;",
        "internalTimeout",
        "Lt71/c;",
        "connectionErrorStatus",
        "",
        "carDisconnected",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;",
        "createParkingFailedError",
        "(Ls71/n;Ll71/c;Lt71/c;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;",
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
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;",
        "updateCommon$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;)V",
        "updateCommon",
        "Le81/t;",
        "toRPAViewModel$remoteparkassistcoremeb_release",
        "()Le81/t;",
        "toRPAViewModel",
        "reconnect",
        "()V",
        "Lz71/e;",
        "parkingFailedObserver",
        "notifyOnRegister",
        "addObserver",
        "(Lz71/e;Z)V",
        "removeObserver",
        "(Lz71/e;)V",
        "Ln71/d;",
        "observing",
        "Ln71/d;",
        "Ls71/l;",
        "representingScreen",
        "Ls71/l;",
        "getRepresentingScreen",
        "()Ls71/l;",
        "value",
        "isReconnectPossible",
        "Z",
        "()Z",
        "setReconnectPossible",
        "(Z)V",
        "error",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;",
        "getError",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;",
        "setError",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V",
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
.field private error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

.field private isReconnectPossible:Z

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
    new-instance v0, Ln71/d;

    .line 10
    .line 11
    iget-object p1, p1, Ll71/w;->a:Ln71/a;

    .line 12
    .line 13
    invoke-direct {v0, p1}, Ln71/d;-><init>(Ln71/a;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->observing:Ln71/d;

    .line 17
    .line 18
    sget-object p1, Ls71/l;->k:Ls71/l;

    .line 19
    .line 20
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->representingScreen:Ls71/l;

    .line 21
    .line 22
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/b;

    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/b;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MalFunction;

    .line 28
    .line 29
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 30
    .line 31
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 32
    .line 33
    const-class v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState;

    .line 34
    .line 35
    invoke-virtual {p1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState;

    .line 40
    .line 41
    invoke-virtual {p1, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 46
    .line 47
    invoke-virtual {p1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;

    .line 52
    .line 53
    invoke-virtual {p1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    const/4 v3, 0x4

    .line 58
    new-array v3, v3, [Lhy0/d;

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    aput-object v0, v3, v4

    .line 62
    .line 63
    const/4 v0, 0x1

    .line 64
    aput-object v1, v3, v0

    .line 65
    .line 66
    const/4 v0, 0x2

    .line 67
    aput-object v2, v3, v0

    .line 68
    .line 69
    const/4 v0, 0x3

    .line 70
    aput-object p1, v3, v0

    .line 71
    .line 72
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 77
    .line 78
    sget-object p1, Ls71/p;->D:Ls71/p;

    .line 79
    .line 80
    invoke-static {p1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 85
    .line 86
    return-void
.end method

.method private static final _set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;Lz71/e;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/e;->parkingFailedErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isReconnectPossible_$lambda$0(ZLz71/e;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/e;->parkingFailedIsReconnectPossibleDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;Lz71/e;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->_set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;Lz71/e;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final createParkingFailedError(Ls71/n;Ll71/c;Lt71/c;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;
    .locals 1

    .line 1
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;->Companion:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/b;

    .line 2
    .line 3
    sget-object v0, Ls71/f;->d:Ls71/f;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    if-eqz p3, :cond_0

    .line 9
    .line 10
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Connection;

    .line 11
    .line 12
    invoke-direct {p0, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Connection;-><init>(Lt71/c;)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    if-eqz p1, :cond_1

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    packed-switch p0, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :pswitch_0
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KABVokoVkmOn;

    .line 32
    .line 33
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KABVokoVkmOn;-><init>(Ls71/c;)V

    .line 36
    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KABVovoVkmOff;

    .line 40
    .line 41
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KABVovoVkmOff;-><init>(Ls71/c;)V

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_2
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationIncreasedDrivingResistance;

    .line 48
    .line 49
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationIncreasedDrivingResistance;-><init>(Ls71/c;)V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_3
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$StandbyIncreasedDrivingResistance;

    .line 56
    .line 57
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$StandbyIncreasedDrivingResistance;-><init>(Ls71/c;)V

    .line 60
    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_4
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationTSKGradient;

    .line 64
    .line 65
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationTSKGradient;-><init>(Ls71/c;)V

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_5
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$PPLossPOSOK;

    .line 72
    .line 73
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 74
    .line 75
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$PPLossPOSOK;-><init>(Ls71/c;)V

    .line 76
    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_6
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$PPErrorKeyAuthorizer;

    .line 80
    .line 81
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$PPErrorKeyAuthorizer;-><init>(Ls71/c;)V

    .line 84
    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_7
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationEscIntervention;

    .line 88
    .line 89
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 90
    .line 91
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationEscIntervention;-><init>(Ls71/c;)V

    .line 92
    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_8
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrailerDetected;

    .line 96
    .line 97
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrailerDetected;-><init>(Ls71/c;)V

    .line 100
    .line 101
    .line 102
    return-object p0

    .line 103
    :pswitch_9
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ObstacleDetected;

    .line 104
    .line 105
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 106
    .line 107
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ObstacleDetected;-><init>(Ls71/c;Ls71/f;)V

    .line 108
    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_a
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KeyOutOfRange;

    .line 112
    .line 113
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 114
    .line 115
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KeyOutOfRange;-><init>(Ls71/c;)V

    .line 116
    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_b
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ParkingSpaceTooSmall;

    .line 120
    .line 121
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ParkingSpaceTooSmall;-><init>(Ls71/c;)V

    .line 124
    .line 125
    .line 126
    return-object p0

    .line 127
    :pswitch_c
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MaxMovesReached;

    .line 128
    .line 129
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 130
    .line 131
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MaxMovesReached;-><init>(Ls71/c;)V

    .line 132
    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_d
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationByGWSM;

    .line 136
    .line 137
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 138
    .line 139
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TerminationByGWSM;-><init>(Ls71/c;)V

    .line 140
    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_e
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ShuntingAreaTooSmall;

    .line 144
    .line 145
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ShuntingAreaTooSmall;-><init>(Ls71/c;)V

    .line 148
    .line 149
    .line 150
    return-object p0

    .line 151
    :pswitch_f
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MaxDistanceReached;

    .line 152
    .line 153
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 154
    .line 155
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MaxDistanceReached;-><init>(Ls71/c;)V

    .line 156
    .line 157
    .line 158
    return-object p0

    .line 159
    :pswitch_10
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$AirSuspensionHeightNio;

    .line 160
    .line 161
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 162
    .line 163
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$AirSuspensionHeightNio;-><init>(Ls71/c;)V

    .line 164
    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_11
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$OffRoadActive;

    .line 168
    .line 169
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$OffRoadActive;-><init>(Ls71/c;)V

    .line 172
    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_12
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MultipleKeysDetected;

    .line 176
    .line 177
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 178
    .line 179
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MultipleKeysDetected;-><init>(Ls71/c;)V

    .line 180
    .line 181
    .line 182
    return-object p0

    .line 183
    :pswitch_13
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KeyInsideInterior;

    .line 184
    .line 185
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 186
    .line 187
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KeyInsideInterior;-><init>(Ls71/c;)V

    .line 188
    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_14
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$GarageDoorOpen;

    .line 192
    .line 193
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 194
    .line 195
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$GarageDoorOpen;-><init>(Ls71/c;)V

    .line 196
    .line 197
    .line 198
    return-object p0

    .line 199
    :pswitch_15
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$RouteNotTrained;

    .line 200
    .line 201
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 202
    .line 203
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$RouteNotTrained;-><init>(Ls71/c;)V

    .line 204
    .line 205
    .line 206
    return-object p0

    .line 207
    :pswitch_16
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KeySwitchOperated;

    .line 208
    .line 209
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 210
    .line 211
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$KeySwitchOperated;-><init>(Ls71/c;)V

    .line 212
    .line 213
    .line 214
    return-object p0

    .line 215
    :pswitch_17
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$CountryNotAllowed;

    .line 216
    .line 217
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 218
    .line 219
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$CountryNotAllowed;-><init>(Ls71/c;)V

    .line 220
    .line 221
    .line 222
    return-object p0

    .line 223
    :pswitch_18
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ChargeLevelLow;

    .line 224
    .line 225
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 226
    .line 227
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ChargeLevelLow;-><init>(Ls71/c;)V

    .line 228
    .line 229
    .line 230
    return-object p0

    .line 231
    :pswitch_19
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ReceptionObstructed;

    .line 232
    .line 233
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 234
    .line 235
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ReceptionObstructed;-><init>(Ls71/c;)V

    .line 236
    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_1a
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ChargingPlugPlugged;

    .line 240
    .line 241
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 242
    .line 243
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$ChargingPlugPlugged;-><init>(Ls71/c;)V

    .line 244
    .line 245
    .line 246
    return-object p0

    .line 247
    :pswitch_1b
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$NoContinuationOfTheJourney;

    .line 248
    .line 249
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 250
    .line 251
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$NoContinuationOfTheJourney;-><init>(Ls71/c;)V

    .line 252
    .line 253
    .line 254
    return-object p0

    .line 255
    :pswitch_1c
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Timeout;

    .line 256
    .line 257
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 258
    .line 259
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Timeout;-><init>(Ls71/c;)V

    .line 260
    .line 261
    .line 262
    return-object p0

    .line 263
    :pswitch_1d
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$IntrusionVehicleSystem;

    .line 264
    .line 265
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 266
    .line 267
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$IntrusionVehicleSystem;-><init>(Ls71/c;)V

    .line 268
    .line 269
    .line 270
    return-object p0

    .line 271
    :pswitch_1e
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$InteractionDetected;

    .line 272
    .line 273
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 274
    .line 275
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$InteractionDetected;-><init>(Ls71/c;)V

    .line 276
    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_1f
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;

    .line 280
    .line 281
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 282
    .line 283
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$TrafficDetected;-><init>(Ls71/c;)V

    .line 284
    .line 285
    .line 286
    return-object p0

    .line 287
    :pswitch_20
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$DoorsAndFlaps;

    .line 288
    .line 289
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 290
    .line 291
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$DoorsAndFlaps;-><init>(Ls71/c;)V

    .line 292
    .line 293
    .line 294
    return-object p0

    .line 295
    :pswitch_21
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$FunctionNotAvailable;

    .line 296
    .line 297
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 298
    .line 299
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$FunctionNotAvailable;-><init>(Ls71/c;)V

    .line 300
    .line 301
    .line 302
    return-object p0

    .line 303
    :pswitch_22
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MalFunction;

    .line 304
    .line 305
    sget-object p1, Ls71/c;->d:Ls71/c;

    .line 306
    .line 307
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MalFunction;-><init>(Ls71/c;)V

    .line 308
    .line 309
    .line 310
    return-object p0

    .line 311
    :cond_1
    sget-object p0, Ll71/c;->d:Ll71/c;

    .line 312
    .line 313
    if-ne p2, p0, :cond_2

    .line 314
    .line 315
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$InternalMotorStartTimeout;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$InternalMotorStartTimeout;

    .line 316
    .line 317
    return-object p0

    .line 318
    :cond_2
    sget-object p0, Ll71/c;->e:Ll71/c;

    .line 319
    .line 320
    if-ne p2, p0, :cond_3

    .line 321
    .line 322
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$InternalTouchDiagnosisDidTimeout;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$InternalTouchDiagnosisDidTimeout;

    .line 323
    .line 324
    return-object p0

    .line 325
    :cond_3
    if-eqz p4, :cond_4

    .line 326
    .line 327
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Timeout;

    .line 328
    .line 329
    sget-object p1, Ls71/c;->e:Ls71/c;

    .line 330
    .line 331
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Timeout;-><init>(Ls71/c;)V

    .line 332
    .line 333
    .line 334
    return-object p0

    .line 335
    :cond_4
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/b;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$MalFunction;

    .line 336
    .line 337
    return-object p0

    .line 338
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static synthetic createParkingFailedError$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;Ls71/n;Ll71/c;Lt71/c;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;
    .locals 0

    .line 1
    and-int/lit8 p5, p5, 0x8

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->createParkingFailedError(Ls71/n;Ll71/c;Lt71/c;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static synthetic d(Lz71/e;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->_set_isReconnectPossible_$lambda$0(ZLz71/e;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public addObserver(Lz71/e;Z)V
    .locals 1

    .line 1
    const-string v0, "parkingFailedObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ln71/d;->a(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-interface {p1, p2}, Lz71/e;->parkingFailedErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->isReconnectPossible()Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-interface {p1, p0}, Lz71/e;->parkingFailedIsReconnectPossibleDidChange(Z)V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRepresentingScreen()Ls71/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->representingScreen:Ls71/l;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->supportedScreenStates:Ljava/util/Set;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public isReconnectPossible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->isReconnectPossible:Z

    .line 2
    .line 3
    return p0
.end method

.method public reconnect()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->isReconnectPossible()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ls71/p;->D:Ls71/p;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 18
    .line 19
    const-string v0, "reconnect() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public removeObserver(Lz71/e;)V
    .locals 1

    .line 1
    const-string v0, "parkingFailedObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ln71/d;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V
    .locals 2

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 7
    .line 8
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 15
    .line 16
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->observing:Ln71/d;

    .line 17
    .line 18
    new-instance v0, La2/e;

    .line 19
    .line 20
    const/16 v1, 0x1c

    .line 21
    .line 22
    invoke-direct {v0, p1, v1}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void
.end method

.method public setReconnectPossible(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->isReconnectPossible:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->isReconnectPossible:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x9

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

.method public toRPAViewModel$remoteparkassistcoremeb_release()Le81/t;
    .locals 0

    .line 1
    return-object p0
.end method

.method public updateCommon$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;)V
    .locals 7

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;

    .line 11
    .line 12
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;->getConnectionErrorStatus()Lt71/c;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    const/16 v5, 0x8

    .line 17
    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v1, 0x0

    .line 20
    const/4 v2, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    move-object v0, p0

    .line 23
    invoke-static/range {v0 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->createParkingFailedError$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;Ls71/n;Ll71/c;Lt71/c;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 28
    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setReconnectPossible(Z)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    move-object v0, p0

    .line 36
    instance-of p0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithoutRetry;

    .line 37
    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithoutRetry;

    .line 41
    .line 42
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithoutRetry;->getConnectionErrorStatus()Lt71/c;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    const/16 v5, 0x8

    .line 47
    .line 48
    const/4 v6, 0x0

    .line 49
    const/4 v1, 0x0

    .line 50
    const/4 v2, 0x0

    .line 51
    const/4 v4, 0x0

    .line 52
    invoke-static/range {v0 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->createParkingFailedError$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;Ls71/n;Ll71/c;Lt71/c;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setReconnectPossible(Z)V

    .line 61
    .line 62
    .line 63
    :cond_1
    return-void
.end method

.method public updateMEB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V
    .locals 8

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;

    .line 11
    .line 12
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Llp/ed;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;)Ls71/n;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState$ParkingFailed;->getInternalTimeout()Ll71/c;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    const/16 v6, 0x8

    .line 25
    .line 26
    const/4 v7, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    move-object v1, p0

    .line 30
    invoke-static/range {v1 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->createParkingFailedError$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;Ls71/n;Ll71/c;Lt71/c;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method public updateMLB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V
    .locals 8

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;

    .line 11
    .line 12
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->getErrorState()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Lkp/o;->i(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;)Ls71/n;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState$ParkingFailed;->getInternalTimeout()Ll71/c;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    const/16 v6, 0x8

    .line 25
    .line 26
    const/4 v7, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    move-object v1, p0

    .line 30
    invoke-static/range {v1 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->createParkingFailedError$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;Ls71/n;Ll71/c;Lt71/c;ZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method public updatePPE$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;)V
    .locals 3

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;

    .line 11
    .line 12
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Lpm/a;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ls71/n;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;->getInternalTimeout()Ll71/c;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    const/4 v2, 0x0

    .line 25
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;->getCarDisconnected()Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    invoke-direct {p0, v0, v1, v2, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->createParkingFailedError(Ls71/n;Ll71/c;Lt71/c;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    return-void
.end method
