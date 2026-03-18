.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;
.super Le81/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le81/s;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0088\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u000b\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u00002\u00020\u00012\u00020\u0002B\u0011\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J!\u0010\u000c\u001a\u00020\u000b2\u0008\u0010\u0008\u001a\u0004\u0018\u00010\u00072\u0006\u0010\n\u001a\u00020\tH\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0017\u0010\u0012\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u000eH\u0010\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0017\u0010\u0016\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u0013H\u0010\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0017\u0010\u001a\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u0017H\u0010\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u0017\u0010\u001d\u001a\u00020\u000b2\u0006\u0010\u0008\u001a\u00020\u0007H\u0010\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u000f\u0010!\u001a\u00020\u001eH\u0010\u00a2\u0006\u0004\u0008\u001f\u0010 J\u001f\u0010%\u001a\u00020\u000b2\u0006\u0010#\u001a\u00020\"2\u0006\u0010$\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008%\u0010&J\u0017\u0010\'\u001a\u00020\u000b2\u0006\u0010#\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008\'\u0010(J\u000f\u0010)\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008)\u0010*J\u000f\u0010+\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008+\u0010*J\u000f\u0010,\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008,\u0010*R\u001a\u0010.\u001a\u00020-8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008.\u0010/\u001a\u0004\u00080\u00101R(\u00105\u001a\u0010\u0012\u000c\u0012\n\u0012\u0006\u0008\u0001\u0012\u00020403028\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u00085\u00106\u001a\u0004\u00087\u00108R \u0010:\u001a\u0008\u0012\u0004\u0012\u000209028\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008:\u00106\u001a\u0004\u0008;\u00108R\u0018\u0010<\u001a\u0004\u0018\u00010\u00078\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008<\u0010=R\u0016\u0010\n\u001a\u00020\t8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\n\u0010>R\u001a\u0010@\u001a\u0008\u0012\u0004\u0012\u00020\"0?8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008@\u0010AR*\u0010C\u001a\u00020\t2\u0006\u0010B\u001a\u00020\t8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008C\u0010>\u001a\u0004\u0008C\u0010D\"\u0004\u0008E\u0010FR*\u0010G\u001a\u00020\t2\u0006\u0010B\u001a\u00020\t8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008G\u0010>\u001a\u0004\u0008G\u0010D\"\u0004\u0008H\u0010FR*\u0010I\u001a\u00020\t2\u0006\u0010B\u001a\u00020\t8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008I\u0010>\u001a\u0004\u0008I\u0010D\"\u0004\u0008J\u0010FR*\u0010L\u001a\u00020K2\u0006\u0010B\u001a\u00020K8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008L\u0010M\u001a\u0004\u0008N\u0010O\"\u0004\u0008P\u0010QR.\u0010S\u001a\u0004\u0018\u00010R2\u0008\u0010B\u001a\u0004\u0018\u00010R8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008S\u0010T\u001a\u0004\u0008U\u0010V\"\u0004\u0008W\u0010X\u00a8\u0006Y"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;",
        "Le81/x;",
        "Le81/s;",
        "Ll71/w;",
        "dependencies",
        "<init>",
        "(Ll71/w;)V",
        "Ll71/x;",
        "values",
        "",
        "multiTouchDetected",
        "Llx0/b0;",
        "updateRPAError",
        "(Ll71/x;Z)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;",
        "newState",
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
        "onStateValuesChange$remoteparkassistcoremeb_release",
        "(Ll71/x;)V",
        "onStateValuesChange",
        "Le81/t;",
        "toRPAViewModel$remoteparkassistcoremeb_release",
        "()Le81/t;",
        "toRPAViewModel",
        "Lz71/j;",
        "touchDiagnosisObserver",
        "notifyOnRegister",
        "addObserver",
        "(Lz71/j;Z)V",
        "removeObserver",
        "(Lz71/j;)V",
        "startUnlock",
        "()V",
        "cancelUnlock",
        "finishUnlock",
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
        "latestStateValues",
        "Ll71/x;",
        "Z",
        "Ln71/d;",
        "observing",
        "Ln71/d;",
        "value",
        "isUnlockTouchThresholdExceeded",
        "()Z",
        "setUnlockTouchThresholdExceeded",
        "(Z)V",
        "isUnlockActionInProgress",
        "setUnlockActionInProgress",
        "isUnlockActionEnabled",
        "setUnlockActionEnabled",
        "Ls71/h;",
        "parkingManeuverStatus",
        "Ls71/h;",
        "getParkingManeuverStatus",
        "()Ls71/h;",
        "setParkingManeuverStatus",
        "(Ls71/h;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "error",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "getError",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "setError",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V",
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
.field private error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field private isUnlockActionEnabled:Z

.field private isUnlockActionInProgress:Z

.field private isUnlockTouchThresholdExceeded:Z

.field private latestStateValues:Ll71/x;

.field private multiTouchDetected:Z

.field private final observing:Ln71/d;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ln71/d;"
        }
    .end annotation
.end field

.field private parkingManeuverStatus:Ls71/h;

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
    sget-object v0, Ls71/l;->e:Ls71/l;

    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->representingScreen:Ls71/l;

    .line 12
    .line 13
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState;

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

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
    const/4 v1, 0x2

    .line 43
    aput-object v0, v3, v1

    .line 44
    .line 45
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 50
    .line 51
    sget-object v0, Ls71/p;->g:Ls71/p;

    .line 52
    .line 53
    sget-object v1, Ls71/p;->h:Ls71/p;

    .line 54
    .line 55
    sget-object v2, Ls71/p;->i:Ls71/p;

    .line 56
    .line 57
    filled-new-array {v0, v1, v2}, [Ls71/p;

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
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->supportedUserActions:Ljava/util/Set;

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
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 75
    .line 76
    sget-object p1, Ls71/h;->d:Ls71/h;

    .line 77
    .line 78
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 79
    .line 80
    return-void
.end method

.method private static final _set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/j;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/j;->touchDiagnosisErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isUnlockActionEnabled_$lambda$0(ZLz71/j;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/j;->touchDiagnosisIsUnlockActionEnabledDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isUnlockActionInProgress_$lambda$0(ZLz71/j;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/j;->touchDiagnosisIsUnlockActionInProgressDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isUnlockTouchThresholdExceeded_$lambda$0(ZLz71/j;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/j;->touchDiagnosisIsUnlockTouchThresholdExceeded(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_parkingManeuverStatus_$lambda$0(Ls71/h;Lz71/j;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/j;->touchDiagnosisParkingManeuverStatusDidChange(Ls71/h;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic c(Ls71/h;Lz71/j;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->_set_parkingManeuverStatus_$lambda$0(Ls71/h;Lz71/j;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lz71/j;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->_set_isUnlockTouchThresholdExceeded_$lambda$0(ZLz71/j;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/j;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->_set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/j;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Lz71/j;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->_set_isUnlockActionInProgress_$lambda$0(ZLz71/j;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Lz71/j;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->_set_isUnlockActionEnabled_$lambda$0(ZLz71/j;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/d;

    .line 14
    .line 15
    const/4 v1, 0x4

    .line 16
    invoke-direct {v0, p1, v1}, Le81/d;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method private setParkingManeuverStatus(Ls71/h;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/c;

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    invoke-direct {v0, p1, v1}, Le81/c;-><init>(Ls71/h;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ln71/d;->b(Lay0/k;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method private setUnlockActionEnabled(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionEnabled:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionEnabled:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x12

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

.method private setUnlockActionInProgress(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionInProgress:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionInProgress:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x13

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

.method private setUnlockTouchThresholdExceeded(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockTouchThresholdExceeded:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockTouchThresholdExceeded:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x14

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

.method private final updateRPAError(Ll71/x;Z)V
    .locals 7

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x1b

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v0, p1

    .line 10
    move v3, p2

    .line 11
    invoke-static/range {v0 .. v6}, Ll71/x;->b(Ll71/x;ZLjava/lang/Boolean;ZZLjava/lang/Boolean;I)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p1, 0x0

    .line 17
    :goto_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public addObserver(Lz71/j;Z)V
    .locals 1

    .line 1
    const-string v0, "touchDiagnosisObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ln71/d;->a(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockTouchThresholdExceeded()Z

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    invoke-interface {p1, p2}, Lz71/j;->touchDiagnosisIsUnlockTouchThresholdExceeded(Z)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionInProgress()Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-interface {p1, p2}, Lz71/j;->touchDiagnosisIsUnlockActionInProgressDidChange(Z)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionEnabled()Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    invoke-interface {p1, p2}, Lz71/j;->touchDiagnosisIsUnlockActionEnabledDidChange(Z)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    invoke-interface {p1, p2}, Lz71/j;->touchDiagnosisErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->getParkingManeuverStatus()Ls71/h;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-interface {p1, p0}, Lz71/j;->touchDiagnosisParkingManeuverStatusDidChange(Ls71/h;)V

    .line 46
    .line 47
    .line 48
    :cond_0
    return-void
.end method

.method public cancelUnlock()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->i:Ls71/p;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public finishUnlock()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ls71/p;->h:Ls71/p;

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
    const-string v0, "finishUnlock() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParkingManeuverStatus()Ls71/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRepresentingScreen()Ls71/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->representingScreen:Ls71/l;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->supportedScreenStates:Ljava/util/Set;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public isUnlockActionEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isUnlockActionInProgress()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionInProgress:Z

    .line 2
    .line 3
    return p0
.end method

.method public isUnlockTouchThresholdExceeded()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockTouchThresholdExceeded:Z

    .line 2
    .line 3
    return p0
.end method

.method public onStateValuesChange$remoteparkassistcoremeb_release(Ll71/x;)V
    .locals 5

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    const/4 v2, 0x2

    .line 10
    const/4 v3, 0x1

    .line 11
    const-string v4, "<this>"

    .line 12
    .line 13
    if-eqz v0, :cond_3

    .line 14
    .line 15
    move-object v0, p1

    .line 16
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 17
    .line 18
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 19
    .line 20
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sget-object v4, Lk81/b;->a:[I

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    aget v0, v4, v0

    .line 30
    .line 31
    if-eq v0, v3, :cond_2

    .line 32
    .line 33
    if-eq v0, v2, :cond_1

    .line 34
    .line 35
    if-ne v0, v1, :cond_0

    .line 36
    .line 37
    sget-object v0, Ls71/h;->f:Ls71/h;

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance p0, La8/r0;

    .line 41
    .line 42
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :cond_1
    sget-object v0, Ls71/h;->e:Ls71/h;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    sget-object v0, Ls71/h;->d:Ls71/h;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 53
    .line 54
    if-eqz v0, :cond_7

    .line 55
    .line 56
    move-object v0, p1

    .line 57
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 58
    .line 59
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 60
    .line 61
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    sget-object v4, Lr81/b;->a:[I

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    aget v0, v4, v0

    .line 71
    .line 72
    if-eq v0, v3, :cond_6

    .line 73
    .line 74
    if-eq v0, v2, :cond_5

    .line 75
    .line 76
    if-ne v0, v1, :cond_4

    .line 77
    .line 78
    sget-object v0, Ls71/h;->f:Ls71/h;

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_4
    new-instance p0, La8/r0;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_5
    sget-object v0, Ls71/h;->e:Ls71/h;

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_6
    sget-object v0, Ls71/h;->d:Ls71/h;

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_7
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 94
    .line 95
    if-eqz v0, :cond_8

    .line 96
    .line 97
    move-object v0, p1

    .line 98
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 99
    .line 100
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->g:Ls71/h;

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_8
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->getParkingManeuverStatus()Ls71/h;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    :goto_0
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setParkingManeuverStatus(Ls71/h;)V

    .line 108
    .line 109
    .line 110
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->latestStateValues:Ll71/x;

    .line 111
    .line 112
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 113
    .line 114
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->updateRPAError(Ll71/x;Z)V

    .line 115
    .line 116
    .line 117
    return-void
.end method

.method public removeObserver(Lz71/j;)V
    .locals 1

    .line 1
    const-string v0, "touchDiagnosisObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ln71/d;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public startUnlock()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->isUnlockActionEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ls71/p;->g:Ls71/p;

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
    const-string v0, "startUnlock() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$LockedByDefault;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-nez v0, :cond_5

    .line 11
    .line 12
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$LockedByCar;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgress;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 25
    .line 26
    .line 27
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 28
    .line 29
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 30
    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgressThresholdReached;

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 38
    .line 39
    .line 40
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 41
    .line 42
    .line 43
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 44
    .line 45
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;

    .line 50
    .line 51
    if-nez v0, :cond_4

    .line 52
    .line 53
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$WaitingForNewFunctionState;

    .line 54
    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_3
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;

    .line 59
    .line 60
    if-eqz p1, :cond_6

    .line 61
    .line 62
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 66
    .line 67
    .line 68
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 69
    .line 70
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_4
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 75
    .line 76
    .line 77
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 78
    .line 79
    .line 80
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 81
    .line 82
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_5
    :goto_1
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 87
    .line 88
    .line 89
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 90
    .line 91
    .line 92
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 93
    .line 94
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 95
    .line 96
    .line 97
    :cond_6
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->latestStateValues:Ll71/x;

    .line 98
    .line 99
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 100
    .line 101
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->updateRPAError(Ll71/x;Z)V

    .line 102
    .line 103
    .line 104
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByDefault;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-nez v0, :cond_5

    .line 11
    .line 12
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$LockedByCar;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgress;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 25
    .line 26
    .line 27
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 28
    .line 29
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 30
    .line 31
    .line 32
    goto :goto_2

    .line 33
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockInProgressThresholdReached;

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 38
    .line 39
    .line 40
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 41
    .line 42
    .line 43
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 44
    .line 45
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;

    .line 50
    .line 51
    if-nez v0, :cond_4

    .line 52
    .line 53
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState$WaitingForNewFunctionState;

    .line 54
    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_3
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;

    .line 59
    .line 60
    if-eqz p1, :cond_6

    .line 61
    .line 62
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 66
    .line 67
    .line 68
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 69
    .line 70
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_4
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 75
    .line 76
    .line 77
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 78
    .line 79
    .line 80
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 81
    .line 82
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_5
    :goto_1
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 87
    .line 88
    .line 89
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 90
    .line 91
    .line 92
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 93
    .line 94
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 95
    .line 96
    .line 97
    :cond_6
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->latestStateValues:Ll71/x;

    .line 98
    .line 99
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 100
    .line 101
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->updateRPAError(Ll71/x;Z)V

    .line 102
    .line 103
    .line 104
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByDefault;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 15
    .line 16
    .line 17
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 18
    .line 19
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 20
    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;

    .line 24
    .line 25
    const/4 v2, 0x1

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 29
    .line 30
    .line 31
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 32
    .line 33
    .line 34
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 35
    .line 36
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgress;

    .line 41
    .line 42
    if-eqz v0, :cond_2

    .line 43
    .line 44
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 45
    .line 46
    .line 47
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 48
    .line 49
    .line 50
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 51
    .line 52
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgressThresholdReached;

    .line 57
    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 61
    .line 62
    .line 63
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 64
    .line 65
    .line 66
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 67
    .line 68
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;

    .line 73
    .line 74
    if-nez v0, :cond_5

    .line 75
    .line 76
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$WaitingForNewFunctionState;

    .line 77
    .line 78
    if-eqz v0, :cond_4

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_4
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 82
    .line 83
    if-eqz p1, :cond_6

    .line 84
    .line 85
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 86
    .line 87
    .line 88
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 89
    .line 90
    .line 91
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 92
    .line 93
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    :goto_0
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionInProgress(Z)V

    .line 98
    .line 99
    .line 100
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockActionEnabled(Z)V

    .line 101
    .line 102
    .line 103
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 104
    .line 105
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->setUnlockTouchThresholdExceeded(Z)V

    .line 106
    .line 107
    .line 108
    :cond_6
    :goto_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->latestStateValues:Ll71/x;

    .line 109
    .line 110
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->multiTouchDetected:Z

    .line 111
    .line 112
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->updateRPAError(Ll71/x;Z)V

    .line 113
    .line 114
    .line 115
    return-void
.end method
