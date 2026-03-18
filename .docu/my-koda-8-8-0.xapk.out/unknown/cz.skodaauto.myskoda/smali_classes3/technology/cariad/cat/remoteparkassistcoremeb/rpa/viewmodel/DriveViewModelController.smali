.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;
.super Le81/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le81/m;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00c8\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u000f\u0018\u00002\u00020\u00012\u00020\u0002B\u0019\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0017\u0010\u000e\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\tH\u0010\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0017\u0010\u0012\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\u000fH\u0010\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0017\u0010\u0016\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\u0013H\u0010\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0017\u0010\u001b\u001a\u00020\u000b2\u0006\u0010\u0018\u001a\u00020\u0017H\u0010\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\u000f\u0010\u001f\u001a\u00020\u001cH\u0010\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\u001f\u0010$\u001a\u00020\u000b2\u0006\u0010!\u001a\u00020 2\u0006\u0010#\u001a\u00020\"H\u0016\u00a2\u0006\u0004\u0008$\u0010%J\u0017\u0010&\u001a\u00020\u000b2\u0006\u0010!\u001a\u00020 H\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u000f\u0010(\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008(\u0010)J\u000f\u0010*\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008*\u0010)J\u000f\u0010+\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008+\u0010)J\u000f\u0010,\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008,\u0010)J\u000f\u0010-\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008-\u0010)J\u000f\u0010.\u001a\u00020\u000bH\u0002\u00a2\u0006\u0004\u0008.\u0010)J1\u00102\u001a\u00020\u000b2\u0008\u0010\u0018\u001a\u0004\u0018\u00010\u00172\u0006\u0010/\u001a\u00020\"2\u0006\u00100\u001a\u00020\"2\u0006\u00101\u001a\u00020\"H\u0002\u00a2\u0006\u0004\u00082\u00103J\u000f\u00104\u001a\u00020\u000bH\u0002\u00a2\u0006\u0004\u00084\u0010)J\u0017\u00107\u001a\u0004\u0018\u000106*\u0004\u0018\u000105H\u0002\u00a2\u0006\u0004\u00087\u00108J\u0017\u00107\u001a\u0004\u0018\u000106*\u0004\u0018\u000109H\u0002\u00a2\u0006\u0004\u00087\u0010:R\u001a\u0010<\u001a\u00020;8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008<\u0010=\u001a\u0004\u0008>\u0010?R(\u0010C\u001a\u0010\u0012\u000c\u0012\n\u0012\u0006\u0008\u0001\u0012\u00020B0A0@8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008C\u0010D\u001a\u0004\u0008E\u0010FR \u0010H\u001a\u0008\u0012\u0004\u0012\u00020G0@8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008H\u0010D\u001a\u0004\u0008I\u0010FR\u0018\u0010J\u001a\u0004\u0018\u00010\u00178\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008J\u0010KR\u0016\u00100\u001a\u00020\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00080\u0010LR\u0016\u0010M\u001a\u00020\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008M\u0010LR\u0016\u0010O\u001a\u00020N8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008O\u0010PR\u0014\u0010R\u001a\u00020Q8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008R\u0010SR\u0014\u0010U\u001a\u00020T8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008U\u0010VR\u0016\u00101\u001a\u00020\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00081\u0010LR\u001a\u0010X\u001a\u0008\u0012\u0004\u0012\u00020 0W8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008X\u0010YR*\u0010\\\u001a\u00020Z2\u0006\u0010[\u001a\u00020Z8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\\\u0010]\u001a\u0004\u0008^\u0010_\"\u0004\u0008`\u0010aR*\u0010b\u001a\u00020\"2\u0006\u0010[\u001a\u00020\"8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008b\u0010L\u001a\u0004\u0008b\u0010c\"\u0004\u0008d\u0010eR*\u0010f\u001a\u00020\"2\u0006\u0010[\u001a\u00020\"8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008f\u0010L\u001a\u0004\u0008f\u0010c\"\u0004\u0008g\u0010eR*\u0010h\u001a\u00020\"2\u0006\u0010[\u001a\u00020\"8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008h\u0010L\u001a\u0004\u0008h\u0010c\"\u0004\u0008i\u0010eR.\u0010k\u001a\u0004\u0018\u00010j2\u0008\u0010[\u001a\u0004\u0018\u00010j8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008k\u0010l\u001a\u0004\u0008m\u0010n\"\u0004\u0008o\u0010pR*\u0010r\u001a\u00020q2\u0006\u0010[\u001a\u00020q8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008r\u0010s\u001a\u0004\u0008t\u0010u\"\u0004\u0008v\u0010wR*\u0010y\u001a\u00020x2\u0006\u0010[\u001a\u00020x8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008y\u0010z\u001a\u0004\u0008{\u0010|\"\u0004\u0008}\u0010~R3\u0010\u007f\u001a\u0004\u0018\u0001062\u0008\u0010[\u001a\u0004\u0018\u0001068\u0016@RX\u0096\u000e\u00a2\u0006\u0017\n\u0005\u0008\u007f\u0010\u0080\u0001\u001a\u0006\u0008\u0081\u0001\u0010\u0082\u0001\"\u0006\u0008\u0083\u0001\u0010\u0084\u0001R.\u0010\u0085\u0001\u001a\u00020\"2\u0006\u0010[\u001a\u00020\"8\u0016@RX\u0096\u000e\u00a2\u0006\u0015\n\u0005\u0008\u0085\u0001\u0010L\u001a\u0005\u0008\u0085\u0001\u0010c\"\u0005\u0008\u0086\u0001\u0010e\u00a8\u0006\u0087\u0001"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;",
        "Le81/x;",
        "Le81/m;",
        "Ll71/w;",
        "dependencies",
        "Ll71/z;",
        "trajectoryConfig",
        "<init>",
        "(Ll71/w;Ll71/z;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;",
        "newState",
        "Llx0/b0;",
        "updatePPE$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;)V",
        "updatePPE",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;",
        "updateMLB$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V",
        "updateMLB",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;",
        "updateMEB$remoteparkassistcoremeb_release",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V",
        "updateMEB",
        "Ll71/x;",
        "values",
        "onStateValuesChange$remoteparkassistcoremeb_release",
        "(Ll71/x;)V",
        "onStateValuesChange",
        "Le81/t;",
        "toRPAViewModel$remoteparkassistcoremeb_release",
        "()Le81/t;",
        "toRPAViewModel",
        "Lz71/d;",
        "driveObserver",
        "",
        "notifyOnRegister",
        "addObserver",
        "(Lz71/d;Z)V",
        "removeObserver",
        "(Lz71/d;)V",
        "startParking",
        "()V",
        "stopParking",
        "startUndoing",
        "stopUndoing",
        "stopEngine",
        "triggerStopEngineIfNecessary",
        "isUndoingNotPossibleInterruption",
        "multiTouchDetected",
        "holdKeyInterruption",
        "updateRPAError",
        "(Ll71/x;ZZZ)V",
        "updateIsUndoActionPossible",
        "Lq81/b;",
        "Lv71/b;",
        "toTrajectoryData",
        "(Lq81/b;)Lv71/b;",
        "Lx81/b;",
        "(Lx81/b;)Lv71/b;",
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
        "hasUndoingNotPossibleInterruption",
        "Ls71/j;",
        "parkingSideStatus",
        "Ls71/j;",
        "Lq81/a;",
        "trajectoryBuilderMLB",
        "Lq81/a;",
        "Lx81/a;",
        "trajectoryBuilderPPE",
        "Lx81/a;",
        "Ln71/d;",
        "observing",
        "Ln71/d;",
        "Lt71/d;",
        "value",
        "driveMovementStatus",
        "Lt71/d;",
        "getDriveMovementStatus",
        "()Lt71/d;",
        "setDriveMovementStatus",
        "(Lt71/d;)V",
        "isUndoActionPossible",
        "()Z",
        "setUndoActionPossible",
        "(Z)V",
        "isParkActionPossible",
        "setParkActionPossible",
        "isInTargetPosition",
        "setInTargetPosition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "error",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "getError",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "setError",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V",
        "Ls71/h;",
        "parkingManeuverStatus",
        "Ls71/h;",
        "getParkingManeuverStatus",
        "()Ls71/h;",
        "setParkingManeuverStatus",
        "(Ls71/h;)V",
        "Ls71/k;",
        "currentScenario",
        "Ls71/k;",
        "getCurrentScenario",
        "()Ls71/k;",
        "setCurrentScenario",
        "(Ls71/k;)V",
        "vehicleTrajectory",
        "Lv71/b;",
        "getVehicleTrajectory",
        "()Lv71/b;",
        "setVehicleTrajectory",
        "(Lv71/b;)V",
        "isUndoActionSupported",
        "setUndoActionSupported",
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
.field private currentScenario:Ls71/k;

.field private driveMovementStatus:Lt71/d;

.field private error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field private hasUndoingNotPossibleInterruption:Z

.field private holdKeyInterruption:Z

.field private isInTargetPosition:Z

.field private isParkActionPossible:Z

.field private isUndoActionPossible:Z

.field private isUndoActionSupported:Z

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

.field private parkingSideStatus:Ls71/j;

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

.field private final trajectoryBuilderMLB:Lq81/a;

.field private final trajectoryBuilderPPE:Lx81/a;

.field private vehicleTrajectory:Lv71/b;


# direct methods
.method public constructor <init>(Ll71/w;Ll71/z;)V
    .locals 5

    .line 1
    const-string v0, "dependencies"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "trajectoryConfig"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1}, Le81/x;-><init>(Ll71/w;)V

    .line 12
    .line 13
    .line 14
    sget-object v0, Ls71/l;->g:Ls71/l;

    .line 15
    .line 16
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->representingScreen:Ls71/l;

    .line 17
    .line 18
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 19
    .line 20
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState;

    .line 27
    .line 28
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;

    .line 33
    .line 34
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    const/4 v3, 0x3

    .line 39
    new-array v3, v3, [Lhy0/d;

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    aput-object v1, v3, v4

    .line 43
    .line 44
    const/4 v1, 0x1

    .line 45
    aput-object v2, v3, v1

    .line 46
    .line 47
    const/4 v1, 0x2

    .line 48
    aput-object v0, v3, v1

    .line 49
    .line 50
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 55
    .line 56
    sget-object v0, Ls71/p;->w:Ls71/p;

    .line 57
    .line 58
    sget-object v1, Ls71/p;->x:Ls71/p;

    .line 59
    .line 60
    sget-object v2, Ls71/p;->u:Ls71/p;

    .line 61
    .line 62
    sget-object v3, Ls71/p;->v:Ls71/p;

    .line 63
    .line 64
    sget-object v4, Ls71/p;->e:Ls71/p;

    .line 65
    .line 66
    filled-new-array {v0, v1, v2, v3, v4}, [Ls71/p;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 75
    .line 76
    sget-object v0, Ls71/j;->d:Ls71/j;

    .line 77
    .line 78
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingSideStatus:Ls71/j;

    .line 79
    .line 80
    new-instance v0, Lq81/a;

    .line 81
    .line 82
    invoke-direct {v0, p2}, Lq81/a;-><init>(Ll71/z;)V

    .line 83
    .line 84
    .line 85
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->trajectoryBuilderMLB:Lq81/a;

    .line 86
    .line 87
    new-instance v0, Lx81/a;

    .line 88
    .line 89
    invoke-direct {v0, p2}, Lx81/a;-><init>(Ll71/z;)V

    .line 90
    .line 91
    .line 92
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->trajectoryBuilderPPE:Lx81/a;

    .line 93
    .line 94
    new-instance p2, Ln71/d;

    .line 95
    .line 96
    iget-object p1, p1, Ll71/w;->a:Ln71/a;

    .line 97
    .line 98
    invoke-direct {p2, p1}, Ln71/d;-><init>(Ln71/a;)V

    .line 99
    .line 100
    .line 101
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 102
    .line 103
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 104
    .line 105
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->driveMovementStatus:Lt71/d;

    .line 106
    .line 107
    sget-object p1, Ls71/h;->d:Ls71/h;

    .line 108
    .line 109
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 110
    .line 111
    sget-object p1, Ls71/k;->e:Ls71/k;

    .line 112
    .line 113
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->currentScenario:Ls71/k;

    .line 114
    .line 115
    return-void
.end method

.method private static final _set_currentScenario_$lambda$0(Ls71/k;Lz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveCurrentScenarioDidChange(Ls71/k;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_driveMovementStatus_$lambda$0(Lt71/d;Lz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveMovementStatusDidChange(Lt71/d;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isInTargetPosition_$lambda$0(ZLz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveIsInTargetPositionDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isParkActionPossible_$lambda$0(ZLz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveIsParkActionPossibleDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isUndoActionPossible_$lambda$0(ZLz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveIsUndoActionPossibleDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isUndoActionSupported_$lambda$0(ZLz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveIsUndoActionSupportedDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_parkingManeuverStatus_$lambda$0(Ls71/h;Lz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveParkingManeuverStatusDidChange(Ls71/h;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_vehicleTrajectory_$lambda$0(Lv71/b;Lz71/d;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/d;->driveVehicleTrajectoryDidChange(Lv71/b;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic c(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->onStateValuesChange$lambda$0$0(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->onStateValuesChange$lambda$1$0(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lz71/d;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_isUndoActionSupported_$lambda$0(ZLz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Lt71/d;Lz71/d;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_driveMovementStatus_$lambda$0(Lt71/d;Lz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Lv71/b;Lz71/d;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_vehicleTrajectory_$lambda$0(Lv71/b;Lz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/d;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i(Ls71/k;Lz71/d;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_currentScenario_$lambda$0(Ls71/k;Lz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->onStateValuesChange$lambda$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->onStateValuesChange$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Ls71/h;Lz71/d;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_parkingManeuverStatus_$lambda$0(Ls71/h;Lz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic m(Lz71/d;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_isParkActionPossible_$lambda$0(ZLz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n(Lz71/d;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_isUndoActionPossible_$lambda$0(ZLz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic o(Lz71/d;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->_set_isInTargetPosition_$lambda$0(ZLz71/d;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onStateValuesChange$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;)Llx0/b0;
    .locals 3

    .line 1
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 2
    .line 3
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->j:Lq81/b;

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->toTrajectoryData(Lq81/b;)Lv71/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 14
    .line 15
    new-instance v1, Le81/j;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v1, p1, p0, v2}, Le81/j;-><init>(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;I)V

    .line 19
    .line 20
    .line 21
    const-wide/16 p0, 0x0

    .line 22
    .line 23
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method

.method private static final onStateValuesChange$lambda$0$0(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;)Llx0/b0;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setVehicleTrajectory(Lv71/b;)V

    .line 4
    .line 5
    .line 6
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final onStateValuesChange$lambda$1(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;)Llx0/b0;
    .locals 3

    .line 1
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 2
    .line 3
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->i:Lx81/b;

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->toTrajectoryData(Lx81/b;)Lv71/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 14
    .line 15
    new-instance v1, Le81/j;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-direct {v1, p1, p0, v2}, Le81/j;-><init>(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;I)V

    .line 19
    .line 20
    .line 21
    const-wide/16 p0, 0x0

    .line 22
    .line 23
    invoke-interface {v0, p0, p1, v1}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method

.method private static final onStateValuesChange$lambda$1$0(Lv71/b;Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;)Llx0/b0;
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setVehicleTrajectory(Lv71/b;)V

    .line 4
    .line 5
    .line 6
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private setCurrentScenario(Ls71/k;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->currentScenario:Ls71/k;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->currentScenario:Ls71/k;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/h;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {v0, p1, v1}, Le81/h;-><init>(Ls71/k;I)V

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

.method private setDriveMovementStatus(Lt71/d;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->driveMovementStatus:Lt71/d;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->driveMovementStatus:Lt71/d;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, p1, v1}, Le81/g;-><init>(Lt71/d;I)V

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

.method private setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/d;

    .line 14
    .line 15
    const/4 v1, 0x2

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

.method private setInTargetPosition(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isInTargetPosition:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isInTargetPosition:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/4 v1, 0x7

    .line 12
    invoke-direct {v0, v1, p1}, Le81/b;-><init>(IZ)V

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

.method private setParkActionPossible(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isParkActionPossible:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isParkActionPossible:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/4 v1, 0x5

    .line 12
    invoke-direct {v0, v1, p1}, Le81/b;-><init>(IZ)V

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

.method private setParkingManeuverStatus(Ls71/h;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/c;

    .line 10
    .line 11
    const/4 v1, 0x2

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

.method private setUndoActionPossible(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionPossible:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionPossible:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/4 v1, 0x6

    .line 12
    invoke-direct {v0, v1, p1}, Le81/b;-><init>(IZ)V

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

.method private setUndoActionSupported(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionSupported:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionSupported:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x8

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

.method private setVehicleTrajectory(Lv71/b;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->vehicleTrajectory:Lv71/b;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->vehicleTrajectory:Lv71/b;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/f;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, p1, v1}, Le81/f;-><init>(Lv71/b;I)V

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

.method private final toTrajectoryData(Lq81/b;)Lv71/b;
    .locals 27

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const/4 v2, 0x0

    if-eqz v1, :cond_22

    .line 1
    iget-object v6, v1, Lq81/b;->c:Ls71/o;

    .line 2
    iget-object v13, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->trajectoryBuilderMLB:Lq81/a;

    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getDriveMovementStatus()Lt71/d;

    move-result-object v9

    .line 4
    iget-object v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingSideStatus:Ls71/j;

    sget-object v4, Ls71/j;->g:Ls71/j;

    const/4 v14, 0x1

    if-ne v3, v4, :cond_0

    move v3, v14

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    .line 5
    :goto_0
    iget-object v11, v13, Lq81/a;->b:Leb/j0;

    .line 6
    iget-object v8, v1, Lq81/b;->e:Ljava/util/List;

    iget-object v7, v1, Lq81/b;->d:Lw71/b;

    const-string v4, "driveMovementStatus"

    invoke-static {v9, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    iput-object v2, v13, Lq81/a;->c:Lv71/b;

    .line 8
    iget-object v4, v13, Lq81/a;->d:Lb6/f;

    .line 9
    sget-object v5, Lt71/d;->f:Lt71/d;

    if-ne v9, v5, :cond_1

    move v5, v14

    goto :goto_1

    :cond_1
    const/4 v5, 0x0

    .line 10
    :goto_1
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    iget-object v12, v4, Lb6/f;->e:Ljava/lang/Object;

    check-cast v12, Lq81/b;

    if-eqz v12, :cond_2

    .line 12
    iget-object v12, v12, Lq81/b;->e:Ljava/util/List;

    goto :goto_2

    :cond_2
    move-object v12, v2

    .line 13
    :goto_2
    invoke-static {v12, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    .line 14
    iget-object v15, v4, Lb6/f;->e:Ljava/lang/Object;

    check-cast v15, Lq81/b;

    .line 15
    invoke-virtual {v1, v15}, Lq81/b;->equals(Ljava/lang/Object;)Z

    move-result v15

    if-nez v15, :cond_1a

    if-eqz v3, :cond_3

    move-object/from16 v20, v6

    move-object/from16 v17, v11

    goto/16 :goto_d

    .line 16
    :cond_3
    iget v3, v1, Lq81/b;->a:I

    .line 17
    iget-object v15, v4, Lb6/f;->e:Ljava/lang/Object;

    check-cast v15, Lq81/b;

    move-object/from16 v16, v2

    if-eqz v15, :cond_4

    .line 18
    iget-object v2, v15, Lq81/b;->c:Ls71/o;

    :cond_4
    if-eq v6, v2, :cond_5

    if-nez v5, :cond_5

    move v2, v14

    goto :goto_3

    :cond_5
    const/4 v2, 0x0

    .line 19
    :goto_3
    iget-boolean v5, v4, Lb6/f;->d:Z

    if-nez v5, :cond_6

    if-eqz v2, :cond_6

    .line 20
    iput-boolean v14, v4, Lb6/f;->d:Z

    .line 21
    :cond_6
    iget-boolean v2, v4, Lb6/f;->d:Z

    move-object/from16 v17, v11

    const-wide/16 v10, 0x0

    if-eqz v2, :cond_15

    if-nez v15, :cond_9

    if-eqz v3, :cond_f

    .line 22
    move-object v2, v8

    check-cast v2, Ljava/lang/Iterable;

    .line 23
    instance-of v3, v2, Ljava/util/Collection;

    if-eqz v3, :cond_7

    move-object v3, v2

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_7

    goto/16 :goto_7

    .line 24
    :cond_7
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_11

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lw71/c;

    .line 25
    new-instance v5, Lw71/c;

    invoke-direct {v5, v10, v11, v10, v11}, Lw71/c;-><init>(DD)V

    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_8

    goto :goto_5

    :cond_9
    if-nez v3, :cond_a

    .line 26
    iget v2, v15, Lq81/b;->a:I

    if-nez v2, :cond_a

    goto :goto_5

    :cond_a
    const/4 v2, 0x0

    :goto_4
    if-ge v2, v3, :cond_11

    .line 27
    invoke-interface {v8, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lw71/c;

    .line 28
    iget-object v14, v15, Lq81/b;->e:Ljava/util/List;

    .line 29
    invoke-static {v2, v14}, Llp/bd;->f(ILjava/util/List;)Lw71/c;

    move-result-object v14

    if-nez v14, :cond_b

    new-instance v14, Lw71/c;

    .line 30
    invoke-direct {v14, v10, v11, v10, v11}, Lw71/c;-><init>(DD)V

    :cond_b
    move-wide/from16 v18, v10

    .line 31
    iget-object v10, v15, Lq81/b;->d:Lw71/b;

    .line 32
    sget-object v11, Ls71/o;->d:Ls71/o;

    if-ne v6, v11, :cond_c

    if-eqz v2, :cond_d

    .line 33
    :cond_c
    sget-object v11, Ls71/o;->e:Ls71/o;

    if-ne v6, v11, :cond_e

    add-int/lit8 v11, v3, -0x1

    if-ne v2, v11, :cond_e

    .line 34
    :cond_d
    iget-object v10, v10, Lw71/b;->a:Lw71/c;

    .line 35
    invoke-static {v5, v10}, Lw71/d;->d(Lw71/c;Lw71/c;)Z

    move-result v5

    if-nez v5, :cond_13

    goto :goto_5

    .line 36
    :cond_e
    invoke-static {v5, v14}, Lw71/d;->d(Lw71/c;Lw71/c;)Z

    move-result v5

    if-eqz v5, :cond_13

    .line 37
    :cond_f
    :goto_5
    iget-object v2, v4, Lb6/f;->e:Ljava/lang/Object;

    check-cast v2, Lq81/b;

    if-eqz v2, :cond_10

    .line 38
    iget-object v2, v2, Lq81/b;->d:Lw71/b;

    goto :goto_6

    :cond_10
    move-object/from16 v2, v16

    .line 39
    :goto_6
    invoke-virtual {v7, v2}, Lw71/b;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_12

    :cond_11
    :goto_7
    const/4 v2, 0x0

    goto :goto_8

    :cond_12
    move-object/from16 v20, v6

    goto/16 :goto_e

    :cond_13
    add-int/lit8 v2, v2, 0x1

    move-wide/from16 v10, v18

    const/4 v14, 0x1

    goto :goto_4

    .line 40
    :goto_8
    iput-boolean v2, v4, Lb6/f;->d:Z

    :cond_14
    :goto_9
    move-object/from16 v20, v6

    goto/16 :goto_d

    :cond_15
    move-wide/from16 v18, v10

    const/4 v2, 0x0

    const/4 v5, 0x2

    if-gt v3, v5, :cond_16

    :goto_a
    goto :goto_9

    :cond_16
    sub-int/2addr v3, v5

    .line 41
    invoke-static {v2, v3}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v3

    .line 42
    instance-of v10, v3, Ljava/util/Collection;

    if-eqz v10, :cond_17

    move-object v10, v3

    check-cast v10, Ljava/util/Collection;

    invoke-interface {v10}, Ljava/util/Collection;->isEmpty()Z

    move-result v10

    if-eqz v10, :cond_17

    goto :goto_a

    .line 43
    :cond_17
    invoke-virtual {v3}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_b
    move-object v10, v3

    check-cast v10, Lgy0/i;

    .line 44
    iget-boolean v10, v10, Lgy0/i;->f:Z

    if-eqz v10, :cond_14

    .line 45
    move-object v10, v3

    check-cast v10, Lmx0/w;

    invoke-virtual {v10}, Lmx0/w;->nextInt()I

    move-result v10

    .line 46
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Lw71/c;

    add-int/lit8 v14, v10, 0x1

    .line 47
    invoke-interface {v8, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Lw71/c;

    add-int/2addr v10, v5

    .line 48
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Lw71/c;

    move-object v15, v3

    .line 49
    iget-wide v2, v14, Lw71/c;->a:D

    move-object/from16 v20, v6

    iget-wide v5, v11, Lw71/c;->a:D

    sub-double v5, v2, v5

    move-wide/from16 v21, v2

    .line 50
    iget-wide v2, v14, Lw71/c;->b:D

    move-wide/from16 v23, v2

    iget-wide v2, v11, Lw71/c;->b:D

    sub-double v2, v23, v2

    move-wide/from16 v25, v2

    .line 51
    iget-wide v2, v10, Lw71/c;->a:D

    sub-double v2, v2, v21

    .line 52
    iget-wide v10, v10, Lw71/c;->b:D

    sub-double v10, v10, v23

    mul-double v21, v5, v2

    mul-double v23, v25, v10

    add-double v23, v23, v21

    mul-double/2addr v5, v5

    mul-double v21, v25, v25

    add-double v21, v21, v5

    .line 53
    invoke-static/range {v21 .. v22}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v5

    mul-double/2addr v2, v2

    mul-double/2addr v10, v10

    add-double/2addr v10, v2

    invoke-static {v10, v11}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v2

    mul-double/2addr v2, v5

    cmpg-double v5, v2, v18

    if-nez v5, :cond_18

    const-wide v2, 0x7fefffffffffffffL    # Double.MAX_VALUE

    goto :goto_c

    :cond_18
    div-double v23, v23, v2

    .line 54
    invoke-static/range {v23 .. v24}, Ljava/lang/Math;->acos(D)D

    move-result-wide v2

    const/16 v5, 0xb4

    int-to-double v5, v5

    mul-double/2addr v2, v5

    const-wide v5, 0x400921fb54442d18L    # Math.PI

    div-double/2addr v2, v5

    .line 55
    :goto_c
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(D)D

    move-result-wide v2

    const-wide/high16 v5, 0x4049000000000000L    # 50.0

    cmpl-double v2, v2, v5

    if-ltz v2, :cond_19

    goto :goto_e

    :cond_19
    move-object v3, v15

    move-object/from16 v6, v20

    const/4 v2, 0x0

    const/4 v5, 0x2

    goto/16 :goto_b

    :goto_d
    const/4 v2, 0x1

    goto :goto_f

    :cond_1a
    move-object/from16 v20, v6

    move-object/from16 v17, v11

    :goto_e
    const/4 v2, 0x0

    :goto_f
    if-eqz v2, :cond_1b

    .line 56
    iput-object v1, v4, Lb6/f;->e:Ljava/lang/Object;

    :cond_1b
    if-eqz v2, :cond_21

    .line 57
    sget-object v2, Lt71/d;->f:Lt71/d;

    if-ne v9, v2, :cond_1c

    :goto_10
    const/4 v3, 0x0

    goto :goto_11

    .line 58
    :cond_1c
    sget-object v3, Lt71/d;->g:Lt71/d;

    if-ne v9, v3, :cond_1d

    iget-boolean v3, v13, Lq81/a;->e:Z

    if-eqz v3, :cond_1d

    goto :goto_10

    :cond_1d
    const/4 v3, 0x1

    .line 59
    :goto_11
    iget-boolean v4, v1, Lq81/b;->b:Z

    if-eqz v4, :cond_1e

    if-eqz v3, :cond_1e

    const/4 v5, 0x1

    goto :goto_12

    :cond_1e
    const/4 v5, 0x0

    .line 60
    :goto_12
    iget v4, v1, Lq81/b;->a:I

    .line 61
    new-instance v3, Lq81/b;

    move-object/from16 v6, v20

    invoke-direct/range {v3 .. v8}, Lq81/b;-><init>(IZLs71/o;Lw71/b;Ljava/util/List;)V

    if-eqz v12, :cond_1f

    .line 62
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 v1, v17

    .line 63
    invoke-virtual {v1, v3}, Leb/j0;->n(Lv71/h;)Lv71/b;

    move-result-object v1

    goto :goto_14

    :cond_1f
    move-object/from16 v1, v17

    if-ne v9, v2, :cond_20

    const/4 v10, 0x1

    goto :goto_13

    :cond_20
    const/4 v10, 0x0

    .line 64
    :goto_13
    iput-boolean v10, v13, Lq81/a;->e:Z

    .line 65
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    iput-object v2, v1, Leb/j0;->e:Ljava/lang/Object;

    .line 66
    iput-object v2, v1, Leb/j0;->f:Ljava/lang/Object;

    .line 67
    invoke-virtual {v3}, Lq81/b;->b()Ls71/o;

    move-result-object v2

    iput-object v2, v1, Leb/j0;->g:Ljava/lang/Object;

    .line 68
    invoke-virtual {v1, v3}, Leb/j0;->n(Lv71/h;)Lv71/b;

    move-result-object v1

    goto :goto_14

    :cond_21
    move-object/from16 v6, v20

    .line 69
    new-instance v1, Lv71/f;

    .line 70
    iget-object v4, v7, Lw71/b;->a:Lw71/c;

    .line 71
    iget-wide v9, v7, Lw71/b;->b:D

    .line 72
    iget-object v2, v13, Lq81/a;->a:Ll71/z;

    .line 73
    iget-object v2, v2, Ll71/z;->b:Lv71/e;

    .line 74
    invoke-direct {v1, v4, v9, v10, v2}, Lv71/f;-><init>(Lw71/c;DLv71/e;)V

    .line 75
    iget-object v2, v1, Lv71/f;->e:Lv71/g;

    iget-object v3, v2, Lv71/g;->a:Lw71/c;

    iget-object v5, v1, Lv71/f;->d:Lv71/g;

    iget-object v7, v5, Lv71/g;->a:Lw71/c;

    .line 76
    filled-new-array {v3, v7}, [Lw71/c;

    move-result-object v3

    invoke-static {v3}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    .line 77
    iget-object v2, v2, Lv71/g;->b:Lw71/c;

    iget-object v5, v5, Lv71/g;->b:Lw71/c;

    .line 78
    filled-new-array {v2, v5}, [Lw71/c;

    move-result-object v2

    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    .line 79
    new-instance v5, Lv71/b;

    .line 80
    invoke-static {v3, v2}, Llp/bb;->a(Ljava/util/List;Ljava/util/List;)Lv71/c;

    move-result-object v6

    .line 81
    new-instance v11, Lv71/d;

    invoke-direct {v11, v3, v2}, Lv71/d;-><init>(Ljava/util/List;Ljava/util/List;)V

    const/4 v12, 0x1

    .line 82
    iget-object v1, v1, Lv71/f;->g:Lw71/c;

    const/4 v7, 0x0

    move-object v3, v5

    move-object/from16 v8, v20

    move-object v5, v1

    invoke-direct/range {v3 .. v12}, Lv71/b;-><init>(Lw71/c;Lw71/c;Lv71/c;Lv71/a;Ls71/o;DLv71/d;Z)V

    move-object v1, v3

    .line 83
    :goto_14
    iput-object v1, v13, Lq81/a;->c:Lv71/b;

    const/4 v2, 0x1

    .line 84
    invoke-static {v1, v2}, Lv71/b;->a(Lv71/b;Z)Lv71/b;

    move-result-object v1

    iput-object v1, v13, Lq81/a;->c:Lv71/b;

    .line 85
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->trajectoryBuilderMLB:Lq81/a;

    .line 86
    iget-object v0, v0, Lq81/a;->c:Lv71/b;

    return-object v0

    :cond_22
    move-object/from16 v16, v2

    return-object v16
.end method

.method private final toTrajectoryData(Lx81/b;)Lv71/b;
    .locals 13

    if-eqz p1, :cond_8

    .line 87
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->trajectoryBuilderPPE:Lx81/a;

    .line 88
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getParkingManeuverStatus()Ls71/h;

    move-result-object v1

    .line 89
    const-string v2, "<this>"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    sget-object v2, Ls71/h;->g:Ls71/h;

    sget-object v3, Ls71/h;->h:Ls71/h;

    filled-new-array {v2, v3}, [Ls71/h;

    move-result-object v2

    .line 91
    invoke-static {v2}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v2

    .line 92
    invoke-interface {v2, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v1

    .line 93
    iget-object v2, v0, Lx81/a;->a:Leb/j0;

    .line 94
    iget-object v3, v0, Lx81/a;->c:Ljava/lang/Integer;

    .line 95
    iget v4, p1, Lx81/b;->e:I

    const/4 v5, 0x0

    if-nez v3, :cond_0

    goto :goto_0

    .line 96
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    move-result v3

    if-ne v3, v4, :cond_1

    const/4 v3, 0x1

    goto :goto_1

    :cond_1
    :goto_0
    move v3, v5

    :goto_1
    if-nez v3, :cond_3

    .line 97
    iget-object v6, v0, Lx81/a;->b:Lv71/b;

    if-eqz v6, :cond_2

    new-instance v7, Lw71/b;

    .line 98
    iget-object v8, v6, Lv71/b;->a:Lw71/c;

    .line 99
    iget-wide v9, v6, Lv71/b;->f:D

    .line 100
    invoke-direct {v7, v8, v9, v10}, Lw71/b;-><init>(Lw71/c;D)V

    iput-object v7, v0, Lx81/a;->d:Lw71/b;

    .line 101
    :cond_2
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    iput-object v4, v0, Lx81/a;->c:Ljava/lang/Integer;

    :cond_3
    if-eqz v1, :cond_4

    goto :goto_3

    .line 102
    :cond_4
    iget-object v1, v0, Lx81/a;->d:Lw71/b;

    if-eqz v1, :cond_6

    .line 103
    iget-object v4, p1, Lx81/b;->d:Lw71/b;

    .line 104
    invoke-static {v4, v1}, Llp/ad;->f(Lw71/b;Lw71/b;)Lw71/b;

    move-result-object v10

    .line 105
    iget-object v4, p1, Lx81/b;->f:Ljava/util/ArrayList;

    .line 106
    new-instance v12, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v12, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 107
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_5

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    .line 108
    check-cast v6, Lw71/b;

    .line 109
    invoke-static {v6, v1}, Llp/ad;->f(Lw71/b;Lw71/b;)Lw71/b;

    move-result-object v6

    .line 110
    invoke-virtual {v12, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    .line 111
    :cond_5
    iget v11, p1, Lx81/b;->e:I

    .line 112
    iget v7, p1, Lx81/b;->a:I

    .line 113
    iget-boolean v8, p1, Lx81/b;->b:Z

    .line 114
    iget-object v9, p1, Lx81/b;->c:Ls71/o;

    .line 115
    new-instance v6, Lx81/b;

    invoke-direct/range {v6 .. v12}, Lx81/b;-><init>(IZLs71/o;Lw71/b;ILjava/util/ArrayList;)V

    move-object p1, v6

    :cond_6
    :goto_3
    if-eqz v3, :cond_7

    .line 116
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    invoke-virtual {v2, p1}, Leb/j0;->n(Lv71/h;)Lv71/b;

    move-result-object p1

    goto :goto_4

    .line 118
    :cond_7
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    iput-object v1, v2, Leb/j0;->e:Ljava/lang/Object;

    .line 119
    iput-object v1, v2, Leb/j0;->f:Ljava/lang/Object;

    .line 120
    invoke-virtual {p1}, Lx81/b;->b()Ls71/o;

    move-result-object v1

    iput-object v1, v2, Leb/j0;->g:Ljava/lang/Object;

    .line 121
    invoke-virtual {v2, p1}, Leb/j0;->n(Lv71/h;)Lv71/b;

    move-result-object p1

    .line 122
    :goto_4
    iput-object p1, v0, Lx81/a;->b:Lv71/b;

    .line 123
    invoke-static {p1, v5}, Lv71/b;->a(Lv71/b;Z)Lv71/b;

    move-result-object p1

    iput-object p1, v0, Lx81/a;->b:Lv71/b;

    .line 124
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->trajectoryBuilderPPE:Lx81/a;

    .line 125
    iget-object p0, p0, Lx81/a;->b:Lv71/b;

    return-object p0

    :cond_8
    const/4 p0, 0x0

    return-object p0
.end method

.method private final triggerStopEngineIfNecessary()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isInTargetPosition()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionPossible()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionSupported()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    :cond_0
    sget-object v0, Ls71/p;->e:Ls71/p;

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 22
    .line 23
    .line 24
    :cond_1
    return-void
.end method

.method private final updateIsUndoActionPossible()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->latestStateValues:Ll71/x;

    .line 2
    .line 3
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    move-object v2, v0

    .line 13
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 14
    .line 15
    :cond_0
    if-eqz v2, :cond_5

    .line 16
    .line 17
    iget-boolean v0, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->e:Z

    .line 18
    .line 19
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_1
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 24
    .line 25
    if-eqz v1, :cond_3

    .line 26
    .line 27
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 28
    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    move-object v2, v0

    .line 32
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 33
    .line 34
    :cond_2
    if-eqz v2, :cond_5

    .line 35
    .line 36
    iget-boolean v0, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->f:Z

    .line 37
    .line 38
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_3
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 43
    .line 44
    if-eqz v1, :cond_5

    .line 45
    .line 46
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 47
    .line 48
    if-eqz v1, :cond_4

    .line 49
    .line 50
    move-object v2, v0

    .line 51
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 52
    .line 53
    :cond_4
    if-eqz v2, :cond_5

    .line 54
    .line 55
    iget-boolean v0, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->e:Z

    .line 56
    .line 57
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 58
    .line 59
    .line 60
    :cond_5
    return-void
.end method

.method private final updateRPAError(Ll71/x;ZZZ)V
    .locals 7

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x12

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    move-object v0, p1

    .line 8
    move v1, p2

    .line 9
    move v3, p3

    .line 10
    move v4, p4

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
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public addObserver(Lz71/d;Z)V
    .locals 1

    .line 1
    const-string v0, "driveObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ln71/d;->a(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getDriveMovementStatus()Lt71/d;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-interface {p1, p2}, Lz71/d;->driveMovementStatusDidChange(Lt71/d;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isParkActionPossible()Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-interface {p1, p2}, Lz71/d;->driveIsParkActionPossibleDidChange(Z)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionPossible()Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    invoke-interface {p1, p2}, Lz71/d;->driveIsUndoActionPossibleDidChange(Z)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isInTargetPosition()Z

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    invoke-interface {p1, p2}, Lz71/d;->driveIsInTargetPositionDidChange(Z)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-interface {p1, p2}, Lz71/d;->driveErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getParkingManeuverStatus()Ls71/h;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    invoke-interface {p1, p2}, Lz71/d;->driveParkingManeuverStatusDidChange(Ls71/h;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getCurrentScenario()Ls71/k;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    invoke-interface {p1, p2}, Lz71/d;->driveCurrentScenarioDidChange(Ls71/k;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->getVehicleTrajectory()Lv71/b;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-interface {p1, p2}, Lz71/d;->driveVehicleTrajectoryDidChange(Lv71/b;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionSupported()Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    invoke-interface {p1, p0}, Lz71/d;->driveIsUndoActionSupportedDidChange(Z)V

    .line 74
    .line 75
    .line 76
    :cond_0
    return-void
.end method

.method public getCurrentScenario()Ls71/k;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->currentScenario:Ls71/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDriveMovementStatus()Lt71/d;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->driveMovementStatus:Lt71/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParkingManeuverStatus()Ls71/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRepresentingScreen()Ls71/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->representingScreen:Ls71/l;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->supportedScreenStates:Ljava/util/Set;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVehicleTrajectory()Lv71/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->vehicleTrajectory:Lv71/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public isInTargetPosition()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isInTargetPosition:Z

    .line 2
    .line 3
    return p0
.end method

.method public isParkActionPossible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isParkActionPossible:Z

    .line 2
    .line 3
    return p0
.end method

.method public isUndoActionPossible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionPossible:Z

    .line 2
    .line 3
    return p0
.end method

.method public isUndoActionSupported()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionSupported:Z

    .line 2
    .line 3
    return p0
.end method

.method public onStateValuesChange$remoteparkassistcoremeb_release(Ll71/x;)V
    .locals 9

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
    const-string v3, "<this>"

    .line 11
    .line 12
    const/4 v4, 0x1

    .line 13
    if-eqz v0, :cond_3

    .line 14
    .line 15
    move-object v0, p1

    .line 16
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 17
    .line 18
    iget-object v5, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 19
    .line 20
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sget-object v3, Lk81/b;->a:[I

    .line 24
    .line 25
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    aget v3, v3, v5

    .line 30
    .line 31
    if-eq v3, v4, :cond_2

    .line 32
    .line 33
    if-eq v3, v2, :cond_1

    .line 34
    .line 35
    if-ne v3, v1, :cond_0

    .line 36
    .line 37
    sget-object v1, Ls71/h;->f:Ls71/h;

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
    sget-object v1, Ls71/h;->e:Ls71/h;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    sget-object v1, Ls71/h;->d:Ls71/h;

    .line 50
    .line 51
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkingManeuverStatus(Ls71/h;)V

    .line 52
    .line 53
    .line 54
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->i:Ls71/k;

    .line 55
    .line 56
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 57
    .line 58
    .line 59
    iget-boolean v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->e:Z

    .line 60
    .line 61
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 62
    .line 63
    .line 64
    invoke-direct {p0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionSupported(Z)V

    .line 65
    .line 66
    .line 67
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->triggerStopEngineIfNecessary()V

    .line 68
    .line 69
    .line 70
    goto/16 :goto_2

    .line 71
    .line 72
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 73
    .line 74
    const-wide/16 v5, 0x0

    .line 75
    .line 76
    const/4 v7, 0x0

    .line 77
    if-eqz v0, :cond_7

    .line 78
    .line 79
    move-object v0, p1

    .line 80
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 81
    .line 82
    iget-object v8, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 83
    .line 84
    invoke-static {v8, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    sget-object v3, Lr81/b;->a:[I

    .line 88
    .line 89
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 90
    .line 91
    .line 92
    move-result v8

    .line 93
    aget v3, v3, v8

    .line 94
    .line 95
    if-eq v3, v4, :cond_6

    .line 96
    .line 97
    if-eq v3, v2, :cond_5

    .line 98
    .line 99
    if-ne v3, v1, :cond_4

    .line 100
    .line 101
    sget-object v1, Ls71/h;->f:Ls71/h;

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_4
    new-instance p0, La8/r0;

    .line 105
    .line 106
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :cond_5
    sget-object v1, Ls71/h;->e:Ls71/h;

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_6
    sget-object v1, Ls71/h;->d:Ls71/h;

    .line 114
    .line 115
    :goto_1
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkingManeuverStatus(Ls71/h;)V

    .line 116
    .line 117
    .line 118
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->m:Ls71/k;

    .line 119
    .line 120
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 121
    .line 122
    .line 123
    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->f:Z

    .line 124
    .line 125
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    iget-object v1, v1, Ll71/w;->a:Ln71/a;

    .line 133
    .line 134
    new-instance v2, Le81/i;

    .line 135
    .line 136
    const/4 v3, 0x1

    .line 137
    invoke-direct {v2, p0, p1, v3}, Le81/i;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;I)V

    .line 138
    .line 139
    .line 140
    invoke-interface {v1, v5, v6, v2}, Ln71/a;->dispatchToIOThread(JLay0/a;)Ln71/b;

    .line 141
    .line 142
    .line 143
    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->k:Z

    .line 144
    .line 145
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionSupported(Z)V

    .line 146
    .line 147
    .line 148
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->l:Ls71/j;

    .line 149
    .line 150
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->parkingSideStatus:Ls71/j;

    .line 151
    .line 152
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 153
    .line 154
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 155
    .line 156
    if-ne v0, v1, :cond_9

    .line 157
    .line 158
    iput-boolean v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_7
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 162
    .line 163
    if-eqz v0, :cond_9

    .line 164
    .line 165
    move-object v0, p1

    .line 166
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 167
    .line 168
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->g:Ls71/h;

    .line 169
    .line 170
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkingManeuverStatus(Ls71/h;)V

    .line 171
    .line 172
    .line 173
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->k:Ls71/k;

    .line 174
    .line 175
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 176
    .line 177
    .line 178
    iget-boolean v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->e:Z

    .line 179
    .line 180
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 181
    .line 182
    .line 183
    invoke-direct {p0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionSupported(Z)V

    .line 184
    .line 185
    .line 186
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 187
    .line 188
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 189
    .line 190
    if-ne v0, v1, :cond_8

    .line 191
    .line 192
    iput-boolean v7, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 193
    .line 194
    :cond_8
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    iget-object v0, v0, Ll71/w;->a:Ln71/a;

    .line 199
    .line 200
    new-instance v1, Le81/i;

    .line 201
    .line 202
    const/4 v2, 0x0

    .line 203
    invoke-direct {v1, p0, p1, v2}, Le81/i;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;Ll71/x;I)V

    .line 204
    .line 205
    .line 206
    invoke-interface {v0, v5, v6, v1}, Ln71/a;->dispatchToIOThread(JLay0/a;)Ln71/b;

    .line 207
    .line 208
    .line 209
    :cond_9
    :goto_2
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->latestStateValues:Ll71/x;

    .line 210
    .line 211
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 212
    .line 213
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 214
    .line 215
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 216
    .line 217
    invoke-direct {p0, p1, v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 218
    .line 219
    .line 220
    return-void
.end method

.method public removeObserver(Lz71/d;)V
    .locals 1

    .line 1
    const-string v0, "driveObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ln71/d;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public startParking()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isParkActionPossible()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ls71/p;->w:Ls71/p;

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
    const-string v0, "startParking() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public startUndoing()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->isUndoActionPossible()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ls71/p;->u:Ls71/p;

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
    const-string v0, "startUndoing() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public stopEngine()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->e:Ls71/p;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public stopParking()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->x:Ls71/p;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public stopUndoing()V
    .locals 1

    .line 1
    sget-object v0, Ls71/p;->v:Ls71/p;

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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 13
    .line 14
    .line 15
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 21
    .line 22
    .line 23
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 24
    .line 25
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 26
    .line 27
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 28
    .line 29
    .line 30
    goto/16 :goto_2

    .line 31
    .line 32
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$RequestedParking;

    .line 33
    .line 34
    if-nez v0, :cond_7

    .line 35
    .line 36
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;

    .line 37
    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    goto/16 :goto_1

    .line 41
    .line 42
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 47
    .line 48
    .line 49
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 52
    .line 53
    .line 54
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 55
    .line 56
    .line 57
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 58
    .line 59
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 60
    .line 61
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 62
    .line 63
    .line 64
    goto/16 :goto_2

    .line 65
    .line 66
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$RequestedUndoing;

    .line 67
    .line 68
    if-nez v0, :cond_6

    .line 69
    .line 70
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Undoing;

    .line 71
    .line 72
    if-eqz v0, :cond_3

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$PausedUndoingNotPossible;

    .line 76
    .line 77
    if-eqz v0, :cond_4

    .line 78
    .line 79
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 80
    .line 81
    .line 82
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 85
    .line 86
    .line 87
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 88
    .line 89
    .line 90
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 91
    .line 92
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 93
    .line 94
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_4
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$TargetPositionReached;

    .line 99
    .line 100
    if-eqz v0, :cond_5

    .line 101
    .line 102
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 103
    .line 104
    .line 105
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 108
    .line 109
    .line 110
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 111
    .line 112
    .line 113
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 114
    .line 115
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 116
    .line 117
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->triggerStopEngineIfNecessary()V

    .line 118
    .line 119
    .line 120
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_5
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;

    .line 125
    .line 126
    if-eqz p1, :cond_8

    .line 127
    .line 128
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 129
    .line 130
    .line 131
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 132
    .line 133
    .line 134
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 135
    .line 136
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 137
    .line 138
    .line 139
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 140
    .line 141
    .line 142
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 143
    .line 144
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_6
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 148
    .line 149
    .line 150
    sget-object p1, Lt71/d;->f:Lt71/d;

    .line 151
    .line 152
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 153
    .line 154
    .line 155
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 156
    .line 157
    .line 158
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 159
    .line 160
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 161
    .line 162
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 163
    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_7
    :goto_1
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 167
    .line 168
    .line 169
    sget-object p1, Lt71/d;->e:Lt71/d;

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 172
    .line 173
    .line 174
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setInTargetPosition(Z)V

    .line 175
    .line 176
    .line 177
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 178
    .line 179
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 180
    .line 181
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 182
    .line 183
    .line 184
    :cond_8
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->latestStateValues:Ll71/x;

    .line 185
    .line 186
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 187
    .line 188
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 189
    .line 190
    invoke-direct {p0, p1, v0, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 191
    .line 192
    .line 193
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 13
    .line 14
    .line 15
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 18
    .line 19
    .line 20
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 21
    .line 22
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 23
    .line 24
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 25
    .line 26
    sget-object p1, Lq81/a;->f:Lv71/b;

    .line 27
    .line 28
    sget-object p1, Lq81/a;->f:Lv71/b;

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setVehicleTrajectory(Lv71/b;)V

    .line 31
    .line 32
    .line 33
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_2

    .line 37
    .line 38
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$RequestedParking;

    .line 39
    .line 40
    if-nez v0, :cond_8

    .line 41
    .line 42
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$Parking;

    .line 43
    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    goto/16 :goto_1

    .line 47
    .line 48
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$PausedAndHoldKeyInterruption;

    .line 49
    .line 50
    if-eqz v0, :cond_2

    .line 51
    .line 52
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 53
    .line 54
    .line 55
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 58
    .line 59
    .line 60
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 61
    .line 62
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 63
    .line 64
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 65
    .line 66
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_2

    .line 70
    .line 71
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$Paused;

    .line 72
    .line 73
    if-eqz v0, :cond_3

    .line 74
    .line 75
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 76
    .line 77
    .line 78
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 81
    .line 82
    .line 83
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 84
    .line 85
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 86
    .line 87
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 88
    .line 89
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$RequestedUndoing;

    .line 94
    .line 95
    if-nez v0, :cond_7

    .line 96
    .line 97
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$Undoing;

    .line 98
    .line 99
    if-eqz v0, :cond_4

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_4
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$PausedUndoingNotPossible;

    .line 103
    .line 104
    if-eqz v0, :cond_5

    .line 105
    .line 106
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 107
    .line 108
    .line 109
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 112
    .line 113
    .line 114
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 115
    .line 116
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 117
    .line 118
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 119
    .line 120
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_5
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$BadConnection;

    .line 125
    .line 126
    if-eqz v0, :cond_6

    .line 127
    .line 128
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 129
    .line 130
    .line 131
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 132
    .line 133
    .line 134
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 135
    .line 136
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 137
    .line 138
    .line 139
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 140
    .line 141
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_6
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;

    .line 145
    .line 146
    if-eqz p1, :cond_9

    .line 147
    .line 148
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 149
    .line 150
    .line 151
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 152
    .line 153
    .line 154
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 155
    .line 156
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 157
    .line 158
    .line 159
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 160
    .line 161
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 162
    .line 163
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_7
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 167
    .line 168
    .line 169
    sget-object p1, Lt71/d;->f:Lt71/d;

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 172
    .line 173
    .line 174
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 175
    .line 176
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 177
    .line 178
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 179
    .line 180
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 181
    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_8
    :goto_1
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 185
    .line 186
    .line 187
    sget-object p1, Lt71/d;->e:Lt71/d;

    .line 188
    .line 189
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 190
    .line 191
    .line 192
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 193
    .line 194
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 195
    .line 196
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 197
    .line 198
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 199
    .line 200
    .line 201
    :cond_9
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->latestStateValues:Ll71/x;

    .line 202
    .line 203
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 204
    .line 205
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 206
    .line 207
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 208
    .line 209
    invoke-direct {p0, p1, v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 210
    .line 211
    .line 212
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 13
    .line 14
    .line 15
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 18
    .line 19
    .line 20
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 21
    .line 22
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 23
    .line 24
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 25
    .line 26
    sget-object p1, Lx81/a;->e:Lv71/b;

    .line 27
    .line 28
    sget-object p1, Lx81/a;->e:Lv71/b;

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setVehicleTrajectory(Lv71/b;)V

    .line 31
    .line 32
    .line 33
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_2

    .line 37
    .line 38
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$RequestedParking;

    .line 39
    .line 40
    if-nez v0, :cond_8

    .line 41
    .line 42
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;

    .line 43
    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    goto/16 :goto_1

    .line 47
    .line 48
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedAndHoldKeyInterruption;

    .line 49
    .line 50
    if-eqz v0, :cond_2

    .line 51
    .line 52
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 53
    .line 54
    .line 55
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 58
    .line 59
    .line 60
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 61
    .line 62
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 63
    .line 64
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 65
    .line 66
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_2

    .line 70
    .line 71
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;

    .line 72
    .line 73
    if-eqz v0, :cond_3

    .line 74
    .line 75
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 76
    .line 77
    .line 78
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 81
    .line 82
    .line 83
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 84
    .line 85
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 86
    .line 87
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 88
    .line 89
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$RequestedUndoing;

    .line 94
    .line 95
    if-nez v0, :cond_7

    .line 96
    .line 97
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Undoing;

    .line 98
    .line 99
    if-eqz v0, :cond_4

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_4
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;

    .line 103
    .line 104
    if-eqz v0, :cond_5

    .line 105
    .line 106
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 107
    .line 108
    .line 109
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 112
    .line 113
    .line 114
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 115
    .line 116
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 117
    .line 118
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 119
    .line 120
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_5
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$BadConnection;

    .line 125
    .line 126
    if-eqz v0, :cond_6

    .line 127
    .line 128
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 129
    .line 130
    .line 131
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 132
    .line 133
    .line 134
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 135
    .line 136
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 137
    .line 138
    .line 139
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 140
    .line 141
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_6
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 145
    .line 146
    if-eqz p1, :cond_9

    .line 147
    .line 148
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 149
    .line 150
    .line 151
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setUndoActionPossible(Z)V

    .line 152
    .line 153
    .line 154
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 155
    .line 156
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 157
    .line 158
    .line 159
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 160
    .line 161
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 162
    .line 163
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_7
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 167
    .line 168
    .line 169
    sget-object p1, Lt71/d;->f:Lt71/d;

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 172
    .line 173
    .line 174
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 175
    .line 176
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 177
    .line 178
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 179
    .line 180
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 181
    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_8
    :goto_1
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setParkActionPossible(Z)V

    .line 185
    .line 186
    .line 187
    sget-object p1, Lt71/d;->e:Lt71/d;

    .line 188
    .line 189
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 190
    .line 191
    .line 192
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 193
    .line 194
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 195
    .line 196
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 197
    .line 198
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateIsUndoActionPossible()V

    .line 199
    .line 200
    .line 201
    :cond_9
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->latestStateValues:Ll71/x;

    .line 202
    .line 203
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->hasUndoingNotPossibleInterruption:Z

    .line 204
    .line 205
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->holdKeyInterruption:Z

    .line 206
    .line 207
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->multiTouchDetected:Z

    .line 208
    .line 209
    invoke-direct {p0, p1, v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 210
    .line 211
    .line 212
    return-void
.end method
