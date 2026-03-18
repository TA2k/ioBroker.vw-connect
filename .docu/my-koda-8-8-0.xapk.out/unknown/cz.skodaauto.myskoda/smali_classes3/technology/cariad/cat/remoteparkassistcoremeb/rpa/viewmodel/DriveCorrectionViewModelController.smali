.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;
.super Le81/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le81/o;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00a0\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u000f\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u00002\u00020\u00012\u00020\u0002B\u0011\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u000c\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\u0007H\u0010\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0017\u0010\u0010\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\rH\u0010\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u0017\u0010\u0014\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\u0011H\u0010\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u0017\u0010\u0019\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u0015H\u0010\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u000f\u0010\u001d\u001a\u00020\u001aH\u0010\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u001f\u0010\"\u001a\u00020\t2\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010!\u001a\u00020 H\u0016\u00a2\u0006\u0004\u0008\"\u0010#J\u0017\u0010$\u001a\u00020\t2\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008$\u0010%J\u000f\u0010&\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u000f\u0010(\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008(\u0010\'J\u000f\u0010)\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008)\u0010\'J\u000f\u0010*\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008*\u0010\'J\u000f\u0010+\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008+\u0010\'J)\u0010.\u001a\u00020\t2\u0008\u0010\u0016\u001a\u0004\u0018\u00010\u00152\u0006\u0010,\u001a\u00020 2\u0006\u0010-\u001a\u00020 H\u0002\u00a2\u0006\u0004\u0008.\u0010/J\u0017\u00102\u001a\u00020\t2\u0006\u00101\u001a\u000200H\u0002\u00a2\u0006\u0004\u00082\u00103J\u000f\u00104\u001a\u00020\tH\u0002\u00a2\u0006\u0004\u00084\u0010\'R\u001a\u00106\u001a\u0002058\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00086\u00107\u001a\u0004\u00088\u00109R(\u0010=\u001a\u0010\u0012\u000c\u0012\n\u0012\u0006\u0008\u0001\u0012\u00020<0;0:8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008=\u0010>\u001a\u0004\u0008?\u0010@R \u0010B\u001a\u0008\u0012\u0004\u0012\u00020A0:8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008B\u0010>\u001a\u0004\u0008C\u0010@R\u0018\u0010D\u001a\u0004\u0018\u00010\u00158\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008D\u0010ER\u0016\u0010-\u001a\u00020 8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008-\u0010FR\u0016\u0010,\u001a\u00020 8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008,\u0010FR\u001a\u0010H\u001a\u0008\u0012\u0004\u0012\u00020\u001e0G8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008H\u0010IR*\u0010L\u001a\u00020J2\u0006\u0010K\u001a\u00020J8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008L\u0010M\u001a\u0004\u0008N\u0010O\"\u0004\u0008P\u0010QR*\u0010R\u001a\u00020 2\u0006\u0010K\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008R\u0010F\u001a\u0004\u0008R\u0010S\"\u0004\u0008T\u0010UR*\u0010V\u001a\u00020 2\u0006\u0010K\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008V\u0010F\u001a\u0004\u0008V\u0010S\"\u0004\u0008W\u0010UR.\u0010Y\u001a\u0004\u0018\u00010X2\u0008\u0010K\u001a\u0004\u0018\u00010X8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008Y\u0010Z\u001a\u0004\u0008[\u0010\\\"\u0004\u0008]\u0010^R*\u0010`\u001a\u00020_2\u0006\u0010K\u001a\u00020_8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008`\u0010a\u001a\u0004\u0008b\u0010c\"\u0004\u0008d\u0010eR.\u0010g\u001a\u0004\u0018\u00010f2\u0008\u0010K\u001a\u0004\u0018\u00010f8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008g\u0010h\u001a\u0004\u0008i\u0010j\"\u0004\u0008k\u0010l\u00a8\u0006m"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;",
        "Le81/x;",
        "Le81/o;",
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
        "Lz71/c;",
        "driveCorrectionObserver",
        "",
        "notifyOnRegister",
        "addObserver",
        "(Lz71/c;Z)V",
        "removeObserver",
        "(Lz71/c;)V",
        "startCorrectionMoveForward",
        "()V",
        "startCorrectionMoveBackward",
        "stopParking",
        "stopCorrectionMoveForward",
        "stopCorrectionMoveBackward",
        "holdKeyInterruption",
        "multiTouchDetected",
        "updateRPAError",
        "(Ll71/x;ZZ)V",
        "Ls71/c;",
        "interruptionResolveAction",
        "updateDriveActionsForInterruptionResolveAction",
        "(Ls71/c;)V",
        "resolveRPAError",
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
        "Lt71/d;",
        "value",
        "driveMovementStatus",
        "Lt71/d;",
        "getDriveMovementStatus",
        "()Lt71/d;",
        "setDriveMovementStatus",
        "(Lt71/d;)V",
        "isDriveForwardPossible",
        "()Z",
        "setDriveForwardPossible",
        "(Z)V",
        "isDriveBackwardPossible",
        "setDriveBackwardPossible",
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
        "Lv71/b;",
        "vehicleTrajectory",
        "Lv71/b;",
        "getVehicleTrajectory",
        "()Lv71/b;",
        "setVehicleTrajectory",
        "(Lv71/b;)V",
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
.field private driveMovementStatus:Lt71/d;

.field private error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field private holdKeyInterruption:Z

.field private isDriveBackwardPossible:Z

.field private isDriveForwardPossible:Z

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

.field private vehicleTrajectory:Lv71/b;


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
    sget-object v0, Ls71/l;->h:Ls71/l;

    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->representingScreen:Ls71/l;

    .line 12
    .line 13
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const/4 v2, 0x2

    .line 28
    new-array v2, v2, [Lhy0/d;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    aput-object v1, v2, v3

    .line 32
    .line 33
    const/4 v1, 0x1

    .line 34
    aput-object v0, v2, v1

    .line 35
    .line 36
    invoke-static {v2}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 41
    .line 42
    sget-object v0, Ls71/p;->w:Ls71/p;

    .line 43
    .line 44
    sget-object v1, Ls71/p;->u:Ls71/p;

    .line 45
    .line 46
    sget-object v2, Ls71/p;->x:Ls71/p;

    .line 47
    .line 48
    sget-object v3, Ls71/p;->v:Ls71/p;

    .line 49
    .line 50
    sget-object v4, Ls71/p;->e:Ls71/p;

    .line 51
    .line 52
    filled-new-array {v0, v1, v2, v3, v4}, [Ls71/p;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 61
    .line 62
    new-instance v0, Ln71/d;

    .line 63
    .line 64
    iget-object p1, p1, Ll71/w;->a:Ln71/a;

    .line 65
    .line 66
    invoke-direct {v0, p1}, Ln71/d;-><init>(Ln71/a;)V

    .line 67
    .line 68
    .line 69
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 70
    .line 71
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 72
    .line 73
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->driveMovementStatus:Lt71/d;

    .line 74
    .line 75
    sget-object p1, Ls71/h;->d:Ls71/h;

    .line 76
    .line 77
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 78
    .line 79
    return-void
.end method

.method private static final _set_driveMovementStatus_$lambda$0(Lt71/d;Lz71/c;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionDriveMovementStatusDidChange(Lt71/d;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/c;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isDriveBackwardPossible_$lambda$0(ZLz71/c;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionIsDriveBackwardPossibleDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isDriveForwardPossible_$lambda$0(ZLz71/c;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionIsDriveForwardPossibleDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_parkingManeuverStatus_$lambda$0(Ls71/h;Lz71/c;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionParkingManeuverStatusDidChange(Ls71/h;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_vehicleTrajectory_$lambda$0(Lv71/b;Lz71/c;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionVehicleTrajectoryDidChange(Lv71/b;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic c(Lv71/b;Lz71/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->_set_vehicleTrajectory_$lambda$0(Lv71/b;Lz71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lz71/c;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->_set_isDriveBackwardPossible_$lambda$0(ZLz71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lz71/c;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->_set_isDriveForwardPossible_$lambda$0(ZLz71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Lt71/d;Lz71/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->_set_driveMovementStatus_$lambda$0(Lt71/d;Lz71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->_set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ls71/h;Lz71/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->_set_parkingManeuverStatus_$lambda$0(Ls71/h;Lz71/c;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final resolveRPAError()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/StoppingReasonError;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/StoppingReasonError;

    .line 10
    .line 11
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/StoppingReasonError;->getType()Ls71/c;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->updateDriveActionsForInterruptionResolveAction(Ls71/c;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    const/4 v0, 0x1

    .line 20
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method private setDriveBackwardPossible(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveBackwardPossible:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveBackwardPossible:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/4 v1, 0x3

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

.method private setDriveForwardPossible(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveForwardPossible:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveForwardPossible:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/4 v1, 0x4

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

.method private setDriveMovementStatus(Lt71/d;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->driveMovementStatus:Lt71/d;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->driveMovementStatus:Lt71/d;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/g;

    .line 10
    .line 11
    const/4 v1, 0x0

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/d;

    .line 14
    .line 15
    const/4 v1, 0x1

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
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/c;

    .line 10
    .line 11
    const/4 v1, 0x1

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

.method private setVehicleTrajectory(Lv71/b;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->vehicleTrajectory:Lv71/b;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->vehicleTrajectory:Lv71/b;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/f;

    .line 14
    .line 15
    const/4 v1, 0x0

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

.method private final updateDriveActionsForInterruptionResolveAction(Ls71/c;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x1

    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    if-ne p1, v0, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, La8/r0;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method private final updateRPAError(Ll71/x;ZZ)V
    .locals 7

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x13

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    move-object v0, p1

    .line 9
    move v4, p2

    .line 10
    move v3, p3

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
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public addObserver(Lz71/c;Z)V
    .locals 1

    .line 1
    const-string v0, "driveCorrectionObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ln71/d;->a(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->getDriveMovementStatus()Lt71/d;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-interface {p1, p2}, Lz71/c;->driveCorrectionDriveMovementStatusDidChange(Lt71/d;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveForwardPossible()Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-interface {p1, p2}, Lz71/c;->driveCorrectionIsDriveForwardPossibleDidChange(Z)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveBackwardPossible()Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    invoke-interface {p1, p2}, Lz71/c;->driveCorrectionIsDriveBackwardPossibleDidChange(Z)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    invoke-interface {p1, p2}, Lz71/c;->driveCorrectionErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->getParkingManeuverStatus()Ls71/h;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-interface {p1, p2}, Lz71/c;->driveCorrectionParkingManeuverStatusDidChange(Ls71/h;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->getVehicleTrajectory()Lv71/b;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-interface {p1, p0}, Lz71/c;->driveCorrectionVehicleTrajectoryDidChange(Lv71/b;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    return-void
.end method

.method public getDriveMovementStatus()Lt71/d;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->driveMovementStatus:Lt71/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParkingManeuverStatus()Ls71/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRepresentingScreen()Ls71/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->representingScreen:Ls71/l;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->supportedScreenStates:Ljava/util/Set;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVehicleTrajectory()Lv71/b;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->vehicleTrajectory:Lv71/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public isDriveBackwardPossible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveBackwardPossible:Z

    .line 2
    .line 3
    return p0
.end method

.method public isDriveForwardPossible()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveForwardPossible:Z

    .line 2
    .line 3
    return p0
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 7
    .line 8
    if-nez v0, :cond_4

    .line 9
    .line 10
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_3

    .line 14
    .line 15
    move-object v0, p1

    .line 16
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 17
    .line 18
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 19
    .line 20
    const-string v3, "<this>"

    .line 21
    .line 22
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    sget-object v3, Lr81/b;->a:[I

    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    aget v2, v3, v2

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eq v2, v3, :cond_2

    .line 35
    .line 36
    const/4 v3, 0x2

    .line 37
    if-eq v2, v3, :cond_1

    .line 38
    .line 39
    const/4 v3, 0x3

    .line 40
    if-ne v2, v3, :cond_0

    .line 41
    .line 42
    sget-object v2, Ls71/h;->f:Ls71/h;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    new-instance p0, La8/r0;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_1
    sget-object v2, Ls71/h;->e:Ls71/h;

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    sget-object v2, Ls71/h;->d:Ls71/h;

    .line 55
    .line 56
    :goto_0
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setParkingManeuverStatus(Ls71/h;)V

    .line 57
    .line 58
    .line 59
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 60
    .line 61
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 62
    .line 63
    if-ne v0, v2, :cond_4

    .line 64
    .line 65
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 69
    .line 70
    if-eqz v0, :cond_4

    .line 71
    .line 72
    move-object v0, p1

    .line 73
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 74
    .line 75
    iget-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->g:Ls71/h;

    .line 76
    .line 77
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setParkingManeuverStatus(Ls71/h;)V

    .line 78
    .line 79
    .line 80
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 81
    .line 82
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 83
    .line 84
    if-ne v0, v2, :cond_4

    .line 85
    .line 86
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 87
    .line 88
    :cond_4
    :goto_1
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->latestStateValues:Ll71/x;

    .line 89
    .line 90
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 91
    .line 92
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 93
    .line 94
    invoke-direct {p0, p1, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->updateRPAError(Ll71/x;ZZ)V

    .line 95
    .line 96
    .line 97
    return-void
.end method

.method public removeObserver(Lz71/c;)V
    .locals 1

    .line 1
    const-string v0, "driveCorrectionObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ln71/d;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public startCorrectionMoveBackward()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveBackwardPossible()Z

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
    const-string v0, "startCorrectionMoveBackward() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public startCorrectionMoveForward()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->isDriveForwardPossible()Z

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
    const-string v0, "startCorrectionMoveForward() was called, but is currently not allowed!"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public stopCorrectionMoveBackward()V
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

.method public stopCorrectionMoveForward()V
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

.method public stopParking()V
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

.method public toRPAViewModel$remoteparkassistcoremeb_release()Le81/t;
    .locals 0

    .line 1
    return-object p0
.end method

.method public updateMEB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;)V
    .locals 0

    .line 1
    const-string p0, "newState"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 16
    .line 17
    .line 18
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 21
    .line 22
    .line 23
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 24
    .line 25
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 26
    .line 27
    sget-object p1, Lq81/a;->f:Lv71/b;

    .line 28
    .line 29
    sget-object p1, Lq81/a;->f:Lv71/b;

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setVehicleTrajectory(Lv71/b;)V

    .line 32
    .line 33
    .line 34
    goto/16 :goto_2

    .line 35
    .line 36
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingForward;

    .line 37
    .line 38
    if-nez v0, :cond_7

    .line 39
    .line 40
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingForward;

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$ParkingBackward;

    .line 46
    .line 47
    if-nez v0, :cond_6

    .line 48
    .line 49
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$RequestedParkingBackward;

    .line 50
    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedParking;

    .line 55
    .line 56
    if-eqz v0, :cond_3

    .line 57
    .line 58
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 61
    .line 62
    .line 63
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->resolveRPAError()V

    .line 64
    .line 65
    .line 66
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 67
    .line 68
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 72
    .line 73
    if-eqz v0, :cond_4

    .line 74
    .line 75
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 78
    .line 79
    .line 80
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 81
    .line 82
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->resolveRPAError()V

    .line 83
    .line 84
    .line 85
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;

    .line 89
    .line 90
    if-eqz p1, :cond_5

    .line 91
    .line 92
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 93
    .line 94
    .line 95
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 96
    .line 97
    .line 98
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 99
    .line 100
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 101
    .line 102
    .line 103
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 104
    .line 105
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 109
    .line 110
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 111
    .line 112
    .line 113
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 114
    .line 115
    .line 116
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 117
    .line 118
    .line 119
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 120
    .line 121
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_6
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 125
    .line 126
    .line 127
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 128
    .line 129
    .line 130
    sget-object p1, Lt71/d;->f:Lt71/d;

    .line 131
    .line 132
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 133
    .line 134
    .line 135
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 136
    .line 137
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_7
    :goto_1
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 141
    .line 142
    .line 143
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 144
    .line 145
    .line 146
    sget-object p1, Lt71/d;->e:Lt71/d;

    .line 147
    .line 148
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 149
    .line 150
    .line 151
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 152
    .line 153
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 154
    .line 155
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->latestStateValues:Ll71/x;

    .line 156
    .line 157
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 158
    .line 159
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 160
    .line 161
    invoke-direct {p0, p1, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->updateRPAError(Ll71/x;ZZ)V

    .line 162
    .line 163
    .line 164
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 16
    .line 17
    .line 18
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 21
    .line 22
    .line 23
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 24
    .line 25
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 26
    .line 27
    sget-object p1, Lx81/a;->e:Lv71/b;

    .line 28
    .line 29
    sget-object p1, Lx81/a;->e:Lv71/b;

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setVehicleTrajectory(Lv71/b;)V

    .line 32
    .line 33
    .line 34
    goto/16 :goto_2

    .line 35
    .line 36
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;

    .line 37
    .line 38
    if-nez v0, :cond_7

    .line 39
    .line 40
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingBackward;

    .line 46
    .line 47
    if-nez v0, :cond_6

    .line 48
    .line 49
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingBackward;

    .line 50
    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 55
    .line 56
    if-eqz v0, :cond_3

    .line 57
    .line 58
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 61
    .line 62
    .line 63
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->resolveRPAError()V

    .line 64
    .line 65
    .line 66
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 67
    .line 68
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 72
    .line 73
    if-eqz v0, :cond_4

    .line 74
    .line 75
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 78
    .line 79
    .line 80
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 81
    .line 82
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->resolveRPAError()V

    .line 83
    .line 84
    .line 85
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 89
    .line 90
    if-eqz p1, :cond_5

    .line 91
    .line 92
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 93
    .line 94
    .line 95
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 96
    .line 97
    .line 98
    sget-object p1, Lt71/d;->g:Lt71/d;

    .line 99
    .line 100
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 101
    .line 102
    .line 103
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 104
    .line 105
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    sget-object p1, Lt71/d;->d:Lt71/d;

    .line 109
    .line 110
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 111
    .line 112
    .line 113
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 114
    .line 115
    .line 116
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 117
    .line 118
    .line 119
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 120
    .line 121
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_6
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 125
    .line 126
    .line 127
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 128
    .line 129
    .line 130
    sget-object p1, Lt71/d;->f:Lt71/d;

    .line 131
    .line 132
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 133
    .line 134
    .line 135
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 136
    .line 137
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_7
    :goto_1
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveForwardPossible(Z)V

    .line 141
    .line 142
    .line 143
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveBackwardPossible(Z)V

    .line 144
    .line 145
    .line 146
    sget-object p1, Lt71/d;->e:Lt71/d;

    .line 147
    .line 148
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->setDriveMovementStatus(Lt71/d;)V

    .line 149
    .line 150
    .line 151
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 152
    .line 153
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 154
    .line 155
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->latestStateValues:Ll71/x;

    .line 156
    .line 157
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->multiTouchDetected:Z

    .line 158
    .line 159
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->holdKeyInterruption:Z

    .line 160
    .line 161
    invoke-direct {p0, p1, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->updateRPAError(Ll71/x;ZZ)V

    .line 162
    .line 163
    .line 164
    return-void
.end method
