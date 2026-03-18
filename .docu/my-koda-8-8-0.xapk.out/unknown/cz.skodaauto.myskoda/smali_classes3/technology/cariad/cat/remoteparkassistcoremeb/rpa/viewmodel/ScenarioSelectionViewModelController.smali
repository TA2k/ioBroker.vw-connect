.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;
.super Le81/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le81/r;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00a4\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0012\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0018\u00002\u00020\u00012\u00020\u0002B\u0011\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u000c\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\u0007H\u0010\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0017\u0010\u0010\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\rH\u0010\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u0017\u0010\u0014\u001a\u00020\t2\u0006\u0010\u0008\u001a\u00020\u0011H\u0010\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u0017\u0010\u0019\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u0015H\u0010\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u000f\u0010\u001d\u001a\u00020\u001aH\u0010\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u001f\u0010\"\u001a\u00020\t2\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010!\u001a\u00020 H\u0016\u00a2\u0006\u0004\u0008\"\u0010#J\u0017\u0010$\u001a\u00020\t2\u0006\u0010\u001f\u001a\u00020\u001eH\u0016\u00a2\u0006\u0004\u0008$\u0010%J\u0017\u0010(\u001a\u00020\t2\u0006\u0010\'\u001a\u00020&H\u0016\u00a2\u0006\u0004\u0008(\u0010)J\u0017\u0010,\u001a\u00020\t2\u0006\u0010+\u001a\u00020*H\u0016\u00a2\u0006\u0004\u0008,\u0010-J\u000f\u0010.\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u0008.\u0010/J\u000f\u00100\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u00080\u0010/J\u000f\u00101\u001a\u00020\tH\u0016\u00a2\u0006\u0004\u00081\u0010/J1\u00105\u001a\u00020\t2\u0008\u0010\u0016\u001a\u0004\u0018\u00010\u00152\u0006\u00102\u001a\u00020 2\u0006\u00103\u001a\u00020 2\u0006\u00104\u001a\u00020 H\u0002\u00a2\u0006\u0004\u00085\u00106R\u001a\u00108\u001a\u0002078\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00088\u00109\u001a\u0004\u0008:\u0010;R(\u0010?\u001a\u0010\u0012\u000c\u0012\n\u0012\u0006\u0008\u0001\u0012\u00020>0=0<8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008?\u0010@\u001a\u0004\u0008A\u0010BR&\u0010D\u001a\u0008\u0012\u0004\u0012\u00020C0<8\u0010X\u0090\u0004\u00a2\u0006\u0012\n\u0004\u0008D\u0010@\u0012\u0004\u0008F\u0010/\u001a\u0004\u0008E\u0010BR\u0018\u0010G\u001a\u0004\u0018\u00010\u00158\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008G\u0010HR\u0016\u00103\u001a\u00020 8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00083\u0010IR\u0016\u00104\u001a\u00020 8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00084\u0010IR\u0016\u0010J\u001a\u00020 8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008J\u0010IR\u001a\u0010L\u001a\u0008\u0012\u0004\u0012\u00020\u001e0K8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008L\u0010MR\u0016\u00102\u001a\u00020 8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00082\u0010IR*\u0010O\u001a\u00020&2\u0006\u0010N\u001a\u00020&8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008O\u0010P\u001a\u0004\u0008Q\u0010R\"\u0004\u0008S\u0010)R*\u0010T\u001a\u00020 2\u0006\u0010N\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008T\u0010I\u001a\u0004\u0008T\u0010U\"\u0004\u0008V\u0010WR*\u0010X\u001a\u00020 2\u0006\u0010N\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008X\u0010I\u001a\u0004\u0008X\u0010U\"\u0004\u0008Y\u0010WR*\u0010Z\u001a\u00020 2\u0006\u0010N\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008Z\u0010I\u001a\u0004\u0008Z\u0010U\"\u0004\u0008[\u0010WR*\u0010\\\u001a\u00020 2\u0006\u0010N\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\\\u0010I\u001a\u0004\u0008\\\u0010U\"\u0004\u0008]\u0010WR.\u0010_\u001a\u0004\u0018\u00010^2\u0008\u0010N\u001a\u0004\u0018\u00010^8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008_\u0010`\u001a\u0004\u0008a\u0010b\"\u0004\u0008c\u0010dR6\u0010e\u001a\u0008\u0012\u0004\u0012\u00020&0<2\u000c\u0010N\u001a\u0008\u0012\u0004\u0012\u00020&0<8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008e\u0010@\u001a\u0004\u0008f\u0010B\"\u0004\u0008g\u0010hR6\u0010i\u001a\u0008\u0012\u0004\u0012\u00020&0<2\u000c\u0010N\u001a\u0008\u0012\u0004\u0012\u00020&0<8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008i\u0010@\u001a\u0004\u0008j\u0010B\"\u0004\u0008k\u0010hR6\u0010n\u001a\u0008\u0012\u0004\u0012\u00020m0l2\u000c\u0010N\u001a\u0008\u0012\u0004\u0012\u00020m0l8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008n\u0010o\u001a\u0004\u0008p\u0010q\"\u0004\u0008r\u0010sR*\u0010t\u001a\u00020 2\u0006\u0010N\u001a\u00020 8\u0016@RX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008t\u0010I\u001a\u0004\u0008t\u0010U\"\u0004\u0008u\u0010WR\u001a\u0010w\u001a\u00020v8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008w\u0010x\u001a\u0004\u0008y\u0010z\u00a8\u0006{"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;",
        "Le81/x;",
        "Le81/r;",
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
        "Lz71/i;",
        "scenarioSelectionObserver",
        "",
        "notifyOnRegister",
        "addObserver",
        "(Lz71/i;Z)V",
        "removeObserver",
        "(Lz71/i;)V",
        "Ls71/k;",
        "newScenario",
        "changeScenario",
        "(Ls71/k;)V",
        "",
        "parkingSlotId",
        "changeTPAManeuver",
        "(I)V",
        "startParking",
        "()V",
        "stopParking",
        "stopEngine",
        "holdKeyInterruption",
        "multiTouchDetected",
        "isScenarioSelectionFailed",
        "updateRPAError",
        "(Ll71/x;ZZZ)V",
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
        "Ls71/q;",
        "supportedUserActions",
        "getSupportedUserActions$remoteparkassistcoremeb_release",
        "getSupportedUserActions$remoteparkassistcoremeb_release$annotations",
        "latestStateValues",
        "Ll71/x;",
        "Z",
        "hasUserStartedParkingProcess",
        "Ln71/d;",
        "observing",
        "Ln71/d;",
        "value",
        "currentScenario",
        "Ls71/k;",
        "getCurrentScenario",
        "()Ls71/k;",
        "setCurrentScenario",
        "isSelectionDisabled",
        "()Z",
        "setSelectionDisabled",
        "(Z)V",
        "isStartParkingEnabled",
        "setStartParkingEnabled",
        "isWaitingForScenarioConfirmation",
        "setWaitingForScenarioConfirmation",
        "isScenarioConfirmationSuccessful",
        "setScenarioConfirmationSuccessful",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "error",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "getError",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;",
        "setError",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V",
        "supportedScenarios",
        "getSupportedScenarios",
        "setSupportedScenarios",
        "(Ljava/util/Set;)V",
        "enabledScenarios",
        "getEnabledScenarios",
        "setEnabledScenarios",
        "",
        "Ll71/y;",
        "availableTPAManeuvers",
        "Ljava/util/List;",
        "getAvailableTPAManeuvers",
        "()Ljava/util/List;",
        "setAvailableTPAManeuvers",
        "(Ljava/util/List;)V",
        "isUndoActionSupported",
        "setUndoActionSupported",
        "Ls71/h;",
        "parkingManeuverStatus",
        "Ls71/h;",
        "getParkingManeuverStatus",
        "()Ls71/h;",
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
.field private availableTPAManeuvers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ll71/y;",
            ">;"
        }
    .end annotation
.end field

.field private currentScenario:Ls71/k;

.field private enabledScenarios:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;"
        }
    .end annotation
.end field

.field private error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field private hasUserStartedParkingProcess:Z

.field private holdKeyInterruption:Z

.field private isScenarioConfirmationSuccessful:Z

.field private isScenarioSelectionFailed:Z

.field private isSelectionDisabled:Z

.field private isStartParkingEnabled:Z

.field private isUndoActionSupported:Z

.field private isWaitingForScenarioConfirmation:Z

.field private latestStateValues:Ll71/x;

.field private multiTouchDetected:Z

.field private final observing:Ln71/d;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ln71/d;"
        }
    .end annotation
.end field

.field private final parkingManeuverStatus:Ls71/h;

.field private final representingScreen:Ls71/l;

.field private supportedScenarios:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;"
        }
    .end annotation
.end field

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
            "Ls71/q;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ll71/w;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "dependencies"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct/range {p0 .. p1}, Le81/x;-><init>(Ll71/w;)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Ls71/l;->f:Ls71/l;

    .line 14
    .line 15
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->representingScreen:Ls71/l;

    .line 16
    .line 17
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 18
    .line 19
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState;

    .line 20
    .line 21
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    const-class v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState;

    .line 26
    .line 27
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;

    .line 32
    .line 33
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    const/4 v6, 0x3

    .line 38
    new-array v6, v6, [Lhy0/d;

    .line 39
    .line 40
    const/4 v7, 0x0

    .line 41
    aput-object v3, v6, v7

    .line 42
    .line 43
    const/4 v3, 0x1

    .line 44
    aput-object v4, v6, v3

    .line 45
    .line 46
    const/4 v4, 0x2

    .line 47
    aput-object v5, v6, v4

    .line 48
    .line 49
    invoke-static {v6}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    iput-object v4, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedScreenStates:Ljava/util/Set;

    .line 54
    .line 55
    sget-object v5, Ls71/p;->t:Ls71/p;

    .line 56
    .line 57
    sget-object v6, Ls71/p;->j:Ls71/p;

    .line 58
    .line 59
    sget-object v7, Ls71/p;->k:Ls71/p;

    .line 60
    .line 61
    sget-object v8, Ls71/p;->l:Ls71/p;

    .line 62
    .line 63
    sget-object v9, Ls71/p;->m:Ls71/p;

    .line 64
    .line 65
    sget-object v10, Ls71/p;->p:Ls71/p;

    .line 66
    .line 67
    sget-object v11, Ls71/p;->q:Ls71/p;

    .line 68
    .line 69
    sget-object v12, Ls71/p;->r:Ls71/p;

    .line 70
    .line 71
    sget-object v13, Ls71/p;->s:Ls71/p;

    .line 72
    .line 73
    sget-object v14, Ls71/p;->n:Ls71/p;

    .line 74
    .line 75
    sget-object v15, Ls71/p;->o:Ls71/p;

    .line 76
    .line 77
    sget-object v16, Ls71/p;->e:Ls71/p;

    .line 78
    .line 79
    const-class v4, Ls71/r;

    .line 80
    .line 81
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 82
    .line 83
    .line 84
    move-result-object v17

    .line 85
    filled-new-array/range {v5 .. v17}, [Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    invoke-static {v2}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 94
    .line 95
    new-instance v2, Ln71/d;

    .line 96
    .line 97
    iget-object v1, v1, Ll71/w;->a:Ln71/a;

    .line 98
    .line 99
    invoke-direct {v2, v1}, Ln71/d;-><init>(Ln71/a;)V

    .line 100
    .line 101
    .line 102
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 103
    .line 104
    sget-object v1, Ls71/k;->e:Ls71/k;

    .line 105
    .line 106
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->currentScenario:Ls71/k;

    .line 107
    .line 108
    iput-boolean v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled:Z

    .line 109
    .line 110
    iput-boolean v3, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isStartParkingEnabled:Z

    .line 111
    .line 112
    sget-object v1, Lmx0/u;->d:Lmx0/u;

    .line 113
    .line 114
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedScenarios:Ljava/util/Set;

    .line 115
    .line 116
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->enabledScenarios:Ljava/util/Set;

    .line 117
    .line 118
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 119
    .line 120
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->availableTPAManeuvers:Ljava/util/List;

    .line 121
    .line 122
    sget-object v1, Ls71/h;->f:Ls71/h;

    .line 123
    .line 124
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 125
    .line 126
    return-void
.end method

.method private static final _set_availableTPAManeuvers_$lambda$0(Ljava/util/List;Lz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionAvailableTPAManeuversDidChange(Ljava/util/List;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_currentScenario_$lambda$0(Ls71/k;Lz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionCurrentScenarioDidChange(Ls71/k;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_enabledScenarios_$lambda$0(Ljava/util/Set;Lz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionEnabledScenariosDidChange(Ljava/util/Set;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isScenarioConfirmationSuccessful_$lambda$0(ZLz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionConfirmationSuccessfulDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isSelectionDisabled_$lambda$0(ZLz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionIsSelectionDisabledDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isStartParkingEnabled_$lambda$0(ZLz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionStartParkingEnabledDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isUndoActionSupported_$lambda$0(ZLz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionIsUndoActionSupportedChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_isWaitingForScenarioConfirmation_$lambda$0(ZLz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionWaitingForScenarioConfirmationDidChange(Z)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final _set_supportedScenarios_$lambda$0(Ljava/util/Set;Lz71/i;)Llx0/b0;
    .locals 1

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionSupportedScenariosDidChange(Ljava/util/Set;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic c(Ljava/util/List;Lz71/i;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_availableTPAManeuvers_$lambda$0(Ljava/util/List;Lz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/i;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_error_$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;Lz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lz71/i;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_isWaitingForScenarioConfirmation_$lambda$0(ZLz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ljava/util/Set;Lz71/i;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_supportedScenarios_$lambda$0(Ljava/util/Set;Lz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Lz71/i;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_isSelectionDisabled_$lambda$0(ZLz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic getSupportedUserActions$remoteparkassistcoremeb_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic h(Lz71/i;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_isStartParkingEnabled_$lambda$0(ZLz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic i(Ls71/k;Lz71/i;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_currentScenario_$lambda$0(Ls71/k;Lz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Lz71/i;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_isUndoActionSupported_$lambda$0(ZLz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ljava/util/Set;Lz71/i;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_enabledScenarios_$lambda$0(Ljava/util/Set;Lz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Lz71/i;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->_set_isScenarioConfirmationSuccessful_$lambda$0(ZLz71/i;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private setAvailableTPAManeuvers(Ljava/util/List;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ll71/y;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->availableTPAManeuvers:Ljava/util/List;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->availableTPAManeuvers:Ljava/util/List;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/u;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, p1, v1}, Le81/u;-><init>(Ljava/util/List;I)V

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

.method private setCurrentScenario(Ls71/k;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->currentScenario:Ls71/k;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->currentScenario:Ls71/k;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/h;

    .line 10
    .line 11
    const/4 v1, 0x1

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

.method private setEnabledScenarios(Ljava/util/Set;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->enabledScenarios:Ljava/util/Set;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->enabledScenarios:Ljava/util/Set;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/v;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, v1, p1}, Le81/v;-><init>(ILjava/util/Set;)V

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

.method private setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/d;

    .line 14
    .line 15
    const/4 v1, 0x3

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

.method private setScenarioConfirmationSuccessful(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioConfirmationSuccessful:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioConfirmationSuccessful:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x11

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

.method private setSelectionDisabled(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0xe

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

.method private setStartParkingEnabled(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isStartParkingEnabled:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isStartParkingEnabled:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0xd

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

.method private setSupportedScenarios(Ljava/util/Set;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedScenarios:Ljava/util/Set;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedScenarios:Ljava/util/Set;

    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 12
    .line 13
    new-instance v0, Le81/v;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, v1, p1}, Le81/v;-><init>(ILjava/util/Set;)V

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

.method private setUndoActionSupported(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isUndoActionSupported:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isUndoActionSupported:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0x10

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

.method private setWaitingForScenarioConfirmation(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 8
    .line 9
    new-instance v0, Le81/b;

    .line 10
    .line 11
    const/16 v1, 0xf

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

.method private final updateRPAError(Ll71/x;ZZZ)V
    .locals 7

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-static {p4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 4
    .line 5
    .line 6
    move-result-object v2

    .line 7
    const/4 v5, 0x0

    .line 8
    const/16 v6, 0x11

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    move-object v0, p1

    .line 12
    move v4, p2

    .line 13
    move v3, p3

    .line 14
    invoke-static/range {v0 .. v6}, Ll71/x;->b(Ll71/x;ZLjava/lang/Boolean;ZZLjava/lang/Boolean;I)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 p1, 0x0

    .line 20
    :goto_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setError(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public addObserver(Lz71/i;Z)V
    .locals 1

    .line 1
    const-string v0, "scenarioSelectionObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ln71/d;->a(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getCurrentScenario()Ls71/k;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionCurrentScenarioDidChange(Ls71/k;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled()Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionIsSelectionDisabledDidChange(Z)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isStartParkingEnabled()Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionStartParkingEnabledDidChange(Z)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionErrorDidChange(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation()Z

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionWaitingForScenarioConfirmationDidChange(Z)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioConfirmationSuccessful()Z

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionConfirmationSuccessfulDidChange(Z)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getSupportedScenarios()Ljava/util/Set;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionSupportedScenariosDidChange(Ljava/util/Set;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getEnabledScenarios()Ljava/util/Set;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionEnabledScenariosDidChange(Ljava/util/Set;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getAvailableTPAManeuvers()Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    invoke-interface {p1, p2}, Lz71/i;->scenarioSelectionAvailableTPAManeuversDidChange(Ljava/util/List;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isUndoActionSupported()Z

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    invoke-interface {p1, p0}, Lz71/i;->scenarioSelectionIsUndoActionSupportedChange(Z)V

    .line 81
    .line 82
    .line 83
    :cond_0
    return-void
.end method

.method public changeScenario(Ls71/k;)V
    .locals 3

    .line 1
    const-string v0, "newScenario"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const-string v1, "changeScenario("

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 19
    .line 20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p1, ") was called, but is currently not allowed!"

    .line 29
    .line 30
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getCurrentScenario()Ls71/k;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    if-ne v0, p1, :cond_1

    .line 46
    .line 47
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 52
    .line 53
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getCurrentScenario()Ls71/k;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    new-instance v2, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string p1, ") was called, but scenario ("

    .line 66
    .line 67
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string p0, ") is already selected"

    .line 74
    .line 75
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-static {v0, p0}, Lo71/a;->b(Lo71/a;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    packed-switch p1, :pswitch_data_0

    .line 91
    .line 92
    .line 93
    new-instance p0, La8/r0;

    .line 94
    .line 95
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 96
    .line 97
    .line 98
    throw p0

    .line 99
    :pswitch_0
    sget-object p1, Ls71/p;->t:Ls71/p;

    .line 100
    .line 101
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :pswitch_1
    sget-object p1, Ls71/p;->s:Ls71/p;

    .line 106
    .line 107
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 108
    .line 109
    .line 110
    return-void

    .line 111
    :pswitch_2
    sget-object p1, Ls71/p;->r:Ls71/p;

    .line 112
    .line 113
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 114
    .line 115
    .line 116
    return-void

    .line 117
    :pswitch_3
    sget-object p1, Ls71/p;->q:Ls71/p;

    .line 118
    .line 119
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :pswitch_4
    sget-object p1, Ls71/p;->p:Ls71/p;

    .line 124
    .line 125
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 126
    .line 127
    .line 128
    return-void

    .line 129
    :pswitch_5
    sget-object p1, Ls71/p;->m:Ls71/p;

    .line 130
    .line 131
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 132
    .line 133
    .line 134
    return-void

    .line 135
    :pswitch_6
    sget-object p1, Ls71/p;->l:Ls71/p;

    .line 136
    .line 137
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 138
    .line 139
    .line 140
    return-void

    .line 141
    :pswitch_7
    sget-object p1, Ls71/p;->k:Ls71/p;

    .line 142
    .line 143
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 144
    .line 145
    .line 146
    return-void

    .line 147
    :pswitch_8
    sget-object p1, Ls71/p;->j:Ls71/p;

    .line 148
    .line 149
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 150
    .line 151
    .line 152
    :pswitch_9
    return-void

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
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

.method public changeTPAManeuver(I)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getAvailableTPAManeuvers()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/Iterable;

    .line 6
    .line 7
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    move-object v2, v1

    .line 22
    check-cast v2, Ll71/y;

    .line 23
    .line 24
    iget v2, v2, Ll71/y;->b:I

    .line 25
    .line 26
    if-ne v2, p1, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 v1, 0x0

    .line 30
    :goto_0
    check-cast v1, Ll71/y;

    .line 31
    .line 32
    const-string v0, "changeTPAManeuver("

    .line 33
    .line 34
    if-nez v1, :cond_2

    .line 35
    .line 36
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 41
    .line 42
    new-instance v1, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p1, ") was called, but cannot find tpa maneuver with this id!"

    .line 51
    .line 52
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_2
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled()Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_3

    .line 68
    .line 69
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    iget-object p0, p0, Ll71/w;->b:Lu61/b;

    .line 74
    .line 75
    new-instance p1, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v0, ") was called, but is currently not allowed!"

    .line 84
    .line 85
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-static {p0, p1}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :cond_3
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getAvailableTPAManeuvers()Ljava/util/List;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-interface {p1, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-nez p1, :cond_4

    .line 105
    .line 106
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    iget-object p1, p1, Ll71/w;->b:Lu61/b;

    .line 111
    .line 112
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->getAvailableTPAManeuvers()Ljava/util/List;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    new-instance v2, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string v0, ") was called, but the maneuver is not available in the availableTPAManeuvers: "

    .line 125
    .line 126
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    const-string p0, "!"

    .line 133
    .line 134
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    invoke-static {p1, p0}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    return-void

    .line 145
    :cond_4
    sget-object p1, Ls71/k;->n:Ls71/k;

    .line 146
    .line 147
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->changeScenario(Ls71/k;)V

    .line 148
    .line 149
    .line 150
    new-instance p1, Ls71/r;

    .line 151
    .line 152
    invoke-direct {p1, v1}, Ls71/r;-><init>(Ll71/y;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p0, p1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 156
    .line 157
    .line 158
    return-void
.end method

.method public getAvailableTPAManeuvers()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ll71/y;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->availableTPAManeuvers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCurrentScenario()Ls71/k;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->currentScenario:Ls71/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEnabledScenarios()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ls71/k;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->enabledScenarios:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public getError()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->error:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 2
    .line 3
    return-object p0
.end method

.method public getParkingManeuverStatus()Ls71/h;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->parkingManeuverStatus:Ls71/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRepresentingScreen()Ls71/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->representingScreen:Ls71/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSupportedScenarios()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ls71/k;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedScenarios:Ljava/util/Set;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedScreenStates:Ljava/util/Set;

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
            "Ls71/q;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->supportedUserActions:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public isScenarioConfirmationSuccessful()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioConfirmationSuccessful:Z

    .line 2
    .line 3
    return p0
.end method

.method public isSelectionDisabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isSelectionDisabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isStartParkingEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isStartParkingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isUndoActionSupported()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isUndoActionSupported:Z

    .line 2
    .line 3
    return p0
.end method

.method public isWaitingForScenarioConfirmation()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation:Z

    .line 2
    .line 3
    return p0
.end method

.method public onStateValuesChange$remoteparkassistcoremeb_release(Ll71/x;)V
    .locals 3

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    move-object v0, p1

    .line 11
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 12
    .line 13
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 14
    .line 15
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 16
    .line 17
    if-ne v1, v2, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 22
    .line 23
    :goto_0
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 24
    .line 25
    iget-boolean v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->k:Z

    .line 26
    .line 27
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setUndoActionSupported(Z)V

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    const/4 v0, 0x1

    .line 32
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setUndoActionSupported(Z)V

    .line 33
    .line 34
    .line 35
    :goto_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 36
    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    move-object v0, p1

    .line 40
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 41
    .line 42
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->j:Ljava/util/Set;

    .line 43
    .line 44
    check-cast v0, Ljava/lang/Iterable;

    .line 45
    .line 46
    new-instance v1, La5/f;

    .line 47
    .line 48
    const/4 v2, 0x6

    .line 49
    invoke-direct {v1, v2}, La5/f;-><init>(I)V

    .line 50
    .line 51
    .line 52
    invoke-static {v0, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setAvailableTPAManeuvers(Ljava/util/List;)V

    .line 57
    .line 58
    .line 59
    :cond_2
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->latestStateValues:Ll71/x;

    .line 60
    .line 61
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 62
    .line 63
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 64
    .line 65
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 66
    .line 67
    invoke-direct {p0, p1, v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 68
    .line 69
    .line 70
    return-void
.end method

.method public removeObserver(Lz71/i;)V
    .locals 1

    .line 1
    const-string v0, "scenarioSelectionObserver"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->observing:Ln71/d;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ln71/d;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public startParking()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 3
    .line 4
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isStartParkingEnabled()Z

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    sget-object v1, Ls71/p;->n:Ls71/p;

    .line 11
    .line 12
    invoke-virtual {p0, v1}, Le81/x;->triggerUserAction$remoteparkassistcoremeb_release(Ls71/q;)V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Le81/x;->getDependencies()Ll71/w;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iget-object v1, v1, Ll71/w;->b:Lu61/b;

    .line 21
    .line 22
    const-string v2, "startParking() was called, but is currently not allowed!"

    .line 23
    .line 24
    invoke-static {v1, v2}, Lo71/a;->d(Lo71/a;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 28
    .line 29
    .line 30
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
    sget-object v0, Ls71/p;->o:Ls71/p;

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
    .locals 4

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionFailed;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 18
    .line 19
    .line 20
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionFailed;

    .line 21
    .line 22
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 41
    .line 42
    .line 43
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 44
    .line 45
    .line 46
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 47
    .line 48
    .line 49
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 50
    .line 51
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 52
    .line 53
    goto/16 :goto_1

    .line 54
    .line 55
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$Init;

    .line 56
    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 60
    .line 61
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 62
    .line 63
    .line 64
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 65
    .line 66
    .line 67
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$Init;

    .line 68
    .line 69
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 88
    .line 89
    .line 90
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 91
    .line 92
    .line 93
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 94
    .line 95
    .line 96
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 97
    .line 98
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 99
    .line 100
    goto/16 :goto_1

    .line 101
    .line 102
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;

    .line 103
    .line 104
    if-eqz v0, :cond_2

    .line 105
    .line 106
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation()Z

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    iget-boolean v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 111
    .line 112
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 113
    .line 114
    .line 115
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 116
    .line 117
    .line 118
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;

    .line 119
    .line 120
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 139
    .line 140
    .line 141
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 142
    .line 143
    .line 144
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 145
    .line 146
    .line 147
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 148
    .line 149
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 153
    .line 154
    if-eqz v0, :cond_3

    .line 155
    .line 156
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 157
    .line 158
    .line 159
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 160
    .line 161
    .line 162
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 163
    .line 164
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getTargetScenario()Ls71/k;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 183
    .line 184
    .line 185
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 186
    .line 187
    .line 188
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 189
    .line 190
    .line 191
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 192
    .line 193
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 194
    .line 195
    goto :goto_1

    .line 196
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;

    .line 197
    .line 198
    if-eqz v0, :cond_5

    .line 199
    .line 200
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 201
    .line 202
    .line 203
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 204
    .line 205
    .line 206
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 207
    .line 208
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 209
    .line 210
    .line 211
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 212
    .line 213
    .line 214
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 215
    .line 216
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;

    .line 217
    .line 218
    if-eqz v0, :cond_4

    .line 219
    .line 220
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;

    .line 221
    .line 222
    goto :goto_0

    .line 223
    :cond_4
    const/4 p1, 0x0

    .line 224
    :goto_0
    if-eqz p1, :cond_5

    .line 225
    .line 226
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 245
    .line 246
    .line 247
    :cond_5
    :goto_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->latestStateValues:Ll71/x;

    .line 248
    .line 249
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 250
    .line 251
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 252
    .line 253
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 254
    .line 255
    invoke-direct {p0, p1, v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 256
    .line 257
    .line 258
    return-void
.end method

.method public updateMLB$remoteparkassistcoremeb_release(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;)V
    .locals 4

    .line 1
    const-string v0, "newState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionFailed;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 18
    .line 19
    .line 20
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionFailed;

    .line 21
    .line 22
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 41
    .line 42
    .line 43
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 44
    .line 45
    .line 46
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 47
    .line 48
    .line 49
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 50
    .line 51
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 52
    .line 53
    goto/16 :goto_1

    .line 54
    .line 55
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 56
    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 60
    .line 61
    .line 62
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 63
    .line 64
    .line 65
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 66
    .line 67
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getTargetScenario()Ls71/k;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 86
    .line 87
    .line 88
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 89
    .line 90
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 91
    .line 92
    .line 93
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 94
    .line 95
    .line 96
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 97
    .line 98
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 99
    .line 100
    goto/16 :goto_1

    .line 101
    .line 102
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionPaused;

    .line 103
    .line 104
    if-eqz v0, :cond_2

    .line 105
    .line 106
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 107
    .line 108
    .line 109
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 110
    .line 111
    .line 112
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionPaused;

    .line 113
    .line 114
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 133
    .line 134
    .line 135
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 136
    .line 137
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 138
    .line 139
    .line 140
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 141
    .line 142
    .line 143
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 144
    .line 145
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 146
    .line 147
    goto/16 :goto_1

    .line 148
    .line 149
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionGeneral;

    .line 150
    .line 151
    if-eqz v0, :cond_3

    .line 152
    .line 153
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation()Z

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    iget-boolean v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 158
    .line 159
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 160
    .line 161
    .line 162
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 163
    .line 164
    .line 165
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionGeneral;

    .line 166
    .line 167
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 186
    .line 187
    .line 188
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 189
    .line 190
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 191
    .line 192
    .line 193
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 194
    .line 195
    .line 196
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 197
    .line 198
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 199
    .line 200
    goto :goto_1

    .line 201
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$HoldKeyInterruption;

    .line 202
    .line 203
    if-eqz v0, :cond_4

    .line 204
    .line 205
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 206
    .line 207
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 208
    .line 209
    .line 210
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 211
    .line 212
    .line 213
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$HoldKeyInterruption;

    .line 214
    .line 215
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 234
    .line 235
    .line 236
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 237
    .line 238
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 239
    .line 240
    .line 241
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 242
    .line 243
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 244
    .line 245
    goto :goto_1

    .line 246
    :cond_4
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;

    .line 247
    .line 248
    if-eqz v0, :cond_6

    .line 249
    .line 250
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 251
    .line 252
    .line 253
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 254
    .line 255
    .line 256
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 257
    .line 258
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 259
    .line 260
    .line 261
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 262
    .line 263
    .line 264
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 265
    .line 266
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 267
    .line 268
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;

    .line 269
    .line 270
    if-eqz v0, :cond_5

    .line 271
    .line 272
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;

    .line 273
    .line 274
    goto :goto_0

    .line 275
    :cond_5
    const/4 p1, 0x0

    .line 276
    :goto_0
    if-eqz p1, :cond_6

    .line 277
    .line 278
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getSupportedScenarios()Ljava/util/Set;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 293
    .line 294
    .line 295
    move-result-object p1

    .line 296
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 297
    .line 298
    .line 299
    :cond_6
    :goto_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->latestStateValues:Ll71/x;

    .line 300
    .line 301
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 302
    .line 303
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 304
    .line 305
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 306
    .line 307
    invoke-direct {p0, p1, v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 308
    .line 309
    .line 310
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
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionFailed;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 18
    .line 19
    .line 20
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->Companion:Lw81/f;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->access$getSupportedScenarios$cp()Ljava/util/Set;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 30
    .line 31
    .line 32
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionFailed;

    .line 33
    .line 34
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionGeneral;->getEnabledScenarios()Ljava/util/Set;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 46
    .line 47
    .line 48
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 49
    .line 50
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 51
    .line 52
    .line 53
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 54
    .line 55
    .line 56
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 57
    .line 58
    goto/16 :goto_1

    .line 59
    .line 60
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$DelayingScenarioConfirmation;

    .line 61
    .line 62
    if-eqz v0, :cond_1

    .line 63
    .line 64
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 65
    .line 66
    .line 67
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 68
    .line 69
    .line 70
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->Companion:Lw81/f;

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->access$getSupportedScenarios$cp()Ljava/util/Set;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 80
    .line 81
    .line 82
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$DelayingScenarioConfirmation;

    .line 83
    .line 84
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$DelayingScenarioConfirmation;->getEnabledScenarios()Ljava/util/Set;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$DelayingScenarioConfirmation;->getTargetScenario()Ls71/k;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 96
    .line 97
    .line 98
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 99
    .line 100
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 101
    .line 102
    .line 103
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 104
    .line 105
    .line 106
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 107
    .line 108
    goto/16 :goto_1

    .line 109
    .line 110
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 111
    .line 112
    if-eqz v0, :cond_2

    .line 113
    .line 114
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 115
    .line 116
    .line 117
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 118
    .line 119
    .line 120
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->Companion:Lw81/f;

    .line 121
    .line 122
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->access$getSupportedScenarios$cp()Ljava/util/Set;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 130
    .line 131
    .line 132
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 133
    .line 134
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$WaitingForScenarioConfirmation;->getEnabledScenarios()Ljava/util/Set;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getTargetScenario()Ls71/k;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 146
    .line 147
    .line 148
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 149
    .line 150
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 151
    .line 152
    .line 153
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 154
    .line 155
    .line 156
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 157
    .line 158
    goto/16 :goto_1

    .line 159
    .line 160
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;

    .line 161
    .line 162
    if-eqz v0, :cond_3

    .line 163
    .line 164
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 165
    .line 166
    .line 167
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 168
    .line 169
    .line 170
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->Companion:Lw81/f;

    .line 171
    .line 172
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->access$getSupportedScenarios$cp()Ljava/util/Set;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 180
    .line 181
    .line 182
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;

    .line 183
    .line 184
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->getEnabledScenarios()Ljava/util/Set;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 196
    .line 197
    .line 198
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 199
    .line 200
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 201
    .line 202
    .line 203
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 204
    .line 205
    .line 206
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 207
    .line 208
    goto :goto_1

    .line 209
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionGeneral;

    .line 210
    .line 211
    if-eqz v0, :cond_4

    .line 212
    .line 213
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isWaitingForScenarioConfirmation()Z

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    iget-boolean v3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->hasUserStartedParkingProcess:Z

    .line 218
    .line 219
    invoke-direct {p0, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 220
    .line 221
    .line 222
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 223
    .line 224
    .line 225
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->Companion:Lw81/f;

    .line 226
    .line 227
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->access$getSupportedScenarios$cp()Ljava/util/Set;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 235
    .line 236
    .line 237
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionGeneral;

    .line 238
    .line 239
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionGeneral;->getEnabledScenarios()Ljava/util/Set;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 247
    .line 248
    .line 249
    move-result-object p1

    .line 250
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 251
    .line 252
    .line 253
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 254
    .line 255
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 256
    .line 257
    .line 258
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 259
    .line 260
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 261
    .line 262
    .line 263
    goto :goto_1

    .line 264
    :cond_4
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 265
    .line 266
    if-eqz v0, :cond_6

    .line 267
    .line 268
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSelectionDisabled(Z)V

    .line 269
    .line 270
    .line 271
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setStartParkingEnabled(Z)V

    .line 272
    .line 273
    .line 274
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 275
    .line 276
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setWaitingForScenarioConfirmation(Z)V

    .line 277
    .line 278
    .line 279
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setScenarioConfirmationSuccessful(Z)V

    .line 280
    .line 281
    .line 282
    iput-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 283
    .line 284
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->Companion:Lw81/f;

    .line 285
    .line 286
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 287
    .line 288
    .line 289
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;->access$getSupportedScenarios$cp()Ljava/util/Set;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setSupportedScenarios(Ljava/util/Set;)V

    .line 294
    .line 295
    .line 296
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;

    .line 297
    .line 298
    if-eqz v0, :cond_5

    .line 299
    .line 300
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;

    .line 301
    .line 302
    goto :goto_0

    .line 303
    :cond_5
    const/4 p1, 0x0

    .line 304
    :goto_0
    if-eqz p1, :cond_6

    .line 305
    .line 306
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getEnabledScenarios()Ljava/util/Set;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setEnabledScenarios(Ljava/util/Set;)V

    .line 311
    .line 312
    .line 313
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getCurrentScenario()Ls71/k;

    .line 314
    .line 315
    .line 316
    move-result-object p1

    .line 317
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->setCurrentScenario(Ls71/k;)V

    .line 318
    .line 319
    .line 320
    :cond_6
    :goto_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->latestStateValues:Ll71/x;

    .line 321
    .line 322
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->multiTouchDetected:Z

    .line 323
    .line 324
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->holdKeyInterruption:Z

    .line 325
    .line 326
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->isScenarioSelectionFailed:Z

    .line 327
    .line 328
    invoke-direct {p0, p1, v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->updateRPAError(Ll71/x;ZZZ)V

    .line 329
    .line 330
    .line 331
    return-void
.end method
