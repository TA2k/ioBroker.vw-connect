.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$LockedByCar;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$LockedByDefault;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$MEBTouchDiagnosisSubState;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$MEBUnlockSubState;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgress;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockInProgressThresholdReached;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;,
        Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState$WaitingForNewFunctionState;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\r\u0008\u0000\u0018\u00002\u00020\u0001:\u0008\u001d\u001e\u001f !\"#$B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\t\u0010\nR\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010\u000bR$\u0010\r\u001a\u00020\u00042\u0006\u0010\u000c\u001a\u00020\u00048\u0006@BX\u0086\u000e\u00a2\u0006\u000c\n\u0004\u0008\r\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010R(\u0010\u0014\u001a\u0010\u0012\u0004\u0012\u00020\u0012\u0012\u0006\u0012\u0004\u0018\u00010\u00130\u00118\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0014\u0010\u0015\u001a\u0004\u0008\u0016\u0010\u0017R\u001a\u0010\u0019\u001a\u00020\u00188\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0019\u0010\u001a\u001a\u0004\u0008\u001b\u0010\u001c\u00a8\u0006%"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;",
        "",
        "isTouchDiagnosisRequestByCar",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;",
        "initialStateValues",
        "<init>",
        "(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V",
        "Llx0/b0;",
        "onStart",
        "()V",
        "Z",
        "value",
        "values",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
        "stateMachine",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
        "getStateMachine",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
        "LockedByCar",
        "LockedByDefault",
        "UnlockInProgress",
        "UnlockInProgressThresholdReached",
        "UnlockRequestedWaitingForResponseByCar",
        "WaitingForNewFunctionState",
        "MEBUnlockSubState",
        "MEBTouchDiagnosisSubState",
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
.field private final isTouchDiagnosisRequestByCar:Z

.field private final stateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

.field private final transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;


# direct methods
.method public constructor <init>(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V
    .locals 1

    .line 1
    const-string v0, "initialStateValues"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->isTouchDiagnosisRequestByCar:Z

    .line 10
    .line 11
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 12
    .line 13
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/c;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/c;

    .line 14
    .line 15
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->transition:Lay0/k;

    .line 16
    .line 17
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/q;

    .line 18
    .line 19
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/q;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;)V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->stateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 23
    .line 24
    return-void
.end method

.method public static final synthetic access$isTouchDiagnosisRequestByCar$p(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->isTouchDiagnosisRequestByCar:Z

    .line 2
    .line 3
    return p0
.end method

.method public static final synthetic access$setValues$p(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 2
    .line 3
    return-void
.end method


# virtual methods
.method public getStateMachine()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->stateMachine:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTransition()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public onStart()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 8
    .line 9
    invoke-interface {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onStateValuesChange(Ll71/x;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method
