.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "PausedUndoingNotPossible"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u000f\u0010\u0005\u001a\u00020\u0004H\u0016\u00a2\u0006\u0004\u0008\u0005\u0010\u0003R(\u0010\t\u001a\u0010\u0012\u0004\u0012\u00020\u0007\u0012\u0006\u0012\u0004\u0018\u00010\u00080\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000c\u00a8\u0006\r"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;",
        "<init>",
        "()V",
        "Llx0/b0;",
        "onStart",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
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
.field private final transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvb/a;

    .line 5
    .line 6
    const/16 v1, 0x1d

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lvb/a;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;->transition:Lay0/k;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 11
    .line 12
    invoke-static {p0}, Lps/t1;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$BadConnection;

    .line 19
    .line 20
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$BadConnection;-><init>()V

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 29
    .line 30
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object v0, Ls71/p;->w:Ls71/p;

    .line 35
    .line 36
    if-ne p0, v0, :cond_1

    .line 37
    .line 38
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$RequestedParking;

    .line 39
    .line 40
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$RequestedParking;-><init>()V

    .line 41
    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    const/4 p0, 0x0

    .line 45
    return-object p0
.end method


# virtual methods
.method public getTransition()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public onStart()V
    .locals 1

    .line 1
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->onStart()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    sget-object v0, Ls71/m;->f:Ls71/m;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
