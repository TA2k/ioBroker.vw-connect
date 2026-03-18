.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lp81/e;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "WindowClosingPossible"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u0002B\u000f\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006R\"\u0010\u0004\u001a\u00020\u00038\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\"\u0004\u0008\n\u0010\u0006R0\u0010\u000e\u001a\u0010\u0012\u0004\u0012\u00020\u000c\u0012\u0006\u0012\u0004\u0018\u00010\r0\u000b8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u000e\u0010\u000f\u001a\u0004\u0008\u0010\u0010\u0011\"\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u0014"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;",
        "Lp81/e;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;",
        "values",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;",
        "setValues",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
        "setTransition",
        "(Lay0/k;)V",
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
.field private transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V
    .locals 1

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 10
    .line 11
    new-instance p1, Lp61/d;

    .line 12
    .line 13
    const/16 v0, 0x14

    .line 14
    .line 15
    invoke-direct {p1, p0, v0}, Lp61/d;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->transition:Lay0/k;

    .line 19
    .line 20
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 11
    .line 12
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v0, Ls71/p;->z:Ls71/p;

    .line 17
    .line 18
    if-ne p1, v0, :cond_3

    .line 19
    .line 20
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$ClosingWindows;

    .line 21
    .line 22
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$ClosingWindows;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V

    .line 27
    .line 28
    .line 29
    return-object p1

    .line 30
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 35
    .line 36
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getLogger()Lo71/a;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {p0, p1, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->updateValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;Lo71/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    iget-object p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 52
    .line 53
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 54
    .line 55
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingNotPossible;

    .line 62
    .line 63
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingNotPossible;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 72
    .line 73
    if-eqz v0, :cond_3

    .line 74
    .line 75
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 76
    .line 77
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getLogger()Lo71/a;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-virtual {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->isTimeoutReachedOnInactivity(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;Lo71/a;)Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    if-eqz p1, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-eqz p0, :cond_2

    .line 92
    .line 93
    sget-object p1, Ls71/m;->h:Ls71/m;

    .line 94
    .line 95
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    :cond_2
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Timeout;

    .line 99
    .line 100
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$Timeout;-><init>()V

    .line 101
    .line 102
    .line 103
    return-object p0

    .line 104
    :cond_3
    const/4 p0, 0x0

    .line 105
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge isTimeoutReachedOnInactivity(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;Lo71/a;)Z
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lp81/e;->isTimeoutReachedOnInactivity(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;Lo71/a;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public setTransition(Lay0/k;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->transition:Lay0/k;

    .line 7
    .line 8
    return-void
.end method

.method public setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState$WindowClosingPossible;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 7
    .line 8
    return-void
.end method

.method public bridge updateValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;Lo71/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Lp81/e;->updateValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;Lo71/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method
