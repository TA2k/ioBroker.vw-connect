.class public abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008 \u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R(\u0010\u0007\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u0008\u001a\u0004\u0008\t\u0010\nR$\u0010\u0011\u001a\u00020\u000b2\u0006\u0010\u000c\u001a\u00020\u000b8&@dX\u00a6\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\r\u0010\u000e\"\u0004\u0008\u000f\u0010\u0010R$\u0010\u0017\u001a\u00020\u00122\u0006\u0010\u000c\u001a\u00020\u00128&@dX\u00a6\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0013\u0010\u0014\"\u0004\u0008\u0015\u0010\u0016\u00a8\u0006\u0018"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;",
        "<init>",
        "()V",
        "Lkotlin/Function1;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;",
        "transition",
        "Lay0/k;",
        "getTransition",
        "()Lay0/k;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "value",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "setValues",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V",
        "values",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;",
        "getCurrentFunctionStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;",
        "setCurrentFunctionStatus",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V",
        "currentFunctionStatus",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lp61/d;

    .line 5
    .line 6
    const/16 v1, 0x8

    .line 7
    .line 8
    invoke-direct {v0, p0, v1}, Lp61/d;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->transition:Lay0/k;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 7
    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 11
    .line 12
    invoke-static {p1}, Lkp/q;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->setCurrentFunctionStatus(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    .line 17
    .line 18
    .line 19
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->n:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 20
    .line 21
    invoke-static {p1}, Ljp/fa;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-nez v1, :cond_3

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    iget-object v1, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 43
    .line 44
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    iget-object v2, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 49
    .line 50
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    iget-object v3, v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 55
    .line 56
    invoke-static {v1, v2, v3}, Lkp/r;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_0

    .line 61
    .line 62
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    if-eqz v1, :cond_0

    .line 67
    .line 68
    sget-object v2, Ls71/m;->f:Ls71/m;

    .line 69
    .line 70
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_0
    iget-object v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 74
    .line 75
    invoke-static {v1}, Lkp/r;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_1

    .line 80
    .line 81
    instance-of p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;

    .line 82
    .line 83
    if-nez p0, :cond_3

    .line 84
    .line 85
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;

    .line 86
    .line 87
    invoke-static {p1}, Lkp/q;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    invoke-direct {p0, v0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$HoldKeyState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    .line 92
    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    if-eqz p0, :cond_3

    .line 100
    .line 101
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onStateValuesChange(Ll71/x;)V

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 106
    .line 107
    if-eqz v0, :cond_3

    .line 108
    .line 109
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 114
    .line 115
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->PULLOUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 116
    .line 117
    if-ne v0, v1, :cond_3

    .line 118
    .line 119
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 120
    .line 121
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;->getTimeSinceStateStarted-UwyO8pc()J

    .line 122
    .line 123
    .line 124
    move-result-wide v0

    .line 125
    sget-wide v2, Ln81/b;->d:J

    .line 126
    .line 127
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->c(JJ)I

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    if-ltz p1, :cond_3

    .line 132
    .line 133
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-eqz p0, :cond_3

    .line 138
    .line 139
    sget-object p1, Ls71/m;->j:Ls71/m;

    .line 140
    .line 141
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 145
    return-object p0
.end method


# virtual methods
.method public abstract getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;
.end method

.method public abstract setCurrentFunctionStatus(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V
.end method

.method public abstract setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V
.end method
