.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Pressing"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007R*\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0008\u001a\u00020\u00028\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010\t\u001a\u0004\u0008\n\u0010\u000b\"\u0004\u0008\u000c\u0010\rR*\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u00048\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0005\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010\"\u0004\u0008\u0011\u0010\u0012R(\u0010\u0016\u001a\u0010\u0012\u0004\u0012\u00020\u0014\u0012\u0006\u0012\u0004\u0018\u00010\u00150\u00138\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0016\u0010\u0017\u001a\u0004\u0008\u0018\u0010\u0019\u00a8\u0006\u001a"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "values",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;",
        "currentFunctionStatus",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V",
        "value",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;",
        "setValues",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;",
        "getCurrentFunctionStatus",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;",
        "setCurrentFunctionStatus",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V",
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
.field private currentFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

.field private final transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V
    .locals 1

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "currentFunctionStatus"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 15
    .line 16
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->currentFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 17
    .line 18
    new-instance p1, Lp61/d;

    .line 19
    .line 20
    const/4 p2, 0x3

    .line 21
    invoke-direct {p1, p0, p2}, Lp61/d;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->transition:Lay0/k;

    .line 25
    .line 26
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationSubState;->getTransition()Lay0/k;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_0
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->ABORTED_RESUMING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 28
    .line 29
    if-ne p1, v0, :cond_6

    .line 30
    .line 31
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingNotAllowed;

    .line 32
    .line 33
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-direct {p1, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingNotAllowed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    .line 42
    .line 43
    .line 44
    return-object p1

    .line 45
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 46
    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 50
    .line 51
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    sget-object v0, Ls71/p;->C:Ls71/p;

    .line 56
    .line 57
    if-ne p1, v0, :cond_2

    .line 58
    .line 59
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressTimeThresholdNotReached;

    .line 60
    .line 61
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {p1, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressTimeThresholdNotReached;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    .line 70
    .line 71
    .line 72
    return-object p1

    .line 73
    :cond_2
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 74
    .line 75
    if-ne p1, v0, :cond_6

    .line 76
    .line 77
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingAllowed;

    .line 78
    .line 79
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-direct {p1, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$PressingAllowed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    .line 88
    .line 89
    .line 90
    return-object p1

    .line 91
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 92
    .line 93
    if-eqz v0, :cond_6

    .line 94
    .line 95
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 100
    .line 101
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->PARKING:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 102
    .line 103
    if-ne v0, v1, :cond_4

    .line 104
    .line 105
    sget v0, Ln81/b;->l:I

    .line 106
    .line 107
    sget-wide v0, Ln81/b;->b:J

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_4
    sget v0, Ln81/b;->l:I

    .line 111
    .line 112
    sget-wide v0, Ln81/b;->a:J

    .line 113
    .line 114
    :goto_0
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 115
    .line 116
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;->getTimeSinceStateStarted-UwyO8pc()J

    .line 117
    .line 118
    .line 119
    move-result-wide v2

    .line 120
    invoke-static {v2, v3, v0, v1}, Lmy0/c;->c(JJ)I

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-ltz p1, :cond_6

    .line 125
    .line 126
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    if-eqz p1, :cond_5

    .line 131
    .line 132
    sget-object v0, Ls71/m;->l:Ls71/m;

    .line 133
    .line 134
    invoke-interface {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    :cond_5
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$WaitingForResponse;

    .line 138
    .line 139
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-direct {p1, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$WaitingForResponse;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V

    .line 148
    .line 149
    .line 150
    return-object p1

    .line 151
    :cond_6
    const/4 p0, 0x0

    .line 152
    return-object p0
.end method


# virtual methods
.method public getCurrentFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->currentFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public setCurrentFunctionStatus(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->currentFunctionStatus:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 7
    .line 8
    return-void
.end method

.method public setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState$Pressing;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 7
    .line 8
    return-void
.end method
