.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Pressing"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R*\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00028\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\"\u0004\u0008\n\u0010\u0005R(\u0010\u000e\u001a\u0010\u0012\u0004\u0012\u00020\u000c\u0012\u0006\u0012\u0004\u0018\u00010\r0\u000b8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000e\u0010\u000f\u001a\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
        "values",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V",
        "value",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
        "setValues",
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

.field private values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V
    .locals 3

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {p0, v2, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;-><init>(ZILkotlin/jvm/internal/g;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 13
    .line 14
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 15
    .line 16
    const/16 v0, 0x16

    .line 17
    .line 18
    invoke-direct {p1, p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->transition:Lay0/k;

    .line 22
    .line 23
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;->getTransition()Lay0/k;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->ABORTED_RESUMING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 30
    .line 31
    if-ne p1, v0, :cond_6

    .line 32
    .line 33
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingNotAllowed;

    .line 34
    .line 35
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;->isKeyOutOfRangeErrorActive()Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-direct {p1, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingNotAllowed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 44
    .line 45
    .line 46
    return-object p1

    .line 47
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 48
    .line 49
    if-eqz v0, :cond_3

    .line 50
    .line 51
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 52
    .line 53
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    sget-object v0, Ls71/p;->C:Ls71/p;

    .line 58
    .line 59
    if-ne p1, v0, :cond_2

    .line 60
    .line 61
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressTimeThresholdNotReached;

    .line 62
    .line 63
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressTimeThresholdNotReached;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :cond_2
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 72
    .line 73
    if-ne p1, v0, :cond_6

    .line 74
    .line 75
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingAllowed;

    .line 76
    .line 77
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationSubState;->isKeyOutOfRangeErrorActive()Z

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    invoke-direct {p1, v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$PressingAllowed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 86
    .line 87
    .line 88
    return-object p1

    .line 89
    :cond_3
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 90
    .line 91
    if-eqz v0, :cond_6

    .line 92
    .line 93
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->g:Ls71/h;

    .line 98
    .line 99
    sget-object v1, Ls71/h;->e:Ls71/h;

    .line 100
    .line 101
    if-ne v0, v1, :cond_4

    .line 102
    .line 103
    sget v0, Lu81/b;->n:I

    .line 104
    .line 105
    sget-wide v0, Lu81/b;->f:J

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_4
    sget v0, Lu81/b;->n:I

    .line 109
    .line 110
    sget-wide v0, Lu81/b;->g:J

    .line 111
    .line 112
    :goto_0
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 113
    .line 114
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;->getTimeSinceStateStarted-UwyO8pc()J

    .line 115
    .line 116
    .line 117
    move-result-wide v2

    .line 118
    invoke-static {v2, v3, v0, v1}, Lmy0/c;->c(JJ)I

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    if-ltz p1, :cond_6

    .line 123
    .line 124
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    if-eqz p1, :cond_5

    .line 129
    .line 130
    sget-object v0, Ls71/m;->l:Ls71/m;

    .line 131
    .line 132
    invoke-interface {p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_5
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$WaitingForResponse;

    .line 136
    .line 137
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$WaitingForResponse;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 142
    .line 143
    .line 144
    return-object p1

    .line 145
    :cond_6
    const/4 p0, 0x0

    .line 146
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState$Pressing;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 7
    .line 8
    return-void
.end method
