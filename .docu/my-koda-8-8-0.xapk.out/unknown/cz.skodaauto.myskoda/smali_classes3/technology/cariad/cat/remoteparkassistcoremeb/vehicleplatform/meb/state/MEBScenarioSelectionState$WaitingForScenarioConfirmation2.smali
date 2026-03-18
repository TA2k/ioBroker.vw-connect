.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "WaitingForScenarioConfirmation2"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0004\u001a\u00020\u0002\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008R(\u0010\u000c\u001a\u0010\u0012\u0004\u0012\u00020\n\u0012\u0006\u0012\u0004\u0018\u00010\u000b0\t8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000c\u0010\r\u001a\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0010"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;",
        "Ls71/k;",
        "currentScenario",
        "targetScenario",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;",
        "values",
        "<init>",
        "(Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V",
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
.method public constructor <init>(Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V
    .locals 7

    .line 1
    const-string v0, "currentScenario"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "targetScenario"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "values"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, p2, p1, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;-><init>(Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 17
    .line 18
    .line 19
    new-instance v1, Lbg/a;

    .line 20
    .line 21
    const/16 v6, 0x14

    .line 22
    .line 23
    move-object v2, p0

    .line 24
    move-object v5, p1

    .line 25
    move-object v3, p2

    .line 26
    move-object v4, p3

    .line 27
    invoke-direct/range {v1 .. v6}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 28
    .line 29
    .line 30
    iput-object v1, v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;->transition:Lay0/k;

    .line 31
    .line 32
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    check-cast p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 11
    .line 12
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0, p4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionSubState;->updateValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p4}, Llp/ed;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ls71/k;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    if-ne p0, p1, :cond_0

    .line 24
    .line 25
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;

    .line 26
    .line 27
    invoke-direct {p1, p0, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;-><init>(Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 28
    .line 29
    .line 30
    return-object p1

    .line 31
    :cond_0
    if-eq p0, p3, :cond_4

    .line 32
    .line 33
    new-instance p3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 34
    .line 35
    invoke-direct {p3, p1, p0, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;-><init>(Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 36
    .line 37
    .line 38
    return-object p3

    .line 39
    :cond_1
    instance-of p0, p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 40
    .line 41
    if-eqz p0, :cond_3

    .line 42
    .line 43
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState;->access$getSupportedScenarioSelectionUserAction$cp()Ljava/util/Set;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Ljava/lang/Iterable;

    .line 48
    .line 49
    check-cast p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 50
    .line 51
    invoke-static {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-static {p0, v0}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_4

    .line 60
    .line 61
    invoke-static {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getTargetScenarioOption(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/k;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    if-ne p3, p0, :cond_2

    .line 66
    .line 67
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;

    .line 68
    .line 69
    invoke-direct {p0, p3, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelection;-><init>(Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 70
    .line 71
    .line 72
    return-object p0

    .line 73
    :cond_2
    if-eq p1, p0, :cond_4

    .line 74
    .line 75
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 76
    .line 77
    invoke-direct {p1, p0, p3, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation;-><init>(Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 78
    .line 79
    .line 80
    return-object p1

    .line 81
    :cond_3
    instance-of p0, p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 82
    .line 83
    if-eqz p0, :cond_4

    .line 84
    .line 85
    check-cast p4, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 86
    .line 87
    invoke-virtual {p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;->getTimeSinceStateStarted-UwyO8pc()J

    .line 88
    .line 89
    .line 90
    move-result-wide p0

    .line 91
    sget p4, Li81/b;->k:I

    .line 92
    .line 93
    sget-wide v0, Li81/b;->g:J

    .line 94
    .line 95
    invoke-static {p0, p1, v0, v1}, Lmy0/c;->c(JJ)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-ltz p0, :cond_4

    .line 100
    .line 101
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionFailed;

    .line 102
    .line 103
    invoke-direct {p0, p3, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$ScenarioSelectionFailed;-><init>(Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 104
    .line 105
    .line 106
    return-object p0

    .line 107
    :cond_4
    const/4 p0, 0x0

    .line 108
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState$WaitingForScenarioConfirmation2;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
