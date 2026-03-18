.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ScenarioSelectionPaused"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\"\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B-\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0004\u001a\u00020\u0002\u0012\u000c\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u00a2\u0006\u0004\u0008\t\u0010\nR6\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00052\u000c\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00058\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0006\u0010\u000c\u001a\u0004\u0008\r\u0010\u000e\"\u0004\u0008\u000f\u0010\u0010R*\u0010\u0008\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\u00078\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0008\u0010\u0011\u001a\u0004\u0008\u0012\u0010\u0013\"\u0004\u0008\u0014\u0010\u0015R(\u0010\u0019\u001a\u0010\u0012\u0004\u0012\u00020\u0017\u0012\u0006\u0012\u0004\u0018\u00010\u00180\u00168\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0019\u0010\u001a\u001a\u0004\u0008\u001b\u0010\u001c\u00a8\u0006\u001d"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;",
        "Ls71/k;",
        "currentScenario",
        "targetScenario",
        "",
        "enabledScenarios",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
        "values",
        "<init>",
        "(Ls71/k;Ls71/k;Ljava/util/Set;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V",
        "value",
        "Ljava/util/Set;",
        "getEnabledScenarios",
        "()Ljava/util/Set;",
        "setEnabledScenarios",
        "(Ljava/util/Set;)V",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
        "setValues",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V",
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

.field private final transition:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field private values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;


# direct methods
.method public constructor <init>(Ls71/k;Ls71/k;Ljava/util/Set;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ls71/k;",
            "Ls71/k;",
            "Ljava/util/Set<",
            "+",
            "Ls71/k;",
            ">;",
            "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;",
            ")V"
        }
    .end annotation

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
    const-string v0, "enabledScenarios"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "values"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;-><init>(Ls71/k;Ls71/k;)V

    .line 22
    .line 23
    .line 24
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->enabledScenarios:Ljava/util/Set;

    .line 25
    .line 26
    iput-object p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 27
    .line 28
    new-instance p3, Lkv0/e;

    .line 29
    .line 30
    const/16 p4, 0x1b

    .line 31
    .line 32
    invoke-direct {p3, p0, p1, p2, p4}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->transition:Lay0/k;

    .line 36
    .line 37
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;Ls71/k;Ls71/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 9

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->getTransition()Lay0/k;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

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
    instance-of v0, p3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    check-cast p3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 24
    .line 25
    invoke-static {p3}, Lps/t1;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->READY_TO_START:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 30
    .line 31
    if-ne p3, v0, :cond_2

    .line 32
    .line 33
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$WaitingForScenarioConfirmation;

    .line 34
    .line 35
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->getEnabledScenarios()Ljava/util/Set;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    const/16 v7, 0x10

    .line 44
    .line 45
    const/4 v8, 0x0

    .line 46
    const/4 v6, 0x0

    .line 47
    move-object v2, p1

    .line 48
    move-object v3, p2

    .line 49
    invoke-direct/range {v1 .. v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$WaitingForScenarioConfirmation;-><init>(Ls71/k;Ls71/k;Ljava/util/Set;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;ILkotlin/jvm/internal/g;)V

    .line 50
    .line 51
    .line 52
    return-object v1

    .line 53
    :cond_1
    move-object v2, p1

    .line 54
    move-object v3, p2

    .line 55
    instance-of p1, p3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 56
    .line 57
    if-eqz p1, :cond_2

    .line 58
    .line 59
    check-cast p3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 60
    .line 61
    invoke-static {p3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionSubState;->isUserActionSupported(Ls71/q;)Z

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-eqz p1, :cond_2

    .line 70
    .line 71
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->getEnabledScenarios()Ljava/util/Set;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    new-instance p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$DelayingScenarioConfirmation;

    .line 80
    .line 81
    invoke-direct {p2, p0, v2, v3, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$DelayingScenarioConfirmation;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Ls71/k;Ls71/k;Ljava/util/Set;)V

    .line 82
    .line 83
    .line 84
    return-object p2

    .line 85
    :cond_2
    const/4 p0, 0x0

    .line 86
    return-object p0
.end method


# virtual methods
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->enabledScenarios:Ljava/util/Set;

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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public setEnabledScenarios(Ljava/util/Set;)V
    .locals 1
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
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->enabledScenarios:Ljava/util/Set;

    .line 7
    .line 8
    return-void
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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState$ScenarioSelectionPaused;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 7
    .line 8
    return-void
.end method
