.class public abstract Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPETouchDiagnosisSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "PPEUnlockSubState"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008 \u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R(\u0010\t\u001a\u0010\u0012\u0004\u0012\u00020\u0007\u0012\u0006\u0012\u0004\u0018\u00010\u00080\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000c\u00a8\u0006\r"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPETouchDiagnosisSubState;",
        "",
        "isTouchDiagnosisRequestByCar",
        "<init>",
        "(Z)V",
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
.method public constructor <init>(Z)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPETouchDiagnosisSubState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lh2/d9;

    .line 5
    .line 6
    const/4 v1, 0x7

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lh2/d9;-><init>(Ljava/lang/Object;ZI)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;->transition:Lay0/k;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPETouchDiagnosisSubState;->getTransition()Lay0/k;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    instance-of p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    check-cast p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 25
    .line 26
    invoke-static {p2}, Lps/t1;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->isTouchDiagnosisRequest()Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_7

    .line 35
    .line 36
    if-nez p1, :cond_7

    .line 37
    .line 38
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;

    .line 39
    .line 40
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;-><init>()V

    .line 41
    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    instance-of p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 45
    .line 46
    if-eqz p0, :cond_7

    .line 47
    .line 48
    check-cast p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 49
    .line 50
    invoke-static {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    sget-object p2, Ls71/p;->h:Ls71/p;

    .line 55
    .line 56
    if-ne p0, p2, :cond_3

    .line 57
    .line 58
    if-eqz p1, :cond_2

    .line 59
    .line 60
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;

    .line 61
    .line 62
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;-><init>()V

    .line 63
    .line 64
    .line 65
    return-object p0

    .line 66
    :cond_2
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$WaitingForNewFunctionState;

    .line 67
    .line 68
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$WaitingForNewFunctionState;-><init>()V

    .line 69
    .line 70
    .line 71
    return-object p0

    .line 72
    :cond_3
    sget-object p2, Ls71/p;->i:Ls71/p;

    .line 73
    .line 74
    if-eq p0, p2, :cond_5

    .line 75
    .line 76
    sget-object p2, Ls71/p;->E:Ls71/p;

    .line 77
    .line 78
    if-ne p0, p2, :cond_4

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_4
    return-object v0

    .line 82
    :cond_5
    :goto_0
    if-eqz p1, :cond_6

    .line 83
    .line 84
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;

    .line 85
    .line 86
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;-><init>()V

    .line 87
    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_6
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByDefault;

    .line 91
    .line 92
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByDefault;-><init>()V

    .line 93
    .line 94
    .line 95
    return-object p0

    .line 96
    :cond_7
    return-object v0
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$PPEUnlockSubState;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
