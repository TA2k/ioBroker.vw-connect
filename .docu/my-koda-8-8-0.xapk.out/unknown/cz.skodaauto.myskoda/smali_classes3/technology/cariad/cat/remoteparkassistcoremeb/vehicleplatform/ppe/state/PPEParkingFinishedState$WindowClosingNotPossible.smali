.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "WindowClosingNotPossible"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R*\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00028\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\"\u0004\u0008\n\u0010\u0005R(\u0010\u000e\u001a\u0010\u0012\u0004\u0012\u00020\u000c\u0012\u0006\u0012\u0004\u0018\u00010\r0\u000b8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000e\u0010\u000f\u001a\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;",
        "values",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V",
        "value",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;",
        "getValues",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;",
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

.field private values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V
    .locals 1

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 10
    .line 11
    new-instance p1, Lw81/c;

    .line 12
    .line 13
    const/16 v0, 0xa

    .line 14
    .line 15
    invoke-direct {p1, p0, v0}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->transition:Lay0/k;

    .line 19
    .line 20
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;->getTransition()Lay0/k;

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
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->CLAMP_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 30
    .line 31
    if-ne p1, v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;->isWindowsClosingPossible(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_1

    .line 42
    .line 43
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;

    .line 44
    .line 45
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V

    .line 50
    .line 51
    .line 52
    return-object p1

    .line 53
    :cond_1
    const/4 p0, 0x0

    .line 54
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 2
    .line 3
    return-object p0
.end method

.method public setValues(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 7
    .line 8
    return-void
.end method
