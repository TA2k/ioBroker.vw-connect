.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "RequestedParkingForward"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R*\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00028\u0016@TX\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010\u0007\u001a\u0004\u0008\u0008\u0010\t\"\u0004\u0008\n\u0010\u0005R(\u0010\u000e\u001a\u0010\u0012\u0004\u0012\u00020\u000c\u0012\u0006\u0012\u0004\u0018\u00010\r0\u000b8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000e\u0010\u000f\u001a\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;",
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
    .locals 1

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 10
    .line 11
    new-instance p1, Lw81/c;

    .line 12
    .line 13
    const/4 v0, 0x4

    .line 14
    invoke-direct {p1, p0, v0}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->transition:Lay0/k;

    .line 18
    .line 19
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;->getTransition()Lay0/k;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/g;->a:[I

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    aget p1, v0, p1

    .line 30
    .line 31
    const/4 v0, 0x1

    .line 32
    if-eq p1, v0, :cond_1

    .line 33
    .line 34
    const/4 v0, 0x2

    .line 35
    if-eq p1, v0, :cond_0

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    if-eq p1, v0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 42
    .line 43
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :cond_1
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;

    .line 52
    .line 53
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 58
    .line 59
    .line 60
    return-object p1

    .line 61
    :cond_2
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 62
    .line 63
    if-eqz v0, :cond_4

    .line 64
    .line 65
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 66
    .line 67
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 72
    .line 73
    if-eq p1, v0, :cond_3

    .line 74
    .line 75
    sget-object v0, Ls71/p;->x:Ls71/p;

    .line 76
    .line 77
    if-ne p1, v0, :cond_4

    .line 78
    .line 79
    :cond_3
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 80
    .line 81
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 86
    .line 87
    .line 88
    return-object p1

    .line 89
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 90
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public getValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

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
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->values:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 7
    .line 8
    return-void
.end method
