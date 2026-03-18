.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Paused"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0011\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R(\u0010\t\u001a\u0010\u0012\u0004\u0012\u00020\u0007\u0012\u0006\u0012\u0004\u0018\u00010\u00080\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000c\u00a8\u0006\r"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;",
        "",
        "pausedWhileUndoingIsActive",
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
.method public constructor <init>()V
    .locals 3

    .line 1
    const/4 v0, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {p0, v2, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;-><init>(ZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;-><init>()V

    .line 3
    new-instance v0, Lh2/d9;

    const/4 v1, 0x6

    invoke-direct {v0, p1, p0, v1}, Lh2/d9;-><init>(ZLjava/lang/Object;I)V

    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;->transition:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(ZILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    const/4 p1, 0x0

    .line 4
    :cond_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;-><init>(Z)V

    return-void
.end method

.method public static synthetic a(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;->transition$lambda$0(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 7
    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    check-cast p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 11
    .line 12
    invoke-static {p2}, Llp/fd;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$PausedUndoingNotPossible;

    .line 25
    .line 26
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$PausedUndoingNotPossible;-><init>()V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_0
    invoke-static {p2}, Llp/fd;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 35
    .line 36
    if-ne p0, p2, :cond_4

    .line 37
    .line 38
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getLogger()Lo71/a;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    const-string p1, "Received `IN_PROGRESS` after `PAUSED` without sending a `DRIVE_1` or `DRIVE_2` command."

    .line 45
    .line 46
    invoke-static {p0, p1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;

    .line 50
    .line 51
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;-><init>()V

    .line 52
    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_2
    instance-of p0, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 56
    .line 57
    if-eqz p0, :cond_4

    .line 58
    .line 59
    check-cast p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 60
    .line 61
    invoke-static {p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    sget-object p1, Ls71/p;->w:Ls71/p;

    .line 66
    .line 67
    if-ne p0, p1, :cond_3

    .line 68
    .line 69
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$RequestedParking;

    .line 70
    .line 71
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$RequestedParking;-><init>()V

    .line 72
    .line 73
    .line 74
    return-object p0

    .line 75
    :cond_3
    sget-object p1, Ls71/p;->u:Ls71/p;

    .line 76
    .line 77
    if-ne p0, p1, :cond_4

    .line 78
    .line 79
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$RequestedUndoing;

    .line 80
    .line 81
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$RequestedUndoing;-><init>()V

    .line 82
    .line 83
    .line 84
    return-object p0

    .line 85
    :cond_4
    const/4 p0, 0x0

    .line 86
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
