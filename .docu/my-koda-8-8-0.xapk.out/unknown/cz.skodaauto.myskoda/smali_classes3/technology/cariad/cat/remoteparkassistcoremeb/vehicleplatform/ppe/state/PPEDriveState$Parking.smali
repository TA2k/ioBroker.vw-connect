.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Parking"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R(\u0010\u0007\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u0008\u001a\u0004\u0008\t\u0010\n\u00a8\u0006\u000b"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;",
        "<init>",
        "()V",
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
    .locals 2

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvb/a;

    .line 5
    .line 6
    const/16 v1, 0x1b

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lvb/a;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;->transition:Lay0/k;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x1

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 14
    .line 15
    invoke-static {p0}, Lps/t1;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$BadConnection;

    .line 22
    .line 23
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$BadConnection;-><init>()V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    invoke-static {p0}, Lps/t1;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/j;->a:[I

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    aget p0, v0, p0

    .line 38
    .line 39
    if-ne p0, v3, :cond_3

    .line 40
    .line 41
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;

    .line 42
    .line 43
    invoke-direct {p0, v1, v3, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;-><init>(ZILkotlin/jvm/internal/g;)V

    .line 44
    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_1
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 48
    .line 49
    if-eqz v0, :cond_3

    .line 50
    .line 51
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 52
    .line 53
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 58
    .line 59
    if-eq p0, v0, :cond_2

    .line 60
    .line 61
    sget-object v0, Ls71/p;->x:Ls71/p;

    .line 62
    .line 63
    if-ne p0, v0, :cond_3

    .line 64
    .line 65
    :cond_2
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;

    .line 66
    .line 67
    invoke-direct {p0, v1, v3, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;-><init>(ZILkotlin/jvm/internal/g;)V

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_3
    return-object v2
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
