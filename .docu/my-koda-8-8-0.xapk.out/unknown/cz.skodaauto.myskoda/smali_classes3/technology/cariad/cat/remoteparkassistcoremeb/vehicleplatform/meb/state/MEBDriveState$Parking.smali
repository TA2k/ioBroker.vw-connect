.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState;
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
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubScreenState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lt40/a;

    .line 5
    .line 6
    const/4 v1, 0x7

    .line 7
    invoke-direct {v0, v1}, Lt40/a;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;->transition:Lay0/k;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;
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
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 14
    .line 15
    invoke-static {p0}, Llp/fd;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->PAUSED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 20
    .line 21
    if-ne p0, v0, :cond_2

    .line 22
    .line 23
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;

    .line 24
    .line 25
    invoke-direct {p0, v2, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;-><init>(ZILkotlin/jvm/internal/g;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 30
    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 34
    .line 35
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    sget-object v0, Ls71/p;->x:Ls71/p;

    .line 40
    .line 41
    if-eq p0, v0, :cond_1

    .line 42
    .line 43
    sget-object v0, Ls71/p;->E:Ls71/p;

    .line 44
    .line 45
    if-ne p0, v0, :cond_2

    .line 46
    .line 47
    :cond_1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;

    .line 48
    .line 49
    invoke-direct {p0, v2, v1, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Paused;-><init>(ZILkotlin/jvm/internal/g;)V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_2
    return-object v3
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState$Parking;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
