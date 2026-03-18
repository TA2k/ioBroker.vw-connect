.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Connecting"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0000\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R(\u0010\u0007\u001a\u0010\u0012\u0004\u0012\u00020\u0005\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u0008\u001a\u0004\u0008\t\u0010\n\u00a8\u0006\u000b"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, La2/e;

    .line 5
    .line 6
    const/16 v1, 0x11

    .line 7
    .line 8
    invoke-direct {v0, p0, v1}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;->transition:Lay0/k;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;->transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final transition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 11
    .line 12
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;->getTimeSinceStateStarted-UwyO8pc()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    sget p1, La81/a;->c:I

    .line 17
    .line 18
    sget-wide v2, La81/a;->b:J

    .line 19
    .line 20
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->c(JJ)I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-lez p1, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateCallback()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    sget-object p1, Ls71/m;->m:Ls71/m;

    .line 33
    .line 34
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;

    .line 38
    .line 39
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;-><init>()V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_1
    const/4 p0, 0x0

    .line 44
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
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;->transition:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method
