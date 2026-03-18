.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/d;
.super Ld81/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ld81/c;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 5
    .line 6
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 7
    .line 8
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithoutRetry;

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const/4 v4, 0x2

    .line 21
    new-array v5, v4, [Lhy0/d;

    .line 22
    .line 23
    const/4 v6, 0x0

    .line 24
    aput-object v2, v5, v6

    .line 25
    .line 26
    const/4 v2, 0x1

    .line 27
    aput-object v3, v5, v2

    .line 28
    .line 29
    invoke-static {v5}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 34
    .line 35
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 40
    .line 41
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    new-array v4, v4, [Lhy0/d;

    .line 46
    .line 47
    aput-object v5, v4, v6

    .line 48
    .line 49
    aput-object v1, v4, v2

    .line 50
    .line 51
    invoke-static {v4}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;->getConnectionErrorStatus()Lt71/c;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-static {v1}, Ljp/wf;->a(Lt71/c;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_0

    .line 64
    .line 65
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;->isConnectionAllowed()Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_0

    .line 70
    .line 71
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;

    .line 72
    .line 73
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;->getConnectionErrorStatus()Lt71/c;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-direct {v1, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;-><init>(Lt71/c;)V

    .line 78
    .line 79
    .line 80
    :goto_0
    move-object v4, v1

    .line 81
    goto :goto_1

    .line 82
    :cond_0
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithoutRetry;

    .line 83
    .line 84
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;->getConnectionErrorStatus()Lt71/c;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-direct {v1, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithoutRetry;-><init>(Lt71/c;)V

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :goto_1
    sget-object v5, Lmx0/u;->d:Lmx0/u;

    .line 93
    .line 94
    move-object v1, v3

    .line 95
    const/4 v3, 0x0

    .line 96
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 97
    .line 98
    .line 99
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 100
    .line 101
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method
