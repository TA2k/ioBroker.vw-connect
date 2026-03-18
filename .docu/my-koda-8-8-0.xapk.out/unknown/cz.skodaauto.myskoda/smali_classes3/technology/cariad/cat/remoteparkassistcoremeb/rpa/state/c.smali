.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/c;
.super Ld81/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method public constructor <init>()V
    .locals 12

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
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connected;

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;

    .line 21
    .line 22
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    const/4 v6, 0x3

    .line 27
    new-array v7, v6, [Lhy0/d;

    .line 28
    .line 29
    const/4 v8, 0x0

    .line 30
    aput-object v2, v7, v8

    .line 31
    .line 32
    const/4 v2, 0x1

    .line 33
    aput-object v4, v7, v2

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    aput-object v5, v7, v4

    .line 37
    .line 38
    invoke-static {v7}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 43
    .line 44
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 45
    .line 46
    .line 47
    move-result-object v7

    .line 48
    const-class v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 49
    .line 50
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 51
    .line 52
    .line 53
    move-result-object v9

    .line 54
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 55
    .line 56
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 57
    .line 58
    .line 59
    move-result-object v10

    .line 60
    new-array v6, v6, [Lhy0/d;

    .line 61
    .line 62
    aput-object v7, v6, v8

    .line 63
    .line 64
    aput-object v9, v6, v2

    .line 65
    .line 66
    aput-object v10, v6, v4

    .line 67
    .line 68
    invoke-static {v6}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    move-object v4, v3

    .line 73
    new-instance v3, Lck/b;

    .line 74
    .line 75
    const/16 v6, 0x19

    .line 76
    .line 77
    invoke-direct {v3, v6}, Lck/b;-><init>(I)V

    .line 78
    .line 79
    .line 80
    move-object v6, v4

    .line 81
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;

    .line 82
    .line 83
    invoke-direct {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-static {v1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    move-object v11, v5

    .line 95
    move-object v5, v1

    .line 96
    move-object v1, v11

    .line 97
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 98
    .line 99
    .line 100
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 101
    .line 102
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/c;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method
