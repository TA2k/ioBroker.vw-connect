.class public final Lx41/g0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lx41/u0;

.field public final synthetic g:Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;


# direct methods
.method public constructor <init>(Lx41/u0;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx41/g0;->f:Lx41/u0;

    .line 2
    .line 3
    iput-object p2, p0, Lx41/g0;->g:Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lx41/g0;

    .line 2
    .line 3
    iget-object v1, p0, Lx41/g0;->f:Lx41/u0;

    .line 4
    .line 5
    iget-object p0, p0, Lx41/g0;->g:Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lx41/g0;-><init>(Lx41/u0;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lx41/g0;->e:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/l;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lx41/g0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lx41/g0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lx41/g0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lx41/g0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Llx0/l;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lx41/g0;->d:I

    .line 10
    .line 11
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    const/4 v5, 0x1

    .line 14
    const/4 v6, 0x2

    .line 15
    iget-object v7, v0, Lx41/g0;->g:Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 16
    .line 17
    iget-object v8, v0, Lx41/g0;->f:Lx41/u0;

    .line 18
    .line 19
    const/4 v9, 0x0

    .line 20
    if-eqz v3, :cond_2

    .line 21
    .line 22
    if-eq v3, v5, :cond_1

    .line 23
    .line 24
    if-ne v3, v6, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_3

    .line 30
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 46
    .line 47
    move-object v14, v1

    .line 48
    check-cast v14, Ltechnology/cariad/cat/genx/GenXError;

    .line 49
    .line 50
    instance-of v1, v14, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 51
    .line 52
    if-eqz v1, :cond_6

    .line 53
    .line 54
    move-object v1, v14

    .line 55
    check-cast v1, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 56
    .line 57
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->getStatus()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    sget-object v3, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 62
    .line 63
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getConnectFailedAndPairingIsInvalid()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_6

    .line 72
    .line 73
    new-instance v13, Ltechnology/cariad/cat/genx/keyexchange/f;

    .line 74
    .line 75
    const/4 v1, 0x3

    .line 76
    invoke-direct {v13, v7, v1}, Ltechnology/cariad/cat/genx/keyexchange/f;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;I)V

    .line 77
    .line 78
    .line 79
    new-instance v10, Lt51/j;

    .line 80
    .line 81
    invoke-static {v8}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v15

    .line 85
    const-string v1, "getName(...)"

    .line 86
    .line 87
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v16

    .line 91
    const-string v11, "Car2PhonePairing"

    .line 92
    .line 93
    sget-object v12, Lt51/f;->a:Lt51/f;

    .line 94
    .line 95
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 99
    .line 100
    .line 101
    iput-object v9, v0, Lx41/g0;->e:Ljava/lang/Object;

    .line 102
    .line 103
    iput v5, v0, Lx41/g0;->d:I

    .line 104
    .line 105
    invoke-virtual {v7}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-virtual {v7}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    invoke-virtual {v8, v1, v3, v0}, Lx41/u0;->k(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Lrx0/c;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    if-ne v1, v2, :cond_3

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_3
    move-object v1, v4

    .line 121
    :goto_0
    if-ne v1, v2, :cond_4

    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_4
    :goto_1
    iget-object v1, v8, Lx41/u0;->r:Lyy0/q1;

    .line 125
    .line 126
    iput-object v9, v0, Lx41/g0;->e:Ljava/lang/Object;

    .line 127
    .line 128
    iput v6, v0, Lx41/g0;->d:I

    .line 129
    .line 130
    invoke-virtual {v1, v7, v0}, Lyy0/q1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    if-ne v0, v2, :cond_5

    .line 135
    .line 136
    :goto_2
    return-object v2

    .line 137
    :cond_5
    :goto_3
    iget-object v0, v8, Lx41/u0;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 138
    .line 139
    invoke-virtual {v0, v7}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    check-cast v0, Lvy0/i1;

    .line 144
    .line 145
    if-eqz v0, :cond_6

    .line 146
    .line 147
    const-string v1, "Pairing invalidated"

    .line 148
    .line 149
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 150
    .line 151
    .line 152
    :cond_6
    return-object v4
.end method
