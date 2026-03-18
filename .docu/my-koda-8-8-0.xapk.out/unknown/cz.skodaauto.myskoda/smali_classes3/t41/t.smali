.class public final Lt41/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lt41/z;

.field public final synthetic g:Lt41/v;

.field public final synthetic h:Lorg/altbeacon/beacon/Region;


# direct methods
.method public constructor <init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lt41/v;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lt41/t;->d:I

    .line 1
    iput-object p1, p0, Lt41/t;->f:Lt41/z;

    iput-object p2, p0, Lt41/t;->h:Lorg/altbeacon/beacon/Region;

    iput-object p3, p0, Lt41/t;->g:Lt41/v;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lt41/z;Lt41/v;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lt41/t;->d:I

    .line 2
    iput-object p1, p0, Lt41/t;->f:Lt41/z;

    iput-object p2, p0, Lt41/t;->g:Lt41/v;

    iput-object p3, p0, Lt41/t;->h:Lorg/altbeacon/beacon/Region;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lt41/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lt41/t;

    .line 7
    .line 8
    iget-object v1, p0, Lt41/t;->g:Lt41/v;

    .line 9
    .line 10
    iget-object v2, p0, Lt41/t;->h:Lorg/altbeacon/beacon/Region;

    .line 11
    .line 12
    iget-object p0, p0, Lt41/t;->f:Lt41/z;

    .line 13
    .line 14
    invoke-direct {v0, p0, v1, v2, p2}, Lt41/t;-><init>(Lt41/z;Lt41/v;Lorg/altbeacon/beacon/Region;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v0, Lt41/t;->e:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v0, Lt41/t;

    .line 21
    .line 22
    iget-object v1, p0, Lt41/t;->h:Lorg/altbeacon/beacon/Region;

    .line 23
    .line 24
    iget-object v2, p0, Lt41/t;->g:Lt41/v;

    .line 25
    .line 26
    iget-object p0, p0, Lt41/t;->f:Lt41/z;

    .line 27
    .line 28
    invoke-direct {v0, p0, v1, v2, p2}, Lt41/t;-><init>(Lt41/z;Lorg/altbeacon/beacon/Region;Lt41/v;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, v0, Lt41/t;->e:Ljava/lang/Object;

    .line 32
    .line 33
    return-object v0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lt41/t;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lt41/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lt41/t;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lt41/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lt41/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lt41/t;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lt41/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lt41/t;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object v2, p0, Lt41/t;->h:Lorg/altbeacon/beacon/Region;

    .line 6
    .line 7
    iget-object v3, p0, Lt41/t;->g:Lt41/v;

    .line 8
    .line 9
    const-string v4, "getName(...)"

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lt41/t;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lvy0/b0;

    .line 17
    .line 18
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    sget-object p1, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 24
    .line 25
    iget-object p1, p1, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 26
    .line 27
    iget-object p1, p1, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 28
    .line 29
    sget-object v0, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    .line 30
    .line 31
    if-ne p1, v0, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance v8, Lqf0/d;

    .line 35
    .line 36
    const/16 p1, 0x1c

    .line 37
    .line 38
    invoke-direct {v8, p1}, Lqf0/d;-><init>(I)V

    .line 39
    .line 40
    .line 41
    new-instance v5, Lt51/j;

    .line 42
    .line 43
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v10

    .line 47
    invoke-static {v4}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v11

    .line 51
    const-string v6, "BeaconScanner"

    .line 52
    .line 53
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 54
    .line 55
    const/4 v9, 0x0

    .line 56
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 60
    .line 61
    .line 62
    invoke-static {v2}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    const/4 p1, 0x1

    .line 67
    invoke-static {v3, p0, p1}, Lt41/v;->a(Lt41/v;Lt41/b;Z)V

    .line 68
    .line 69
    .line 70
    :goto_0
    return-object v1

    .line 71
    :pswitch_0
    iget-object v0, p0, Lt41/t;->e:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Lvy0/b0;

    .line 74
    .line 75
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 76
    .line 77
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lt41/t;->f:Lt41/z;

    .line 81
    .line 82
    invoke-virtual {p0}, Lt41/z;->a()Lorg/altbeacon/beacon/BeaconManager;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {p0, v2}, Lorg/altbeacon/beacon/BeaconManager;->startRangingBeacons(Lorg/altbeacon/beacon/Region;)V

    .line 87
    .line 88
    .line 89
    sget-object p0, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 90
    .line 91
    iget-object p0, p0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 92
    .line 93
    iget-object p0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 94
    .line 95
    sget-object p1, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    .line 96
    .line 97
    if-ne p0, p1, :cond_1

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_1
    new-instance v8, Lqf0/d;

    .line 101
    .line 102
    const/16 p0, 0x1b

    .line 103
    .line 104
    invoke-direct {v8, p0}, Lqf0/d;-><init>(I)V

    .line 105
    .line 106
    .line 107
    new-instance v5, Lt51/j;

    .line 108
    .line 109
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v10

    .line 113
    invoke-static {v4}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v11

    .line 117
    const-string v6, "BeaconScanner"

    .line 118
    .line 119
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 120
    .line 121
    const/4 v9, 0x0

    .line 122
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 126
    .line 127
    .line 128
    invoke-static {v2}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    const/4 p1, 0x0

    .line 133
    invoke-static {v3, p0, p1}, Lt41/v;->a(Lt41/v;Lt41/b;Z)V

    .line 134
    .line 135
    .line 136
    :goto_1
    return-object v1

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
