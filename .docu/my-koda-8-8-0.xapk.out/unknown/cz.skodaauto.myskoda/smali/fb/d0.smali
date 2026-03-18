.class public final Lfb/d0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lfb/f0;


# direct methods
.method public synthetic constructor <init>(Lfb/f0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lfb/d0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfb/d0;->f:Lfb/f0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lfb/d0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lfb/d0;

    .line 7
    .line 8
    iget-object p0, p0, Lfb/d0;->f:Lfb/f0;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lfb/d0;-><init>(Lfb/f0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lfb/d0;

    .line 16
    .line 17
    iget-object p0, p0, Lfb/d0;->f:Lfb/f0;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lfb/d0;-><init>(Lfb/f0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lfb/d0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lfb/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lfb/d0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lfb/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lfb/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lfb/d0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lfb/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lfb/d0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lfb/d0;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lfb/d0;->f:Lfb/f0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lfb/x; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_1

    .line 23
    :catch_0
    move-exception p0

    .line 24
    goto :goto_2

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :try_start_1
    iget-object p1, v2, Lfb/f0;->m:Lvy0/k1;

    .line 37
    .line 38
    new-instance v1, Lfb/d0;

    .line 39
    .line 40
    const/4 v4, 0x0

    .line 41
    const/4 v5, 0x0

    .line 42
    invoke-direct {v1, v2, v5, v4}, Lfb/d0;-><init>(Lfb/f0;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput v3, p0, Lfb/d0;->e:I

    .line 46
    .line 47
    invoke-static {p1, v1, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    if-ne p1, v0, :cond_2

    .line 52
    .line 53
    goto :goto_4

    .line 54
    :cond_2
    :goto_0
    check-cast p1, Lfb/c0;
    :try_end_1
    .catch Lfb/x; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :goto_1
    sget-object p1, Lfb/g0;->a:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    const-string v1, "Unexpected error in WorkerWrapper"

    .line 64
    .line 65
    invoke-virtual {v0, p1, v1, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 66
    .line 67
    .line 68
    new-instance p1, Lfb/z;

    .line 69
    .line 70
    invoke-direct {p1}, Lfb/z;-><init>()V

    .line 71
    .line 72
    .line 73
    goto :goto_3

    .line 74
    :catch_1
    new-instance p1, Lfb/z;

    .line 75
    .line 76
    invoke-direct {p1}, Lfb/z;-><init>()V

    .line 77
    .line 78
    .line 79
    goto :goto_3

    .line 80
    :goto_2
    new-instance p1, Lfb/b0;

    .line 81
    .line 82
    iget p0, p0, Lfb/x;->d:I

    .line 83
    .line 84
    invoke-direct {p1, p0}, Lfb/b0;-><init>(I)V

    .line 85
    .line 86
    .line 87
    :goto_3
    iget-object p0, v2, Lfb/f0;->h:Landroidx/work/impl/WorkDatabase;

    .line 88
    .line 89
    new-instance v0, Lcom/google/firebase/messaging/h;

    .line 90
    .line 91
    const/4 v1, 0x3

    .line 92
    invoke-direct {v0, v1, p1, v2}, Lcom/google/firebase/messaging/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    new-instance p1, Lh50/q0;

    .line 96
    .line 97
    const/16 v1, 0x17

    .line 98
    .line 99
    invoke-direct {p1, v0, v1}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0, p1}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    const-string p0, "runInTransaction(...)"

    .line 107
    .line 108
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    :goto_4
    return-object v0

    .line 112
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 113
    .line 114
    iget v1, p0, Lfb/d0;->e:I

    .line 115
    .line 116
    const/4 v2, 0x1

    .line 117
    if-eqz v1, :cond_4

    .line 118
    .line 119
    if-ne v1, v2, :cond_3

    .line 120
    .line 121
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 128
    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0

    .line 133
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iput v2, p0, Lfb/d0;->e:I

    .line 137
    .line 138
    iget-object p1, p0, Lfb/d0;->f:Lfb/f0;

    .line 139
    .line 140
    invoke-static {p1, p0}, Lfb/f0;->a(Lfb/f0;Lrx0/c;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    if-ne p1, v0, :cond_5

    .line 145
    .line 146
    move-object p1, v0

    .line 147
    :cond_5
    :goto_5
    return-object p1

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
