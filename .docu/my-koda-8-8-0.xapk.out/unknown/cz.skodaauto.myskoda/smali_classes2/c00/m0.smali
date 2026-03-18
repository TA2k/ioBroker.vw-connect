.class public final Lc00/m0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc00/q0;


# direct methods
.method public synthetic constructor <init>(Lc00/q0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/m0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/m0;->f:Lc00/q0;

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
    iget p1, p0, Lc00/m0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc00/m0;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/m0;->f:Lc00/q0;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc00/m0;-><init>(Lc00/q0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc00/m0;

    .line 16
    .line 17
    iget-object p0, p0, Lc00/m0;->f:Lc00/q0;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc00/m0;-><init>(Lc00/q0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lc00/m0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/m0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/m0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/m0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/m0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc00/m0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc00/m0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lc00/m0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    .line 5
    .line 6
    iget-object v3, p0, Lc00/m0;->f:Lc00/q0;

    .line 7
    .line 8
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object v0, v3, Lc00/q0;->q:Llb0/i;

    .line 15
    .line 16
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v7, p0, Lc00/m0;->e:I

    .line 19
    .line 20
    if-eqz v7, :cond_1

    .line 21
    .line 22
    if-ne v7, v5, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    sget-object p1, Lmb0/j;->k:Lmb0/j;

    .line 38
    .line 39
    invoke-virtual {v0, p1}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    sget-object v2, Lmb0/j;->j:Lmb0/j;

    .line 44
    .line 45
    invoke-virtual {v0, v2}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    sget-object v7, Lmb0/j;->h:Lmb0/j;

    .line 50
    .line 51
    invoke-virtual {v0, v7}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    sget-object v8, Lmb0/j;->i:Lmb0/j;

    .line 56
    .line 57
    invoke-virtual {v0, v8}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    const/4 v8, 0x4

    .line 62
    new-array v8, v8, [Lyy0/i;

    .line 63
    .line 64
    const/4 v9, 0x0

    .line 65
    aput-object p1, v8, v9

    .line 66
    .line 67
    aput-object v2, v8, v5

    .line 68
    .line 69
    const/4 p1, 0x2

    .line 70
    aput-object v7, v8, p1

    .line 71
    .line 72
    const/4 p1, 0x3

    .line 73
    aput-object v0, v8, p1

    .line 74
    .line 75
    invoke-static {v8}, Lyy0/u;->D([Lyy0/i;)Lyy0/e;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    new-instance v0, La60/b;

    .line 80
    .line 81
    invoke-direct {v0, v3, v1}, La60/b;-><init>(Lql0/j;I)V

    .line 82
    .line 83
    .line 84
    iput v5, p0, Lc00/m0;->e:I

    .line 85
    .line 86
    new-instance v1, Lwk0/o0;

    .line 87
    .line 88
    const/16 v2, 0x11

    .line 89
    .line 90
    invoke-direct {v1, v0, v2}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, v1, p0}, Lzy0/e;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    if-ne p0, v6, :cond_2

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_2
    move-object p0, v4

    .line 101
    :goto_0
    if-ne p0, v6, :cond_3

    .line 102
    .line 103
    move-object v4, v6

    .line 104
    :cond_3
    :goto_1
    return-object v4

    .line 105
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 106
    .line 107
    iget v6, p0, Lc00/m0;->e:I

    .line 108
    .line 109
    if-eqz v6, :cond_5

    .line 110
    .line 111
    if-ne v6, v5, :cond_4

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, v3, Lc00/q0;->j:Llb0/p;

    .line 127
    .line 128
    invoke-virtual {p1, v5}, Llb0/p;->b(Z)Lyy0/i;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    new-instance v2, Lac0/e;

    .line 133
    .line 134
    invoke-direct {v2, v3, v1}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 135
    .line 136
    .line 137
    iput v5, p0, Lc00/m0;->e:I

    .line 138
    .line 139
    check-cast p1, Lzy0/f;

    .line 140
    .line 141
    invoke-virtual {p1, v2, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    if-ne p0, v0, :cond_6

    .line 146
    .line 147
    move-object v4, v0

    .line 148
    :cond_6
    :goto_2
    return-object v4

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
