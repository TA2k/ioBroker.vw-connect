.class public final Lc00/e0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lc00/i0;


# direct methods
.method public synthetic constructor <init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lc00/e0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lc00/e0;->h:Lc00/i0;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lc00/e0;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Lc00/e0;

    .line 11
    .line 12
    iget-object p0, p0, Lc00/e0;->h:Lc00/i0;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    invoke-direct {v0, v1, p0, p3}, Lc00/e0;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lc00/e0;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lc00/e0;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lc00/e0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lc00/e0;

    .line 30
    .line 31
    iget-object p0, p0, Lc00/e0;->h:Lc00/i0;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, v1, p0, p3}, Lc00/e0;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lc00/e0;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lc00/e0;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lc00/e0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lc00/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lc00/e0;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lc00/e0;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lc00/e0;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lqr0/q;

    .line 35
    .line 36
    iget-object v3, p0, Lc00/e0;->h:Lc00/i0;

    .line 37
    .line 38
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    check-cast v4, Lc00/d0;

    .line 43
    .line 44
    iget-object v4, v4, Lc00/d0;->d:Lc00/a0;

    .line 45
    .line 46
    sget-object v5, Lc00/a0;->d:Lc00/a0;

    .line 47
    .line 48
    const/4 v6, 0x0

    .line 49
    if-ne v4, v5, :cond_2

    .line 50
    .line 51
    iget-object v4, v3, Lc00/i0;->r:Llb0/k0;

    .line 52
    .line 53
    new-instance v5, Llb0/h0;

    .line 54
    .line 55
    iget-object v3, v3, Lc00/i0;->E:Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-direct {v5, v1, v3}, Llb0/h0;-><init>(Lqr0/q;Ljava/lang/Boolean;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v4, v5}, Llb0/k0;->b(Llb0/h0;)Lyy0/m1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    goto :goto_0

    .line 65
    :cond_2
    iget-object v4, v3, Lc00/i0;->q:Llb0/g0;

    .line 66
    .line 67
    new-instance v5, Llb0/f0;

    .line 68
    .line 69
    iget-object v7, v3, Lc00/i0;->E:Ljava/lang/Boolean;

    .line 70
    .line 71
    invoke-direct {v5, v1, v7}, Llb0/f0;-><init>(Lqr0/q;Ljava/lang/Boolean;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v4, v5}, Llb0/g0;->a(Llb0/f0;)Lam0/i;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    new-instance v4, Lc00/w;

    .line 79
    .line 80
    const/4 v5, 0x3

    .line 81
    invoke-direct {v4, v5, v3, v6}, Lc00/w;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v4, v1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    :goto_0
    iput-object v6, p0, Lc00/e0;->f:Lyy0/j;

    .line 89
    .line 90
    iput-object v6, p0, Lc00/e0;->g:Ljava/lang/Object;

    .line 91
    .line 92
    iput v2, p0, Lc00/e0;->e:I

    .line 93
    .line 94
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v0, :cond_3

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    :goto_2
    return-object v0

    .line 104
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v1, p0, Lc00/e0;->e:I

    .line 107
    .line 108
    const/4 v2, 0x1

    .line 109
    if-eqz v1, :cond_5

    .line 110
    .line 111
    if-ne v1, v2, :cond_4

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 120
    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, p0, Lc00/e0;->f:Lyy0/j;

    .line 129
    .line 130
    iget-object v1, p0, Lc00/e0;->g:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v1, Lne0/t;

    .line 133
    .line 134
    iget-object v1, p0, Lc00/e0;->h:Lc00/i0;

    .line 135
    .line 136
    iget-object v1, v1, Lc00/i0;->i:Llb0/b;

    .line 137
    .line 138
    new-instance v3, Llb0/a;

    .line 139
    .line 140
    const/4 v4, 0x0

    .line 141
    invoke-direct {v3, v4}, Llb0/a;-><init>(Z)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v1, v3}, Llb0/b;->a(Llb0/a;)Lzy0/j;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    const/4 v3, 0x0

    .line 149
    iput-object v3, p0, Lc00/e0;->f:Lyy0/j;

    .line 150
    .line 151
    iput-object v3, p0, Lc00/e0;->g:Ljava/lang/Object;

    .line 152
    .line 153
    iput v2, p0, Lc00/e0;->e:I

    .line 154
    .line 155
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v0, :cond_6

    .line 160
    .line 161
    goto :goto_4

    .line 162
    :cond_6
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    :goto_4
    return-object v0

    .line 165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
