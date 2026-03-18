.class public final Lw30/v0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lw30/x0;


# direct methods
.method public synthetic constructor <init>(Lw30/x0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lw30/v0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/v0;->f:Lw30/x0;

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
    iget p1, p0, Lw30/v0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lw30/v0;

    .line 7
    .line 8
    iget-object p0, p0, Lw30/v0;->f:Lw30/x0;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lw30/v0;-><init>(Lw30/x0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lw30/v0;

    .line 16
    .line 17
    iget-object p0, p0, Lw30/v0;->f:Lw30/x0;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lw30/v0;-><init>(Lw30/x0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lw30/v0;

    .line 25
    .line 26
    iget-object p0, p0, Lw30/v0;->f:Lw30/x0;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lw30/v0;-><init>(Lw30/x0;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lw30/v0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lw30/v0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lw30/v0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lw30/v0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lw30/v0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lw30/v0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lw30/v0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lw30/v0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lw30/v0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lw30/v0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lw30/v0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lw30/v0;->e:I

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
    goto :goto_0

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
    iget-object p1, p0, Lw30/v0;->f:Lw30/x0;

    .line 31
    .line 32
    iget-object v1, p1, Lw30/x0;->i:Lu30/k0;

    .line 33
    .line 34
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Lw30/w0;

    .line 39
    .line 40
    iget-boolean v3, v3, Lw30/w0;->d:Z

    .line 41
    .line 42
    iget-object v1, v1, Lu30/k0;->a:Lu30/m0;

    .line 43
    .line 44
    check-cast v1, Ls30/i;

    .line 45
    .line 46
    iget-object v4, v1, Ls30/i;->a:Lxl0/f;

    .line 47
    .line 48
    new-instance v5, Ls30/e;

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    const/4 v7, 0x1

    .line 52
    invoke-direct {v5, v1, v3, v6, v7}, Ls30/e;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v4, v5}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    new-instance v3, Lw30/u0;

    .line 64
    .line 65
    const/4 v4, 0x1

    .line 66
    invoke-direct {v3, p1, v4}, Lw30/u0;-><init>(Lw30/x0;I)V

    .line 67
    .line 68
    .line 69
    iput v2, p0, Lw30/v0;->e:I

    .line 70
    .line 71
    invoke-virtual {v1, v3, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-ne p0, v0, :cond_2

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    :goto_1
    return-object v0

    .line 81
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    iget v1, p0, Lw30/v0;->e:I

    .line 84
    .line 85
    const/4 v2, 0x1

    .line 86
    if-eqz v1, :cond_4

    .line 87
    .line 88
    if-ne v1, v2, :cond_3

    .line 89
    .line 90
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 97
    .line 98
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object p1, p0, Lw30/v0;->f:Lw30/x0;

    .line 106
    .line 107
    iget-object v1, p1, Lw30/x0;->j:Lwr0/i;

    .line 108
    .line 109
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    check-cast v1, Lyy0/i;

    .line 114
    .line 115
    new-instance v3, Ls10/a0;

    .line 116
    .line 117
    const/4 v4, 0x0

    .line 118
    const/16 v5, 0x1a

    .line 119
    .line 120
    invoke-direct {v3, p1, v4, v5}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 121
    .line 122
    .line 123
    iput v2, p0, Lw30/v0;->e:I

    .line 124
    .line 125
    invoke-static {v3, p0, v1}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-ne p0, v0, :cond_5

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    :goto_3
    return-object v0

    .line 135
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 136
    .line 137
    iget v1, p0, Lw30/v0;->e:I

    .line 138
    .line 139
    const/4 v2, 0x1

    .line 140
    if-eqz v1, :cond_7

    .line 141
    .line 142
    if-ne v1, v2, :cond_6

    .line 143
    .line 144
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 149
    .line 150
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 151
    .line 152
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    throw p0

    .line 156
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iget-object p1, p0, Lw30/v0;->f:Lw30/x0;

    .line 160
    .line 161
    iget-object v1, p1, Lw30/x0;->h:Lu30/h;

    .line 162
    .line 163
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    check-cast v1, Lyy0/i;

    .line 168
    .line 169
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    new-instance v3, Lw30/u0;

    .line 174
    .line 175
    const/4 v4, 0x0

    .line 176
    invoke-direct {v3, p1, v4}, Lw30/u0;-><init>(Lw30/x0;I)V

    .line 177
    .line 178
    .line 179
    iput v2, p0, Lw30/v0;->e:I

    .line 180
    .line 181
    invoke-virtual {v1, v3, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    if-ne p0, v0, :cond_8

    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    :goto_5
    return-object v0

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
