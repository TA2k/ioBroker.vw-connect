.class public final Lh40/c1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/f1;


# direct methods
.method public synthetic constructor <init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/c1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/c1;->f:Lh40/f1;

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
    iget p1, p0, Lh40/c1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/c1;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/c1;->f:Lh40/f1;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/c1;-><init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/c1;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/c1;->f:Lh40/f1;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/c1;-><init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh40/c1;

    .line 25
    .line 26
    iget-object p0, p0, Lh40/c1;->f:Lh40/f1;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lh40/c1;-><init>(Lh40/f1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lh40/c1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/c1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/c1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh40/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh40/c1;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh40/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 13

    .line 1
    iget v0, p0, Lh40/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh40/c1;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v3, p0, Lh40/c1;->f:Lh40/f1;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    if-eqz v1, :cond_3

    .line 17
    .line 18
    if-eq v1, v5, :cond_2

    .line 19
    .line 20
    if-ne v1, v4, :cond_1

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    move-object v0, v2

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p1, v3, Lh40/f1;->q:Lbq0/j;

    .line 43
    .line 44
    iput v5, p0, Lh40/c1;->e:I

    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget-object v10, p1, Lbq0/j;->a:Lbq0/h;

    .line 50
    .line 51
    move-object v1, v10

    .line 52
    check-cast v1, Lzp0/c;

    .line 53
    .line 54
    iget-object v5, v1, Lzp0/c;->o:Lyy0/l1;

    .line 55
    .line 56
    iget-object v1, v1, Lzp0/c;->d:Lez0/c;

    .line 57
    .line 58
    new-instance v6, La90/r;

    .line 59
    .line 60
    const/4 v7, 0x0

    .line 61
    const/4 v8, 0x2

    .line 62
    const-class v9, Lbq0/h;

    .line 63
    .line 64
    const-string v11, "isServiceDetailValid"

    .line 65
    .line 66
    const-string v12, "isServiceDetailValid()Z"

    .line 67
    .line 68
    invoke-direct/range {v6 .. v12}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    new-instance v7, Lbq0/i;

    .line 72
    .line 73
    const/4 v8, 0x0

    .line 74
    const/4 v9, 0x0

    .line 75
    invoke-direct {v7, p1, v8, v9}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v5, v1, v6, v7}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ne p1, v0, :cond_4

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_4
    :goto_0
    check-cast p1, Lyy0/i;

    .line 86
    .line 87
    new-instance v1, Lh40/b1;

    .line 88
    .line 89
    const/4 v5, 0x2

    .line 90
    invoke-direct {v1, v3, v5}, Lh40/b1;-><init>(Lh40/f1;I)V

    .line 91
    .line 92
    .line 93
    iput v4, p0, Lh40/c1;->e:I

    .line 94
    .line 95
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    if-ne p0, v0, :cond_0

    .line 100
    .line 101
    :goto_1
    return-object v0

    .line 102
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    iget v1, p0, Lh40/c1;->e:I

    .line 105
    .line 106
    const/4 v2, 0x1

    .line 107
    if-eqz v1, :cond_6

    .line 108
    .line 109
    if-ne v1, v2, :cond_5

    .line 110
    .line 111
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 116
    .line 117
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, p0, Lh40/c1;->f:Lh40/f1;

    .line 127
    .line 128
    iget-object v1, p1, Lh40/f1;->s:Lf40/l1;

    .line 129
    .line 130
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    check-cast v1, Lyy0/i;

    .line 135
    .line 136
    new-instance v3, Lh40/b1;

    .line 137
    .line 138
    const/4 v4, 0x1

    .line 139
    invoke-direct {v3, p1, v4}, Lh40/b1;-><init>(Lh40/f1;I)V

    .line 140
    .line 141
    .line 142
    iput v2, p0, Lh40/c1;->e:I

    .line 143
    .line 144
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    if-ne p0, v0, :cond_7

    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_7
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 152
    .line 153
    :goto_3
    return-object v0

    .line 154
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 155
    .line 156
    iget v1, p0, Lh40/c1;->e:I

    .line 157
    .line 158
    const/4 v2, 0x1

    .line 159
    if-eqz v1, :cond_9

    .line 160
    .line 161
    if-ne v1, v2, :cond_8

    .line 162
    .line 163
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    goto :goto_4

    .line 167
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 168
    .line 169
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 170
    .line 171
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    throw p0

    .line 175
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    iget-object p1, p0, Lh40/c1;->f:Lh40/f1;

    .line 179
    .line 180
    iget-object v1, p1, Lh40/f1;->i:Lbq0/k;

    .line 181
    .line 182
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    check-cast v1, Lyy0/i;

    .line 187
    .line 188
    new-instance v3, Lh40/b1;

    .line 189
    .line 190
    const/4 v4, 0x0

    .line 191
    invoke-direct {v3, p1, v4}, Lh40/b1;-><init>(Lh40/f1;I)V

    .line 192
    .line 193
    .line 194
    iput v2, p0, Lh40/c1;->e:I

    .line 195
    .line 196
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    if-ne p0, v0, :cond_a

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_a
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    :goto_5
    return-object v0

    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
