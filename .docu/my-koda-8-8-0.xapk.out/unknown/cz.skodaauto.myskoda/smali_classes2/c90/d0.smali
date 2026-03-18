.class public final Lc90/d0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc90/g0;


# direct methods
.method public synthetic constructor <init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc90/d0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc90/d0;->f:Lc90/g0;

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
    iget p1, p0, Lc90/d0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc90/d0;

    .line 7
    .line 8
    iget-object p0, p0, Lc90/d0;->f:Lc90/g0;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc90/d0;-><init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc90/d0;

    .line 16
    .line 17
    iget-object p0, p0, Lc90/d0;->f:Lc90/g0;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc90/d0;-><init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc90/d0;

    .line 25
    .line 26
    iget-object p0, p0, Lc90/d0;->f:Lc90/g0;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc90/d0;-><init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lc90/d0;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc90/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc90/d0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc90/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc90/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc90/d0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc90/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc90/d0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc90/d0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc90/d0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lc90/d0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lc90/d0;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Lc90/d0;->f:Lc90/g0;

    .line 38
    .line 39
    iget-object p1, p1, Lc90/g0;->j:La90/g;

    .line 40
    .line 41
    iput v3, p0, Lc90/d0;->e:I

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iget-object v1, p1, La90/g;->b:La90/u;

    .line 47
    .line 48
    check-cast v1, Ly80/b;

    .line 49
    .line 50
    iget-object v3, v1, Ly80/b;->a:Lxl0/f;

    .line 51
    .line 52
    new-instance v4, Lus0/a;

    .line 53
    .line 54
    const/4 v5, 0x5

    .line 55
    const/4 v6, 0x0

    .line 56
    invoke-direct {v4, v1, v6, v5}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    new-instance v1, Lxy/f;

    .line 60
    .line 61
    invoke-direct {v1, v5}, Lxy/f;-><init>(I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v3, v4, v1, v6}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    new-instance v3, La60/f;

    .line 69
    .line 70
    const/4 v4, 0x3

    .line 71
    invoke-direct {v3, p1, v6, v4}, La60/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 72
    .line 73
    .line 74
    new-instance p1, Lne0/n;

    .line 75
    .line 76
    const/4 v4, 0x5

    .line 77
    invoke-direct {p1, v1, v3, v4}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 78
    .line 79
    .line 80
    if-ne p1, v0, :cond_3

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    :goto_0
    check-cast p1, Lyy0/i;

    .line 84
    .line 85
    iput v2, p0, Lc90/d0;->e:I

    .line 86
    .line 87
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-ne p0, v0, :cond_4

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    :goto_2
    return-object v0

    .line 97
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v1, p0, Lc90/d0;->e:I

    .line 100
    .line 101
    iget-object v2, p0, Lc90/d0;->f:Lc90/g0;

    .line 102
    .line 103
    const/4 v3, 0x1

    .line 104
    if-eqz v1, :cond_6

    .line 105
    .line 106
    if-ne v1, v3, :cond_5

    .line 107
    .line 108
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 115
    .line 116
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-object p1, v2, Lc90/g0;->n:Lfj0/i;

    .line 124
    .line 125
    iput v3, p0, Lc90/d0;->e:I

    .line 126
    .line 127
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, p0}, Lfj0/i;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-ne p0, v0, :cond_7

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_7
    :goto_3
    iget-object p0, v2, Lc90/g0;->o:Lnr0/a;

    .line 138
    .line 139
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    :goto_4
    return-object v0

    .line 145
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 146
    .line 147
    iget v1, p0, Lc90/d0;->e:I

    .line 148
    .line 149
    iget-object v2, p0, Lc90/d0;->f:Lc90/g0;

    .line 150
    .line 151
    const/4 v3, 0x2

    .line 152
    const/4 v4, 0x1

    .line 153
    if-eqz v1, :cond_a

    .line 154
    .line 155
    if-eq v1, v4, :cond_9

    .line 156
    .line 157
    if-ne v1, v3, :cond_8

    .line 158
    .line 159
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    goto :goto_6

    .line 163
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 164
    .line 165
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 166
    .line 167
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw p0

    .line 171
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    goto :goto_5

    .line 175
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    iget-object p1, v2, Lc90/g0;->i:La90/t;

    .line 179
    .line 180
    iput v4, p0, Lc90/d0;->e:I

    .line 181
    .line 182
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    iget-object v9, p1, La90/t;->a:La90/q;

    .line 186
    .line 187
    move-object v1, v9

    .line 188
    check-cast v1, Ly80/a;

    .line 189
    .line 190
    iget-object v4, v1, Ly80/a;->c:Lyy0/l1;

    .line 191
    .line 192
    iget-object v1, v1, Ly80/a;->d:Lez0/c;

    .line 193
    .line 194
    new-instance v5, La90/r;

    .line 195
    .line 196
    const/4 v6, 0x0

    .line 197
    const/4 v7, 0x0

    .line 198
    const-class v8, La90/q;

    .line 199
    .line 200
    const-string v10, "isDataValid"

    .line 201
    .line 202
    const-string v11, "isDataValid()Z"

    .line 203
    .line 204
    invoke-direct/range {v5 .. v11}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    new-instance v6, La90/s;

    .line 208
    .line 209
    const/4 v7, 0x0

    .line 210
    const/4 v8, 0x0

    .line 211
    invoke-direct {v6, p1, v7, v8}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 212
    .line 213
    .line 214
    invoke-static {v4, v1, v5, v6}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 215
    .line 216
    .line 217
    move-result-object p1

    .line 218
    if-ne p1, v0, :cond_b

    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_b
    :goto_5
    check-cast p1, Lyy0/i;

    .line 222
    .line 223
    new-instance v1, La60/b;

    .line 224
    .line 225
    const/16 v4, 0x8

    .line 226
    .line 227
    invoke-direct {v1, v2, v4}, La60/b;-><init>(Lql0/j;I)V

    .line 228
    .line 229
    .line 230
    iput v3, p0, Lc90/d0;->e:I

    .line 231
    .line 232
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    if-ne p0, v0, :cond_c

    .line 237
    .line 238
    goto :goto_7

    .line 239
    :cond_c
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    :goto_7
    return-object v0

    .line 242
    nop

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
