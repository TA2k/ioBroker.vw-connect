.class public final Lw40/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lw40/m;


# direct methods
.method public synthetic constructor <init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lw40/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw40/k;->f:Lw40/m;

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
    iget p1, p0, Lw40/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lw40/k;

    .line 7
    .line 8
    iget-object p0, p0, Lw40/k;->f:Lw40/m;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lw40/k;-><init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lw40/k;

    .line 16
    .line 17
    iget-object p0, p0, Lw40/k;->f:Lw40/m;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lw40/k;-><init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lw40/k;

    .line 25
    .line 26
    iget-object p0, p0, Lw40/k;->f:Lw40/m;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lw40/k;-><init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lw40/k;

    .line 34
    .line 35
    iget-object p0, p0, Lw40/k;->f:Lw40/m;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lw40/k;-><init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lw40/k;

    .line 43
    .line 44
    iget-object p0, p0, Lw40/k;->f:Lw40/m;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lw40/k;-><init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lw40/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lw40/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lw40/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lw40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lw40/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lw40/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lw40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lw40/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lw40/k;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lw40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lw40/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lw40/k;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lw40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lw40/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lw40/k;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lw40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lw40/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lw40/k;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-ne v1, v3, :cond_1

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    move-object v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_1
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
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, p0, Lw40/k;->f:Lw40/m;

    .line 34
    .line 35
    iget-object p1, p1, Lw40/m;->n:Lnn0/m;

    .line 36
    .line 37
    iput v3, p0, Lw40/k;->e:I

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, p0}, Lnn0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-ne p0, v0, :cond_0

    .line 47
    .line 48
    :goto_0
    return-object v0

    .line 49
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 50
    .line 51
    iget v1, p0, Lw40/k;->e:I

    .line 52
    .line 53
    const/4 v2, 0x1

    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    if-ne v1, v2, :cond_3

    .line 57
    .line 58
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iget-object p1, p0, Lw40/k;->f:Lw40/m;

    .line 74
    .line 75
    iget-object v1, p1, Lw40/m;->j:Lu40/c;

    .line 76
    .line 77
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    check-cast v3, Lw40/l;

    .line 82
    .line 83
    iget-object v3, v3, Lw40/l;->a:Ljava/lang/String;

    .line 84
    .line 85
    invoke-virtual {v1, v3}, Lu40/c;->a(Ljava/lang/String;)Lyy0/i;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    new-instance v3, Ls90/a;

    .line 90
    .line 91
    const/16 v4, 0xf

    .line 92
    .line 93
    invoke-direct {v3, p1, v4}, Ls90/a;-><init>(Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    iput v2, p0, Lw40/k;->e:I

    .line 97
    .line 98
    check-cast v1, Lyy0/m1;

    .line 99
    .line 100
    invoke-virtual {v1, v3, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v0, :cond_5

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_5
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    :goto_2
    return-object v0

    .line 110
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 111
    .line 112
    iget v1, p0, Lw40/k;->e:I

    .line 113
    .line 114
    const/4 v2, 0x1

    .line 115
    if-eqz v1, :cond_7

    .line 116
    .line 117
    if-ne v1, v2, :cond_6

    .line 118
    .line 119
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 126
    .line 127
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    iget-object p1, p0, Lw40/k;->f:Lw40/m;

    .line 135
    .line 136
    iget-object v1, p1, Lw40/m;->k:Lud0/b;

    .line 137
    .line 138
    iget-object v3, p1, Lw40/m;->p:Lij0/a;

    .line 139
    .line 140
    new-instance v4, Lvd0/a;

    .line 141
    .line 142
    const/4 v5, 0x0

    .line 143
    new-array v6, v5, [Ljava/lang/Object;

    .line 144
    .line 145
    move-object v7, v3

    .line 146
    check-cast v7, Ljj0/f;

    .line 147
    .line 148
    const v8, 0x7f120e02

    .line 149
    .line 150
    .line 151
    invoke-virtual {v7, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    check-cast v7, Lw40/l;

    .line 160
    .line 161
    iget-object v7, v7, Lw40/l;->c:Ljava/lang/String;

    .line 162
    .line 163
    invoke-direct {v4, v6, v7}, Lvd0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v1, v4}, Lud0/b;->a(Lvd0/a;)V

    .line 167
    .line 168
    .line 169
    iget-object p1, p1, Lw40/m;->l:Lrq0/f;

    .line 170
    .line 171
    new-instance v1, Lsq0/c;

    .line 172
    .line 173
    new-array v4, v5, [Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v3, Ljj0/f;

    .line 176
    .line 177
    const v6, 0x7f120dfc

    .line 178
    .line 179
    .line 180
    invoke-virtual {v3, v6, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    const/4 v4, 0x6

    .line 185
    const/4 v6, 0x0

    .line 186
    invoke-direct {v1, v4, v3, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    iput v2, p0, Lw40/k;->e:I

    .line 190
    .line 191
    invoke-virtual {p1, v1, v5, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    if-ne p0, v0, :cond_8

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :cond_8
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 199
    .line 200
    :goto_4
    return-object v0

    .line 201
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 202
    .line 203
    iget v1, p0, Lw40/k;->e:I

    .line 204
    .line 205
    const/4 v2, 0x1

    .line 206
    if-eqz v1, :cond_a

    .line 207
    .line 208
    if-ne v1, v2, :cond_9

    .line 209
    .line 210
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    goto :goto_5

    .line 214
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 215
    .line 216
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 217
    .line 218
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    throw p0

    .line 222
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    iget-object p1, p0, Lw40/k;->f:Lw40/m;

    .line 226
    .line 227
    iget-object v1, p1, Lw40/m;->l:Lrq0/f;

    .line 228
    .line 229
    new-instance v3, Lsq0/c;

    .line 230
    .line 231
    iget-object p1, p1, Lw40/m;->p:Lij0/a;

    .line 232
    .line 233
    const/4 v4, 0x0

    .line 234
    new-array v5, v4, [Ljava/lang/Object;

    .line 235
    .line 236
    check-cast p1, Ljj0/f;

    .line 237
    .line 238
    const v6, 0x7f12019c

    .line 239
    .line 240
    .line 241
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p1

    .line 245
    const/4 v5, 0x6

    .line 246
    const/4 v6, 0x0

    .line 247
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    iput v2, p0, Lw40/k;->e:I

    .line 251
    .line 252
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    if-ne p0, v0, :cond_b

    .line 257
    .line 258
    goto :goto_6

    .line 259
    :cond_b
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 260
    .line 261
    :goto_6
    return-object v0

    .line 262
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 263
    .line 264
    iget v1, p0, Lw40/k;->e:I

    .line 265
    .line 266
    const/4 v2, 0x1

    .line 267
    if-eqz v1, :cond_d

    .line 268
    .line 269
    if-ne v1, v2, :cond_c

    .line 270
    .line 271
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    goto :goto_7

    .line 275
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 276
    .line 277
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 278
    .line 279
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw p0

    .line 283
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    iget-object p1, p0, Lw40/k;->f:Lw40/m;

    .line 287
    .line 288
    iget-object v1, p1, Lw40/m;->i:Lnn0/f;

    .line 289
    .line 290
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v1

    .line 294
    check-cast v1, Lyy0/i;

    .line 295
    .line 296
    new-instance v3, Lh50/y0;

    .line 297
    .line 298
    const/16 v4, 0x15

    .line 299
    .line 300
    invoke-direct {v3, p1, v4}, Lh50/y0;-><init>(Ljava/lang/Object;I)V

    .line 301
    .line 302
    .line 303
    iput v2, p0, Lw40/k;->e:I

    .line 304
    .line 305
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    if-ne p0, v0, :cond_e

    .line 310
    .line 311
    goto :goto_8

    .line 312
    :cond_e
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    :goto_8
    return-object v0

    .line 315
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
