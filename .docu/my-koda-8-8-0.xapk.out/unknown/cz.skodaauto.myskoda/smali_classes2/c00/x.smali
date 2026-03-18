.class public final Lc00/x;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc00/i0;


# direct methods
.method public synthetic constructor <init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lc00/x;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lc00/x;->f:Lc00/i0;

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
    .locals 1

    .line 1
    iget p1, p0, Lc00/x;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc00/x;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/x;->f:Lc00/i0;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, v0, p0, p2}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc00/x;

    .line 16
    .line 17
    iget-object p0, p0, Lc00/x;->f:Lc00/i0;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, v0, p0, p2}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc00/x;

    .line 25
    .line 26
    iget-object p0, p0, Lc00/x;->f:Lc00/i0;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, v0, p0, p2}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lc00/x;

    .line 34
    .line 35
    iget-object p0, p0, Lc00/x;->f:Lc00/i0;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, v0, p0, p2}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lc00/x;

    .line 43
    .line 44
    iget-object p0, p0, Lc00/x;->f:Lc00/i0;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, v0, p0, p2}, Lc00/x;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

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
    iget v0, p0, Lc00/x;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/x;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc00/x;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc00/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc00/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc00/x;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc00/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lc00/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lc00/x;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lc00/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lc00/x;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lc00/x;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lc00/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 14

    .line 1
    iget v0, p0, Lc00/x;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x5

    .line 5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    iget-object v5, p0, Lc00/x;->f:Lc00/i0;

    .line 10
    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v7, 0x0

    .line 13
    const/4 v8, 0x1

    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    iget v1, p0, Lc00/x;->e:I

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    if-ne v1, v8, :cond_0

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object p1, v5, Lc00/i0;->i:Llb0/b;

    .line 39
    .line 40
    new-instance v1, Llb0/a;

    .line 41
    .line 42
    invoke-direct {v1, v7}, Llb0/a;-><init>(Z)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p1, v1}, Llb0/b;->a(Llb0/a;)Lzy0/j;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    new-instance v1, Lc00/v;

    .line 50
    .line 51
    invoke-direct {v1, v2, v5, v6}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 52
    .line 53
    .line 54
    invoke-static {v1, p1}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    new-instance v1, Lc00/g0;

    .line 59
    .line 60
    invoke-direct {v1, v5, v8}, Lc00/g0;-><init>(Lc00/i0;I)V

    .line 61
    .line 62
    .line 63
    iput v8, p0, Lc00/x;->e:I

    .line 64
    .line 65
    invoke-virtual {p1, v1, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    if-ne p0, v0, :cond_2

    .line 70
    .line 71
    move-object v3, v0

    .line 72
    :cond_2
    :goto_0
    return-object v3

    .line 73
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 74
    .line 75
    iget v1, p0, Lc00/x;->e:I

    .line 76
    .line 77
    if-eqz v1, :cond_4

    .line 78
    .line 79
    if-ne v1, v8, :cond_3

    .line 80
    .line 81
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 86
    .line 87
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iput v8, p0, Lc00/x;->e:I

    .line 95
    .line 96
    iget-object p1, v5, Lc00/i0;->y:Llb0/g;

    .line 97
    .line 98
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    check-cast p1, Lyy0/i;

    .line 103
    .line 104
    new-instance v1, Lc00/e0;

    .line 105
    .line 106
    invoke-direct {v1, v7, v5, v6}, Lc00/e0;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 107
    .line 108
    .line 109
    invoke-static {p1, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    if-ne p0, v0, :cond_5

    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_5
    move-object p0, v3

    .line 121
    :goto_1
    if-ne p0, v0, :cond_6

    .line 122
    .line 123
    move-object v3, v0

    .line 124
    :cond_6
    :goto_2
    return-object v3

    .line 125
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 126
    .line 127
    iget v9, p0, Lc00/x;->e:I

    .line 128
    .line 129
    if-eqz v9, :cond_8

    .line 130
    .line 131
    if-ne v9, v8, :cond_7

    .line 132
    .line 133
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    iput v8, p0, Lc00/x;->e:I

    .line 147
    .line 148
    iget-object p1, v5, Lc00/i0;->n:Llb0/p;

    .line 149
    .line 150
    invoke-virtual {p1, v7}, Llb0/p;->b(Z)Lyy0/i;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    iget-object v4, v5, Lc00/i0;->w:Llb0/i;

    .line 155
    .line 156
    sget-object v9, Lmb0/j;->f:Lmb0/j;

    .line 157
    .line 158
    invoke-virtual {v4, v9}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 159
    .line 160
    .line 161
    move-result-object v9

    .line 162
    sget-object v10, Lmb0/j;->g:Lmb0/j;

    .line 163
    .line 164
    invoke-virtual {v4, v10}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 165
    .line 166
    .line 167
    move-result-object v10

    .line 168
    sget-object v11, Lmb0/j;->l:Lmb0/j;

    .line 169
    .line 170
    invoke-virtual {v4, v11}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 171
    .line 172
    .line 173
    move-result-object v11

    .line 174
    sget-object v12, Lmb0/j;->n:Lmb0/j;

    .line 175
    .line 176
    invoke-virtual {v4, v12}, Llb0/i;->b(Lmb0/j;)Lyy0/x;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    new-instance v12, Ltz/h0;

    .line 181
    .line 182
    const/4 v13, 0x2

    .line 183
    invoke-direct {v12, v13, v6}, Ltz/h0;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 184
    .line 185
    .line 186
    new-array v2, v2, [Lyy0/i;

    .line 187
    .line 188
    aput-object p1, v2, v7

    .line 189
    .line 190
    aput-object v9, v2, v8

    .line 191
    .line 192
    aput-object v10, v2, v13

    .line 193
    .line 194
    aput-object v11, v2, v1

    .line 195
    .line 196
    const/4 p1, 0x4

    .line 197
    aput-object v4, v2, p1

    .line 198
    .line 199
    new-instance p1, Lyy0/f1;

    .line 200
    .line 201
    invoke-direct {p1, v2, v12}, Lyy0/f1;-><init>([Lyy0/i;Lay0/r;)V

    .line 202
    .line 203
    .line 204
    invoke-static {p1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    new-instance v1, La7/o;

    .line 209
    .line 210
    const/16 v2, 0x10

    .line 211
    .line 212
    invoke-direct {v1, v5, v6, v2}, La7/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 213
    .line 214
    .line 215
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    if-ne p0, v0, :cond_9

    .line 220
    .line 221
    goto :goto_3

    .line 222
    :cond_9
    move-object p0, v3

    .line 223
    :goto_3
    if-ne p0, v0, :cond_a

    .line 224
    .line 225
    move-object v3, v0

    .line 226
    :cond_a
    :goto_4
    return-object v3

    .line 227
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 228
    .line 229
    iget v7, p0, Lc00/x;->e:I

    .line 230
    .line 231
    if-eqz v7, :cond_c

    .line 232
    .line 233
    if-ne v7, v8, :cond_b

    .line 234
    .line 235
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    goto :goto_5

    .line 239
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 240
    .line 241
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    throw p0

    .line 245
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    iget-object p1, v5, Lc00/i0;->B:Lyy0/c2;

    .line 249
    .line 250
    iget-object v4, v5, Lc00/i0;->C:Lyy0/c2;

    .line 251
    .line 252
    new-instance v7, Lal0/y0;

    .line 253
    .line 254
    invoke-direct {v7, v1, v6, v8}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 255
    .line 256
    .line 257
    new-instance v1, Lbn0/f;

    .line 258
    .line 259
    invoke-direct {v1, p1, v4, v7, v2}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 260
    .line 261
    .line 262
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 263
    .line 264
    .line 265
    move-result-object p1

    .line 266
    new-instance v1, Lc/m;

    .line 267
    .line 268
    invoke-direct {v1, v5, v6, v8}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 269
    .line 270
    .line 271
    iput v8, p0, Lc00/x;->e:I

    .line 272
    .line 273
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    if-ne p0, v0, :cond_d

    .line 278
    .line 279
    move-object v3, v0

    .line 280
    :cond_d
    :goto_5
    return-object v3

    .line 281
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 282
    .line 283
    iget v1, p0, Lc00/x;->e:I

    .line 284
    .line 285
    if-eqz v1, :cond_f

    .line 286
    .line 287
    if-ne v1, v8, :cond_e

    .line 288
    .line 289
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    goto :goto_6

    .line 293
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 294
    .line 295
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    throw p0

    .line 299
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    iget-object p1, v5, Lc00/i0;->o:Lkf0/v;

    .line 303
    .line 304
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object p1

    .line 308
    check-cast p1, Lyy0/i;

    .line 309
    .line 310
    sget-object v1, Lss0/e;->g:Lss0/e;

    .line 311
    .line 312
    new-instance v2, Lc00/v;

    .line 313
    .line 314
    invoke-direct {v2, v7, v5, v6}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 315
    .line 316
    .line 317
    invoke-static {p1, v1, v2}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 318
    .line 319
    .line 320
    move-result-object p1

    .line 321
    new-instance v2, Lc00/v;

    .line 322
    .line 323
    invoke-direct {v2, v8, v5, v6}, Lc00/v;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 324
    .line 325
    .line 326
    invoke-static {p1, v1, v2}, Llp/rf;->c(Lzy0/j;Lss0/e;Lay0/n;)Lzy0/j;

    .line 327
    .line 328
    .line 329
    move-result-object p1

    .line 330
    new-instance v1, Lc00/w;

    .line 331
    .line 332
    invoke-direct {v1, v7, v5, v6}, Lc00/w;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 333
    .line 334
    .line 335
    iput v8, p0, Lc00/x;->e:I

    .line 336
    .line 337
    invoke-static {v1, p0, p1}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    if-ne p0, v0, :cond_10

    .line 342
    .line 343
    move-object v3, v0

    .line 344
    :cond_10
    :goto_6
    return-object v3

    .line 345
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
