.class public final Ltz/k0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/n0;


# direct methods
.method public synthetic constructor <init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/k0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/k0;->f:Ltz/n0;

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
    iget p1, p0, Ltz/k0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/k0;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/k0;->f:Ltz/n0;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/k0;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/k0;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/k0;->f:Ltz/n0;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/k0;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ltz/k0;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/k0;->f:Ltz/n0;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ltz/k0;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ltz/k0;

    .line 34
    .line 35
    iget-object p0, p0, Ltz/k0;->f:Ltz/n0;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ltz/k0;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ltz/k0;

    .line 43
    .line 44
    iget-object p0, p0, Ltz/k0;->f:Ltz/n0;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ltz/k0;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltz/k0;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/k0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/k0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/k0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/k0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/k0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/k0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ltz/k0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ltz/k0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ltz/k0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ltz/k0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ltz/k0;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ltz/k0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ltz/k0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ltz/k0;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ltz/k0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltz/k0;->d:I

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x2

    .line 9
    iget-object v6, v0, Ltz/k0;->f:Ltz/n0;

    .line 10
    .line 11
    const-string v7, "call to \'resume\' before \'invoke\' with coroutine"

    .line 12
    .line 13
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    const/4 v9, 0x1

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v10, v0, Ltz/k0;->e:I

    .line 22
    .line 23
    if-eqz v10, :cond_1

    .line 24
    .line 25
    if-ne v10, v9, :cond_0

    .line 26
    .line 27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto/16 :goto_3

    .line 31
    .line 32
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iput v9, v0, Ltz/k0;->e:I

    .line 42
    .line 43
    iget-object v7, v6, Ltz/n0;->k:Lqd0/p0;

    .line 44
    .line 45
    invoke-static {v7}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v7

    .line 49
    check-cast v7, Lyy0/i;

    .line 50
    .line 51
    iget-object v10, v6, Ltz/n0;->l:Lqd0/j0;

    .line 52
    .line 53
    sget-object v11, Lrd0/f0;->e:Lrd0/f0;

    .line 54
    .line 55
    invoke-virtual {v10, v11}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 56
    .line 57
    .line 58
    move-result-object v11

    .line 59
    new-instance v12, Lru0/l;

    .line 60
    .line 61
    const/16 v13, 0x9

    .line 62
    .line 63
    invoke-direct {v12, v5, v3, v13}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 64
    .line 65
    .line 66
    new-instance v13, Lne0/n;

    .line 67
    .line 68
    invoke-direct {v13, v12, v11}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 69
    .line 70
    .line 71
    sget-object v11, Lrd0/f0;->h:Lrd0/f0;

    .line 72
    .line 73
    invoke-virtual {v10, v11}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 74
    .line 75
    .line 76
    move-result-object v11

    .line 77
    new-instance v12, Lru0/l;

    .line 78
    .line 79
    const/16 v14, 0xa

    .line 80
    .line 81
    invoke-direct {v12, v5, v3, v14}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 82
    .line 83
    .line 84
    new-instance v14, Lne0/n;

    .line 85
    .line 86
    invoke-direct {v14, v12, v11}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 87
    .line 88
    .line 89
    sget-object v11, Lrd0/f0;->i:Lrd0/f0;

    .line 90
    .line 91
    invoke-virtual {v10, v11}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 92
    .line 93
    .line 94
    move-result-object v11

    .line 95
    new-instance v12, Lru0/l;

    .line 96
    .line 97
    const/16 v15, 0xb

    .line 98
    .line 99
    invoke-direct {v12, v5, v3, v15}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 100
    .line 101
    .line 102
    new-instance v15, Lne0/n;

    .line 103
    .line 104
    invoke-direct {v15, v12, v11}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 105
    .line 106
    .line 107
    sget-object v11, Lrd0/f0;->j:Lrd0/f0;

    .line 108
    .line 109
    invoke-virtual {v10, v11}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 110
    .line 111
    .line 112
    move-result-object v11

    .line 113
    new-instance v12, Lru0/l;

    .line 114
    .line 115
    move/from16 v16, v9

    .line 116
    .line 117
    const/16 v9, 0xc

    .line 118
    .line 119
    invoke-direct {v12, v5, v3, v9}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 120
    .line 121
    .line 122
    new-instance v9, Lne0/n;

    .line 123
    .line 124
    invoke-direct {v9, v12, v11}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 125
    .line 126
    .line 127
    sget-object v11, Lrd0/f0;->l:Lrd0/f0;

    .line 128
    .line 129
    invoke-virtual {v10, v11}, Lqd0/j0;->b(Lrd0/f0;)Lyy0/i;

    .line 130
    .line 131
    .line 132
    move-result-object v10

    .line 133
    new-instance v11, Lru0/l;

    .line 134
    .line 135
    const/16 v12, 0xd

    .line 136
    .line 137
    invoke-direct {v11, v5, v3, v12}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 138
    .line 139
    .line 140
    new-instance v12, Lne0/n;

    .line 141
    .line 142
    invoke-direct {v12, v11, v10}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 143
    .line 144
    .line 145
    new-instance v10, Ltz/h0;

    .line 146
    .line 147
    invoke-direct {v10, v4, v3}, Ltz/h0;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 148
    .line 149
    .line 150
    new-array v2, v2, [Lyy0/i;

    .line 151
    .line 152
    aput-object v13, v2, v4

    .line 153
    .line 154
    aput-object v14, v2, v16

    .line 155
    .line 156
    aput-object v15, v2, v5

    .line 157
    .line 158
    const/4 v11, 0x3

    .line 159
    aput-object v9, v2, v11

    .line 160
    .line 161
    const/4 v9, 0x4

    .line 162
    aput-object v12, v2, v9

    .line 163
    .line 164
    new-instance v9, Lyy0/f1;

    .line 165
    .line 166
    invoke-direct {v9, v2, v10}, Lyy0/f1;-><init>([Lyy0/i;Lay0/r;)V

    .line 167
    .line 168
    .line 169
    new-instance v2, Ltz/i0;

    .line 170
    .line 171
    invoke-direct {v2, v6, v3, v4}, Ltz/i0;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 172
    .line 173
    .line 174
    new-array v5, v5, [Lyy0/i;

    .line 175
    .line 176
    aput-object v7, v5, v4

    .line 177
    .line 178
    aput-object v9, v5, v16

    .line 179
    .line 180
    new-instance v4, Lyy0/g1;

    .line 181
    .line 182
    invoke-direct {v4, v2, v3}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 183
    .line 184
    .line 185
    sget-object v2, Lyy0/h1;->d:Lyy0/h1;

    .line 186
    .line 187
    sget-object v3, Lzy0/q;->d:Lzy0/q;

    .line 188
    .line 189
    invoke-static {v2, v4, v0, v3, v5}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 194
    .line 195
    if-ne v0, v2, :cond_2

    .line 196
    .line 197
    goto :goto_0

    .line 198
    :cond_2
    move-object v0, v8

    .line 199
    :goto_0
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 200
    .line 201
    if-ne v0, v2, :cond_3

    .line 202
    .line 203
    goto :goto_1

    .line 204
    :cond_3
    move-object v0, v8

    .line 205
    :goto_1
    if-ne v0, v1, :cond_4

    .line 206
    .line 207
    goto :goto_2

    .line 208
    :cond_4
    move-object v0, v8

    .line 209
    :goto_2
    if-ne v0, v1, :cond_5

    .line 210
    .line 211
    move-object v8, v1

    .line 212
    :cond_5
    :goto_3
    return-object v8

    .line 213
    :pswitch_0
    move/from16 v16, v9

    .line 214
    .line 215
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 216
    .line 217
    iget v4, v0, Ltz/k0;->e:I

    .line 218
    .line 219
    if-eqz v4, :cond_8

    .line 220
    .line 221
    if-eq v4, v9, :cond_7

    .line 222
    .line 223
    if-ne v4, v5, :cond_6

    .line 224
    .line 225
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    goto :goto_6

    .line 229
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 230
    .line 231
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    throw v0

    .line 235
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    move-object/from16 v3, p1

    .line 239
    .line 240
    goto :goto_4

    .line 241
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    iget-object v4, v6, Ltz/n0;->h:Lqd0/d0;

    .line 245
    .line 246
    iput v9, v0, Ltz/k0;->e:I

    .line 247
    .line 248
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 249
    .line 250
    .line 251
    iget-object v6, v4, Lqd0/d0;->a:Lyb0/l;

    .line 252
    .line 253
    new-instance v9, Lyb0/i;

    .line 254
    .line 255
    sget-object v10, Lzb0/d;->e:Lzb0/d;

    .line 256
    .line 257
    const/4 v13, 0x0

    .line 258
    const/16 v14, 0x3c

    .line 259
    .line 260
    const-string v11, "charging"

    .line 261
    .line 262
    const/4 v12, 0x0

    .line 263
    invoke-direct/range {v9 .. v14}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v6, v9}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 267
    .line 268
    .line 269
    move-result-object v6

    .line 270
    new-instance v7, Llb0/y;

    .line 271
    .line 272
    const/16 v9, 0x8

    .line 273
    .line 274
    invoke-direct {v7, v9, v6, v4}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    new-instance v6, Lny/f0;

    .line 278
    .line 279
    const/16 v9, 0x11

    .line 280
    .line 281
    invoke-direct {v6, v4, v3, v9}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 282
    .line 283
    .line 284
    new-instance v3, Lne0/n;

    .line 285
    .line 286
    invoke-direct {v3, v7, v6, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 287
    .line 288
    .line 289
    if-ne v3, v1, :cond_9

    .line 290
    .line 291
    goto :goto_5

    .line 292
    :cond_9
    :goto_4
    check-cast v3, Lyy0/i;

    .line 293
    .line 294
    iput v5, v0, Ltz/k0;->e:I

    .line 295
    .line 296
    invoke-static {v3, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    if-ne v0, v1, :cond_a

    .line 301
    .line 302
    :goto_5
    move-object v8, v1

    .line 303
    :cond_a
    :goto_6
    return-object v8

    .line 304
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 305
    .line 306
    iget v2, v0, Ltz/k0;->e:I

    .line 307
    .line 308
    if-eqz v2, :cond_c

    .line 309
    .line 310
    const/4 v9, 0x1

    .line 311
    if-ne v2, v9, :cond_b

    .line 312
    .line 313
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    goto :goto_7

    .line 317
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 318
    .line 319
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    throw v0

    .line 323
    :cond_c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    iget-object v2, v6, Ltz/n0;->s:Lqd0/a1;

    .line 327
    .line 328
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v2

    .line 332
    check-cast v2, Lyy0/i;

    .line 333
    .line 334
    new-instance v4, Ltz/u;

    .line 335
    .line 336
    invoke-direct {v4, v6, v3, v5}, Ltz/u;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 337
    .line 338
    .line 339
    invoke-static {v4, v2}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 340
    .line 341
    .line 342
    move-result-object v2

    .line 343
    new-instance v3, Ltz/l0;

    .line 344
    .line 345
    const/4 v9, 0x1

    .line 346
    invoke-direct {v3, v6, v9}, Ltz/l0;-><init>(Ltz/n0;I)V

    .line 347
    .line 348
    .line 349
    iput v9, v0, Ltz/k0;->e:I

    .line 350
    .line 351
    invoke-virtual {v2, v3, v0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    if-ne v0, v1, :cond_d

    .line 356
    .line 357
    move-object v8, v1

    .line 358
    :cond_d
    :goto_7
    return-object v8

    .line 359
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 360
    .line 361
    iget v2, v0, Ltz/k0;->e:I

    .line 362
    .line 363
    if-eqz v2, :cond_f

    .line 364
    .line 365
    if-ne v2, v9, :cond_e

    .line 366
    .line 367
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 368
    .line 369
    .line 370
    goto :goto_8

    .line 371
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 372
    .line 373
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    throw v0

    .line 377
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 378
    .line 379
    .line 380
    iget-object v2, v6, Ltz/n0;->r:Lqd0/z0;

    .line 381
    .line 382
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v2

    .line 386
    check-cast v2, Lyy0/i;

    .line 387
    .line 388
    new-instance v5, Ltz/u;

    .line 389
    .line 390
    invoke-direct {v5, v6, v3, v9}, Ltz/u;-><init>(Ltz/n0;Lkotlin/coroutines/Continuation;I)V

    .line 391
    .line 392
    .line 393
    invoke-static {v5, v2}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 394
    .line 395
    .line 396
    move-result-object v2

    .line 397
    new-instance v3, Ltz/l0;

    .line 398
    .line 399
    invoke-direct {v3, v6, v4}, Ltz/l0;-><init>(Ltz/n0;I)V

    .line 400
    .line 401
    .line 402
    iput v9, v0, Ltz/k0;->e:I

    .line 403
    .line 404
    invoke-virtual {v2, v3, v0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    if-ne v0, v1, :cond_10

    .line 409
    .line 410
    move-object v8, v1

    .line 411
    :cond_10
    :goto_8
    return-object v8

    .line 412
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 413
    .line 414
    iget v2, v0, Ltz/k0;->e:I

    .line 415
    .line 416
    if-eqz v2, :cond_12

    .line 417
    .line 418
    if-ne v2, v9, :cond_11

    .line 419
    .line 420
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 421
    .line 422
    .line 423
    goto :goto_9

    .line 424
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 425
    .line 426
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    throw v0

    .line 430
    :cond_12
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    iget-object v2, v6, Ltz/n0;->B:Ltn0/b;

    .line 434
    .line 435
    sget-object v3, Lun0/a;->e:Lun0/a;

    .line 436
    .line 437
    iput v9, v0, Ltz/k0;->e:I

    .line 438
    .line 439
    invoke-virtual {v2, v3, v0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v0

    .line 443
    if-ne v0, v1, :cond_13

    .line 444
    .line 445
    move-object v8, v1

    .line 446
    goto :goto_a

    .line 447
    :cond_13
    :goto_9
    iget-object v0, v6, Ltz/n0;->q:Lrz/a0;

    .line 448
    .line 449
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    :goto_a
    return-object v8

    .line 453
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
