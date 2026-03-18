.class public abstract Llp/mf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v10, p3

    .line 6
    .line 7
    const-string v0, "vin"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "profileUuid"

    .line 13
    .line 14
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v11, p2

    .line 18
    .line 19
    check-cast v11, Ll2/t;

    .line 20
    .line 21
    const v0, -0x61b41756

    .line 22
    .line 23
    .line 24
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v3, 0x4

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    move v0, v3

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int/2addr v0, v10

    .line 38
    invoke-virtual {v11, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    const/16 v5, 0x20

    .line 43
    .line 44
    if-eqz v4, :cond_1

    .line 45
    .line 46
    move v4, v5

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/16 v4, 0x10

    .line 49
    .line 50
    :goto_1
    or-int/2addr v0, v4

    .line 51
    and-int/lit8 v4, v0, 0x13

    .line 52
    .line 53
    const/16 v6, 0x12

    .line 54
    .line 55
    const/4 v8, 0x0

    .line 56
    if-eq v4, v6, :cond_2

    .line 57
    .line 58
    const/4 v4, 0x1

    .line 59
    goto :goto_2

    .line 60
    :cond_2
    move v4, v8

    .line 61
    :goto_2
    and-int/lit8 v6, v0, 0x1

    .line 62
    .line 63
    invoke-virtual {v11, v6, v4}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    if-eqz v4, :cond_10

    .line 68
    .line 69
    new-array v4, v8, [Lz9/j0;

    .line 70
    .line 71
    invoke-static {v4, v11}, Ljp/s0;->b([Lz9/j0;Ll2/o;)Lz9/y;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    new-array v6, v8, [Ljava/lang/Object;

    .line 76
    .line 77
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v9

    .line 81
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 82
    .line 83
    if-ne v9, v12, :cond_3

    .line 84
    .line 85
    new-instance v9, Ll31/b;

    .line 86
    .line 87
    const/16 v13, 0xa

    .line 88
    .line 89
    invoke-direct {v9, v13}, Ll31/b;-><init>(I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v11, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_3
    check-cast v9, Lay0/a;

    .line 96
    .line 97
    const/16 v13, 0x30

    .line 98
    .line 99
    invoke-static {v6, v9, v11, v13}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    check-cast v6, Ll2/b1;

    .line 104
    .line 105
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v9

    .line 109
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v13

    .line 113
    if-nez v9, :cond_4

    .line 114
    .line 115
    if-ne v13, v12, :cond_5

    .line 116
    .line 117
    :cond_4
    new-instance v13, Lle/a;

    .line 118
    .line 119
    const/4 v9, 0x1

    .line 120
    invoke-direct {v13, v4, v9}, Lle/a;-><init>(Lz9/y;I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_5
    check-cast v13, Lay0/a;

    .line 127
    .line 128
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v9

    .line 132
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v14

    .line 136
    if-nez v9, :cond_6

    .line 137
    .line 138
    if-ne v14, v12, :cond_7

    .line 139
    .line 140
    :cond_6
    new-instance v14, Lle/a;

    .line 141
    .line 142
    const/4 v9, 0x2

    .line 143
    invoke-direct {v14, v4, v9}, Lle/a;-><init>(Lz9/y;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v11, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :cond_7
    check-cast v14, Lay0/a;

    .line 150
    .line 151
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v9

    .line 155
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v15

    .line 159
    if-nez v9, :cond_8

    .line 160
    .line 161
    if-ne v15, v12, :cond_9

    .line 162
    .line 163
    :cond_8
    new-instance v15, Lle/a;

    .line 164
    .line 165
    const/4 v9, 0x3

    .line 166
    invoke-direct {v15, v4, v9}, Lle/a;-><init>(Lz9/y;I)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v11, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    :cond_9
    check-cast v15, Lay0/a;

    .line 173
    .line 174
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v9

    .line 178
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v7

    .line 182
    if-nez v9, :cond_a

    .line 183
    .line 184
    if-ne v7, v12, :cond_b

    .line 185
    .line 186
    :cond_a
    new-instance v7, Lle/a;

    .line 187
    .line 188
    const/4 v9, 0x4

    .line 189
    invoke-direct {v7, v4, v9}, Lle/a;-><init>(Lz9/y;I)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    :cond_b
    check-cast v7, Lay0/a;

    .line 196
    .line 197
    and-int/lit8 v9, v0, 0xe

    .line 198
    .line 199
    if-ne v9, v3, :cond_c

    .line 200
    .line 201
    const/4 v3, 0x1

    .line 202
    goto :goto_3

    .line 203
    :cond_c
    move v3, v8

    .line 204
    :goto_3
    and-int/lit8 v0, v0, 0x70

    .line 205
    .line 206
    if-ne v0, v5, :cond_d

    .line 207
    .line 208
    const/4 v8, 0x1

    .line 209
    :cond_d
    or-int v0, v3, v8

    .line 210
    .line 211
    invoke-virtual {v11, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    or-int/2addr v0, v3

    .line 216
    invoke-virtual {v11, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v3

    .line 220
    or-int/2addr v0, v3

    .line 221
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    or-int/2addr v0, v3

    .line 226
    invoke-virtual {v11, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    or-int/2addr v0, v3

    .line 231
    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    move-result v3

    .line 235
    or-int/2addr v0, v3

    .line 236
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v3

    .line 240
    or-int/2addr v0, v3

    .line 241
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    if-nez v0, :cond_f

    .line 246
    .line 247
    if-ne v3, v12, :cond_e

    .line 248
    .line 249
    goto :goto_4

    .line 250
    :cond_e
    move-object v5, v4

    .line 251
    goto :goto_5

    .line 252
    :cond_f
    :goto_4
    new-instance v0, Lh2/d1;

    .line 253
    .line 254
    const/4 v9, 0x1

    .line 255
    move-object v5, v4

    .line 256
    move-object v8, v7

    .line 257
    move-object v3, v13

    .line 258
    move-object v4, v14

    .line 259
    move-object v7, v6

    .line 260
    move-object v6, v15

    .line 261
    invoke-direct/range {v0 .. v9}, Lh2/d1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 265
    .line 266
    .line 267
    move-object v3, v0

    .line 268
    :goto_5
    move-object/from16 v19, v3

    .line 269
    .line 270
    check-cast v19, Lay0/k;

    .line 271
    .line 272
    const/16 v22, 0x0

    .line 273
    .line 274
    const/16 v23, 0x3fc

    .line 275
    .line 276
    const-string v12, "KOLA_OVERVIEW_ROUTE"

    .line 277
    .line 278
    const/4 v13, 0x0

    .line 279
    const/4 v14, 0x0

    .line 280
    const/4 v15, 0x0

    .line 281
    const/16 v16, 0x0

    .line 282
    .line 283
    const/16 v17, 0x0

    .line 284
    .line 285
    const/16 v18, 0x0

    .line 286
    .line 287
    const/16 v21, 0x30

    .line 288
    .line 289
    move-object/from16 v20, v11

    .line 290
    .line 291
    move-object v11, v5

    .line 292
    invoke-static/range {v11 .. v23}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 293
    .line 294
    .line 295
    goto :goto_6

    .line 296
    :cond_10
    move-object/from16 v20, v11

    .line 297
    .line 298
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 299
    .line 300
    .line 301
    :goto_6
    invoke-virtual/range {v20 .. v20}, Ll2/t;->s()Ll2/u1;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    if-eqz v0, :cond_11

    .line 306
    .line 307
    new-instance v3, Lbk/c;

    .line 308
    .line 309
    const/4 v4, 0x3

    .line 310
    invoke-direct {v3, v1, v2, v10, v4}, Lbk/c;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 311
    .line 312
    .line 313
    iput-object v3, v0, Ll2/u1;->d:Lay0/n;

    .line 314
    .line 315
    :cond_11
    return-void
.end method

.method public static final b(Lxy0/x;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lxy0/v;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lxy0/v;

    .line 7
    .line 8
    iget v1, v0, Lxy0/v;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lxy0/v;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxy0/v;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lxy0/v;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxy0/v;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lxy0/v;->d:Lay0/a;

    .line 37
    .line 38
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catchall_0
    move-exception p0

    .line 43
    goto :goto_2

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 60
    .line 61
    invoke-interface {p2, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, p0, :cond_4

    .line 66
    .line 67
    :try_start_1
    iput-object p1, v0, Lxy0/v;->d:Lay0/a;

    .line 68
    .line 69
    iput v3, v0, Lxy0/v;->f:I

    .line 70
    .line 71
    new-instance p2, Lvy0/l;

    .line 72
    .line 73
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-direct {p2, v3, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p2}, Lvy0/l;->q()V

    .line 81
    .line 82
    .line 83
    new-instance v0, Lwt0/a;

    .line 84
    .line 85
    const/4 v2, 0x1

    .line 86
    invoke-direct {v0, p2, v2}, Lwt0/a;-><init>(Lvy0/l;I)V

    .line 87
    .line 88
    .line 89
    check-cast p0, Lxy0/w;

    .line 90
    .line 91
    invoke-virtual {p0, v0}, Lxy0/w;->p0(Lwt0/a;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 98
    if-ne p0, v1, :cond_3

    .line 99
    .line 100
    return-object v1

    .line 101
    :cond_3
    :goto_1
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object p0

    .line 107
    :goto_2
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 112
    .line 113
    const-string p1, "awaitClose() can only be invoked from the producer context"

    .line 114
    .line 115
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p0
.end method

.method public static c(Lvy0/b0;ILay0/n;I)Lxy0/w;
    .locals 2

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    :cond_0
    sget-object p3, Lxy0/a;->d:Lxy0/a;

    .line 7
    .line 8
    sget-object v0, Lvy0/c0;->d:Lvy0/c0;

    .line 9
    .line 10
    const/4 v1, 0x4

    .line 11
    invoke-static {p1, v1, p3}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    sget-object p3, Lpx0/h;->d:Lpx0/h;

    .line 16
    .line 17
    invoke-static {p0, p3}, Lvy0/e0;->F(Lvy0/b0;Lpx0/g;)Lpx0/g;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    new-instance p3, Lxy0/w;

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    invoke-direct {p3, p0, p1, v1, v1}, Lxy0/w;-><init>(Lpx0/g;Lxy0/j;ZZ)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p3, v0, p3, p2}, Lvy0/a;->n0(Lvy0/c0;Lvy0/a;Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-object p3
.end method
