.class public abstract Llp/jf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(IILxy0/a;)Lxy0/j;
    .locals 2

    .line 1
    and-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p0, v1

    .line 7
    :cond_0
    and-int/lit8 p1, p1, 0x2

    .line 8
    .line 9
    if-eqz p1, :cond_1

    .line 10
    .line 11
    sget-object p2, Lxy0/a;->d:Lxy0/a;

    .line 12
    .line 13
    :cond_1
    const/4 p1, -0x2

    .line 14
    const/4 v0, 0x1

    .line 15
    if-eq p0, p1, :cond_8

    .line 16
    .line 17
    const/4 p1, -0x1

    .line 18
    if-eq p0, p1, :cond_6

    .line 19
    .line 20
    if-eqz p0, :cond_4

    .line 21
    .line 22
    const p1, 0x7fffffff

    .line 23
    .line 24
    .line 25
    if-eq p0, p1, :cond_3

    .line 26
    .line 27
    sget-object p1, Lxy0/a;->d:Lxy0/a;

    .line 28
    .line 29
    if-ne p2, p1, :cond_2

    .line 30
    .line 31
    new-instance p1, Lxy0/j;

    .line 32
    .line 33
    invoke-direct {p1, p0}, Lxy0/j;-><init>(I)V

    .line 34
    .line 35
    .line 36
    return-object p1

    .line 37
    :cond_2
    new-instance p1, Lxy0/u;

    .line 38
    .line 39
    invoke-direct {p1, p0, p2}, Lxy0/u;-><init>(ILxy0/a;)V

    .line 40
    .line 41
    .line 42
    return-object p1

    .line 43
    :cond_3
    new-instance p0, Lxy0/j;

    .line 44
    .line 45
    invoke-direct {p0, p1}, Lxy0/j;-><init>(I)V

    .line 46
    .line 47
    .line 48
    return-object p0

    .line 49
    :cond_4
    sget-object p0, Lxy0/a;->d:Lxy0/a;

    .line 50
    .line 51
    if-ne p2, p0, :cond_5

    .line 52
    .line 53
    new-instance p0, Lxy0/j;

    .line 54
    .line 55
    invoke-direct {p0, v1}, Lxy0/j;-><init>(I)V

    .line 56
    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_5
    new-instance p0, Lxy0/u;

    .line 60
    .line 61
    invoke-direct {p0, v0, p2}, Lxy0/u;-><init>(ILxy0/a;)V

    .line 62
    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_6
    sget-object p0, Lxy0/a;->d:Lxy0/a;

    .line 66
    .line 67
    if-ne p2, p0, :cond_7

    .line 68
    .line 69
    new-instance p0, Lxy0/u;

    .line 70
    .line 71
    sget-object p1, Lxy0/a;->e:Lxy0/a;

    .line 72
    .line 73
    invoke-direct {p0, v0, p1}, Lxy0/u;-><init>(ILxy0/a;)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 78
    .line 79
    const-string p1, "CONFLATED capacity cannot be used with non-default onBufferOverflow"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_8
    sget-object p0, Lxy0/a;->d:Lxy0/a;

    .line 86
    .line 87
    if-ne p2, p0, :cond_9

    .line 88
    .line 89
    new-instance p0, Lxy0/j;

    .line 90
    .line 91
    sget-object p1, Lxy0/n;->p1:Lxy0/m;

    .line 92
    .line 93
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    sget p1, Lxy0/m;->b:I

    .line 97
    .line 98
    invoke-direct {p0, p1}, Lxy0/j;-><init>(I)V

    .line 99
    .line 100
    .line 101
    return-object p0

    .line 102
    :cond_9
    new-instance p0, Lxy0/u;

    .line 103
    .line 104
    invoke-direct {p0, v0, p2}, Lxy0/u;-><init>(ILxy0/a;)V

    .line 105
    .line 106
    .line 107
    return-object p0
.end method

.method public static final b(Ljava/util/List;Lbd/a;Ll2/o;II)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v12, p2

    .line 4
    .line 5
    check-cast v12, Ll2/t;

    .line 6
    .line 7
    const v0, 0x23c5064a

    .line 8
    .line 9
    .line 10
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p3, v0

    .line 23
    .line 24
    and-int/lit8 v2, p4, 0x2

    .line 25
    .line 26
    const/16 v3, 0x20

    .line 27
    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    or-int/lit8 v0, v0, 0x30

    .line 31
    .line 32
    goto :goto_3

    .line 33
    :cond_1
    and-int/lit8 v4, p3, 0x30

    .line 34
    .line 35
    if-nez v4, :cond_4

    .line 36
    .line 37
    if-nez p1, :cond_2

    .line 38
    .line 39
    const/4 v4, -0x1

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Enum;->ordinal()I

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    :goto_1
    invoke-virtual {v12, v4}, Ll2/t;->e(I)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_3

    .line 50
    .line 51
    move v4, v3

    .line 52
    goto :goto_2

    .line 53
    :cond_3
    const/16 v4, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v4

    .line 56
    :cond_4
    :goto_3
    and-int/lit8 v4, v0, 0x13

    .line 57
    .line 58
    const/16 v5, 0x12

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    const/4 v7, 0x1

    .line 62
    if-eq v4, v5, :cond_5

    .line 63
    .line 64
    move v4, v7

    .line 65
    goto :goto_4

    .line 66
    :cond_5
    move v4, v6

    .line 67
    :goto_4
    and-int/lit8 v5, v0, 0x1

    .line 68
    .line 69
    invoke-virtual {v12, v5, v4}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    if-eqz v4, :cond_12

    .line 74
    .line 75
    if-eqz v2, :cond_6

    .line 76
    .line 77
    sget-object v2, Lbd/a;->d:Lbd/a;

    .line 78
    .line 79
    goto :goto_5

    .line 80
    :cond_6
    move-object/from16 v2, p1

    .line 81
    .line 82
    :goto_5
    const-string v4, "ChargingHistoryFlowScreen"

    .line 83
    .line 84
    invoke-static {v4, v12}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    new-array v5, v6, [Ljava/lang/Object;

    .line 89
    .line 90
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v8

    .line 94
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-ne v8, v9, :cond_7

    .line 97
    .line 98
    new-instance v8, Ll31/b;

    .line 99
    .line 100
    const/16 v10, 0x9

    .line 101
    .line 102
    invoke-direct {v8, v10}, Ll31/b;-><init>(I)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_7
    check-cast v8, Lay0/a;

    .line 109
    .line 110
    const/16 v10, 0x30

    .line 111
    .line 112
    invoke-static {v5, v8, v12, v10}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    move-object v10, v5

    .line 117
    check-cast v10, Ll2/b1;

    .line 118
    .line 119
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    if-ne v5, v9, :cond_8

    .line 124
    .line 125
    new-instance v5, Ljd/a;

    .line 126
    .line 127
    sget-object v8, Lmx0/s;->d:Lmx0/s;

    .line 128
    .line 129
    const/4 v11, 0x0

    .line 130
    invoke-direct {v5, v8, v11, v11}, Ljd/a;-><init>(Ljava/util/List;Lgz0/p;Lgz0/p;)V

    .line 131
    .line 132
    .line 133
    invoke-static {v5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    invoke-virtual {v12, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    :cond_8
    check-cast v5, Ll2/b1;

    .line 141
    .line 142
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v8

    .line 146
    if-ne v8, v9, :cond_9

    .line 147
    .line 148
    new-instance v8, La2/g;

    .line 149
    .line 150
    const/16 v11, 0x1d

    .line 151
    .line 152
    invoke-direct {v8, v5, v11}, La2/g;-><init>(Ll2/b1;I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_9
    check-cast v8, Lay0/k;

    .line 159
    .line 160
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v11

    .line 164
    if-ne v11, v9, :cond_a

    .line 165
    .line 166
    new-instance v11, Ll20/f;

    .line 167
    .line 168
    const/16 v13, 0x9

    .line 169
    .line 170
    invoke-direct {v11, v13}, Ll20/f;-><init>(I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v12, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    :cond_a
    check-cast v11, Lay0/n;

    .line 177
    .line 178
    invoke-virtual {v4, v11}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 179
    .line 180
    .line 181
    move-result-object v11

    .line 182
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v13

    .line 186
    if-ne v13, v9, :cond_b

    .line 187
    .line 188
    new-instance v13, Lkq0/a;

    .line 189
    .line 190
    const/16 v14, 0xc

    .line 191
    .line 192
    invoke-direct {v13, v14}, Lkq0/a;-><init>(I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v12, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    :cond_b
    check-cast v13, Lay0/k;

    .line 199
    .line 200
    invoke-virtual {v4, v13}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 201
    .line 202
    .line 203
    move-result-object v13

    .line 204
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v14

    .line 208
    if-ne v14, v9, :cond_c

    .line 209
    .line 210
    new-instance v14, Lkq0/a;

    .line 211
    .line 212
    const/16 v15, 0xd

    .line 213
    .line 214
    invoke-direct {v14, v15}, Lkq0/a;-><init>(I)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v12, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    :cond_c
    check-cast v14, Lay0/k;

    .line 221
    .line 222
    invoke-virtual {v4, v14}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 223
    .line 224
    .line 225
    move-result-object v14

    .line 226
    move v15, v7

    .line 227
    new-instance v7, Lzb/s0;

    .line 228
    .line 229
    const/4 v6, 0x2

    .line 230
    invoke-direct {v7, v4, v6}, Lzb/s0;-><init>(Lzb/v0;I)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v12, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v6

    .line 237
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v15

    .line 241
    if-nez v6, :cond_d

    .line 242
    .line 243
    if-ne v15, v9, :cond_e

    .line 244
    .line 245
    :cond_d
    new-instance v15, Leh/c;

    .line 246
    .line 247
    const/16 v6, 0xe

    .line 248
    .line 249
    invoke-direct {v15, v10, v6}, Leh/c;-><init>(Ll2/b1;I)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    :cond_e
    check-cast v15, Lay0/n;

    .line 256
    .line 257
    invoke-virtual {v4, v15}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 258
    .line 259
    .line 260
    move-result-object v6

    .line 261
    invoke-virtual {v4}, Lzb/v0;->b()Lz9/y;

    .line 262
    .line 263
    .line 264
    move-result-object v15

    .line 265
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    move-result v4

    .line 269
    invoke-virtual {v12, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result v16

    .line 273
    or-int v4, v4, v16

    .line 274
    .line 275
    invoke-virtual {v12, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v16

    .line 279
    or-int v4, v4, v16

    .line 280
    .line 281
    invoke-virtual {v12, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v16

    .line 285
    or-int v4, v4, v16

    .line 286
    .line 287
    and-int/lit8 v0, v0, 0x70

    .line 288
    .line 289
    if-ne v0, v3, :cond_f

    .line 290
    .line 291
    const/4 v0, 0x1

    .line 292
    goto :goto_6

    .line 293
    :cond_f
    const/4 v0, 0x0

    .line 294
    :goto_6
    or-int/2addr v0, v4

    .line 295
    invoke-virtual {v12, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    move-result v3

    .line 299
    or-int/2addr v0, v3

    .line 300
    invoke-virtual {v12, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v3

    .line 304
    or-int/2addr v0, v3

    .line 305
    invoke-virtual {v12, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result v3

    .line 309
    or-int/2addr v0, v3

    .line 310
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v3

    .line 314
    if-nez v0, :cond_11

    .line 315
    .line 316
    if-ne v3, v9, :cond_10

    .line 317
    .line 318
    goto :goto_7

    .line 319
    :cond_10
    move-object v13, v2

    .line 320
    goto :goto_8

    .line 321
    :cond_11
    :goto_7
    new-instance v0, Lew/c;

    .line 322
    .line 323
    move-object v9, v5

    .line 324
    move-object v5, v6

    .line 325
    move-object v6, v2

    .line 326
    move-object v2, v11

    .line 327
    const/4 v11, 0x2

    .line 328
    move-object v3, v8

    .line 329
    move-object v4, v13

    .line 330
    move-object v8, v14

    .line 331
    invoke-direct/range {v0 .. v11}, Lew/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 332
    .line 333
    .line 334
    move-object v13, v6

    .line 335
    invoke-virtual {v12, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    move-object v3, v0

    .line 339
    :goto_8
    move-object v8, v3

    .line 340
    check-cast v8, Lay0/k;

    .line 341
    .line 342
    const/4 v11, 0x0

    .line 343
    move-object v9, v12

    .line 344
    const/16 v12, 0x3fc

    .line 345
    .line 346
    const-string v1, "/overview"

    .line 347
    .line 348
    const/4 v2, 0x0

    .line 349
    const/4 v3, 0x0

    .line 350
    const/4 v4, 0x0

    .line 351
    const/4 v5, 0x0

    .line 352
    const/4 v6, 0x0

    .line 353
    const/4 v7, 0x0

    .line 354
    const/16 v10, 0x30

    .line 355
    .line 356
    move-object v0, v15

    .line 357
    invoke-static/range {v0 .. v12}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 358
    .line 359
    .line 360
    move-object v2, v13

    .line 361
    goto :goto_9

    .line 362
    :cond_12
    move-object v9, v12

    .line 363
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 364
    .line 365
    .line 366
    move-object/from16 v2, p1

    .line 367
    .line 368
    :goto_9
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 369
    .line 370
    .line 371
    move-result-object v6

    .line 372
    if-eqz v6, :cond_13

    .line 373
    .line 374
    new-instance v0, Lck/h;

    .line 375
    .line 376
    const/16 v5, 0x8

    .line 377
    .line 378
    move-object/from16 v1, p0

    .line 379
    .line 380
    move/from16 v3, p3

    .line 381
    .line 382
    move/from16 v4, p4

    .line 383
    .line 384
    invoke-direct/range {v0 .. v5}, Lck/h;-><init>(Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 385
    .line 386
    .line 387
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 388
    .line 389
    :cond_13
    return-void
.end method
