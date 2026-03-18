.class public abstract Lvv/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lvv/s;->j:Lvv/s;

    .line 2
    .line 3
    new-instance v1, Ll2/e0;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Lvv/l0;->a:Ll2/e0;

    .line 9
    .line 10
    sget-object v0, Lvv/s;->i:Lvv/s;

    .line 11
    .line 12
    new-instance v1, Ll2/e0;

    .line 13
    .line 14
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lvv/l0;->b:Ll2/e0;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Lay0/k;Lay0/k;Ll2/o;II)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v7, p3

    .line 6
    .line 7
    move-object/from16 v8, p5

    .line 8
    .line 9
    move-object/from16 v9, p6

    .line 10
    .line 11
    move/from16 v10, p8

    .line 12
    .line 13
    const-string v2, "$this$ClickableText"

    .line 14
    .line 15
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v2, "text"

    .line 19
    .line 20
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string v2, "isOffsetClickable"

    .line 24
    .line 25
    invoke-static {v8, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    move-object/from16 v5, p7

    .line 29
    .line 30
    check-cast v5, Ll2/t;

    .line 31
    .line 32
    const v2, 0x15e6d4f4

    .line 33
    .line 34
    .line 35
    invoke-virtual {v5, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 36
    .line 37
    .line 38
    and-int/lit8 v2, v10, 0xe

    .line 39
    .line 40
    if-nez v2, :cond_1

    .line 41
    .line 42
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    const/4 v2, 0x4

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 v2, 0x2

    .line 51
    :goto_0
    or-int/2addr v2, v10

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v2, v10

    .line 54
    :goto_1
    and-int/lit8 v3, v10, 0x70

    .line 55
    .line 56
    if-nez v3, :cond_3

    .line 57
    .line 58
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    if-eqz v3, :cond_2

    .line 63
    .line 64
    const/16 v3, 0x20

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_2
    const/16 v3, 0x10

    .line 68
    .line 69
    :goto_2
    or-int/2addr v2, v3

    .line 70
    :cond_3
    or-int/lit16 v2, v2, 0x180

    .line 71
    .line 72
    and-int/lit16 v3, v10, 0x1c00

    .line 73
    .line 74
    const/4 v4, 0x1

    .line 75
    if-nez v3, :cond_5

    .line 76
    .line 77
    invoke-virtual {v5, v4}, Ll2/t;->h(Z)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_4

    .line 82
    .line 83
    const/16 v3, 0x800

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_4
    const/16 v3, 0x400

    .line 87
    .line 88
    :goto_3
    or-int/2addr v2, v3

    .line 89
    :cond_5
    const v3, 0xe000

    .line 90
    .line 91
    .line 92
    and-int v6, v10, v3

    .line 93
    .line 94
    if-nez v6, :cond_7

    .line 95
    .line 96
    invoke-virtual {v5, v4}, Ll2/t;->e(I)Z

    .line 97
    .line 98
    .line 99
    move-result v4

    .line 100
    if-eqz v4, :cond_6

    .line 101
    .line 102
    const/16 v4, 0x4000

    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_6
    const/16 v4, 0x2000

    .line 106
    .line 107
    :goto_4
    or-int/2addr v2, v4

    .line 108
    :cond_7
    const/high16 v4, 0x70000

    .line 109
    .line 110
    and-int v6, v10, v4

    .line 111
    .line 112
    if-nez v6, :cond_9

    .line 113
    .line 114
    const v6, 0x7fffffff

    .line 115
    .line 116
    .line 117
    invoke-virtual {v5, v6}, Ll2/t;->e(I)Z

    .line 118
    .line 119
    .line 120
    move-result v6

    .line 121
    if-eqz v6, :cond_8

    .line 122
    .line 123
    const/high16 v6, 0x20000

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_8
    const/high16 v6, 0x10000

    .line 127
    .line 128
    :goto_5
    or-int/2addr v2, v6

    .line 129
    :cond_9
    const/high16 v6, 0x380000

    .line 130
    .line 131
    and-int v11, v10, v6

    .line 132
    .line 133
    if-nez v11, :cond_b

    .line 134
    .line 135
    invoke-virtual {v5, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v11

    .line 139
    if-eqz v11, :cond_a

    .line 140
    .line 141
    const/high16 v11, 0x100000

    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_a
    const/high16 v11, 0x80000

    .line 145
    .line 146
    :goto_6
    or-int/2addr v2, v11

    .line 147
    :cond_b
    and-int/lit8 v11, p9, 0x40

    .line 148
    .line 149
    if-eqz v11, :cond_c

    .line 150
    .line 151
    const/high16 v12, 0x400000

    .line 152
    .line 153
    or-int/2addr v2, v12

    .line 154
    :cond_c
    const/high16 v12, 0xe000000

    .line 155
    .line 156
    and-int/2addr v12, v10

    .line 157
    if-nez v12, :cond_e

    .line 158
    .line 159
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v12

    .line 163
    if-eqz v12, :cond_d

    .line 164
    .line 165
    const/high16 v12, 0x4000000

    .line 166
    .line 167
    goto :goto_7

    .line 168
    :cond_d
    const/high16 v12, 0x2000000

    .line 169
    .line 170
    :goto_7
    or-int/2addr v2, v12

    .line 171
    :cond_e
    const/high16 v12, 0x70000000

    .line 172
    .line 173
    and-int/2addr v12, v10

    .line 174
    if-nez v12, :cond_10

    .line 175
    .line 176
    invoke-virtual {v5, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v12

    .line 180
    if-eqz v12, :cond_f

    .line 181
    .line 182
    const/high16 v12, 0x20000000

    .line 183
    .line 184
    goto :goto_8

    .line 185
    :cond_f
    const/high16 v12, 0x10000000

    .line 186
    .line 187
    :goto_8
    or-int/2addr v2, v12

    .line 188
    :cond_10
    const/16 v12, 0x40

    .line 189
    .line 190
    if-ne v11, v12, :cond_12

    .line 191
    .line 192
    const v12, 0x5b6db6db

    .line 193
    .line 194
    .line 195
    and-int/2addr v12, v2

    .line 196
    const v13, 0x12492492

    .line 197
    .line 198
    .line 199
    if-ne v12, v13, :cond_12

    .line 200
    .line 201
    invoke-virtual {v5}, Ll2/t;->A()Z

    .line 202
    .line 203
    .line 204
    move-result v12

    .line 205
    if-nez v12, :cond_11

    .line 206
    .line 207
    goto :goto_9

    .line 208
    :cond_11
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 209
    .line 210
    .line 211
    move-object/from16 v3, p2

    .line 212
    .line 213
    move-object v0, v5

    .line 214
    move-object/from16 v5, p4

    .line 215
    .line 216
    goto/16 :goto_b

    .line 217
    .line 218
    :cond_12
    :goto_9
    if-eqz v11, :cond_13

    .line 219
    .line 220
    sget-object v11, Lmx0/t;->d:Lmx0/t;

    .line 221
    .line 222
    goto :goto_a

    .line 223
    :cond_13
    move-object/from16 v11, p4

    .line 224
    .line 225
    :goto_a
    const v12, -0x1d58f75c

    .line 226
    .line 227
    .line 228
    invoke-virtual {v5, v12}, Ll2/t;->Z(I)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v12

    .line 235
    const/4 v13, 0x0

    .line 236
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 237
    .line 238
    if-ne v12, v14, :cond_14

    .line 239
    .line 240
    invoke-static {v13}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 241
    .line 242
    .line 243
    move-result-object v12

    .line 244
    invoke-virtual {v5, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    :cond_14
    const/4 v15, 0x0

    .line 248
    invoke-virtual {v5, v15}, Ll2/t;->q(Z)V

    .line 249
    .line 250
    .line 251
    check-cast v12, Ll2/b1;

    .line 252
    .line 253
    move/from16 p7, v3

    .line 254
    .line 255
    const v3, 0x79f35517

    .line 256
    .line 257
    .line 258
    invoke-virtual {v5, v3}, Ll2/t;->Z(I)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v5, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v3

    .line 265
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    move-result v16

    .line 269
    or-int v3, v3, v16

    .line 270
    .line 271
    move/from16 v16, v4

    .line 272
    .line 273
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    if-nez v3, :cond_15

    .line 278
    .line 279
    if-ne v4, v14, :cond_16

    .line 280
    .line 281
    :cond_15
    new-instance v4, Lvv/i0;

    .line 282
    .line 283
    const/4 v3, 0x1

    .line 284
    invoke-direct {v4, v12, v8, v3}, Lvv/i0;-><init>(Ll2/b1;Lay0/k;I)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    :cond_16
    check-cast v4, Lay0/k;

    .line 291
    .line 292
    invoke-virtual {v5, v15}, Ll2/t;->q(Z)V

    .line 293
    .line 294
    .line 295
    const v3, 0x79f355bc

    .line 296
    .line 297
    .line 298
    invoke-virtual {v5, v3}, Ll2/t;->Z(I)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v5, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result v3

    .line 305
    invoke-virtual {v5, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result v17

    .line 309
    or-int v3, v3, v17

    .line 310
    .line 311
    invoke-virtual {v5, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result v17

    .line 315
    or-int v3, v3, v17

    .line 316
    .line 317
    move/from16 v17, v6

    .line 318
    .line 319
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v6

    .line 323
    if-nez v3, :cond_17

    .line 324
    .line 325
    if-ne v6, v14, :cond_18

    .line 326
    .line 327
    :cond_17
    new-instance v6, Lvh/j;

    .line 328
    .line 329
    invoke-direct {v6, v4, v12, v9, v13}, Lvh/j;-><init>(Lay0/k;Ll2/b1;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 330
    .line 331
    .line 332
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    :cond_18
    check-cast v6, Lay0/n;

    .line 336
    .line 337
    invoke-virtual {v5, v15}, Ll2/t;->q(Z)V

    .line 338
    .line 339
    .line 340
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 341
    .line 342
    invoke-static {v13, v9, v6}, Lp3/f0;->c(Lx2/s;Ljava/lang/Object;Lay0/n;)Lx2/s;

    .line 343
    .line 344
    .line 345
    move-result-object v3

    .line 346
    const v4, 0x79f35719

    .line 347
    .line 348
    .line 349
    invoke-virtual {v5, v4}, Ll2/t;->Z(I)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v5, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 353
    .line 354
    .line 355
    move-result v4

    .line 356
    invoke-virtual {v5, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    move-result v6

    .line 360
    or-int/2addr v4, v6

    .line 361
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v6

    .line 365
    if-nez v4, :cond_19

    .line 366
    .line 367
    if-ne v6, v14, :cond_1a

    .line 368
    .line 369
    :cond_19
    new-instance v6, Lvv/i0;

    .line 370
    .line 371
    const/4 v4, 0x0

    .line 372
    invoke-direct {v6, v12, v7, v4}, Lvv/i0;-><init>(Ll2/b1;Lay0/k;I)V

    .line 373
    .line 374
    .line 375
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 376
    .line 377
    .line 378
    :cond_1a
    check-cast v6, Lay0/k;

    .line 379
    .line 380
    invoke-virtual {v5, v15}, Ll2/t;->q(Z)V

    .line 381
    .line 382
    .line 383
    const/high16 v4, 0x1000000

    .line 384
    .line 385
    and-int/lit8 v12, v2, 0xe

    .line 386
    .line 387
    or-int/2addr v4, v12

    .line 388
    and-int/lit8 v12, v2, 0x70

    .line 389
    .line 390
    or-int/2addr v4, v12

    .line 391
    and-int v12, v2, p7

    .line 392
    .line 393
    or-int/2addr v4, v12

    .line 394
    shl-int/lit8 v12, v2, 0x6

    .line 395
    .line 396
    and-int v12, v12, v16

    .line 397
    .line 398
    or-int/2addr v4, v12

    .line 399
    shl-int/lit8 v2, v2, 0x3

    .line 400
    .line 401
    and-int v2, v2, v17

    .line 402
    .line 403
    or-int/2addr v2, v4

    .line 404
    move-object v4, v6

    .line 405
    move v6, v2

    .line 406
    move-object v2, v3

    .line 407
    move-object v3, v4

    .line 408
    move-object v4, v11

    .line 409
    invoke-static/range {v0 .. v6}, Lvv/l0;->b(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Ll2/o;I)V

    .line 410
    .line 411
    .line 412
    move-object v0, v5

    .line 413
    move-object v3, v13

    .line 414
    move-object v5, v4

    .line 415
    :goto_b
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 416
    .line 417
    .line 418
    move-result-object v11

    .line 419
    if-eqz v11, :cond_1b

    .line 420
    .line 421
    new-instance v0, Lvv/j0;

    .line 422
    .line 423
    move-object/from16 v1, p0

    .line 424
    .line 425
    move-object/from16 v2, p1

    .line 426
    .line 427
    move-object v4, v7

    .line 428
    move-object v6, v8

    .line 429
    move-object v7, v9

    .line 430
    move v8, v10

    .line 431
    move/from16 v9, p9

    .line 432
    .line 433
    invoke-direct/range {v0 .. v9}, Lvv/j0;-><init>(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Lay0/k;Lay0/k;II)V

    .line 434
    .line 435
    .line 436
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 437
    .line 438
    :cond_1b
    return-void
.end method

.method public static final b(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Ll2/o;I)V
    .locals 27

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v0, p6

    .line 6
    .line 7
    const-string v3, "$this$Text"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "text"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v8, p5

    .line 18
    .line 19
    check-cast v8, Ll2/t;

    .line 20
    .line 21
    const v3, 0x215cf550

    .line 22
    .line 23
    .line 24
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    and-int/lit8 v3, v0, 0xe

    .line 28
    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    const/4 v3, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v3, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v0

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move v3, v0

    .line 43
    :goto_1
    and-int/lit8 v4, v0, 0x70

    .line 44
    .line 45
    if-nez v4, :cond_3

    .line 46
    .line 47
    invoke-virtual {v8, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    if-eqz v4, :cond_2

    .line 52
    .line 53
    const/16 v4, 0x20

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v4, 0x10

    .line 57
    .line 58
    :goto_2
    or-int/2addr v3, v4

    .line 59
    :cond_3
    and-int/lit16 v4, v0, 0x380

    .line 60
    .line 61
    if-nez v4, :cond_5

    .line 62
    .line 63
    move-object/from16 v4, p2

    .line 64
    .line 65
    invoke-virtual {v8, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    if-eqz v5, :cond_4

    .line 70
    .line 71
    const/16 v5, 0x100

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_4
    const/16 v5, 0x80

    .line 75
    .line 76
    :goto_3
    or-int/2addr v3, v5

    .line 77
    goto :goto_4

    .line 78
    :cond_5
    move-object/from16 v4, p2

    .line 79
    .line 80
    :goto_4
    and-int/lit16 v5, v0, 0x1c00

    .line 81
    .line 82
    if-nez v5, :cond_7

    .line 83
    .line 84
    move-object/from16 v5, p3

    .line 85
    .line 86
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v6

    .line 90
    if-eqz v6, :cond_6

    .line 91
    .line 92
    const/16 v6, 0x800

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_6
    const/16 v6, 0x400

    .line 96
    .line 97
    :goto_5
    or-int/2addr v3, v6

    .line 98
    goto :goto_6

    .line 99
    :cond_7
    move-object/from16 v5, p3

    .line 100
    .line 101
    :goto_6
    const v6, 0xe000

    .line 102
    .line 103
    .line 104
    and-int v7, v0, v6

    .line 105
    .line 106
    const/4 v9, 0x1

    .line 107
    if-nez v7, :cond_9

    .line 108
    .line 109
    invoke-virtual {v8, v9}, Ll2/t;->e(I)Z

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    if-eqz v7, :cond_8

    .line 114
    .line 115
    const/16 v7, 0x4000

    .line 116
    .line 117
    goto :goto_7

    .line 118
    :cond_8
    const/16 v7, 0x2000

    .line 119
    .line 120
    :goto_7
    or-int/2addr v3, v7

    .line 121
    :cond_9
    const/high16 v7, 0x70000

    .line 122
    .line 123
    and-int v10, v0, v7

    .line 124
    .line 125
    if-nez v10, :cond_b

    .line 126
    .line 127
    invoke-virtual {v8, v9}, Ll2/t;->h(Z)Z

    .line 128
    .line 129
    .line 130
    move-result v9

    .line 131
    if-eqz v9, :cond_a

    .line 132
    .line 133
    const/high16 v9, 0x20000

    .line 134
    .line 135
    goto :goto_8

    .line 136
    :cond_a
    const/high16 v9, 0x10000

    .line 137
    .line 138
    :goto_8
    or-int/2addr v3, v9

    .line 139
    :cond_b
    const/high16 v9, 0x380000

    .line 140
    .line 141
    and-int v10, v0, v9

    .line 142
    .line 143
    if-nez v10, :cond_d

    .line 144
    .line 145
    const v10, 0x7fffffff

    .line 146
    .line 147
    .line 148
    invoke-virtual {v8, v10}, Ll2/t;->e(I)Z

    .line 149
    .line 150
    .line 151
    move-result v10

    .line 152
    if-eqz v10, :cond_c

    .line 153
    .line 154
    const/high16 v10, 0x100000

    .line 155
    .line 156
    goto :goto_9

    .line 157
    :cond_c
    const/high16 v10, 0x80000

    .line 158
    .line 159
    :goto_9
    or-int/2addr v3, v10

    .line 160
    :cond_d
    const v10, 0x5d14719b

    .line 161
    .line 162
    .line 163
    invoke-virtual {v8, v10}, Ll2/t;->Z(I)V

    .line 164
    .line 165
    .line 166
    invoke-static {v1, v8}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 167
    .line 168
    .line 169
    move-result-object v10

    .line 170
    invoke-virtual {v10}, Lg4/p0;->b()J

    .line 171
    .line 172
    .line 173
    move-result-wide v10

    .line 174
    sget-wide v12, Le3/s;->i:J

    .line 175
    .line 176
    cmp-long v12, v10, v12

    .line 177
    .line 178
    if-eqz v12, :cond_e

    .line 179
    .line 180
    :goto_a
    move-wide v13, v10

    .line 181
    goto :goto_b

    .line 182
    :cond_e
    invoke-static {v1, v8}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 183
    .line 184
    .line 185
    move-result-wide v10

    .line 186
    goto :goto_a

    .line 187
    :goto_b
    const/4 v10, 0x0

    .line 188
    invoke-virtual {v8, v10}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    invoke-static {v1, v8}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 192
    .line 193
    .line 194
    move-result-object v12

    .line 195
    const/16 v25, 0x0

    .line 196
    .line 197
    const v26, 0xfffffe

    .line 198
    .line 199
    .line 200
    const-wide/16 v15, 0x0

    .line 201
    .line 202
    const/16 v17, 0x0

    .line 203
    .line 204
    const/16 v18, 0x0

    .line 205
    .line 206
    const-wide/16 v19, 0x0

    .line 207
    .line 208
    const/16 v21, 0x0

    .line 209
    .line 210
    const-wide/16 v22, 0x0

    .line 211
    .line 212
    const/16 v24, 0x0

    .line 213
    .line 214
    invoke-static/range {v12 .. v26}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 215
    .line 216
    .line 217
    move-result-object v10

    .line 218
    shr-int/lit8 v11, v3, 0x3

    .line 219
    .line 220
    and-int/lit8 v12, v11, 0xe

    .line 221
    .line 222
    const/high16 v13, 0x8000000

    .line 223
    .line 224
    or-int/2addr v12, v13

    .line 225
    and-int/lit8 v11, v11, 0x70

    .line 226
    .line 227
    or-int/2addr v11, v12

    .line 228
    and-int/lit16 v12, v3, 0x1c00

    .line 229
    .line 230
    or-int/2addr v11, v12

    .line 231
    and-int/2addr v6, v3

    .line 232
    or-int/2addr v6, v11

    .line 233
    and-int/2addr v7, v3

    .line 234
    or-int/2addr v6, v7

    .line 235
    and-int/2addr v3, v9

    .line 236
    or-int v9, v6, v3

    .line 237
    .line 238
    const/4 v6, 0x0

    .line 239
    move-object/from16 v7, p4

    .line 240
    .line 241
    move-object v3, v4

    .line 242
    move-object v4, v10

    .line 243
    invoke-static/range {v2 .. v9}, Lt1/l0;->b(Lg4/g;Lx2/s;Lg4/p0;Lay0/k;ILjava/util/Map;Ll2/o;I)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 247
    .line 248
    .line 249
    move-result-object v7

    .line 250
    if-eqz v7, :cond_f

    .line 251
    .line 252
    new-instance v0, Lb1/h0;

    .line 253
    .line 254
    move-object/from16 v2, p1

    .line 255
    .line 256
    move-object/from16 v3, p2

    .line 257
    .line 258
    move-object/from16 v4, p3

    .line 259
    .line 260
    move-object/from16 v5, p4

    .line 261
    .line 262
    move/from16 v6, p6

    .line 263
    .line 264
    invoke-direct/range {v0 .. v6}, Lb1/h0;-><init>(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;I)V

    .line 265
    .line 266
    .line 267
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 268
    .line 269
    :cond_f
    return-void
.end method

.method public static final c(Lvv/m0;Ljava/lang/String;Lx2/s;Lay0/k;IZILl2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    const-string v0, "$this$Text"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "text"

    .line 11
    .line 12
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    move-object/from16 v10, p7

    .line 16
    .line 17
    check-cast v10, Ll2/t;

    .line 18
    .line 19
    const v0, -0x56d28f7c

    .line 20
    .line 21
    .line 22
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    and-int/lit8 v0, p8, 0xe

    .line 26
    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const/4 v0, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v0, 0x2

    .line 38
    :goto_0
    or-int v0, p8, v0

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move/from16 v0, p8

    .line 42
    .line 43
    :goto_1
    and-int/lit8 v3, p8, 0x70

    .line 44
    .line 45
    if-nez v3, :cond_3

    .line 46
    .line 47
    invoke-virtual {v10, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_2

    .line 52
    .line 53
    const/16 v3, 0x20

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v3, 0x10

    .line 57
    .line 58
    :goto_2
    or-int/2addr v0, v3

    .line 59
    :cond_3
    const v3, 0x1b6d80

    .line 60
    .line 61
    .line 62
    or-int/2addr v0, v3

    .line 63
    const v3, 0x2db6db

    .line 64
    .line 65
    .line 66
    and-int/2addr v3, v0

    .line 67
    const v4, 0x92492

    .line 68
    .line 69
    .line 70
    if-ne v3, v4, :cond_5

    .line 71
    .line 72
    invoke-virtual {v10}, Ll2/t;->A()Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    if-nez v3, :cond_4

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 80
    .line 81
    .line 82
    move-object/from16 v3, p2

    .line 83
    .line 84
    move-object/from16 v4, p3

    .line 85
    .line 86
    move/from16 v5, p4

    .line 87
    .line 88
    move/from16 v6, p5

    .line 89
    .line 90
    move/from16 v7, p6

    .line 91
    .line 92
    goto :goto_6

    .line 93
    :cond_5
    :goto_3
    sget-object v5, Lvv/b;->o:Lvv/b;

    .line 94
    .line 95
    const v3, 0x5d146f19

    .line 96
    .line 97
    .line 98
    invoke-virtual {v10, v3}, Ll2/t;->Z(I)V

    .line 99
    .line 100
    .line 101
    invoke-static {v1, v10}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-virtual {v3}, Lg4/p0;->b()J

    .line 106
    .line 107
    .line 108
    move-result-wide v3

    .line 109
    sget-wide v6, Le3/s;->i:J

    .line 110
    .line 111
    cmp-long v6, v3, v6

    .line 112
    .line 113
    if-eqz v6, :cond_6

    .line 114
    .line 115
    :goto_4
    move-wide v12, v3

    .line 116
    goto :goto_5

    .line 117
    :cond_6
    invoke-static {v1, v10}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 118
    .line 119
    .line 120
    move-result-wide v3

    .line 121
    goto :goto_4

    .line 122
    :goto_5
    const/4 v3, 0x0

    .line 123
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 124
    .line 125
    .line 126
    invoke-static {v1, v10}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 127
    .line 128
    .line 129
    move-result-object v11

    .line 130
    const/16 v24, 0x0

    .line 131
    .line 132
    const v25, 0xfffffe

    .line 133
    .line 134
    .line 135
    const-wide/16 v14, 0x0

    .line 136
    .line 137
    const/16 v16, 0x0

    .line 138
    .line 139
    const/16 v17, 0x0

    .line 140
    .line 141
    const-wide/16 v18, 0x0

    .line 142
    .line 143
    const/16 v20, 0x0

    .line 144
    .line 145
    const-wide/16 v21, 0x0

    .line 146
    .line 147
    const/16 v23, 0x0

    .line 148
    .line 149
    invoke-static/range {v11 .. v25}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    shr-int/lit8 v3, v0, 0x3

    .line 154
    .line 155
    and-int/lit8 v3, v3, 0x7e

    .line 156
    .line 157
    and-int/lit16 v6, v0, 0x1c00

    .line 158
    .line 159
    or-int/2addr v3, v6

    .line 160
    const v6, 0xe000

    .line 161
    .line 162
    .line 163
    and-int/2addr v6, v0

    .line 164
    or-int/2addr v3, v6

    .line 165
    const/high16 v6, 0x70000

    .line 166
    .line 167
    and-int/2addr v6, v0

    .line 168
    or-int/2addr v3, v6

    .line 169
    const/high16 v6, 0x380000

    .line 170
    .line 171
    and-int/2addr v0, v6

    .line 172
    or-int v11, v3, v0

    .line 173
    .line 174
    const/16 v12, 0x180

    .line 175
    .line 176
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 177
    .line 178
    const/4 v6, 0x1

    .line 179
    const/4 v7, 0x1

    .line 180
    const v8, 0x7fffffff

    .line 181
    .line 182
    .line 183
    const/4 v9, 0x0

    .line 184
    invoke-static/range {v2 .. v12}, Lt1/l0;->d(Ljava/lang/String;Lx2/s;Lg4/p0;Lay0/k;IZIILl2/o;II)V

    .line 185
    .line 186
    .line 187
    move-object v4, v5

    .line 188
    move v5, v6

    .line 189
    move v6, v7

    .line 190
    move v7, v8

    .line 191
    :goto_6
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 192
    .line 193
    .line 194
    move-result-object v9

    .line 195
    if-eqz v9, :cond_7

    .line 196
    .line 197
    new-instance v0, Lvv/k0;

    .line 198
    .line 199
    move-object/from16 v2, p1

    .line 200
    .line 201
    move/from16 v8, p8

    .line 202
    .line 203
    invoke-direct/range {v0 .. v8}, Lvv/k0;-><init>(Lvv/m0;Ljava/lang/String;Lx2/s;Lay0/k;IZII)V

    .line 204
    .line 205
    .line 206
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 207
    .line 208
    :cond_7
    return-void
.end method

.method public static final d(Lvv/m0;Ll2/o;)J
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const p0, -0x17eb6fbe

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Lvv/q0;->a:Ll2/e0;

    .line 15
    .line 16
    const p0, 0x191210e

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Lvv/q0;->a:Ll2/e0;

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lvv/p0;

    .line 29
    .line 30
    iget-object p0, p0, Lvv/p0;->c:Lay0/n;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-interface {p0, p1, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Le3/s;

    .line 45
    .line 46
    iget-wide v1, p0, Le3/s;->a:J

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 49
    .line 50
    .line 51
    return-wide v1
.end method

.method public static final e(Lvv/m0;Ll2/o;)Lg4/p0;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const p0, -0x627a1239

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Lvv/q0;->a:Ll2/e0;

    .line 15
    .line 16
    const p0, -0x17fc1b0a

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Lvv/q0;->a:Ll2/e0;

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lvv/p0;

    .line 29
    .line 30
    iget-object p0, p0, Lvv/p0;->a:Lay0/n;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-interface {p0, p1, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Lg4/p0;

    .line 45
    .line 46
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 47
    .line 48
    .line 49
    return-object p0
.end method
