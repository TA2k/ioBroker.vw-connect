.class public abstract Ln70/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:Lcom/google/android/gms/maps/model/LatLng;

.field public static final c:Luu/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    const/16 v0, 0x1e

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Ln70/o;->a:F

    .line 5
    .line 6
    new-instance v0, Lcom/google/android/gms/maps/model/LatLng;

    .line 7
    .line 8
    const-wide v1, 0x40490dbe6885fb57L    # 50.1073733

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    const-wide v3, 0x402ce8761be60f94L    # 14.4540261

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    invoke-direct {v0, v1, v2, v3, v4}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Ln70/o;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 22
    .line 23
    new-instance v5, Luu/a1;

    .line 24
    .line 25
    const/4 v14, 0x0

    .line 26
    const/4 v15, 0x1

    .line 27
    const/4 v6, 0x0

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v8, 0x0

    .line 30
    const/4 v9, 0x0

    .line 31
    const/4 v10, 0x1

    .line 32
    const/4 v11, 0x1

    .line 33
    const/4 v12, 0x1

    .line 34
    const/4 v13, 0x0

    .line 35
    invoke-direct/range {v5 .. v15}, Luu/a1;-><init>(ZZZZZZZZZZ)V

    .line 36
    .line 37
    .line 38
    sput-object v5, Ln70/o;->c:Luu/a1;

    .line 39
    .line 40
    return-void
.end method

.method public static final a(Ljava/util/List;Lk1/a1;Luu/g;Lxj0/j;Lx2/s;Lay0/k;Lm70/r;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v0, p3

    .line 6
    .line 7
    move-object/from16 v8, p4

    .line 8
    .line 9
    move-object/from16 v9, p6

    .line 10
    .line 11
    move/from16 v10, p8

    .line 12
    .line 13
    const-string v2, "cameraPositionState"

    .line 14
    .line 15
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v2, "mapTileType"

    .line 19
    .line 20
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    move-object/from16 v14, p7

    .line 24
    .line 25
    check-cast v14, Ll2/t;

    .line 26
    .line 27
    const v2, -0x41a0b56b

    .line 28
    .line 29
    .line 30
    invoke-virtual {v14, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 31
    .line 32
    .line 33
    and-int/lit8 v2, v10, 0x6

    .line 34
    .line 35
    if-nez v2, :cond_1

    .line 36
    .line 37
    invoke-virtual {v14, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_0

    .line 42
    .line 43
    const/4 v2, 0x4

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const/4 v2, 0x2

    .line 46
    :goto_0
    or-int/2addr v2, v10

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    move v2, v10

    .line 49
    :goto_1
    and-int/lit8 v4, v10, 0x30

    .line 50
    .line 51
    move-object/from16 v11, p1

    .line 52
    .line 53
    if-nez v4, :cond_3

    .line 54
    .line 55
    invoke-virtual {v14, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_2

    .line 60
    .line 61
    const/16 v4, 0x20

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    const/16 v4, 0x10

    .line 65
    .line 66
    :goto_2
    or-int/2addr v2, v4

    .line 67
    :cond_3
    and-int/lit16 v4, v10, 0x180

    .line 68
    .line 69
    const-string v5, "trip_detail_map"

    .line 70
    .line 71
    if-nez v4, :cond_5

    .line 72
    .line 73
    invoke-virtual {v14, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_4

    .line 78
    .line 79
    const/16 v4, 0x100

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_4
    const/16 v4, 0x80

    .line 83
    .line 84
    :goto_3
    or-int/2addr v2, v4

    .line 85
    :cond_5
    and-int/lit16 v4, v10, 0xc00

    .line 86
    .line 87
    if-nez v4, :cond_8

    .line 88
    .line 89
    and-int/lit16 v4, v10, 0x1000

    .line 90
    .line 91
    if-nez v4, :cond_6

    .line 92
    .line 93
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    goto :goto_4

    .line 98
    :cond_6
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    :goto_4
    if-eqz v4, :cond_7

    .line 103
    .line 104
    const/16 v4, 0x800

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_7
    const/16 v4, 0x400

    .line 108
    .line 109
    :goto_5
    or-int/2addr v2, v4

    .line 110
    :cond_8
    and-int/lit16 v4, v10, 0x6000

    .line 111
    .line 112
    if-nez v4, :cond_a

    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    invoke-virtual {v14, v4}, Ll2/t;->e(I)Z

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    if-eqz v4, :cond_9

    .line 123
    .line 124
    const/16 v4, 0x4000

    .line 125
    .line 126
    goto :goto_6

    .line 127
    :cond_9
    const/16 v4, 0x2000

    .line 128
    .line 129
    :goto_6
    or-int/2addr v2, v4

    .line 130
    :cond_a
    const/high16 v4, 0x30000

    .line 131
    .line 132
    and-int/2addr v4, v10

    .line 133
    if-nez v4, :cond_c

    .line 134
    .line 135
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v4

    .line 139
    if-eqz v4, :cond_b

    .line 140
    .line 141
    const/high16 v4, 0x20000

    .line 142
    .line 143
    goto :goto_7

    .line 144
    :cond_b
    const/high16 v4, 0x10000

    .line 145
    .line 146
    :goto_7
    or-int/2addr v2, v4

    .line 147
    :cond_c
    const/high16 v4, 0x180000

    .line 148
    .line 149
    and-int/2addr v4, v10

    .line 150
    move-object/from16 v12, p5

    .line 151
    .line 152
    if-nez v4, :cond_e

    .line 153
    .line 154
    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v4

    .line 158
    if-eqz v4, :cond_d

    .line 159
    .line 160
    const/high16 v4, 0x100000

    .line 161
    .line 162
    goto :goto_8

    .line 163
    :cond_d
    const/high16 v4, 0x80000

    .line 164
    .line 165
    :goto_8
    or-int/2addr v2, v4

    .line 166
    :cond_e
    const/high16 v4, 0xc00000

    .line 167
    .line 168
    and-int/2addr v4, v10

    .line 169
    if-nez v4, :cond_11

    .line 170
    .line 171
    const/high16 v4, 0x1000000

    .line 172
    .line 173
    and-int/2addr v4, v10

    .line 174
    if-nez v4, :cond_f

    .line 175
    .line 176
    invoke-virtual {v14, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v4

    .line 180
    goto :goto_9

    .line 181
    :cond_f
    invoke-virtual {v14, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    :goto_9
    if-eqz v4, :cond_10

    .line 186
    .line 187
    const/high16 v4, 0x800000

    .line 188
    .line 189
    goto :goto_a

    .line 190
    :cond_10
    const/high16 v4, 0x400000

    .line 191
    .line 192
    :goto_a
    or-int/2addr v2, v4

    .line 193
    :cond_11
    move v13, v2

    .line 194
    const v2, 0x492493

    .line 195
    .line 196
    .line 197
    and-int/2addr v2, v13

    .line 198
    const v4, 0x492492

    .line 199
    .line 200
    .line 201
    const/4 v7, 0x0

    .line 202
    if-eq v2, v4, :cond_12

    .line 203
    .line 204
    const/4 v2, 0x1

    .line 205
    goto :goto_b

    .line 206
    :cond_12
    move v2, v7

    .line 207
    :goto_b
    and-int/lit8 v4, v13, 0x1

    .line 208
    .line 209
    invoke-virtual {v14, v4, v2}, Ll2/t;->O(IZ)Z

    .line 210
    .line 211
    .line 212
    move-result v2

    .line 213
    if-eqz v2, :cond_22

    .line 214
    .line 215
    invoke-static {v8, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 220
    .line 221
    invoke-static {v4, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 222
    .line 223
    .line 224
    move-result-object v4

    .line 225
    iget-wide v6, v14, Ll2/t;->T:J

    .line 226
    .line 227
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 228
    .line 229
    .line 230
    move-result v6

    .line 231
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 232
    .line 233
    .line 234
    move-result-object v7

    .line 235
    invoke-static {v14, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 240
    .line 241
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 242
    .line 243
    .line 244
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 245
    .line 246
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 247
    .line 248
    .line 249
    iget-boolean v15, v14, Ll2/t;->S:Z

    .line 250
    .line 251
    if-eqz v15, :cond_13

    .line 252
    .line 253
    invoke-virtual {v14, v5}, Ll2/t;->l(Lay0/a;)V

    .line 254
    .line 255
    .line 256
    goto :goto_c

    .line 257
    :cond_13
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 258
    .line 259
    .line 260
    :goto_c
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 261
    .line 262
    invoke-static {v5, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 263
    .line 264
    .line 265
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 266
    .line 267
    invoke-static {v4, v7, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 268
    .line 269
    .line 270
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 271
    .line 272
    iget-boolean v5, v14, Ll2/t;->S:Z

    .line 273
    .line 274
    if-nez v5, :cond_14

    .line 275
    .line 276
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v5

    .line 280
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v7

    .line 284
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v5

    .line 288
    if-nez v5, :cond_15

    .line 289
    .line 290
    :cond_14
    invoke-static {v6, v14, v6, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 291
    .line 292
    .line 293
    :cond_15
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 294
    .line 295
    invoke-static {v4, v2, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 296
    .line 297
    .line 298
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 299
    .line 300
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    check-cast v2, Landroid/content/Context;

    .line 305
    .line 306
    sget-object v4, Lw3/h1;->h:Ll2/u2;

    .line 307
    .line 308
    invoke-virtual {v14, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v4

    .line 312
    move-object v5, v4

    .line 313
    check-cast v5, Lt4/c;

    .line 314
    .line 315
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v4

    .line 319
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 320
    .line 321
    if-ne v4, v6, :cond_16

    .line 322
    .line 323
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 324
    .line 325
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 326
    .line 327
    .line 328
    move-result-object v4

    .line 329
    invoke-virtual {v14, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    :cond_16
    check-cast v4, Ll2/b1;

    .line 333
    .line 334
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v7

    .line 338
    if-ne v7, v6, :cond_1a

    .line 339
    .line 340
    move-object v7, v1

    .line 341
    check-cast v7, Ljava/lang/Iterable;

    .line 342
    .line 343
    new-instance v15, Ljava/util/ArrayList;

    .line 344
    .line 345
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 346
    .line 347
    .line 348
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 349
    .line 350
    .line 351
    move-result-object v7

    .line 352
    :goto_d
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 353
    .line 354
    .line 355
    move-result v18

    .line 356
    if-eqz v18, :cond_19

    .line 357
    .line 358
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object v0

    .line 362
    move-object v1, v0

    .line 363
    check-cast v1, Lm70/r;

    .line 364
    .line 365
    iget-object v1, v1, Lm70/r;->c:Lxj0/f;

    .line 366
    .line 367
    if-eqz v1, :cond_17

    .line 368
    .line 369
    const/4 v1, 0x1

    .line 370
    goto :goto_e

    .line 371
    :cond_17
    const/4 v1, 0x0

    .line 372
    :goto_e
    if-eqz v1, :cond_18

    .line 373
    .line 374
    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 375
    .line 376
    .line 377
    :cond_18
    move-object/from16 v1, p0

    .line 378
    .line 379
    move-object/from16 v0, p3

    .line 380
    .line 381
    goto :goto_d

    .line 382
    :cond_19
    invoke-virtual {v14, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 383
    .line 384
    .line 385
    move-object v7, v15

    .line 386
    :cond_1a
    check-cast v7, Ljava/util/List;

    .line 387
    .line 388
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v0

    .line 392
    if-ne v0, v6, :cond_1b

    .line 393
    .line 394
    new-instance v0, Luu/u0;

    .line 395
    .line 396
    invoke-static {v2}, Lsp/j;->x0(Landroid/content/Context;)Lsp/j;

    .line 397
    .line 398
    .line 399
    move-result-object v1

    .line 400
    const/16 v2, 0x1df

    .line 401
    .line 402
    invoke-direct {v0, v1, v2}, Luu/u0;-><init>(Lsp/j;I)V

    .line 403
    .line 404
    .line 405
    invoke-virtual {v14, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 406
    .line 407
    .line 408
    :cond_1b
    check-cast v0, Luu/u0;

    .line 409
    .line 410
    invoke-virtual/range {p3 .. p3}, Ljava/lang/Enum;->ordinal()I

    .line 411
    .line 412
    .line 413
    move-result v1

    .line 414
    if-eqz v1, :cond_1d

    .line 415
    .line 416
    const/4 v15, 0x1

    .line 417
    if-ne v1, v15, :cond_1c

    .line 418
    .line 419
    sget-object v1, Luu/z0;->f:Luu/z0;

    .line 420
    .line 421
    goto :goto_f

    .line 422
    :cond_1c
    new-instance v0, La8/r0;

    .line 423
    .line 424
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 425
    .line 426
    .line 427
    throw v0

    .line 428
    :cond_1d
    const/4 v15, 0x1

    .line 429
    sget-object v1, Luu/z0;->e:Luu/z0;

    .line 430
    .line 431
    :goto_f
    const/16 v2, 0x1bf

    .line 432
    .line 433
    const/4 v15, 0x0

    .line 434
    invoke-static {v0, v15, v1, v2}, Luu/u0;->a(Luu/u0;ZLuu/z0;I)Luu/u0;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    sget-object v1, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 439
    .line 440
    invoke-virtual {v1}, Landroidx/compose/foundation/layout/b;->b()Lx2/s;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    and-int/lit16 v2, v13, 0x1c00

    .line 445
    .line 446
    const/16 v15, 0x800

    .line 447
    .line 448
    if-eq v2, v15, :cond_1f

    .line 449
    .line 450
    and-int/lit16 v2, v13, 0x1000

    .line 451
    .line 452
    if-eqz v2, :cond_1e

    .line 453
    .line 454
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 455
    .line 456
    .line 457
    move-result v2

    .line 458
    if-eqz v2, :cond_1e

    .line 459
    .line 460
    goto :goto_10

    .line 461
    :cond_1e
    const/16 v16, 0x0

    .line 462
    .line 463
    goto :goto_11

    .line 464
    :cond_1f
    :goto_10
    const/16 v16, 0x1

    .line 465
    .line 466
    :goto_11
    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 467
    .line 468
    .line 469
    move-result v2

    .line 470
    or-int v2, v16, v2

    .line 471
    .line 472
    invoke-virtual {v14, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    move-result v15

    .line 476
    or-int/2addr v2, v15

    .line 477
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v15

    .line 481
    if-nez v2, :cond_21

    .line 482
    .line 483
    if-ne v15, v6, :cond_20

    .line 484
    .line 485
    goto :goto_12

    .line 486
    :cond_20
    move-object v2, v15

    .line 487
    move-object v15, v4

    .line 488
    move-object v4, v7

    .line 489
    goto :goto_13

    .line 490
    :cond_21
    :goto_12
    new-instance v2, Lal/i;

    .line 491
    .line 492
    move-object v6, v4

    .line 493
    move-object v4, v7

    .line 494
    const/4 v7, 0x5

    .line 495
    invoke-direct/range {v2 .. v7}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 496
    .line 497
    .line 498
    move-object v15, v6

    .line 499
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 500
    .line 501
    .line 502
    :goto_13
    move-object/from16 v16, v2

    .line 503
    .line 504
    check-cast v16, Lay0/a;

    .line 505
    .line 506
    new-instance v2, Laj0/b;

    .line 507
    .line 508
    const/16 v7, 0x17

    .line 509
    .line 510
    move-object/from16 v3, p3

    .line 511
    .line 512
    move-object v5, v9

    .line 513
    move-object v6, v12

    .line 514
    invoke-direct/range {v2 .. v7}, Laj0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 515
    .line 516
    .line 517
    const v3, -0x3c70f26c

    .line 518
    .line 519
    .line 520
    invoke-static {v3, v14, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 521
    .line 522
    .line 523
    move-result-object v2

    .line 524
    shr-int/lit8 v3, v13, 0x3

    .line 525
    .line 526
    and-int/lit16 v3, v3, 0x380

    .line 527
    .line 528
    shl-int/lit8 v4, v13, 0xc

    .line 529
    .line 530
    const/high16 v5, 0x70000

    .line 531
    .line 532
    and-int/2addr v4, v5

    .line 533
    const/high16 v5, 0x6000000

    .line 534
    .line 535
    or-int/2addr v4, v5

    .line 536
    const/4 v5, 0x1

    .line 537
    const v17, 0x3775a

    .line 538
    .line 539
    .line 540
    move-object/from16 v10, v16

    .line 541
    .line 542
    move/from16 v16, v4

    .line 543
    .line 544
    const/4 v4, 0x0

    .line 545
    sget-object v6, Ln70/o;->c:Luu/a1;

    .line 546
    .line 547
    const/4 v7, 0x0

    .line 548
    const/4 v8, 0x0

    .line 549
    const/4 v9, 0x0

    .line 550
    const/4 v12, 0x0

    .line 551
    move-object v5, v0

    .line 552
    move/from16 p7, v13

    .line 553
    .line 554
    move-object/from16 v0, p3

    .line 555
    .line 556
    move-object v13, v2

    .line 557
    move-object v2, v1

    .line 558
    move-object v1, v15

    .line 559
    move v15, v3

    .line 560
    move-object/from16 v3, p2

    .line 561
    .line 562
    invoke-static/range {v2 .. v17}, Llp/ca;->b(Lx2/s;Luu/g;Lay0/a;Luu/u0;Luu/a1;Luu/o;Lay0/k;Lay0/k;Lay0/a;Lk1/z0;Lay0/n;Lt2/b;Ll2/o;III)V

    .line 563
    .line 564
    .line 565
    new-instance v2, Leh/c;

    .line 566
    .line 567
    const/16 v3, 0x1b

    .line 568
    .line 569
    invoke-direct {v2, v1, v3}, Leh/c;-><init>(Ll2/b1;I)V

    .line 570
    .line 571
    .line 572
    const v1, -0x445b23aa

    .line 573
    .line 574
    .line 575
    invoke-static {v1, v14, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 576
    .line 577
    .line 578
    move-result-object v1

    .line 579
    shr-int/lit8 v2, p7, 0xc

    .line 580
    .line 581
    and-int/lit8 v2, v2, 0xe

    .line 582
    .line 583
    or-int/lit8 v2, v2, 0x30

    .line 584
    .line 585
    invoke-static {v0, v1, v14, v2}, Lzj0/d;->b(Lxj0/j;Lt2/b;Ll2/o;I)V

    .line 586
    .line 587
    .line 588
    const/4 v15, 0x1

    .line 589
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 590
    .line 591
    .line 592
    goto :goto_14

    .line 593
    :cond_22
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 594
    .line 595
    .line 596
    :goto_14
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 597
    .line 598
    .line 599
    move-result-object v9

    .line 600
    if-eqz v9, :cond_23

    .line 601
    .line 602
    new-instance v0, Ld80/i;

    .line 603
    .line 604
    move-object/from16 v1, p0

    .line 605
    .line 606
    move-object/from16 v2, p1

    .line 607
    .line 608
    move-object/from16 v3, p2

    .line 609
    .line 610
    move-object/from16 v4, p3

    .line 611
    .line 612
    move-object/from16 v5, p4

    .line 613
    .line 614
    move-object/from16 v6, p5

    .line 615
    .line 616
    move-object/from16 v7, p6

    .line 617
    .line 618
    move/from16 v8, p8

    .line 619
    .line 620
    invoke-direct/range {v0 .. v8}, Ld80/i;-><init>(Ljava/util/List;Lk1/a1;Luu/g;Lxj0/j;Lx2/s;Lay0/k;Lm70/r;I)V

    .line 621
    .line 622
    .line 623
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 624
    .line 625
    :cond_23
    return-void
.end method
