.class public abstract Lh2/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    int-to-float v0, v0

    .line 3
    sput v0, Lh2/e1;->a:F

    .line 4
    .line 5
    const/16 v1, 0x14

    .line 6
    .line 7
    int-to-float v1, v1

    .line 8
    sput v1, Lh2/e1;->b:F

    .line 9
    .line 10
    sput v0, Lh2/e1;->c:F

    .line 11
    .line 12
    return-void
.end method

.method public static final a(ZLf4/a;Lx2/s;Lh2/b1;Lg3/h;Lg3/h;Ll2/o;I)V
    .locals 25

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move-object/from16 v12, p4

    .line 10
    .line 11
    move-object/from16 v8, p5

    .line 12
    .line 13
    move/from16 v0, p7

    .line 14
    .line 15
    move-object/from16 v5, p6

    .line 16
    .line 17
    check-cast v5, Ll2/t;

    .line 18
    .line 19
    const v6, -0x35209ea0    # -7319728.0f

    .line 20
    .line 21
    .line 22
    invoke-virtual {v5, v6}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    and-int/lit8 v6, v0, 0x6

    .line 26
    .line 27
    const/4 v7, 0x2

    .line 28
    if-nez v6, :cond_1

    .line 29
    .line 30
    invoke-virtual {v5, v1}, Ll2/t;->h(Z)Z

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    if-eqz v6, :cond_0

    .line 35
    .line 36
    const/4 v6, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v6, v7

    .line 39
    :goto_0
    or-int/2addr v6, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v6, v0

    .line 42
    :goto_1
    and-int/lit8 v9, v0, 0x30

    .line 43
    .line 44
    if-nez v9, :cond_3

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v9

    .line 50
    invoke-virtual {v5, v9}, Ll2/t;->e(I)Z

    .line 51
    .line 52
    .line 53
    move-result v9

    .line 54
    if-eqz v9, :cond_2

    .line 55
    .line 56
    const/16 v9, 0x20

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_2
    const/16 v9, 0x10

    .line 60
    .line 61
    :goto_2
    or-int/2addr v6, v9

    .line 62
    :cond_3
    and-int/lit16 v9, v0, 0x180

    .line 63
    .line 64
    if-nez v9, :cond_5

    .line 65
    .line 66
    invoke-virtual {v5, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    if-eqz v9, :cond_4

    .line 71
    .line 72
    const/16 v9, 0x100

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    const/16 v9, 0x80

    .line 76
    .line 77
    :goto_3
    or-int/2addr v6, v9

    .line 78
    :cond_5
    and-int/lit16 v9, v0, 0xc00

    .line 79
    .line 80
    if-nez v9, :cond_7

    .line 81
    .line 82
    invoke-virtual {v5, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v9

    .line 86
    if-eqz v9, :cond_6

    .line 87
    .line 88
    const/16 v9, 0x800

    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_6
    const/16 v9, 0x400

    .line 92
    .line 93
    :goto_4
    or-int/2addr v6, v9

    .line 94
    :cond_7
    and-int/lit16 v9, v0, 0x6000

    .line 95
    .line 96
    if-nez v9, :cond_9

    .line 97
    .line 98
    invoke-virtual {v5, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v9

    .line 102
    if-eqz v9, :cond_8

    .line 103
    .line 104
    const/16 v9, 0x4000

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_8
    const/16 v9, 0x2000

    .line 108
    .line 109
    :goto_5
    or-int/2addr v6, v9

    .line 110
    :cond_9
    const/high16 v9, 0x30000

    .line 111
    .line 112
    and-int/2addr v9, v0

    .line 113
    if-nez v9, :cond_b

    .line 114
    .line 115
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v9

    .line 119
    if-eqz v9, :cond_a

    .line 120
    .line 121
    const/high16 v9, 0x20000

    .line 122
    .line 123
    goto :goto_6

    .line 124
    :cond_a
    const/high16 v9, 0x10000

    .line 125
    .line 126
    :goto_6
    or-int/2addr v6, v9

    .line 127
    :cond_b
    const v9, 0x12493

    .line 128
    .line 129
    .line 130
    and-int/2addr v9, v6

    .line 131
    const v10, 0x12492

    .line 132
    .line 133
    .line 134
    const/4 v11, 0x1

    .line 135
    const/4 v13, 0x0

    .line 136
    if-eq v9, v10, :cond_c

    .line 137
    .line 138
    move v9, v11

    .line 139
    goto :goto_7

    .line 140
    :cond_c
    move v9, v13

    .line 141
    :goto_7
    and-int/lit8 v10, v6, 0x1

    .line 142
    .line 143
    invoke-virtual {v5, v10, v9}, Ll2/t;->O(IZ)Z

    .line 144
    .line 145
    .line 146
    move-result v9

    .line 147
    if-eqz v9, :cond_2f

    .line 148
    .line 149
    shr-int/lit8 v6, v6, 0x3

    .line 150
    .line 151
    and-int/lit8 v6, v6, 0xe

    .line 152
    .line 153
    const/4 v9, 0x0

    .line 154
    invoke-static {v2, v9, v5, v6, v7}, Lc1/z1;->f(Ljava/lang/Object;Ljava/lang/String;Ll2/o;II)Lc1/w1;

    .line 155
    .line 156
    .line 157
    move-result-object v6

    .line 158
    iget-object v9, v6, Lc1/w1;->d:Ll2/j1;

    .line 159
    .line 160
    iget-object v10, v6, Lc1/w1;->a:Lap0/o;

    .line 161
    .line 162
    sget-object v14, Lk2/w;->d:Lk2/w;

    .line 163
    .line 164
    invoke-static {v14, v5}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 165
    .line 166
    .line 167
    move-result-object v20

    .line 168
    sget-object v17, Lc1/d;->j:Lc1/b2;

    .line 169
    .line 170
    invoke-virtual {v10}, Lap0/o;->D()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v14

    .line 174
    check-cast v14, Lf4/a;

    .line 175
    .line 176
    const v15, -0x2dcb949a

    .line 177
    .line 178
    .line 179
    invoke-virtual {v5, v15}, Ll2/t;->Y(I)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 183
    .line 184
    .line 185
    move-result v14

    .line 186
    const/16 v21, 0x0

    .line 187
    .line 188
    const/high16 v22, 0x3f800000    # 1.0f

    .line 189
    .line 190
    if-eqz v14, :cond_d

    .line 191
    .line 192
    if-eq v14, v11, :cond_f

    .line 193
    .line 194
    if-ne v14, v7, :cond_e

    .line 195
    .line 196
    :cond_d
    move/from16 v14, v22

    .line 197
    .line 198
    goto :goto_8

    .line 199
    :cond_e
    new-instance v0, La8/r0;

    .line 200
    .line 201
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 202
    .line 203
    .line 204
    throw v0

    .line 205
    :cond_f
    move/from16 v14, v21

    .line 206
    .line 207
    :goto_8
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    .line 208
    .line 209
    .line 210
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 211
    .line 212
    .line 213
    move-result-object v14

    .line 214
    invoke-virtual {v9}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v16

    .line 218
    check-cast v16, Lf4/a;

    .line 219
    .line 220
    invoke-virtual {v5, v15}, Ll2/t;->Y(I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Enum;->ordinal()I

    .line 224
    .line 225
    .line 226
    move-result v15

    .line 227
    if-eqz v15, :cond_10

    .line 228
    .line 229
    if-eq v15, v11, :cond_12

    .line 230
    .line 231
    if-ne v15, v7, :cond_11

    .line 232
    .line 233
    :cond_10
    move/from16 v15, v22

    .line 234
    .line 235
    goto :goto_9

    .line 236
    :cond_11
    new-instance v0, La8/r0;

    .line 237
    .line 238
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 239
    .line 240
    .line 241
    throw v0

    .line 242
    :cond_12
    move/from16 v15, v21

    .line 243
    .line 244
    :goto_9
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    .line 245
    .line 246
    .line 247
    invoke-static {v15}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 248
    .line 249
    .line 250
    move-result-object v15

    .line 251
    invoke-virtual {v6}, Lc1/w1;->f()Lc1/r1;

    .line 252
    .line 253
    .line 254
    move-result-object v16

    .line 255
    const v7, 0x6a24c466

    .line 256
    .line 257
    .line 258
    invoke-virtual {v5, v7}, Ll2/t;->Y(I)V

    .line 259
    .line 260
    .line 261
    invoke-interface/range {v16 .. v16}, Lc1/r1;->b()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v7

    .line 265
    sget-object v11, Lf4/a;->e:Lf4/a;

    .line 266
    .line 267
    const/16 v13, 0x64

    .line 268
    .line 269
    if-ne v7, v11, :cond_14

    .line 270
    .line 271
    :cond_13
    move-object/from16 v16, v20

    .line 272
    .line 273
    :goto_a
    const/4 v7, 0x0

    .line 274
    goto :goto_b

    .line 275
    :cond_14
    invoke-interface/range {v16 .. v16}, Lc1/r1;->a()Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v7

    .line 279
    if-ne v7, v11, :cond_13

    .line 280
    .line 281
    new-instance v7, Lc1/d1;

    .line 282
    .line 283
    invoke-direct {v7, v13}, Lc1/d1;-><init>(I)V

    .line 284
    .line 285
    .line 286
    move-object/from16 v16, v7

    .line 287
    .line 288
    goto :goto_a

    .line 289
    :goto_b
    invoke-virtual {v5, v7}, Ll2/t;->q(Z)V

    .line 290
    .line 291
    .line 292
    const/16 v19, 0x0

    .line 293
    .line 294
    move-object/from16 v18, v5

    .line 295
    .line 296
    move v5, v13

    .line 297
    move-object v13, v6

    .line 298
    move v6, v7

    .line 299
    invoke-static/range {v13 .. v19}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 300
    .line 301
    .line 302
    move-result-object v7

    .line 303
    move-object v14, v13

    .line 304
    move-object/from16 v13, v18

    .line 305
    .line 306
    invoke-virtual {v10}, Lap0/o;->D()Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v10

    .line 310
    check-cast v10, Lf4/a;

    .line 311
    .line 312
    const v15, 0x6dad01af

    .line 313
    .line 314
    .line 315
    invoke-virtual {v13, v15}, Ll2/t;->Y(I)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 319
    .line 320
    .line 321
    move-result v10

    .line 322
    if-eqz v10, :cond_16

    .line 323
    .line 324
    const/4 v5, 0x1

    .line 325
    if-eq v10, v5, :cond_16

    .line 326
    .line 327
    const/4 v5, 0x2

    .line 328
    if-ne v10, v5, :cond_15

    .line 329
    .line 330
    move/from16 v5, v22

    .line 331
    .line 332
    goto :goto_c

    .line 333
    :cond_15
    new-instance v0, La8/r0;

    .line 334
    .line 335
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 336
    .line 337
    .line 338
    throw v0

    .line 339
    :cond_16
    move/from16 v5, v21

    .line 340
    .line 341
    :goto_c
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 345
    .line 346
    .line 347
    move-result-object v5

    .line 348
    invoke-virtual {v9}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v9

    .line 352
    check-cast v9, Lf4/a;

    .line 353
    .line 354
    invoke-virtual {v13, v15}, Ll2/t;->Y(I)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 358
    .line 359
    .line 360
    move-result v9

    .line 361
    if-eqz v9, :cond_18

    .line 362
    .line 363
    const/4 v10, 0x1

    .line 364
    if-eq v9, v10, :cond_18

    .line 365
    .line 366
    const/4 v10, 0x2

    .line 367
    if-ne v9, v10, :cond_17

    .line 368
    .line 369
    move/from16 v21, v22

    .line 370
    .line 371
    goto :goto_d

    .line 372
    :cond_17
    new-instance v0, La8/r0;

    .line 373
    .line 374
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 375
    .line 376
    .line 377
    throw v0

    .line 378
    :cond_18
    :goto_d
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 379
    .line 380
    .line 381
    invoke-static/range {v21 .. v21}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 382
    .line 383
    .line 384
    move-result-object v15

    .line 385
    invoke-virtual {v14}, Lc1/w1;->f()Lc1/r1;

    .line 386
    .line 387
    .line 388
    move-result-object v9

    .line 389
    const v10, 0x25991aaf

    .line 390
    .line 391
    .line 392
    invoke-virtual {v13, v10}, Ll2/t;->Y(I)V

    .line 393
    .line 394
    .line 395
    invoke-interface {v9}, Lc1/r1;->b()Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v10

    .line 399
    if-ne v10, v11, :cond_1a

    .line 400
    .line 401
    invoke-static {}, Lc1/d;->s()Lc1/d1;

    .line 402
    .line 403
    .line 404
    move-result-object v20

    .line 405
    :cond_19
    move-object/from16 v16, v20

    .line 406
    .line 407
    goto :goto_e

    .line 408
    :cond_1a
    invoke-interface {v9}, Lc1/r1;->a()Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v9

    .line 412
    if-ne v9, v11, :cond_19

    .line 413
    .line 414
    new-instance v9, Lc1/d1;

    .line 415
    .line 416
    const/16 v10, 0x64

    .line 417
    .line 418
    invoke-direct {v9, v10}, Lc1/d1;-><init>(I)V

    .line 419
    .line 420
    .line 421
    move-object/from16 v16, v9

    .line 422
    .line 423
    :goto_e
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 424
    .line 425
    .line 426
    move-object/from16 v18, v13

    .line 427
    .line 428
    move-object v13, v14

    .line 429
    move-object v14, v5

    .line 430
    invoke-static/range {v13 .. v19}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 431
    .line 432
    .line 433
    move-result-object v5

    .line 434
    move-object/from16 v13, v18

    .line 435
    .line 436
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v9

    .line 440
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 441
    .line 442
    if-ne v9, v10, :cond_1b

    .line 443
    .line 444
    new-instance v9, Lh2/a1;

    .line 445
    .line 446
    invoke-direct {v9}, Lh2/a1;-><init>()V

    .line 447
    .line 448
    .line 449
    invoke-virtual {v13, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 450
    .line 451
    .line 452
    :cond_1b
    check-cast v9, Lh2/a1;

    .line 453
    .line 454
    if-ne v2, v11, :cond_1c

    .line 455
    .line 456
    iget-wide v14, v4, Lh2/b1;->b:J

    .line 457
    .line 458
    goto :goto_f

    .line 459
    :cond_1c
    iget-wide v14, v4, Lh2/b1;->a:J

    .line 460
    .line 461
    :goto_f
    invoke-static {v2, v13}, Lh2/b1;->a(Lf4/a;Ll2/o;)Lc1/f1;

    .line 462
    .line 463
    .line 464
    move-result-object v11

    .line 465
    const/16 v18, 0x0

    .line 466
    .line 467
    const/16 v19, 0xc

    .line 468
    .line 469
    const/16 v16, 0x0

    .line 470
    .line 471
    move-object/from16 v17, v13

    .line 472
    .line 473
    move-wide v13, v14

    .line 474
    move-object v15, v11

    .line 475
    invoke-static/range {v13 .. v19}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 476
    .line 477
    .line 478
    move-result-object v11

    .line 479
    move-object/from16 v13, v17

    .line 480
    .line 481
    if-eqz v1, :cond_20

    .line 482
    .line 483
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 484
    .line 485
    .line 486
    move-result v14

    .line 487
    if-eqz v14, :cond_1f

    .line 488
    .line 489
    const/4 v15, 0x1

    .line 490
    if-eq v14, v15, :cond_1e

    .line 491
    .line 492
    const/4 v15, 0x2

    .line 493
    if-ne v14, v15, :cond_1d

    .line 494
    .line 495
    goto :goto_10

    .line 496
    :cond_1d
    new-instance v0, La8/r0;

    .line 497
    .line 498
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 499
    .line 500
    .line 501
    throw v0

    .line 502
    :cond_1e
    iget-wide v14, v4, Lh2/b1;->d:J

    .line 503
    .line 504
    goto :goto_11

    .line 505
    :cond_1f
    :goto_10
    iget-wide v14, v4, Lh2/b1;->c:J

    .line 506
    .line 507
    goto :goto_11

    .line 508
    :cond_20
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 509
    .line 510
    .line 511
    move-result v14

    .line 512
    if-eqz v14, :cond_23

    .line 513
    .line 514
    const/4 v15, 0x1

    .line 515
    if-eq v14, v15, :cond_22

    .line 516
    .line 517
    const/4 v15, 0x2

    .line 518
    if-ne v14, v15, :cond_21

    .line 519
    .line 520
    iget-wide v14, v4, Lh2/b1;->g:J

    .line 521
    .line 522
    goto :goto_11

    .line 523
    :cond_21
    new-instance v0, La8/r0;

    .line 524
    .line 525
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 526
    .line 527
    .line 528
    throw v0

    .line 529
    :cond_22
    iget-wide v14, v4, Lh2/b1;->f:J

    .line 530
    .line 531
    goto :goto_11

    .line 532
    :cond_23
    iget-wide v14, v4, Lh2/b1;->e:J

    .line 533
    .line 534
    :goto_11
    if-eqz v1, :cond_24

    .line 535
    .line 536
    const v6, 0x1d912603

    .line 537
    .line 538
    .line 539
    invoke-virtual {v13, v6}, Ll2/t;->Y(I)V

    .line 540
    .line 541
    .line 542
    move-wide/from16 v16, v14

    .line 543
    .line 544
    invoke-static {v2, v13}, Lh2/b1;->a(Lf4/a;Ll2/o;)Lc1/f1;

    .line 545
    .line 546
    .line 547
    move-result-object v15

    .line 548
    const/16 v18, 0x0

    .line 549
    .line 550
    const/16 v19, 0xc

    .line 551
    .line 552
    move-wide/from16 v23, v16

    .line 553
    .line 554
    move-object/from16 v17, v13

    .line 555
    .line 556
    move-wide/from16 v13, v23

    .line 557
    .line 558
    const/16 v16, 0x0

    .line 559
    .line 560
    invoke-static/range {v13 .. v19}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 561
    .line 562
    .line 563
    move-result-object v6

    .line 564
    move-object/from16 v13, v17

    .line 565
    .line 566
    const/4 v14, 0x0

    .line 567
    invoke-virtual {v13, v14}, Ll2/t;->q(Z)V

    .line 568
    .line 569
    .line 570
    goto :goto_12

    .line 571
    :cond_24
    const v6, 0x1d928665

    .line 572
    .line 573
    .line 574
    invoke-virtual {v13, v6}, Ll2/t;->Y(I)V

    .line 575
    .line 576
    .line 577
    new-instance v6, Le3/s;

    .line 578
    .line 579
    invoke-direct {v6, v14, v15}, Le3/s;-><init>(J)V

    .line 580
    .line 581
    .line 582
    invoke-static {v6, v13}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 583
    .line 584
    .line 585
    move-result-object v6

    .line 586
    const/4 v14, 0x0

    .line 587
    invoke-virtual {v13, v14}, Ll2/t;->q(Z)V

    .line 588
    .line 589
    .line 590
    :goto_12
    if-eqz v1, :cond_28

    .line 591
    .line 592
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 593
    .line 594
    .line 595
    move-result v14

    .line 596
    if-eqz v14, :cond_27

    .line 597
    .line 598
    const/4 v15, 0x1

    .line 599
    if-eq v14, v15, :cond_26

    .line 600
    .line 601
    const/4 v15, 0x2

    .line 602
    if-ne v14, v15, :cond_25

    .line 603
    .line 604
    goto :goto_13

    .line 605
    :cond_25
    new-instance v0, La8/r0;

    .line 606
    .line 607
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 608
    .line 609
    .line 610
    throw v0

    .line 611
    :cond_26
    iget-wide v14, v4, Lh2/b1;->i:J

    .line 612
    .line 613
    goto :goto_14

    .line 614
    :cond_27
    :goto_13
    iget-wide v14, v4, Lh2/b1;->h:J

    .line 615
    .line 616
    goto :goto_14

    .line 617
    :cond_28
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 618
    .line 619
    .line 620
    move-result v14

    .line 621
    if-eqz v14, :cond_2b

    .line 622
    .line 623
    const/4 v15, 0x1

    .line 624
    if-eq v14, v15, :cond_2a

    .line 625
    .line 626
    const/4 v15, 0x2

    .line 627
    if-ne v14, v15, :cond_29

    .line 628
    .line 629
    iget-wide v14, v4, Lh2/b1;->l:J

    .line 630
    .line 631
    goto :goto_14

    .line 632
    :cond_29
    new-instance v0, La8/r0;

    .line 633
    .line 634
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 635
    .line 636
    .line 637
    throw v0

    .line 638
    :cond_2a
    iget-wide v14, v4, Lh2/b1;->k:J

    .line 639
    .line 640
    goto :goto_14

    .line 641
    :cond_2b
    iget-wide v14, v4, Lh2/b1;->j:J

    .line 642
    .line 643
    :goto_14
    if-eqz v1, :cond_2c

    .line 644
    .line 645
    const v0, 0x25be58c6

    .line 646
    .line 647
    .line 648
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 649
    .line 650
    .line 651
    move-wide/from16 v16, v14

    .line 652
    .line 653
    invoke-static {v2, v13}, Lh2/b1;->a(Lf4/a;Ll2/o;)Lc1/f1;

    .line 654
    .line 655
    .line 656
    move-result-object v15

    .line 657
    const/16 v18, 0x0

    .line 658
    .line 659
    const/16 v19, 0xc

    .line 660
    .line 661
    move-wide/from16 v23, v16

    .line 662
    .line 663
    move-object/from16 v17, v13

    .line 664
    .line 665
    move-wide/from16 v13, v23

    .line 666
    .line 667
    const/16 v16, 0x0

    .line 668
    .line 669
    invoke-static/range {v13 .. v19}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 670
    .line 671
    .line 672
    move-result-object v0

    .line 673
    move-object/from16 v14, v17

    .line 674
    .line 675
    const/4 v13, 0x0

    .line 676
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 677
    .line 678
    .line 679
    goto :goto_15

    .line 680
    :cond_2c
    move-wide v0, v14

    .line 681
    move-object v14, v13

    .line 682
    const/4 v13, 0x0

    .line 683
    const v15, 0x25bfb928

    .line 684
    .line 685
    .line 686
    invoke-virtual {v14, v15}, Ll2/t;->Y(I)V

    .line 687
    .line 688
    .line 689
    new-instance v15, Le3/s;

    .line 690
    .line 691
    invoke-direct {v15, v0, v1}, Le3/s;-><init>(J)V

    .line 692
    .line 693
    .line 694
    invoke-static {v15, v14}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 695
    .line 696
    .line 697
    move-result-object v0

    .line 698
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 699
    .line 700
    .line 701
    :goto_15
    sget-object v1, Lx2/c;->h:Lx2/j;

    .line 702
    .line 703
    const/4 v15, 0x2

    .line 704
    invoke-static {v3, v1, v15}, Landroidx/compose/foundation/layout/d;->v(Lx2/s;Lx2/j;I)Lx2/s;

    .line 705
    .line 706
    .line 707
    move-result-object v1

    .line 708
    sget v15, Lh2/e1;->b:F

    .line 709
    .line 710
    invoke-static {v1, v15}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    .line 711
    .line 712
    .line 713
    move-result-object v1

    .line 714
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 715
    .line 716
    .line 717
    move-result v15

    .line 718
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 719
    .line 720
    .line 721
    move-result v16

    .line 722
    or-int v15, v15, v16

    .line 723
    .line 724
    invoke-virtual {v14, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 725
    .line 726
    .line 727
    move-result v16

    .line 728
    or-int v15, v15, v16

    .line 729
    .line 730
    invoke-virtual {v14, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 731
    .line 732
    .line 733
    move-result v16

    .line 734
    or-int v15, v15, v16

    .line 735
    .line 736
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 737
    .line 738
    .line 739
    move-result v16

    .line 740
    or-int v15, v15, v16

    .line 741
    .line 742
    invoke-virtual {v14, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 743
    .line 744
    .line 745
    move-result v16

    .line 746
    or-int v15, v15, v16

    .line 747
    .line 748
    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 749
    .line 750
    .line 751
    move-result v16

    .line 752
    or-int v15, v15, v16

    .line 753
    .line 754
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 755
    .line 756
    .line 757
    move-result-object v13

    .line 758
    if-nez v15, :cond_2d

    .line 759
    .line 760
    if-ne v13, v10, :cond_2e

    .line 761
    .line 762
    :cond_2d
    move-object v13, v9

    .line 763
    move-object v9, v11

    .line 764
    move-object v11, v5

    .line 765
    goto :goto_16

    .line 766
    :cond_2e
    const/4 v0, 0x0

    .line 767
    goto :goto_17

    .line 768
    :goto_16
    new-instance v5, Lh2/d1;

    .line 769
    .line 770
    move-object v10, v7

    .line 771
    move-object v7, v0

    .line 772
    const/4 v0, 0x0

    .line 773
    invoke-direct/range {v5 .. v13}, Lh2/d1;-><init>(Ll2/t2;Ll2/t2;Lg3/h;Ll2/t2;Lc1/t1;Lc1/t1;Lg3/h;Lh2/a1;)V

    .line 774
    .line 775
    .line 776
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 777
    .line 778
    .line 779
    move-object v13, v5

    .line 780
    :goto_17
    check-cast v13, Lay0/k;

    .line 781
    .line 782
    invoke-static {v1, v13, v14, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 783
    .line 784
    .line 785
    goto :goto_18

    .line 786
    :cond_2f
    move-object v14, v5

    .line 787
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 788
    .line 789
    .line 790
    :goto_18
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 791
    .line 792
    .line 793
    move-result-object v8

    .line 794
    if-eqz v8, :cond_30

    .line 795
    .line 796
    new-instance v0, Le71/c;

    .line 797
    .line 798
    move/from16 v1, p0

    .line 799
    .line 800
    move-object/from16 v5, p4

    .line 801
    .line 802
    move-object/from16 v6, p5

    .line 803
    .line 804
    move/from16 v7, p7

    .line 805
    .line 806
    invoke-direct/range {v0 .. v7}, Le71/c;-><init>(ZLf4/a;Lx2/s;Lh2/b1;Lg3/h;Lg3/h;I)V

    .line 807
    .line 808
    .line 809
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 810
    .line 811
    :cond_30
    return-void
.end method

.method public static final b(Lf4/a;Lay0/a;Lg3/h;Lg3/h;Lx2/s;ZLh2/b1;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v7, p4

    .line 4
    .line 5
    move/from16 v8, p8

    .line 6
    .line 7
    move-object/from16 v15, p7

    .line 8
    .line 9
    check-cast v15, Ll2/t;

    .line 10
    .line 11
    const v0, -0x1836c9b1

    .line 12
    .line 13
    .line 14
    invoke-virtual {v15, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v8, 0x6

    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    const/4 v3, 0x2

    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {v15, v0}, Ll2/t;->e(I)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    move v0, v1

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move v0, v3

    .line 36
    :goto_0
    or-int/2addr v0, v8

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v0, v8

    .line 39
    :goto_1
    and-int/lit8 v4, v8, 0x30

    .line 40
    .line 41
    if-nez v4, :cond_3

    .line 42
    .line 43
    invoke-virtual {v15, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-eqz v4, :cond_2

    .line 48
    .line 49
    const/16 v4, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v4, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v4

    .line 55
    :cond_3
    and-int/lit16 v4, v8, 0x180

    .line 56
    .line 57
    move-object/from16 v13, p2

    .line 58
    .line 59
    if-nez v4, :cond_5

    .line 60
    .line 61
    invoke-virtual {v15, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_4

    .line 66
    .line 67
    const/16 v4, 0x100

    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_4
    const/16 v4, 0x80

    .line 71
    .line 72
    :goto_3
    or-int/2addr v0, v4

    .line 73
    :cond_5
    and-int/lit16 v4, v8, 0xc00

    .line 74
    .line 75
    move-object/from16 v14, p3

    .line 76
    .line 77
    if-nez v4, :cond_7

    .line 78
    .line 79
    invoke-virtual {v15, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-eqz v4, :cond_6

    .line 84
    .line 85
    const/16 v4, 0x800

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_6
    const/16 v4, 0x400

    .line 89
    .line 90
    :goto_4
    or-int/2addr v0, v4

    .line 91
    :cond_7
    and-int/lit16 v4, v8, 0x6000

    .line 92
    .line 93
    if-nez v4, :cond_9

    .line 94
    .line 95
    invoke-virtual {v15, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-eqz v4, :cond_8

    .line 100
    .line 101
    const/16 v4, 0x4000

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_8
    const/16 v4, 0x2000

    .line 105
    .line 106
    :goto_5
    or-int/2addr v0, v4

    .line 107
    :cond_9
    const/high16 v4, 0x30000

    .line 108
    .line 109
    and-int/2addr v4, v8

    .line 110
    move/from16 v9, p5

    .line 111
    .line 112
    if-nez v4, :cond_b

    .line 113
    .line 114
    invoke-virtual {v15, v9}, Ll2/t;->h(Z)Z

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    if-eqz v4, :cond_a

    .line 119
    .line 120
    const/high16 v4, 0x20000

    .line 121
    .line 122
    goto :goto_6

    .line 123
    :cond_a
    const/high16 v4, 0x10000

    .line 124
    .line 125
    :goto_6
    or-int/2addr v0, v4

    .line 126
    :cond_b
    const/high16 v4, 0x180000

    .line 127
    .line 128
    and-int/2addr v4, v8

    .line 129
    move-object/from16 v12, p6

    .line 130
    .line 131
    if-nez v4, :cond_d

    .line 132
    .line 133
    invoke-virtual {v15, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v4

    .line 137
    if-eqz v4, :cond_c

    .line 138
    .line 139
    const/high16 v4, 0x100000

    .line 140
    .line 141
    goto :goto_7

    .line 142
    :cond_c
    const/high16 v4, 0x80000

    .line 143
    .line 144
    :goto_7
    or-int/2addr v0, v4

    .line 145
    :cond_d
    const/high16 v4, 0xc00000

    .line 146
    .line 147
    and-int/2addr v4, v8

    .line 148
    if-nez v4, :cond_f

    .line 149
    .line 150
    const/4 v4, 0x0

    .line 151
    invoke-virtual {v15, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v4

    .line 155
    if-eqz v4, :cond_e

    .line 156
    .line 157
    const/high16 v4, 0x800000

    .line 158
    .line 159
    goto :goto_8

    .line 160
    :cond_e
    const/high16 v4, 0x400000

    .line 161
    .line 162
    :goto_8
    or-int/2addr v0, v4

    .line 163
    :cond_f
    move v10, v0

    .line 164
    const v0, 0x492493

    .line 165
    .line 166
    .line 167
    and-int/2addr v0, v10

    .line 168
    const v4, 0x492492

    .line 169
    .line 170
    .line 171
    const/4 v5, 0x0

    .line 172
    if-eq v0, v4, :cond_10

    .line 173
    .line 174
    const/4 v0, 0x1

    .line 175
    goto :goto_9

    .line 176
    :cond_10
    move v0, v5

    .line 177
    :goto_9
    and-int/lit8 v4, v10, 0x1

    .line 178
    .line 179
    invoke-virtual {v15, v4, v0}, Ll2/t;->O(IZ)Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-eqz v0, :cond_15

    .line 184
    .line 185
    invoke-virtual {v15}, Ll2/t;->T()V

    .line 186
    .line 187
    .line 188
    and-int/lit8 v0, v8, 0x1

    .line 189
    .line 190
    if-eqz v0, :cond_12

    .line 191
    .line 192
    invoke-virtual {v15}, Ll2/t;->y()Z

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-eqz v0, :cond_11

    .line 197
    .line 198
    goto :goto_a

    .line 199
    :cond_11
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 200
    .line 201
    .line 202
    :cond_12
    :goto_a
    invoke-virtual {v15}, Ll2/t;->r()V

    .line 203
    .line 204
    .line 205
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 206
    .line 207
    if-eqz v2, :cond_13

    .line 208
    .line 209
    sget v4, Lk2/h;->d:F

    .line 210
    .line 211
    int-to-float v3, v3

    .line 212
    div-float/2addr v4, v3

    .line 213
    const-wide/16 v6, 0x0

    .line 214
    .line 215
    invoke-static {v6, v7, v4, v1, v5}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    new-instance v5, Ld4/i;

    .line 220
    .line 221
    const/4 v1, 0x1

    .line 222
    invoke-direct {v5, v1}, Ld4/i;-><init>(I)V

    .line 223
    .line 224
    .line 225
    const/4 v2, 0x0

    .line 226
    move-object/from16 v1, p0

    .line 227
    .line 228
    move-object/from16 v6, p1

    .line 229
    .line 230
    move v4, v9

    .line 231
    invoke-static/range {v0 .. v6}, Landroidx/compose/foundation/selection/b;->c(Lx2/s;Lf4/a;Li1/l;Lh2/x7;ZLd4/i;Lay0/a;)Lx2/s;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    goto :goto_b

    .line 236
    :cond_13
    move-object v2, v0

    .line 237
    :goto_b
    if-eqz p1, :cond_14

    .line 238
    .line 239
    sget-object v0, Lh2/k5;->a:Lt3/o;

    .line 240
    .line 241
    sget-object v0, Landroidx/compose/material3/MinimumInteractiveModifier;->b:Landroidx/compose/material3/MinimumInteractiveModifier;

    .line 242
    .line 243
    :cond_14
    move-object/from16 v7, p4

    .line 244
    .line 245
    invoke-interface {v7, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    invoke-interface {v0, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    sget v1, Lh2/e1;->a:F

    .line 254
    .line 255
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v11

    .line 259
    shr-int/lit8 v0, v10, 0xf

    .line 260
    .line 261
    and-int/lit8 v0, v0, 0xe

    .line 262
    .line 263
    shl-int/lit8 v1, v10, 0x3

    .line 264
    .line 265
    and-int/lit8 v1, v1, 0x70

    .line 266
    .line 267
    or-int/2addr v0, v1

    .line 268
    shr-int/lit8 v1, v10, 0x9

    .line 269
    .line 270
    and-int/lit16 v1, v1, 0x1c00

    .line 271
    .line 272
    or-int/2addr v0, v1

    .line 273
    shl-int/lit8 v1, v10, 0x6

    .line 274
    .line 275
    const v2, 0xe000

    .line 276
    .line 277
    .line 278
    and-int/2addr v2, v1

    .line 279
    or-int/2addr v0, v2

    .line 280
    const/high16 v2, 0x70000

    .line 281
    .line 282
    and-int/2addr v1, v2

    .line 283
    or-int v16, v0, v1

    .line 284
    .line 285
    move-object/from16 v10, p0

    .line 286
    .line 287
    move/from16 v9, p5

    .line 288
    .line 289
    invoke-static/range {v9 .. v16}, Lh2/e1;->a(ZLf4/a;Lx2/s;Lh2/b1;Lg3/h;Lg3/h;Ll2/o;I)V

    .line 290
    .line 291
    .line 292
    goto :goto_c

    .line 293
    :cond_15
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 294
    .line 295
    .line 296
    :goto_c
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 297
    .line 298
    .line 299
    move-result-object v9

    .line 300
    if-eqz v9, :cond_16

    .line 301
    .line 302
    new-instance v0, Le71/i;

    .line 303
    .line 304
    move-object/from16 v1, p0

    .line 305
    .line 306
    move-object/from16 v2, p1

    .line 307
    .line 308
    move-object/from16 v3, p2

    .line 309
    .line 310
    move-object/from16 v4, p3

    .line 311
    .line 312
    move/from16 v6, p5

    .line 313
    .line 314
    move-object v5, v7

    .line 315
    move-object/from16 v7, p6

    .line 316
    .line 317
    invoke-direct/range {v0 .. v8}, Le71/i;-><init>(Lf4/a;Lay0/a;Lg3/h;Lg3/h;Lx2/s;ZLh2/b1;I)V

    .line 318
    .line 319
    .line 320
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 321
    .line 322
    :cond_16
    return-void
.end method

.method public static final c(Lf4/a;Lay0/a;Lx2/s;ZLh2/b1;Ll2/o;II)V
    .locals 22

    .line 1
    move/from16 v6, p6

    .line 2
    .line 3
    move-object/from16 v14, p5

    .line 4
    .line 5
    check-cast v14, Ll2/t;

    .line 6
    .line 7
    const v0, -0x5fdd98b1

    .line 8
    .line 9
    .line 10
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v0, v6, 0x6

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {v14, v0}, Ll2/t;->e(I)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, v6

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v6

    .line 33
    :goto_1
    and-int/lit8 v1, v6, 0x30

    .line 34
    .line 35
    move-object/from16 v8, p1

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {v14, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, v6, 0x180

    .line 52
    .line 53
    move-object/from16 v11, p2

    .line 54
    .line 55
    if-nez v1, :cond_5

    .line 56
    .line 57
    invoke-virtual {v14, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-eqz v1, :cond_4

    .line 62
    .line 63
    const/16 v1, 0x100

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    const/16 v1, 0x80

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v1

    .line 69
    :cond_5
    and-int/lit8 v1, p7, 0x8

    .line 70
    .line 71
    if-eqz v1, :cond_7

    .line 72
    .line 73
    or-int/lit16 v0, v0, 0xc00

    .line 74
    .line 75
    :cond_6
    move/from16 v2, p3

    .line 76
    .line 77
    goto :goto_5

    .line 78
    :cond_7
    and-int/lit16 v2, v6, 0xc00

    .line 79
    .line 80
    if-nez v2, :cond_6

    .line 81
    .line 82
    move/from16 v2, p3

    .line 83
    .line 84
    invoke-virtual {v14, v2}, Ll2/t;->h(Z)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-eqz v3, :cond_8

    .line 89
    .line 90
    const/16 v3, 0x800

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_8
    const/16 v3, 0x400

    .line 94
    .line 95
    :goto_4
    or-int/2addr v0, v3

    .line 96
    :goto_5
    and-int/lit16 v3, v6, 0x6000

    .line 97
    .line 98
    move-object/from16 v13, p4

    .line 99
    .line 100
    if-nez v3, :cond_a

    .line 101
    .line 102
    invoke-virtual {v14, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    if-eqz v3, :cond_9

    .line 107
    .line 108
    const/16 v3, 0x4000

    .line 109
    .line 110
    goto :goto_6

    .line 111
    :cond_9
    const/16 v3, 0x2000

    .line 112
    .line 113
    :goto_6
    or-int/2addr v0, v3

    .line 114
    :cond_a
    const/high16 v3, 0x30000

    .line 115
    .line 116
    or-int/2addr v0, v3

    .line 117
    const v3, 0x12493

    .line 118
    .line 119
    .line 120
    and-int/2addr v3, v0

    .line 121
    const v4, 0x12492

    .line 122
    .line 123
    .line 124
    const/4 v5, 0x1

    .line 125
    if-eq v3, v4, :cond_b

    .line 126
    .line 127
    move v3, v5

    .line 128
    goto :goto_7

    .line 129
    :cond_b
    const/4 v3, 0x0

    .line 130
    :goto_7
    and-int/lit8 v4, v0, 0x1

    .line 131
    .line 132
    invoke-virtual {v14, v4, v3}, Ll2/t;->O(IZ)Z

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    if-eqz v3, :cond_f

    .line 137
    .line 138
    invoke-virtual {v14}, Ll2/t;->T()V

    .line 139
    .line 140
    .line 141
    and-int/lit8 v3, v6, 0x1

    .line 142
    .line 143
    if-eqz v3, :cond_e

    .line 144
    .line 145
    invoke-virtual {v14}, Ll2/t;->y()Z

    .line 146
    .line 147
    .line 148
    move-result v3

    .line 149
    if-eqz v3, :cond_c

    .line 150
    .line 151
    goto :goto_9

    .line 152
    :cond_c
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 153
    .line 154
    .line 155
    :cond_d
    :goto_8
    move v12, v2

    .line 156
    goto :goto_a

    .line 157
    :cond_e
    :goto_9
    if-eqz v1, :cond_d

    .line 158
    .line 159
    move v2, v5

    .line 160
    goto :goto_8

    .line 161
    :goto_a
    invoke-virtual {v14}, Ll2/t;->r()V

    .line 162
    .line 163
    .line 164
    sget-object v1, Lw3/h1;->h:Ll2/u2;

    .line 165
    .line 166
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    check-cast v1, Lt4/c;

    .line 171
    .line 172
    sget v2, Lh2/c1;->a:F

    .line 173
    .line 174
    invoke-interface {v1, v2}, Lt4/c;->w0(F)F

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    float-to-double v1, v1

    .line 179
    invoke-static {v1, v2}, Ljava/lang/Math;->floor(D)D

    .line 180
    .line 181
    .line 182
    move-result-wide v1

    .line 183
    double-to-float v1, v1

    .line 184
    new-instance v9, Lg3/h;

    .line 185
    .line 186
    const/16 v20, 0x0

    .line 187
    .line 188
    const/16 v21, 0x1a

    .line 189
    .line 190
    const/16 v17, 0x0

    .line 191
    .line 192
    const/16 v18, 0x2

    .line 193
    .line 194
    const/16 v19, 0x0

    .line 195
    .line 196
    move/from16 v16, v1

    .line 197
    .line 198
    move-object v15, v9

    .line 199
    invoke-direct/range {v15 .. v21}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 200
    .line 201
    .line 202
    new-instance v10, Lg3/h;

    .line 203
    .line 204
    const/16 v21, 0x1e

    .line 205
    .line 206
    const/16 v18, 0x0

    .line 207
    .line 208
    move-object v15, v10

    .line 209
    invoke-direct/range {v15 .. v21}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 210
    .line 211
    .line 212
    and-int/lit8 v1, v0, 0x7e

    .line 213
    .line 214
    shl-int/lit8 v0, v0, 0x6

    .line 215
    .line 216
    const v2, 0xe000

    .line 217
    .line 218
    .line 219
    and-int/2addr v2, v0

    .line 220
    or-int/2addr v1, v2

    .line 221
    const/high16 v2, 0x70000

    .line 222
    .line 223
    and-int/2addr v2, v0

    .line 224
    or-int/2addr v1, v2

    .line 225
    const/high16 v2, 0x380000

    .line 226
    .line 227
    and-int/2addr v2, v0

    .line 228
    or-int/2addr v1, v2

    .line 229
    const/high16 v2, 0x1c00000

    .line 230
    .line 231
    and-int/2addr v0, v2

    .line 232
    or-int v15, v1, v0

    .line 233
    .line 234
    move-object/from16 v7, p0

    .line 235
    .line 236
    invoke-static/range {v7 .. v15}, Lh2/e1;->b(Lf4/a;Lay0/a;Lg3/h;Lg3/h;Lx2/s;ZLh2/b1;Ll2/o;I)V

    .line 237
    .line 238
    .line 239
    move v4, v12

    .line 240
    goto :goto_b

    .line 241
    :cond_f
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 242
    .line 243
    .line 244
    move v4, v2

    .line 245
    :goto_b
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 246
    .line 247
    .line 248
    move-result-object v8

    .line 249
    if-eqz v8, :cond_10

    .line 250
    .line 251
    new-instance v0, Leq0/d;

    .line 252
    .line 253
    move-object/from16 v1, p0

    .line 254
    .line 255
    move-object/from16 v2, p1

    .line 256
    .line 257
    move-object/from16 v3, p2

    .line 258
    .line 259
    move-object/from16 v5, p4

    .line 260
    .line 261
    move/from16 v7, p7

    .line 262
    .line 263
    invoke-direct/range {v0 .. v7}, Leq0/d;-><init>(Lf4/a;Lay0/a;Lx2/s;ZLh2/b1;II)V

    .line 264
    .line 265
    .line 266
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 267
    .line 268
    :cond_10
    return-void
.end method
