.class public abstract Lxf0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lgy0/j;

.field public static final b:Lgy0/j;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lgy0/j;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x64

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lxf0/t;->a:Lgy0/j;

    .line 11
    .line 12
    new-instance v0, Lgy0/j;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lxf0/t;->b:Lgy0/j;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Lx2/s;ILjava/lang/Integer;ZZLjava/lang/Integer;ZZLl2/o;II)V
    .locals 39

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move/from16 v4, p3

    .line 8
    .line 9
    move/from16 v5, p4

    .line 10
    .line 11
    move/from16 v3, p10

    .line 12
    .line 13
    move-object/from16 v11, p8

    .line 14
    .line 15
    check-cast v11, Ll2/t;

    .line 16
    .line 17
    const v6, 0x5d53bc4e

    .line 18
    .line 19
    .line 20
    invoke-virtual {v11, v6}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    if-eqz v6, :cond_0

    .line 28
    .line 29
    const/4 v6, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v6, 0x2

    .line 32
    :goto_0
    or-int v6, p9, v6

    .line 33
    .line 34
    invoke-virtual {v11, v2}, Ll2/t;->e(I)Z

    .line 35
    .line 36
    .line 37
    move-result v8

    .line 38
    if-eqz v8, :cond_1

    .line 39
    .line 40
    const/16 v8, 0x20

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/16 v8, 0x10

    .line 44
    .line 45
    :goto_1
    or-int/2addr v6, v8

    .line 46
    invoke-virtual {v11, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    if-eqz v8, :cond_2

    .line 51
    .line 52
    const/16 v8, 0x100

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_2
    const/16 v8, 0x80

    .line 56
    .line 57
    :goto_2
    or-int/2addr v6, v8

    .line 58
    invoke-virtual {v11, v4}, Ll2/t;->h(Z)Z

    .line 59
    .line 60
    .line 61
    move-result v8

    .line 62
    if-eqz v8, :cond_3

    .line 63
    .line 64
    const/16 v8, 0x800

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    const/16 v8, 0x400

    .line 68
    .line 69
    :goto_3
    or-int/2addr v6, v8

    .line 70
    invoke-virtual {v11, v5}, Ll2/t;->h(Z)Z

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    if-eqz v8, :cond_4

    .line 75
    .line 76
    const/16 v8, 0x4000

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/16 v8, 0x2000

    .line 80
    .line 81
    :goto_4
    or-int/2addr v6, v8

    .line 82
    and-int/lit8 v8, v3, 0x20

    .line 83
    .line 84
    if-eqz v8, :cond_5

    .line 85
    .line 86
    const/high16 v13, 0x30000

    .line 87
    .line 88
    or-int/2addr v6, v13

    .line 89
    move-object/from16 v13, p5

    .line 90
    .line 91
    goto :goto_6

    .line 92
    :cond_5
    move-object/from16 v13, p5

    .line 93
    .line 94
    invoke-virtual {v11, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v16

    .line 98
    if-eqz v16, :cond_6

    .line 99
    .line 100
    const/high16 v16, 0x20000

    .line 101
    .line 102
    goto :goto_5

    .line 103
    :cond_6
    const/high16 v16, 0x10000

    .line 104
    .line 105
    :goto_5
    or-int v6, v6, v16

    .line 106
    .line 107
    :goto_6
    and-int/lit8 v16, v3, 0x40

    .line 108
    .line 109
    if-eqz v16, :cond_7

    .line 110
    .line 111
    const/high16 v17, 0x180000

    .line 112
    .line 113
    or-int v6, v6, v17

    .line 114
    .line 115
    move/from16 v9, p6

    .line 116
    .line 117
    goto :goto_8

    .line 118
    :cond_7
    move/from16 v9, p6

    .line 119
    .line 120
    invoke-virtual {v11, v9}, Ll2/t;->h(Z)Z

    .line 121
    .line 122
    .line 123
    move-result v18

    .line 124
    if-eqz v18, :cond_8

    .line 125
    .line 126
    const/high16 v18, 0x100000

    .line 127
    .line 128
    goto :goto_7

    .line 129
    :cond_8
    const/high16 v18, 0x80000

    .line 130
    .line 131
    :goto_7
    or-int v6, v6, v18

    .line 132
    .line 133
    :goto_8
    and-int/lit16 v10, v3, 0x80

    .line 134
    .line 135
    if-eqz v10, :cond_9

    .line 136
    .line 137
    const/high16 v20, 0xc00000

    .line 138
    .line 139
    or-int v6, v6, v20

    .line 140
    .line 141
    move/from16 v12, p7

    .line 142
    .line 143
    goto :goto_a

    .line 144
    :cond_9
    move/from16 v12, p7

    .line 145
    .line 146
    invoke-virtual {v11, v12}, Ll2/t;->h(Z)Z

    .line 147
    .line 148
    .line 149
    move-result v21

    .line 150
    if-eqz v21, :cond_a

    .line 151
    .line 152
    const/high16 v21, 0x800000

    .line 153
    .line 154
    goto :goto_9

    .line 155
    :cond_a
    const/high16 v21, 0x400000

    .line 156
    .line 157
    :goto_9
    or-int v6, v6, v21

    .line 158
    .line 159
    :goto_a
    const v21, 0x492493

    .line 160
    .line 161
    .line 162
    and-int v15, v6, v21

    .line 163
    .line 164
    const v14, 0x492492

    .line 165
    .line 166
    .line 167
    const/4 v12, 0x0

    .line 168
    const/16 v23, 0x1

    .line 169
    .line 170
    if-eq v15, v14, :cond_b

    .line 171
    .line 172
    move/from16 v14, v23

    .line 173
    .line 174
    goto :goto_b

    .line 175
    :cond_b
    move v14, v12

    .line 176
    :goto_b
    and-int/lit8 v15, v6, 0x1

    .line 177
    .line 178
    invoke-virtual {v11, v15, v14}, Ll2/t;->O(IZ)Z

    .line 179
    .line 180
    .line 181
    move-result v14

    .line 182
    if-eqz v14, :cond_1e

    .line 183
    .line 184
    if-eqz v8, :cond_c

    .line 185
    .line 186
    const/4 v8, 0x0

    .line 187
    move-object v14, v8

    .line 188
    goto :goto_c

    .line 189
    :cond_c
    move-object v14, v13

    .line 190
    :goto_c
    if-eqz v16, :cond_d

    .line 191
    .line 192
    move/from16 v20, v12

    .line 193
    .line 194
    :goto_d
    const/high16 v8, 0x20000

    .line 195
    .line 196
    goto :goto_e

    .line 197
    :cond_d
    move/from16 v20, v9

    .line 198
    .line 199
    goto :goto_d

    .line 200
    :goto_e
    if-eqz v10, :cond_e

    .line 201
    .line 202
    move v3, v12

    .line 203
    goto :goto_f

    .line 204
    :cond_e
    move/from16 v3, p7

    .line 205
    .line 206
    :goto_f
    sget-object v9, Lxf0/t;->a:Lgy0/j;

    .line 207
    .line 208
    invoke-static {v2, v9}, Lkp/r9;->f(ILgy0/g;)I

    .line 209
    .line 210
    .line 211
    move-result v15

    .line 212
    sget-object v9, Lxf0/t;->b:Lgy0/j;

    .line 213
    .line 214
    if-eqz v0, :cond_f

    .line 215
    .line 216
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 217
    .line 218
    .line 219
    move-result v10

    .line 220
    invoke-static {v10, v9}, Lkp/r9;->f(ILgy0/g;)I

    .line 221
    .line 222
    .line 223
    move-result v9

    .line 224
    goto :goto_10

    .line 225
    :cond_f
    iget v9, v9, Lgy0/h;->e:I

    .line 226
    .line 227
    :goto_10
    const/high16 v10, 0x3f800000    # 1.0f

    .line 228
    .line 229
    const/4 v13, 0x0

    .line 230
    if-nez v4, :cond_11

    .line 231
    .line 232
    if-eqz v5, :cond_10

    .line 233
    .line 234
    goto :goto_12

    .line 235
    :cond_10
    const v7, 0x3b1acd1a

    .line 236
    .line 237
    .line 238
    invoke-virtual {v11, v7}, Ll2/t;->Y(I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 242
    .line 243
    .line 244
    move/from16 v27, v6

    .line 245
    .line 246
    move/from16 v28, v9

    .line 247
    .line 248
    move-object v7, v11

    .line 249
    move v0, v12

    .line 250
    :goto_11
    move v10, v13

    .line 251
    goto/16 :goto_15

    .line 252
    .line 253
    :cond_11
    :goto_12
    const v8, 0x3b114228

    .line 254
    .line 255
    .line 256
    invoke-virtual {v11, v8}, Ll2/t;->Y(I)V

    .line 257
    .line 258
    .line 259
    const-string v8, "stripePulseTransition"

    .line 260
    .line 261
    invoke-static {v8, v11, v12}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    .line 262
    .line 263
    .line 264
    move-result-object v8

    .line 265
    if-eqz v3, :cond_12

    .line 266
    .line 267
    if-nez v4, :cond_12

    .line 268
    .line 269
    const v16, 0x3f99999a    # 1.2f

    .line 270
    .line 271
    .line 272
    goto :goto_13

    .line 273
    :cond_12
    move/from16 v16, v13

    .line 274
    .line 275
    :goto_13
    if-eqz v3, :cond_13

    .line 276
    .line 277
    if-nez v4, :cond_13

    .line 278
    .line 279
    const v24, 0x3e4ccccd    # 0.2f

    .line 280
    .line 281
    .line 282
    goto :goto_14

    .line 283
    :cond_13
    move/from16 v24, v10

    .line 284
    .line 285
    :goto_14
    new-instance v7, Lc1/s;

    .line 286
    .line 287
    const v12, 0x3ed70a3d    # 0.42f

    .line 288
    .line 289
    .line 290
    const v0, 0x3f147ae1    # 0.58f

    .line 291
    .line 292
    .line 293
    invoke-direct {v7, v12, v13, v0, v10}, Lc1/s;-><init>(FFFF)V

    .line 294
    .line 295
    .line 296
    new-instance v0, Lc1/a2;

    .line 297
    .line 298
    const/16 v12, 0xbb8

    .line 299
    .line 300
    const/4 v13, 0x0

    .line 301
    invoke-direct {v0, v12, v13, v7}, Lc1/a2;-><init>(IILc1/w;)V

    .line 302
    .line 303
    .line 304
    sget-object v7, Lc1/t0;->d:Lc1/t0;

    .line 305
    .line 306
    const/4 v12, 0x4

    .line 307
    invoke-static {v0, v7, v12}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    const/16 v12, 0x7008

    .line 312
    .line 313
    move/from16 v26, v13

    .line 314
    .line 315
    const/4 v13, 0x0

    .line 316
    move v7, v10

    .line 317
    const-string v10, "stripePulseAnimation"

    .line 318
    .line 319
    move/from16 v27, v6

    .line 320
    .line 321
    move-object v6, v8

    .line 322
    move/from16 v28, v9

    .line 323
    .line 324
    move/from16 v7, v16

    .line 325
    .line 326
    move/from16 v8, v24

    .line 327
    .line 328
    move-object v9, v0

    .line 329
    move/from16 v0, v26

    .line 330
    .line 331
    invoke-static/range {v6 .. v13}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 332
    .line 333
    .line 334
    move-result-object v6

    .line 335
    move-object v7, v11

    .line 336
    iget-object v6, v6, Lc1/g0;->g:Ll2/j1;

    .line 337
    .line 338
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v6

    .line 342
    check-cast v6, Ljava/lang/Number;

    .line 343
    .line 344
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 345
    .line 346
    .line 347
    move-result v13

    .line 348
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 349
    .line 350
    .line 351
    goto :goto_11

    .line 352
    :goto_15
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 353
    .line 354
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v8

    .line 358
    check-cast v8, Lj91/e;

    .line 359
    .line 360
    invoke-virtual {v8}, Lj91/e;->p()J

    .line 361
    .line 362
    .line 363
    move-result-wide v8

    .line 364
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v11

    .line 368
    check-cast v11, Lj91/e;

    .line 369
    .line 370
    invoke-virtual {v11}, Lj91/e;->m()J

    .line 371
    .line 372
    .line 373
    move-result-wide v11

    .line 374
    sget-object v13, Lxf0/h0;->f:Lxf0/h0;

    .line 375
    .line 376
    invoke-virtual {v13, v7}, Lxf0/h0;->a(Ll2/o;)J

    .line 377
    .line 378
    .line 379
    move-result-wide v0

    .line 380
    if-eqz v3, :cond_15

    .line 381
    .line 382
    const v2, -0x6c8e0ab6

    .line 383
    .line 384
    .line 385
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 386
    .line 387
    .line 388
    invoke-static {v7}, Lkp/k;->c(Ll2/o;)Z

    .line 389
    .line 390
    .line 391
    move-result v2

    .line 392
    if-eqz v2, :cond_14

    .line 393
    .line 394
    const v2, 0x57564819

    .line 395
    .line 396
    .line 397
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v2

    .line 404
    check-cast v2, Lj91/e;

    .line 405
    .line 406
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 407
    .line 408
    .line 409
    move-result-wide v16

    .line 410
    :goto_16
    const/4 v2, 0x0

    .line 411
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 412
    .line 413
    .line 414
    goto :goto_17

    .line 415
    :cond_14
    const v2, 0x57564c5a

    .line 416
    .line 417
    .line 418
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v2

    .line 425
    check-cast v2, Lj91/e;

    .line 426
    .line 427
    invoke-virtual {v2}, Lj91/e;->g()J

    .line 428
    .line 429
    .line 430
    move-result-wide v16

    .line 431
    goto :goto_16

    .line 432
    :goto_17
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 433
    .line 434
    .line 435
    :goto_18
    move/from16 p5, v3

    .line 436
    .line 437
    move-wide/from16 v2, v16

    .line 438
    .line 439
    goto :goto_19

    .line 440
    :cond_15
    const v2, -0x6c8c5f40

    .line 441
    .line 442
    .line 443
    invoke-virtual {v7, v2}, Ll2/t;->Y(I)V

    .line 444
    .line 445
    .line 446
    sget-object v2, Lxf0/h0;->g:Lxf0/h0;

    .line 447
    .line 448
    invoke-virtual {v2, v7}, Lxf0/h0;->a(Ll2/o;)J

    .line 449
    .line 450
    .line 451
    move-result-wide v16

    .line 452
    const/4 v2, 0x0

    .line 453
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 454
    .line 455
    .line 456
    goto :goto_18

    .line 457
    :goto_19
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v16

    .line 461
    check-cast v16, Lj91/e;

    .line 462
    .line 463
    invoke-virtual/range {v16 .. v16}, Lj91/e;->h()J

    .line 464
    .line 465
    .line 466
    move-result-wide v4

    .line 467
    move-object/from16 v16, v14

    .line 468
    .line 469
    invoke-virtual {v13, v7}, Lxf0/h0;->a(Ll2/o;)J

    .line 470
    .line 471
    .line 472
    move-result-wide v13

    .line 473
    move-wide/from16 p6, v4

    .line 474
    .line 475
    const v4, 0x3e99999a    # 0.3f

    .line 476
    .line 477
    .line 478
    invoke-static {v13, v14, v4}, Le3/s;->b(JF)J

    .line 479
    .line 480
    .line 481
    move-result-wide v4

    .line 482
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object v13

    .line 486
    check-cast v13, Lj91/e;

    .line 487
    .line 488
    invoke-virtual {v13}, Lj91/e;->k()J

    .line 489
    .line 490
    .line 491
    move-result-wide v13

    .line 492
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v6

    .line 496
    check-cast v6, Lj91/e;

    .line 497
    .line 498
    move-wide/from16 v17, v13

    .line 499
    .line 500
    invoke-virtual {v6}, Lj91/e;->l()J

    .line 501
    .line 502
    .line 503
    move-result-wide v13

    .line 504
    const/16 v6, 0xc

    .line 505
    .line 506
    int-to-float v6, v6

    .line 507
    move-wide/from16 v24, v13

    .line 508
    .line 509
    const/high16 v14, 0x3f800000    # 1.0f

    .line 510
    .line 511
    move-object/from16 v13, p0

    .line 512
    .line 513
    invoke-static {v13, v14}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 514
    .line 515
    .line 516
    move-result-object v14

    .line 517
    invoke-static {v14, v6}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 518
    .line 519
    .line 520
    move-result-object v14

    .line 521
    move/from16 v29, v6

    .line 522
    .line 523
    const/4 v6, 0x2

    .line 524
    int-to-float v6, v6

    .line 525
    div-float v6, v29, v6

    .line 526
    .line 527
    invoke-static {v6}, Ls1/f;->b(F)Ls1/e;

    .line 528
    .line 529
    .line 530
    move-result-object v6

    .line 531
    invoke-static {v14, v6}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 532
    .line 533
    .line 534
    move-result-object v6

    .line 535
    sget-object v14, Le3/j0;->a:Le3/i0;

    .line 536
    .line 537
    invoke-static {v6, v8, v9, v14}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 538
    .line 539
    .line 540
    move-result-object v30

    .line 541
    const/16 v35, 0x0

    .line 542
    .line 543
    const v36, 0x7fffb

    .line 544
    .line 545
    .line 546
    const v31, 0x3f7d70a4    # 0.99f

    .line 547
    .line 548
    .line 549
    const/16 v32, 0x0

    .line 550
    .line 551
    const/16 v33, 0x0

    .line 552
    .line 553
    const/16 v34, 0x0

    .line 554
    .line 555
    invoke-static/range {v30 .. v36}, Landroidx/compose/ui/graphics/a;->c(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 556
    .line 557
    .line 558
    move-result-object v6

    .line 559
    const/high16 v8, 0x1c00000

    .line 560
    .line 561
    move/from16 v9, v27

    .line 562
    .line 563
    and-int/2addr v8, v9

    .line 564
    const/high16 v14, 0x800000

    .line 565
    .line 566
    if-ne v8, v14, :cond_16

    .line 567
    .line 568
    move/from16 v8, v23

    .line 569
    .line 570
    goto :goto_1a

    .line 571
    :cond_16
    const/4 v8, 0x0

    .line 572
    :goto_1a
    invoke-virtual {v7, v4, v5}, Ll2/t;->f(J)Z

    .line 573
    .line 574
    .line 575
    move-result v14

    .line 576
    or-int/2addr v8, v14

    .line 577
    move/from16 v14, v28

    .line 578
    .line 579
    invoke-virtual {v7, v14}, Ll2/t;->e(I)Z

    .line 580
    .line 581
    .line 582
    move-result v21

    .line 583
    or-int v8, v8, v21

    .line 584
    .line 585
    invoke-virtual {v7, v11, v12}, Ll2/t;->f(J)Z

    .line 586
    .line 587
    .line 588
    move-result v21

    .line 589
    or-int v8, v8, v21

    .line 590
    .line 591
    invoke-virtual {v7, v15}, Ll2/t;->e(I)Z

    .line 592
    .line 593
    .line 594
    move-result v21

    .line 595
    or-int v8, v8, v21

    .line 596
    .line 597
    invoke-virtual {v7, v10}, Ll2/t;->d(F)Z

    .line 598
    .line 599
    .line 600
    move-result v21

    .line 601
    or-int v8, v8, v21

    .line 602
    .line 603
    const/high16 v21, 0x70000

    .line 604
    .line 605
    move-wide/from16 v27, v4

    .line 606
    .line 607
    and-int v4, v9, v21

    .line 608
    .line 609
    const/high16 v5, 0x20000

    .line 610
    .line 611
    if-ne v4, v5, :cond_17

    .line 612
    .line 613
    move/from16 v4, v23

    .line 614
    .line 615
    goto :goto_1b

    .line 616
    :cond_17
    const/4 v4, 0x0

    .line 617
    :goto_1b
    or-int/2addr v4, v8

    .line 618
    invoke-virtual {v7, v0, v1}, Ll2/t;->f(J)Z

    .line 619
    .line 620
    .line 621
    move-result v5

    .line 622
    or-int/2addr v4, v5

    .line 623
    invoke-virtual {v7, v2, v3}, Ll2/t;->f(J)Z

    .line 624
    .line 625
    .line 626
    move-result v5

    .line 627
    or-int/2addr v4, v5

    .line 628
    and-int/lit16 v5, v9, 0x1c00

    .line 629
    .line 630
    const/16 v8, 0x800

    .line 631
    .line 632
    if-ne v5, v8, :cond_18

    .line 633
    .line 634
    move/from16 v5, v23

    .line 635
    .line 636
    goto :goto_1c

    .line 637
    :cond_18
    const/4 v5, 0x0

    .line 638
    :goto_1c
    or-int/2addr v4, v5

    .line 639
    const v5, 0xe000

    .line 640
    .line 641
    .line 642
    and-int/2addr v5, v9

    .line 643
    const/16 v8, 0x4000

    .line 644
    .line 645
    if-ne v5, v8, :cond_19

    .line 646
    .line 647
    move/from16 v5, v23

    .line 648
    .line 649
    goto :goto_1d

    .line 650
    :cond_19
    const/4 v5, 0x0

    .line 651
    :goto_1d
    or-int/2addr v4, v5

    .line 652
    move-wide/from16 v21, v0

    .line 653
    .line 654
    move-wide/from16 v0, p6

    .line 655
    .line 656
    invoke-virtual {v7, v0, v1}, Ll2/t;->f(J)Z

    .line 657
    .line 658
    .line 659
    move-result v5

    .line 660
    or-int/2addr v4, v5

    .line 661
    const/high16 v5, 0x380000

    .line 662
    .line 663
    and-int/2addr v5, v9

    .line 664
    const/high16 v8, 0x100000

    .line 665
    .line 666
    if-ne v5, v8, :cond_1a

    .line 667
    .line 668
    move/from16 v5, v23

    .line 669
    .line 670
    goto :goto_1e

    .line 671
    :cond_1a
    const/4 v5, 0x0

    .line 672
    :goto_1e
    or-int/2addr v4, v5

    .line 673
    and-int/lit8 v5, v9, 0x70

    .line 674
    .line 675
    const/16 v8, 0x20

    .line 676
    .line 677
    if-ne v5, v8, :cond_1b

    .line 678
    .line 679
    goto :goto_1f

    .line 680
    :cond_1b
    const/16 v23, 0x0

    .line 681
    .line 682
    :goto_1f
    or-int v4, v4, v23

    .line 683
    .line 684
    move-wide/from16 v8, v17

    .line 685
    .line 686
    invoke-virtual {v7, v8, v9}, Ll2/t;->f(J)Z

    .line 687
    .line 688
    .line 689
    move-result v5

    .line 690
    or-int/2addr v4, v5

    .line 691
    move-wide/from16 p6, v0

    .line 692
    .line 693
    move-wide/from16 v0, v24

    .line 694
    .line 695
    invoke-virtual {v7, v0, v1}, Ll2/t;->f(J)Z

    .line 696
    .line 697
    .line 698
    move-result v5

    .line 699
    or-int/2addr v4, v5

    .line 700
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 701
    .line 702
    .line 703
    move-result-object v5

    .line 704
    if-nez v4, :cond_1c

    .line 705
    .line 706
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 707
    .line 708
    if-ne v5, v4, :cond_1d

    .line 709
    .line 710
    :cond_1c
    move-wide/from16 v17, v8

    .line 711
    .line 712
    move v9, v15

    .line 713
    move-wide/from16 v37, v2

    .line 714
    .line 715
    move-object v3, v6

    .line 716
    move v6, v14

    .line 717
    move-wide/from16 v14, v37

    .line 718
    .line 719
    goto :goto_20

    .line 720
    :cond_1d
    move/from16 v3, p5

    .line 721
    .line 722
    move-object v1, v6

    .line 723
    move-object v0, v7

    .line 724
    move-object/from16 v11, v16

    .line 725
    .line 726
    goto :goto_21

    .line 727
    :goto_20
    new-instance v2, Lxf0/r;

    .line 728
    .line 729
    move-wide/from16 v24, v0

    .line 730
    .line 731
    move-object v1, v3

    .line 732
    move-object v0, v7

    .line 733
    move-wide v7, v11

    .line 734
    move-object/from16 v11, v16

    .line 735
    .line 736
    move-wide/from16 v12, v21

    .line 737
    .line 738
    move-wide/from16 v4, v27

    .line 739
    .line 740
    move/from16 v21, p1

    .line 741
    .line 742
    move/from16 v16, p3

    .line 743
    .line 744
    move/from16 v3, p5

    .line 745
    .line 746
    move-wide/from16 v22, v17

    .line 747
    .line 748
    move/from16 v17, p4

    .line 749
    .line 750
    move-wide/from16 v18, p6

    .line 751
    .line 752
    invoke-direct/range {v2 .. v25}, Lxf0/r;-><init>(ZJIJIFLjava/lang/Integer;JJZZJZIJJ)V

    .line 753
    .line 754
    .line 755
    invoke-virtual {v0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 756
    .line 757
    .line 758
    move-object v5, v2

    .line 759
    :goto_21
    check-cast v5, Lay0/k;

    .line 760
    .line 761
    const/4 v2, 0x0

    .line 762
    invoke-static {v1, v5, v0, v2}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 763
    .line 764
    .line 765
    move v8, v3

    .line 766
    move-object v6, v11

    .line 767
    move/from16 v7, v20

    .line 768
    .line 769
    goto :goto_22

    .line 770
    :cond_1e
    move-object v0, v11

    .line 771
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 772
    .line 773
    .line 774
    move/from16 v8, p7

    .line 775
    .line 776
    move v7, v9

    .line 777
    move-object v6, v13

    .line 778
    :goto_22
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 779
    .line 780
    .line 781
    move-result-object v11

    .line 782
    if-eqz v11, :cond_1f

    .line 783
    .line 784
    new-instance v0, Lxf0/s;

    .line 785
    .line 786
    move-object/from16 v1, p0

    .line 787
    .line 788
    move/from16 v2, p1

    .line 789
    .line 790
    move-object/from16 v3, p2

    .line 791
    .line 792
    move/from16 v4, p3

    .line 793
    .line 794
    move/from16 v5, p4

    .line 795
    .line 796
    move/from16 v9, p9

    .line 797
    .line 798
    move/from16 v10, p10

    .line 799
    .line 800
    invoke-direct/range {v0 .. v10}, Lxf0/s;-><init>(Lx2/s;ILjava/lang/Integer;ZZLjava/lang/Integer;ZZII)V

    .line 801
    .line 802
    .line 803
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 804
    .line 805
    :cond_1f
    return-void
.end method

.method public static final b(Lg3/d;JFFFFF)V
    .locals 22

    .line 1
    const/4 v0, 0x4

    .line 2
    int-to-float v0, v0

    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-interface {v1, v0}, Lt4/c;->w0(F)F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/high16 v2, 0x3f000000    # 0.5f

    .line 10
    .line 11
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    new-instance v3, Le3/s;

    .line 16
    .line 17
    move-wide/from16 v4, p1

    .line 18
    .line 19
    invoke-direct {v3, v4, v5}, Le3/s;-><init>(J)V

    .line 20
    .line 21
    .line 22
    new-instance v4, Llx0/l;

    .line 23
    .line 24
    invoke-direct {v4, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    sget-wide v5, Le3/s;->h:J

    .line 28
    .line 29
    new-instance v3, Le3/s;

    .line 30
    .line 31
    invoke-direct {v3, v5, v6}, Le3/s;-><init>(J)V

    .line 32
    .line 33
    .line 34
    new-instance v5, Llx0/l;

    .line 35
    .line 36
    invoke-direct {v5, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    filled-new-array {v4, v5}, [Llx0/l;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    int-to-long v4, v4

    .line 49
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    int-to-long v6, v6

    .line 54
    const/16 v11, 0x20

    .line 55
    .line 56
    shl-long/2addr v4, v11

    .line 57
    const-wide v12, 0xffffffffL

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    and-long/2addr v6, v12

    .line 63
    or-long v17, v4, v6

    .line 64
    .line 65
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    int-to-long v4, v0

    .line 70
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    int-to-long v6, v0

    .line 75
    shl-long v3, v4, v11

    .line 76
    .line 77
    and-long v5, v6, v12

    .line 78
    .line 79
    or-long v19, v3, v5

    .line 80
    .line 81
    new-instance v15, Ljava/util/ArrayList;

    .line 82
    .line 83
    const/4 v0, 0x2

    .line 84
    invoke-direct {v15, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 85
    .line 86
    .line 87
    const/4 v3, 0x0

    .line 88
    move v4, v3

    .line 89
    :goto_0
    if-ge v4, v0, :cond_0

    .line 90
    .line 91
    aget-object v5, v2, v4

    .line 92
    .line 93
    iget-object v5, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v5, Le3/s;

    .line 96
    .line 97
    iget-wide v5, v5, Le3/s;->a:J

    .line 98
    .line 99
    new-instance v7, Le3/s;

    .line 100
    .line 101
    invoke-direct {v7, v5, v6}, Le3/s;-><init>(J)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v15, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    add-int/lit8 v4, v4, 0x1

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_0
    new-instance v4, Ljava/util/ArrayList;

    .line 111
    .line 112
    invoke-direct {v4, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 113
    .line 114
    .line 115
    :goto_1
    if-ge v3, v0, :cond_1

    .line 116
    .line 117
    aget-object v5, v2, v3

    .line 118
    .line 119
    iget-object v5, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v5, Ljava/lang/Number;

    .line 122
    .line 123
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 128
    .line 129
    .line 130
    move-result-object v5

    .line 131
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    add-int/lit8 v3, v3, 0x1

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_1
    new-instance v2, Le3/b0;

    .line 138
    .line 139
    const/16 v21, 0x1

    .line 140
    .line 141
    move-object v14, v2

    .line 142
    move-object/from16 v16, v4

    .line 143
    .line 144
    invoke-direct/range {v14 .. v21}, Le3/b0;-><init>(Ljava/util/List;Ljava/util/ArrayList;JJI)V

    .line 145
    .line 146
    .line 147
    sub-float v0, p5, p7

    .line 148
    .line 149
    move/from16 v3, p4

    .line 150
    .line 151
    invoke-static {v3, v0}, Ljava/lang/Math;->min(FF)F

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    int-to-long v3, v0

    .line 160
    invoke-static/range {p6 .. p6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    int-to-long v5, v0

    .line 165
    shl-long/2addr v3, v11

    .line 166
    and-long/2addr v5, v12

    .line 167
    or-long/2addr v3, v5

    .line 168
    invoke-static/range {p5 .. p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    int-to-long v5, v0

    .line 173
    invoke-static/range {p6 .. p6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    int-to-long v7, v0

    .line 178
    shl-long/2addr v5, v11

    .line 179
    and-long/2addr v7, v12

    .line 180
    or-long/2addr v5, v7

    .line 181
    const/4 v9, 0x0

    .line 182
    const/16 v10, 0x1e0

    .line 183
    .line 184
    const/4 v8, 0x0

    .line 185
    move/from16 v7, p3

    .line 186
    .line 187
    invoke-static/range {v1 .. v10}, Lg3/d;->A0(Lg3/d;Le3/p;JJFIFI)V

    .line 188
    .line 189
    .line 190
    invoke-static/range {p5 .. p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    int-to-long v0, v0

    .line 195
    invoke-static/range {p6 .. p6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 196
    .line 197
    .line 198
    move-result v3

    .line 199
    int-to-long v3, v3

    .line 200
    shl-long/2addr v0, v11

    .line 201
    and-long/2addr v3, v12

    .line 202
    or-long/2addr v3, v0

    .line 203
    invoke-static/range {p5 .. p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 204
    .line 205
    .line 206
    move-result v0

    .line 207
    int-to-long v0, v0

    .line 208
    invoke-static/range {p6 .. p6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 209
    .line 210
    .line 211
    move-result v5

    .line 212
    int-to-long v5, v5

    .line 213
    shl-long/2addr v0, v11

    .line 214
    and-long/2addr v5, v12

    .line 215
    or-long/2addr v5, v0

    .line 216
    const/4 v8, 0x1

    .line 217
    move-object/from16 v1, p0

    .line 218
    .line 219
    invoke-static/range {v1 .. v10}, Lg3/d;->A0(Lg3/d;Le3/p;JJFIFI)V

    .line 220
    .line 221
    .line 222
    return-void
.end method
