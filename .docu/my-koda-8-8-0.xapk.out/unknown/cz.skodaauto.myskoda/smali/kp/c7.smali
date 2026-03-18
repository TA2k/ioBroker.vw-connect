.class public abstract Lkp/c7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lx2/s;Lf2/p;Le3/n0;Lf2/l;Lk1/z0;Lt2/b;Ll2/o;II)V
    .locals 37

    .line 1
    move/from16 v8, p8

    .line 2
    .line 3
    move/from16 v9, p9

    .line 4
    .line 5
    move-object/from16 v0, p7

    .line 6
    .line 7
    check-cast v0, Ll2/t;

    .line 8
    .line 9
    const v1, -0x40a548e5

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    move-object/from16 v10, p0

    .line 16
    .line 17
    invoke-virtual {v0, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x2

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    const/4 v1, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v1, v2

    .line 27
    :goto_0
    or-int/2addr v1, v8

    .line 28
    and-int/lit8 v4, v9, 0x2

    .line 29
    .line 30
    if-eqz v4, :cond_1

    .line 31
    .line 32
    or-int/lit8 v1, v1, 0x30

    .line 33
    .line 34
    move-object/from16 v5, p1

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_1
    move-object/from16 v5, p1

    .line 38
    .line 39
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-eqz v6, :cond_2

    .line 44
    .line 45
    const/16 v6, 0x20

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    const/16 v6, 0x10

    .line 49
    .line 50
    :goto_1
    or-int/2addr v1, v6

    .line 51
    :goto_2
    and-int/lit16 v6, v8, 0x180

    .line 52
    .line 53
    const/4 v7, 0x1

    .line 54
    if-nez v6, :cond_4

    .line 55
    .line 56
    invoke-virtual {v0, v7}, Ll2/t;->h(Z)Z

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    if-eqz v6, :cond_3

    .line 61
    .line 62
    const/16 v6, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v6, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v1, v6

    .line 68
    :cond_4
    and-int/lit8 v6, v9, 0x8

    .line 69
    .line 70
    const/4 v12, 0x0

    .line 71
    if-eqz v6, :cond_5

    .line 72
    .line 73
    or-int/lit16 v1, v1, 0xc00

    .line 74
    .line 75
    goto :goto_5

    .line 76
    :cond_5
    invoke-virtual {v0, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v6

    .line 80
    if-eqz v6, :cond_6

    .line 81
    .line 82
    const/16 v6, 0x800

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_6
    const/16 v6, 0x400

    .line 86
    .line 87
    :goto_4
    or-int/2addr v1, v6

    .line 88
    :goto_5
    and-int/lit8 v6, v9, 0x10

    .line 89
    .line 90
    if-nez v6, :cond_7

    .line 91
    .line 92
    move-object/from16 v6, p2

    .line 93
    .line 94
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v13

    .line 98
    if-eqz v13, :cond_8

    .line 99
    .line 100
    const/16 v13, 0x4000

    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_7
    move-object/from16 v6, p2

    .line 104
    .line 105
    :cond_8
    const/16 v13, 0x2000

    .line 106
    .line 107
    :goto_6
    or-int/2addr v1, v13

    .line 108
    and-int/lit8 v13, v9, 0x20

    .line 109
    .line 110
    if-nez v13, :cond_9

    .line 111
    .line 112
    move-object/from16 v13, p3

    .line 113
    .line 114
    invoke-virtual {v0, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v14

    .line 118
    if-eqz v14, :cond_a

    .line 119
    .line 120
    const/high16 v14, 0x20000

    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_9
    move-object/from16 v13, p3

    .line 124
    .line 125
    :cond_a
    const/high16 v14, 0x10000

    .line 126
    .line 127
    :goto_7
    or-int/2addr v1, v14

    .line 128
    and-int/lit8 v14, v9, 0x40

    .line 129
    .line 130
    if-eqz v14, :cond_b

    .line 131
    .line 132
    const/high16 v14, 0x180000

    .line 133
    .line 134
    :goto_8
    or-int/2addr v1, v14

    .line 135
    goto :goto_9

    .line 136
    :cond_b
    invoke-virtual {v0, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v14

    .line 140
    if-eqz v14, :cond_c

    .line 141
    .line 142
    const/high16 v14, 0x100000

    .line 143
    .line 144
    goto :goto_8

    .line 145
    :cond_c
    const/high16 v14, 0x80000

    .line 146
    .line 147
    goto :goto_8

    .line 148
    :goto_9
    and-int/lit16 v14, v9, 0x80

    .line 149
    .line 150
    if-nez v14, :cond_d

    .line 151
    .line 152
    move-object/from16 v14, p4

    .line 153
    .line 154
    invoke-virtual {v0, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v15

    .line 158
    if-eqz v15, :cond_e

    .line 159
    .line 160
    const/high16 v15, 0x800000

    .line 161
    .line 162
    goto :goto_a

    .line 163
    :cond_d
    move-object/from16 v14, p4

    .line 164
    .line 165
    :cond_e
    const/high16 v15, 0x400000

    .line 166
    .line 167
    :goto_a
    or-int/2addr v1, v15

    .line 168
    and-int/lit16 v15, v9, 0x100

    .line 169
    .line 170
    if-eqz v15, :cond_f

    .line 171
    .line 172
    const/high16 v16, 0x6000000

    .line 173
    .line 174
    or-int v1, v1, v16

    .line 175
    .line 176
    move-object/from16 v7, p5

    .line 177
    .line 178
    goto :goto_c

    .line 179
    :cond_f
    move-object/from16 v7, p5

    .line 180
    .line 181
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v16

    .line 185
    if-eqz v16, :cond_10

    .line 186
    .line 187
    const/high16 v16, 0x4000000

    .line 188
    .line 189
    goto :goto_b

    .line 190
    :cond_10
    const/high16 v16, 0x2000000

    .line 191
    .line 192
    :goto_b
    or-int v1, v1, v16

    .line 193
    .line 194
    :goto_c
    const v16, 0x12492493

    .line 195
    .line 196
    .line 197
    and-int v11, v1, v16

    .line 198
    .line 199
    const v12, 0x12492492

    .line 200
    .line 201
    .line 202
    const/4 v3, 0x0

    .line 203
    if-eq v11, v12, :cond_11

    .line 204
    .line 205
    const/4 v11, 0x1

    .line 206
    goto :goto_d

    .line 207
    :cond_11
    move v11, v3

    .line 208
    :goto_d
    and-int/lit8 v12, v1, 0x1

    .line 209
    .line 210
    invoke-virtual {v0, v12, v11}, Ll2/t;->O(IZ)Z

    .line 211
    .line 212
    .line 213
    move-result v11

    .line 214
    if-eqz v11, :cond_32

    .line 215
    .line 216
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 217
    .line 218
    .line 219
    and-int/lit8 v11, v8, 0x1

    .line 220
    .line 221
    const v19, -0x70001

    .line 222
    .line 223
    .line 224
    const v20, -0xe001

    .line 225
    .line 226
    .line 227
    const v21, -0x1c00001

    .line 228
    .line 229
    .line 230
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 231
    .line 232
    if-eqz v11, :cond_16

    .line 233
    .line 234
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 235
    .line 236
    .line 237
    move-result v11

    .line 238
    if-eqz v11, :cond_12

    .line 239
    .line 240
    goto :goto_e

    .line 241
    :cond_12
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 242
    .line 243
    .line 244
    and-int/lit8 v2, v9, 0x10

    .line 245
    .line 246
    if-eqz v2, :cond_13

    .line 247
    .line 248
    and-int v1, v1, v20

    .line 249
    .line 250
    :cond_13
    and-int/lit8 v2, v9, 0x20

    .line 251
    .line 252
    if-eqz v2, :cond_14

    .line 253
    .line 254
    and-int v1, v1, v19

    .line 255
    .line 256
    :cond_14
    and-int/lit16 v2, v9, 0x80

    .line 257
    .line 258
    if-eqz v2, :cond_15

    .line 259
    .line 260
    and-int v1, v1, v21

    .line 261
    .line 262
    :cond_15
    move v2, v1

    .line 263
    move-object v1, v14

    .line 264
    goto/16 :goto_14

    .line 265
    .line 266
    :cond_16
    :goto_e
    if-eqz v4, :cond_17

    .line 267
    .line 268
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 269
    .line 270
    goto :goto_f

    .line 271
    :cond_17
    move-object v4, v5

    .line 272
    :goto_f
    and-int/lit8 v5, v9, 0x10

    .line 273
    .line 274
    if-eqz v5, :cond_1a

    .line 275
    .line 276
    sget-object v5, Lf2/c;->a:Lk1/a1;

    .line 277
    .line 278
    int-to-float v2, v2

    .line 279
    const/16 v5, 0x8

    .line 280
    .line 281
    int-to-float v5, v5

    .line 282
    int-to-float v6, v3

    .line 283
    const/4 v11, 0x4

    .line 284
    int-to-float v3, v11

    .line 285
    invoke-virtual {v0, v2}, Ll2/t;->d(F)Z

    .line 286
    .line 287
    .line 288
    move-result v11

    .line 289
    invoke-virtual {v0, v5}, Ll2/t;->d(F)Z

    .line 290
    .line 291
    .line 292
    move-result v22

    .line 293
    or-int v11, v11, v22

    .line 294
    .line 295
    invoke-virtual {v0, v6}, Ll2/t;->d(F)Z

    .line 296
    .line 297
    .line 298
    move-result v22

    .line 299
    or-int v11, v11, v22

    .line 300
    .line 301
    invoke-virtual {v0, v3}, Ll2/t;->d(F)Z

    .line 302
    .line 303
    .line 304
    move-result v22

    .line 305
    or-int v11, v11, v22

    .line 306
    .line 307
    invoke-virtual {v0, v3}, Ll2/t;->d(F)Z

    .line 308
    .line 309
    .line 310
    move-result v22

    .line 311
    or-int v11, v11, v22

    .line 312
    .line 313
    move/from16 v28, v1

    .line 314
    .line 315
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    if-nez v11, :cond_18

    .line 320
    .line 321
    if-ne v1, v12, :cond_19

    .line 322
    .line 323
    :cond_18
    new-instance v22, Lf2/p;

    .line 324
    .line 325
    move/from16 v27, v3

    .line 326
    .line 327
    move/from16 v23, v2

    .line 328
    .line 329
    move/from16 v26, v3

    .line 330
    .line 331
    move/from16 v24, v5

    .line 332
    .line 333
    move/from16 v25, v6

    .line 334
    .line 335
    invoke-direct/range {v22 .. v27}, Lf2/p;-><init>(FFFFF)V

    .line 336
    .line 337
    .line 338
    move-object/from16 v1, v22

    .line 339
    .line 340
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 341
    .line 342
    .line 343
    :cond_19
    check-cast v1, Lf2/p;

    .line 344
    .line 345
    and-int v2, v28, v20

    .line 346
    .line 347
    move-object v6, v1

    .line 348
    move v1, v2

    .line 349
    goto :goto_10

    .line 350
    :cond_1a
    move/from16 v28, v1

    .line 351
    .line 352
    :goto_10
    and-int/lit8 v2, v9, 0x20

    .line 353
    .line 354
    if-eqz v2, :cond_1b

    .line 355
    .line 356
    sget-object v2, Lf2/l0;->a:Ll2/u2;

    .line 357
    .line 358
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object v2

    .line 362
    check-cast v2, Lf2/k0;

    .line 363
    .line 364
    iget-object v2, v2, Lf2/k0;->a:Ls1/e;

    .line 365
    .line 366
    and-int v1, v1, v19

    .line 367
    .line 368
    move-object v13, v2

    .line 369
    :cond_1b
    and-int/lit16 v2, v9, 0x80

    .line 370
    .line 371
    if-eqz v2, :cond_1d

    .line 372
    .line 373
    sget-object v2, Lf2/c;->a:Lk1/a1;

    .line 374
    .line 375
    sget-object v2, Lf2/h;->a:Ll2/u2;

    .line 376
    .line 377
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v3

    .line 381
    check-cast v3, Lf2/g;

    .line 382
    .line 383
    move-object/from16 p1, v4

    .line 384
    .line 385
    invoke-virtual {v3}, Lf2/g;->b()J

    .line 386
    .line 387
    .line 388
    move-result-wide v3

    .line 389
    invoke-static {v3, v4, v0}, Lf2/h;->a(JLl2/o;)J

    .line 390
    .line 391
    .line 392
    move-result-wide v31

    .line 393
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    move-result-object v5

    .line 397
    check-cast v5, Lf2/g;

    .line 398
    .line 399
    move-wide/from16 v29, v3

    .line 400
    .line 401
    invoke-virtual {v5}, Lf2/g;->a()J

    .line 402
    .line 403
    .line 404
    move-result-wide v3

    .line 405
    const v5, 0x3df5c28f    # 0.12f

    .line 406
    .line 407
    .line 408
    invoke-static {v3, v4, v5}, Le3/s;->b(JF)J

    .line 409
    .line 410
    .line 411
    move-result-wide v3

    .line 412
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v5

    .line 416
    check-cast v5, Lf2/g;

    .line 417
    .line 418
    move-object/from16 p2, v6

    .line 419
    .line 420
    invoke-virtual {v5}, Lf2/g;->c()J

    .line 421
    .line 422
    .line 423
    move-result-wide v5

    .line 424
    invoke-static {v3, v4, v5, v6}, Le3/j0;->l(JJ)J

    .line 425
    .line 426
    .line 427
    move-result-wide v33

    .line 428
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v3

    .line 432
    check-cast v3, Lf2/g;

    .line 433
    .line 434
    invoke-virtual {v3}, Lf2/g;->a()J

    .line 435
    .line 436
    .line 437
    move-result-wide v3

    .line 438
    sget-object v5, Lf2/k;->a:Ll2/e0;

    .line 439
    .line 440
    invoke-virtual {v0, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v5

    .line 444
    check-cast v5, Le3/s;

    .line 445
    .line 446
    iget-wide v5, v5, Le3/s;->a:J

    .line 447
    .line 448
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v2

    .line 452
    check-cast v2, Lf2/g;

    .line 453
    .line 454
    invoke-virtual {v2}, Lf2/g;->d()Z

    .line 455
    .line 456
    .line 457
    move-result v2

    .line 458
    if-eqz v2, :cond_1c

    .line 459
    .line 460
    invoke-static {v5, v6}, Le3/j0;->r(J)F

    .line 461
    .line 462
    .line 463
    goto :goto_11

    .line 464
    :cond_1c
    invoke-static {v5, v6}, Le3/j0;->r(J)F

    .line 465
    .line 466
    .line 467
    :goto_11
    const v2, 0x3ec28f5c    # 0.38f

    .line 468
    .line 469
    .line 470
    invoke-static {v3, v4, v2}, Le3/s;->b(JF)J

    .line 471
    .line 472
    .line 473
    move-result-wide v35

    .line 474
    new-instance v28, Lf2/l;

    .line 475
    .line 476
    invoke-direct/range {v28 .. v36}, Lf2/l;-><init>(JJJJ)V

    .line 477
    .line 478
    .line 479
    and-int v1, v1, v21

    .line 480
    .line 481
    goto :goto_12

    .line 482
    :cond_1d
    move-object/from16 p1, v4

    .line 483
    .line 484
    move-object/from16 p2, v6

    .line 485
    .line 486
    move-object/from16 v28, v14

    .line 487
    .line 488
    :goto_12
    if-eqz v15, :cond_1e

    .line 489
    .line 490
    sget-object v2, Lf2/c;->a:Lk1/a1;

    .line 491
    .line 492
    move-object/from16 v5, p1

    .line 493
    .line 494
    move-object/from16 v6, p2

    .line 495
    .line 496
    move-object v7, v2

    .line 497
    :goto_13
    move v2, v1

    .line 498
    move-object/from16 v1, v28

    .line 499
    .line 500
    goto :goto_14

    .line 501
    :cond_1e
    move-object/from16 v5, p1

    .line 502
    .line 503
    move-object/from16 v6, p2

    .line 504
    .line 505
    goto :goto_13

    .line 506
    :goto_14
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 507
    .line 508
    .line 509
    const v3, 0x1dab67c0

    .line 510
    .line 511
    .line 512
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 513
    .line 514
    .line 515
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    move-result-object v3

    .line 519
    if-ne v3, v12, :cond_1f

    .line 520
    .line 521
    invoke-static {v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 522
    .line 523
    .line 524
    move-result-object v3

    .line 525
    :cond_1f
    check-cast v3, Li1/l;

    .line 526
    .line 527
    const/4 v4, 0x0

    .line 528
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 529
    .line 530
    .line 531
    shr-int/lit8 v11, v2, 0x6

    .line 532
    .line 533
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 534
    .line 535
    .line 536
    const v14, -0x7f2ce0b4

    .line 537
    .line 538
    .line 539
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 540
    .line 541
    .line 542
    iget-wide v14, v1, Lf2/l;->b:J

    .line 543
    .line 544
    new-instance v4, Le3/s;

    .line 545
    .line 546
    invoke-direct {v4, v14, v15}, Le3/s;-><init>(J)V

    .line 547
    .line 548
    .line 549
    invoke-static {v4, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 550
    .line 551
    .line 552
    move-result-object v4

    .line 553
    const/4 v14, 0x0

    .line 554
    invoke-virtual {v0, v14}, Ll2/t;->q(Z)V

    .line 555
    .line 556
    .line 557
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 558
    .line 559
    .line 560
    move-result-object v15

    .line 561
    if-ne v15, v12, :cond_20

    .line 562
    .line 563
    new-instance v15, Leh/b;

    .line 564
    .line 565
    const/16 v14, 0x13

    .line 566
    .line 567
    invoke-direct {v15, v14}, Leh/b;-><init>(I)V

    .line 568
    .line 569
    .line 570
    invoke-virtual {v0, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 571
    .line 572
    .line 573
    :cond_20
    check-cast v15, Lay0/k;

    .line 574
    .line 575
    const/4 v14, 0x0

    .line 576
    invoke-static {v5, v14, v15}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 577
    .line 578
    .line 579
    move-result-object v15

    .line 580
    const v14, -0x270e63e3

    .line 581
    .line 582
    .line 583
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 584
    .line 585
    .line 586
    iget-wide v8, v1, Lf2/l;->a:J

    .line 587
    .line 588
    new-instance v14, Le3/s;

    .line 589
    .line 590
    invoke-direct {v14, v8, v9}, Le3/s;-><init>(J)V

    .line 591
    .line 592
    .line 593
    invoke-static {v14, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 594
    .line 595
    .line 596
    move-result-object v8

    .line 597
    const/4 v14, 0x0

    .line 598
    invoke-virtual {v0, v14}, Ll2/t;->q(Z)V

    .line 599
    .line 600
    .line 601
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 602
    .line 603
    .line 604
    move-result-object v8

    .line 605
    check-cast v8, Le3/s;

    .line 606
    .line 607
    iget-wide v8, v8, Le3/s;->a:J

    .line 608
    .line 609
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 610
    .line 611
    .line 612
    move-result-object v14

    .line 613
    check-cast v14, Le3/s;

    .line 614
    .line 615
    move-wide/from16 v26, v8

    .line 616
    .line 617
    iget-wide v8, v14, Le3/s;->a:J

    .line 618
    .line 619
    const/high16 v14, 0x3f800000    # 1.0f

    .line 620
    .line 621
    invoke-static {v8, v9, v14}, Le3/s;->b(JF)J

    .line 622
    .line 623
    .line 624
    move-result-wide v8

    .line 625
    if-nez v6, :cond_21

    .line 626
    .line 627
    const v12, 0x1db19c41

    .line 628
    .line 629
    .line 630
    invoke-virtual {v0, v12}, Ll2/t;->Y(I)V

    .line 631
    .line 632
    .line 633
    const/4 v12, 0x0

    .line 634
    invoke-virtual {v0, v12}, Ll2/t;->q(Z)V

    .line 635
    .line 636
    .line 637
    move-object/from16 p2, v1

    .line 638
    .line 639
    move-object/from16 p5, v3

    .line 640
    .line 641
    move-object/from16 v28, v5

    .line 642
    .line 643
    move-wide/from16 p3, v8

    .line 644
    .line 645
    move v14, v12

    .line 646
    const/4 v12, 0x0

    .line 647
    goto/16 :goto_1c

    .line 648
    .line 649
    :cond_21
    const v14, 0x5389dbc0

    .line 650
    .line 651
    .line 652
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 653
    .line 654
    .line 655
    const v14, -0x5eb281ab

    .line 656
    .line 657
    .line 658
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 659
    .line 660
    .line 661
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 662
    .line 663
    .line 664
    move-result-object v14

    .line 665
    if-ne v14, v12, :cond_22

    .line 666
    .line 667
    new-instance v14, Lv2/o;

    .line 668
    .line 669
    invoke-direct {v14}, Lv2/o;-><init>()V

    .line 670
    .line 671
    .line 672
    invoke-virtual {v0, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 673
    .line 674
    .line 675
    :cond_22
    check-cast v14, Lv2/o;

    .line 676
    .line 677
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 678
    .line 679
    .line 680
    move-result v19

    .line 681
    move-object/from16 p2, v1

    .line 682
    .line 683
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 684
    .line 685
    .line 686
    move-result-object v1

    .line 687
    if-nez v19, :cond_24

    .line 688
    .line 689
    if-ne v1, v12, :cond_23

    .line 690
    .line 691
    goto :goto_15

    .line 692
    :cond_23
    move-object/from16 v28, v5

    .line 693
    .line 694
    move-wide/from16 p3, v8

    .line 695
    .line 696
    goto :goto_16

    .line 697
    :cond_24
    :goto_15
    new-instance v1, Lf2/n;

    .line 698
    .line 699
    move-object/from16 v28, v5

    .line 700
    .line 701
    move-wide/from16 p3, v8

    .line 702
    .line 703
    const/4 v5, 0x0

    .line 704
    const/4 v8, 0x0

    .line 705
    invoke-direct {v1, v3, v14, v5, v8}, Lf2/n;-><init>(Li1/l;Lv2/o;Lkotlin/coroutines/Continuation;I)V

    .line 706
    .line 707
    .line 708
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 709
    .line 710
    .line 711
    :goto_16
    check-cast v1, Lay0/n;

    .line 712
    .line 713
    invoke-static {v1, v3, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 714
    .line 715
    .line 716
    invoke-static {v14}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 717
    .line 718
    .line 719
    move-result-object v1

    .line 720
    check-cast v1, Li1/k;

    .line 721
    .line 722
    instance-of v5, v1, Li1/n;

    .line 723
    .line 724
    if-eqz v5, :cond_25

    .line 725
    .line 726
    iget v5, v6, Lf2/p;->b:F

    .line 727
    .line 728
    goto :goto_17

    .line 729
    :cond_25
    instance-of v5, v1, Li1/i;

    .line 730
    .line 731
    if-eqz v5, :cond_26

    .line 732
    .line 733
    iget v5, v6, Lf2/p;->c:F

    .line 734
    .line 735
    goto :goto_17

    .line 736
    :cond_26
    instance-of v5, v1, Li1/e;

    .line 737
    .line 738
    if-eqz v5, :cond_27

    .line 739
    .line 740
    iget v5, v6, Lf2/p;->d:F

    .line 741
    .line 742
    goto :goto_17

    .line 743
    :cond_27
    iget v5, v6, Lf2/p;->a:F

    .line 744
    .line 745
    :goto_17
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 746
    .line 747
    .line 748
    move-result-object v8

    .line 749
    if-ne v8, v12, :cond_28

    .line 750
    .line 751
    new-instance v8, Lc1/c;

    .line 752
    .line 753
    new-instance v9, Lt4/f;

    .line 754
    .line 755
    invoke-direct {v9, v5}, Lt4/f;-><init>(F)V

    .line 756
    .line 757
    .line 758
    sget-object v14, Lc1/d;->l:Lc1/b2;

    .line 759
    .line 760
    move-object/from16 p5, v3

    .line 761
    .line 762
    const/16 v3, 0xc

    .line 763
    .line 764
    const/4 v10, 0x0

    .line 765
    invoke-direct {v8, v9, v14, v10, v3}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 766
    .line 767
    .line 768
    invoke-virtual {v0, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 769
    .line 770
    .line 771
    goto :goto_18

    .line 772
    :cond_28
    move-object/from16 p5, v3

    .line 773
    .line 774
    :goto_18
    check-cast v8, Lc1/c;

    .line 775
    .line 776
    new-instance v3, Lt4/f;

    .line 777
    .line 778
    invoke-direct {v3, v5}, Lt4/f;-><init>(F)V

    .line 779
    .line 780
    .line 781
    invoke-virtual {v0, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 782
    .line 783
    .line 784
    move-result v9

    .line 785
    invoke-virtual {v0, v5}, Ll2/t;->d(F)Z

    .line 786
    .line 787
    .line 788
    move-result v10

    .line 789
    or-int/2addr v9, v10

    .line 790
    and-int/lit8 v10, v11, 0xe

    .line 791
    .line 792
    xor-int/lit8 v10, v10, 0x6

    .line 793
    .line 794
    const/4 v14, 0x4

    .line 795
    if-le v10, v14, :cond_29

    .line 796
    .line 797
    const/4 v10, 0x1

    .line 798
    invoke-virtual {v0, v10}, Ll2/t;->h(Z)Z

    .line 799
    .line 800
    .line 801
    move-result v16

    .line 802
    if-nez v16, :cond_2a

    .line 803
    .line 804
    goto :goto_19

    .line 805
    :cond_29
    const/4 v10, 0x1

    .line 806
    :goto_19
    and-int/lit8 v10, v11, 0x6

    .line 807
    .line 808
    if-ne v10, v14, :cond_2b

    .line 809
    .line 810
    :cond_2a
    const/4 v10, 0x1

    .line 811
    goto :goto_1a

    .line 812
    :cond_2b
    const/4 v10, 0x0

    .line 813
    :goto_1a
    or-int/2addr v9, v10

    .line 814
    and-int/lit16 v10, v11, 0x380

    .line 815
    .line 816
    xor-int/lit16 v10, v10, 0x180

    .line 817
    .line 818
    const/16 v14, 0x100

    .line 819
    .line 820
    if-le v10, v14, :cond_2c

    .line 821
    .line 822
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 823
    .line 824
    .line 825
    move-result v10

    .line 826
    if-nez v10, :cond_2d

    .line 827
    .line 828
    :cond_2c
    and-int/lit16 v10, v11, 0x180

    .line 829
    .line 830
    if-ne v10, v14, :cond_2e

    .line 831
    .line 832
    :cond_2d
    const/4 v10, 0x1

    .line 833
    goto :goto_1b

    .line 834
    :cond_2e
    const/4 v10, 0x0

    .line 835
    :goto_1b
    or-int/2addr v9, v10

    .line 836
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 837
    .line 838
    .line 839
    move-result v10

    .line 840
    or-int/2addr v9, v10

    .line 841
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 842
    .line 843
    .line 844
    move-result-object v10

    .line 845
    if-nez v9, :cond_2f

    .line 846
    .line 847
    if-ne v10, v12, :cond_30

    .line 848
    .line 849
    :cond_2f
    new-instance v19, Lf2/o;

    .line 850
    .line 851
    const/16 v24, 0x0

    .line 852
    .line 853
    const/16 v25, 0x0

    .line 854
    .line 855
    move-object/from16 v23, v1

    .line 856
    .line 857
    move/from16 v21, v5

    .line 858
    .line 859
    move-object/from16 v22, v6

    .line 860
    .line 861
    move-object/from16 v20, v8

    .line 862
    .line 863
    invoke-direct/range {v19 .. v25}, Lf2/o;-><init>(Ljava/lang/Object;FLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 864
    .line 865
    .line 866
    move-object/from16 v10, v19

    .line 867
    .line 868
    invoke-virtual {v0, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 869
    .line 870
    .line 871
    :cond_30
    check-cast v10, Lay0/n;

    .line 872
    .line 873
    invoke-static {v10, v3, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 874
    .line 875
    .line 876
    iget-object v12, v8, Lc1/c;->c:Lc1/k;

    .line 877
    .line 878
    const/4 v14, 0x0

    .line 879
    invoke-virtual {v0, v14}, Ll2/t;->q(Z)V

    .line 880
    .line 881
    .line 882
    invoke-virtual {v0, v14}, Ll2/t;->q(Z)V

    .line 883
    .line 884
    .line 885
    :goto_1c
    if-eqz v12, :cond_31

    .line 886
    .line 887
    iget-object v1, v12, Lc1/k;->e:Ll2/j1;

    .line 888
    .line 889
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 890
    .line 891
    .line 892
    move-result-object v1

    .line 893
    check-cast v1, Lt4/f;

    .line 894
    .line 895
    iget v1, v1, Lt4/f;->d:F

    .line 896
    .line 897
    :goto_1d
    move/from16 v18, v1

    .line 898
    .line 899
    goto :goto_1e

    .line 900
    :cond_31
    int-to-float v1, v14

    .line 901
    goto :goto_1d

    .line 902
    :goto_1e
    new-instance v1, Lf2/f;

    .line 903
    .line 904
    move-object/from16 v3, p6

    .line 905
    .line 906
    invoke-direct {v1, v4, v7, v3, v14}, Lf2/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 907
    .line 908
    .line 909
    const v4, -0x136739e

    .line 910
    .line 911
    .line 912
    invoke-static {v4, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 913
    .line 914
    .line 915
    move-result-object v20

    .line 916
    and-int/lit8 v1, v2, 0xe

    .line 917
    .line 918
    const/high16 v4, 0x30000000

    .line 919
    .line 920
    or-int/2addr v1, v4

    .line 921
    and-int/lit16 v4, v2, 0x380

    .line 922
    .line 923
    or-int/2addr v1, v4

    .line 924
    and-int/lit16 v4, v11, 0x1c00

    .line 925
    .line 926
    or-int/2addr v1, v4

    .line 927
    const/high16 v4, 0x380000

    .line 928
    .line 929
    and-int/2addr v2, v4

    .line 930
    or-int v22, v1, v2

    .line 931
    .line 932
    const/16 v23, 0x0

    .line 933
    .line 934
    move-object/from16 v10, p0

    .line 935
    .line 936
    move-wide/from16 v16, p3

    .line 937
    .line 938
    move-object/from16 v19, p5

    .line 939
    .line 940
    move-object/from16 v21, v0

    .line 941
    .line 942
    move-object v11, v15

    .line 943
    move-wide/from16 v14, v26

    .line 944
    .line 945
    const/4 v12, 0x1

    .line 946
    invoke-static/range {v10 .. v23}, Lkp/g7;->b(Lay0/a;Lx2/s;ZLe3/n0;JJFLi1/l;Lt2/b;Ll2/o;II)V

    .line 947
    .line 948
    .line 949
    move-object/from16 v5, p2

    .line 950
    .line 951
    move-object/from16 v2, v28

    .line 952
    .line 953
    :goto_1f
    move-object v3, v6

    .line 954
    move-object v6, v7

    .line 955
    move-object v4, v13

    .line 956
    goto :goto_20

    .line 957
    :cond_32
    move-object/from16 v3, p6

    .line 958
    .line 959
    move-object/from16 v21, v0

    .line 960
    .line 961
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 962
    .line 963
    .line 964
    move-object v2, v5

    .line 965
    move-object v5, v14

    .line 966
    goto :goto_1f

    .line 967
    :goto_20
    invoke-virtual/range {v21 .. v21}, Ll2/t;->s()Ll2/u1;

    .line 968
    .line 969
    .line 970
    move-result-object v11

    .line 971
    if-eqz v11, :cond_33

    .line 972
    .line 973
    new-instance v0, Lf2/d;

    .line 974
    .line 975
    const/4 v10, 0x0

    .line 976
    move-object/from16 v1, p0

    .line 977
    .line 978
    move-object/from16 v7, p6

    .line 979
    .line 980
    move/from16 v8, p8

    .line 981
    .line 982
    move/from16 v9, p9

    .line 983
    .line 984
    invoke-direct/range {v0 .. v10}, Lf2/d;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 985
    .line 986
    .line 987
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 988
    .line 989
    :cond_33
    return-void
.end method

.method public static b([FI)[F
    .locals 2

    .line 1
    if-ltz p1, :cond_1

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    if-ltz v0, :cond_0

    .line 5
    .line 6
    invoke-static {p1, v0}, Ljava/lang/Math;->min(II)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    new-array p1, p1, [F

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-static {p0, v1, p1, v1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public static c(Ljava/lang/String;)[Ls5/d;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    move v5, v2

    .line 10
    const/4 v4, 0x1

    .line 11
    :goto_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v6

    .line 15
    if-ge v4, v6, :cond_f

    .line 16
    .line 17
    :goto_1
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    const/16 v7, 0x45

    .line 22
    .line 23
    const/16 v8, 0x65

    .line 24
    .line 25
    if-ge v4, v6, :cond_2

    .line 26
    .line 27
    invoke-virtual {v0, v4}, Ljava/lang/String;->charAt(I)C

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    add-int/lit8 v9, v6, -0x41

    .line 32
    .line 33
    add-int/lit8 v10, v6, -0x5a

    .line 34
    .line 35
    mul-int/2addr v10, v9

    .line 36
    if-lez v10, :cond_0

    .line 37
    .line 38
    add-int/lit8 v9, v6, -0x61

    .line 39
    .line 40
    add-int/lit8 v10, v6, -0x7a

    .line 41
    .line 42
    mul-int/2addr v10, v9

    .line 43
    if-gtz v10, :cond_1

    .line 44
    .line 45
    :cond_0
    if-eq v6, v8, :cond_1

    .line 46
    .line 47
    if-eq v6, v7, :cond_1

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    :goto_2
    invoke-virtual {v0, v5, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    invoke-virtual {v5}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    .line 62
    .line 63
    .line 64
    move-result v6

    .line 65
    if-nez v6, :cond_e

    .line 66
    .line 67
    invoke-virtual {v5, v2}, Ljava/lang/String;->charAt(I)C

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    const/16 v9, 0x7a

    .line 72
    .line 73
    if-eq v6, v9, :cond_d

    .line 74
    .line 75
    invoke-virtual {v5, v2}, Ljava/lang/String;->charAt(I)C

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    const/16 v9, 0x5a

    .line 80
    .line 81
    if-ne v6, v9, :cond_3

    .line 82
    .line 83
    goto/16 :goto_c

    .line 84
    .line 85
    :cond_3
    :try_start_0
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    new-array v6, v6, [F

    .line 90
    .line 91
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    move v11, v2

    .line 96
    const/4 v10, 0x1

    .line 97
    :goto_3
    if-ge v10, v9, :cond_c

    .line 98
    .line 99
    move v13, v2

    .line 100
    move v14, v13

    .line 101
    move v15, v14

    .line 102
    move/from16 v16, v15

    .line 103
    .line 104
    move v12, v10

    .line 105
    :goto_4
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    if-ge v12, v3, :cond_9

    .line 110
    .line 111
    invoke-virtual {v5, v12}, Ljava/lang/String;->charAt(I)C

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    const/16 v2, 0x20

    .line 116
    .line 117
    if-eq v3, v2, :cond_7

    .line 118
    .line 119
    if-eq v3, v7, :cond_6

    .line 120
    .line 121
    if-eq v3, v8, :cond_6

    .line 122
    .line 123
    packed-switch v3, :pswitch_data_0

    .line 124
    .line 125
    .line 126
    goto :goto_6

    .line 127
    :pswitch_0
    if-nez v14, :cond_4

    .line 128
    .line 129
    const/4 v13, 0x0

    .line 130
    const/4 v14, 0x1

    .line 131
    goto :goto_7

    .line 132
    :cond_4
    :goto_5
    const/4 v13, 0x0

    .line 133
    const/4 v15, 0x1

    .line 134
    const/16 v16, 0x1

    .line 135
    .line 136
    goto :goto_7

    .line 137
    :pswitch_1
    if-eq v12, v10, :cond_5

    .line 138
    .line 139
    if-nez v13, :cond_5

    .line 140
    .line 141
    goto :goto_5

    .line 142
    :cond_5
    :goto_6
    const/4 v13, 0x0

    .line 143
    goto :goto_7

    .line 144
    :cond_6
    const/4 v13, 0x1

    .line 145
    goto :goto_7

    .line 146
    :cond_7
    :pswitch_2
    const/4 v13, 0x0

    .line 147
    const/4 v15, 0x1

    .line 148
    :goto_7
    if-eqz v15, :cond_8

    .line 149
    .line 150
    goto :goto_8

    .line 151
    :cond_8
    add-int/lit8 v12, v12, 0x1

    .line 152
    .line 153
    const/4 v2, 0x0

    .line 154
    goto :goto_4

    .line 155
    :cond_9
    :goto_8
    if-ge v10, v12, :cond_a

    .line 156
    .line 157
    add-int/lit8 v2, v11, 0x1

    .line 158
    .line 159
    invoke-virtual {v5, v10, v12}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v3

    .line 163
    invoke-static {v3}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 164
    .line 165
    .line 166
    move-result v3

    .line 167
    aput v3, v6, v11

    .line 168
    .line 169
    move v11, v2

    .line 170
    goto :goto_9

    .line 171
    :catch_0
    move-exception v0

    .line 172
    goto :goto_b

    .line 173
    :cond_a
    :goto_9
    if-eqz v16, :cond_b

    .line 174
    .line 175
    move v10, v12

    .line 176
    :goto_a
    const/4 v2, 0x0

    .line 177
    goto :goto_3

    .line 178
    :cond_b
    add-int/lit8 v10, v12, 0x1

    .line 179
    .line 180
    goto :goto_a

    .line 181
    :cond_c
    invoke-static {v6, v11}, Lkp/c7;->b([FI)[F

    .line 182
    .line 183
    .line 184
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 185
    move-object v3, v2

    .line 186
    const/4 v2, 0x0

    .line 187
    goto :goto_d

    .line 188
    :goto_b
    new-instance v1, Ljava/lang/RuntimeException;

    .line 189
    .line 190
    const-string v2, "error in parsing \""

    .line 191
    .line 192
    const-string v3, "\""

    .line 193
    .line 194
    invoke-static {v2, v5, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 199
    .line 200
    .line 201
    throw v1

    .line 202
    :cond_d
    :goto_c
    new-array v3, v2, [F

    .line 203
    .line 204
    :goto_d
    invoke-virtual {v5, v2}, Ljava/lang/String;->charAt(I)C

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    new-instance v2, Ls5/d;

    .line 209
    .line 210
    invoke-direct {v2, v5, v3}, Ls5/d;-><init>(C[F)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    :cond_e
    add-int/lit8 v2, v4, 0x1

    .line 217
    .line 218
    move v5, v4

    .line 219
    move v4, v2

    .line 220
    const/4 v2, 0x0

    .line 221
    goto/16 :goto_0

    .line 222
    .line 223
    :cond_f
    sub-int/2addr v4, v5

    .line 224
    const/4 v2, 0x1

    .line 225
    if-ne v4, v2, :cond_10

    .line 226
    .line 227
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 228
    .line 229
    .line 230
    move-result v2

    .line 231
    if-ge v5, v2, :cond_10

    .line 232
    .line 233
    invoke-virtual {v0, v5}, Ljava/lang/String;->charAt(I)C

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    const/4 v2, 0x0

    .line 238
    new-array v3, v2, [F

    .line 239
    .line 240
    new-instance v4, Ls5/d;

    .line 241
    .line 242
    invoke-direct {v4, v0, v3}, Ls5/d;-><init>(C[F)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    goto :goto_e

    .line 249
    :cond_10
    const/4 v2, 0x0

    .line 250
    :goto_e
    new-array v0, v2, [Ls5/d;

    .line 251
    .line 252
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    check-cast v0, [Ls5/d;

    .line 257
    .line 258
    return-object v0

    .line 259
    :pswitch_data_0
    .packed-switch 0x2c
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static d(Ljava/lang/String;)Landroid/graphics/Path;
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/Path;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lkp/c7;->c(Ljava/lang/String;)[Ls5/d;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    :try_start_0
    invoke-static {v1, v0}, Ls5/d;->b([Ls5/d;Landroid/graphics/Path;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    .line 13
    return-object v0

    .line 14
    :catch_0
    move-exception v0

    .line 15
    new-instance v1, Ljava/lang/RuntimeException;

    .line 16
    .line 17
    const-string v2, "Error in parsing "

    .line 18
    .line 19
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-direct {v1, p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    throw v1
.end method

.method public static e([Ls5/d;)[Ls5/d;
    .locals 4

    .line 1
    array-length v0, p0

    .line 2
    new-array v0, v0, [Ls5/d;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    array-length v2, p0

    .line 6
    if-ge v1, v2, :cond_0

    .line 7
    .line 8
    new-instance v2, Ls5/d;

    .line 9
    .line 10
    aget-object v3, p0, v1

    .line 11
    .line 12
    invoke-direct {v2, v3}, Ls5/d;-><init>(Ls5/d;)V

    .line 13
    .line 14
    .line 15
    aput-object v2, v0, v1

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    return-object v0
.end method
