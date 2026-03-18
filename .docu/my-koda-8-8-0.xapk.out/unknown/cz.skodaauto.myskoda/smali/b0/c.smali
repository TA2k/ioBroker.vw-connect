.class public abstract Lb0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Lm1/t;Lk1/z0;ZLg1/j1;ZLe1/j;Lx2/d;Lk1/i;Lx2/i;Lk1/g;Lay0/k;Ll2/o;III)V
    .locals 40

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    move/from16 v4, p3

    .line 8
    .line 9
    move/from16 v0, p5

    .line 10
    .line 11
    move-object/from16 v14, p11

    .line 12
    .line 13
    move/from16 v15, p13

    .line 14
    .line 15
    move/from16 v2, p14

    .line 16
    .line 17
    move/from16 v6, p15

    .line 18
    .line 19
    move-object/from16 v7, p12

    .line 20
    .line 21
    check-cast v7, Ll2/t;

    .line 22
    .line 23
    const v8, 0x37213af3

    .line 24
    .line 25
    .line 26
    invoke-virtual {v7, v8}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v8, v15, 0x6

    .line 30
    .line 31
    if-nez v8, :cond_1

    .line 32
    .line 33
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v8

    .line 37
    if-eqz v8, :cond_0

    .line 38
    .line 39
    const/4 v8, 0x4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v8, 0x2

    .line 42
    :goto_0
    or-int/2addr v8, v15

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v8, v15

    .line 45
    :goto_1
    and-int/lit8 v11, v15, 0x30

    .line 46
    .line 47
    if-nez v11, :cond_3

    .line 48
    .line 49
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v11

    .line 53
    if-eqz v11, :cond_2

    .line 54
    .line 55
    const/16 v11, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v11, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr v8, v11

    .line 61
    :cond_3
    and-int/lit16 v11, v15, 0x180

    .line 62
    .line 63
    const/16 v16, 0x80

    .line 64
    .line 65
    if-nez v11, :cond_5

    .line 66
    .line 67
    invoke-virtual {v7, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v11

    .line 71
    if-eqz v11, :cond_4

    .line 72
    .line 73
    const/16 v11, 0x100

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_4
    move/from16 v11, v16

    .line 77
    .line 78
    :goto_3
    or-int/2addr v8, v11

    .line 79
    :cond_5
    and-int/lit16 v11, v15, 0xc00

    .line 80
    .line 81
    const/4 v9, 0x0

    .line 82
    const/16 v18, 0x400

    .line 83
    .line 84
    if-nez v11, :cond_7

    .line 85
    .line 86
    invoke-virtual {v7, v9}, Ll2/t;->h(Z)Z

    .line 87
    .line 88
    .line 89
    move-result v11

    .line 90
    if-eqz v11, :cond_6

    .line 91
    .line 92
    const/16 v11, 0x800

    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_6
    move/from16 v11, v18

    .line 96
    .line 97
    :goto_4
    or-int/2addr v8, v11

    .line 98
    :cond_7
    and-int/lit16 v11, v15, 0x6000

    .line 99
    .line 100
    if-nez v11, :cond_9

    .line 101
    .line 102
    invoke-virtual {v7, v4}, Ll2/t;->h(Z)Z

    .line 103
    .line 104
    .line 105
    move-result v11

    .line 106
    if-eqz v11, :cond_8

    .line 107
    .line 108
    const/16 v11, 0x4000

    .line 109
    .line 110
    goto :goto_5

    .line 111
    :cond_8
    const/16 v11, 0x2000

    .line 112
    .line 113
    :goto_5
    or-int/2addr v8, v11

    .line 114
    :cond_9
    const/high16 v11, 0x30000

    .line 115
    .line 116
    and-int/2addr v11, v15

    .line 117
    if-nez v11, :cond_b

    .line 118
    .line 119
    move-object/from16 v11, p4

    .line 120
    .line 121
    invoke-virtual {v7, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v21

    .line 125
    if-eqz v21, :cond_a

    .line 126
    .line 127
    const/high16 v21, 0x20000

    .line 128
    .line 129
    goto :goto_6

    .line 130
    :cond_a
    const/high16 v21, 0x10000

    .line 131
    .line 132
    :goto_6
    or-int v8, v8, v21

    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_b
    move-object/from16 v11, p4

    .line 136
    .line 137
    :goto_7
    const/high16 v21, 0x180000

    .line 138
    .line 139
    and-int v22, v15, v21

    .line 140
    .line 141
    if-nez v22, :cond_d

    .line 142
    .line 143
    invoke-virtual {v7, v0}, Ll2/t;->h(Z)Z

    .line 144
    .line 145
    .line 146
    move-result v22

    .line 147
    if-eqz v22, :cond_c

    .line 148
    .line 149
    const/high16 v22, 0x100000

    .line 150
    .line 151
    goto :goto_8

    .line 152
    :cond_c
    const/high16 v22, 0x80000

    .line 153
    .line 154
    :goto_8
    or-int v8, v8, v22

    .line 155
    .line 156
    :cond_d
    const/high16 v22, 0xc00000

    .line 157
    .line 158
    and-int v23, v15, v22

    .line 159
    .line 160
    move-object/from16 v9, p6

    .line 161
    .line 162
    if-nez v23, :cond_f

    .line 163
    .line 164
    invoke-virtual {v7, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v24

    .line 168
    if-eqz v24, :cond_e

    .line 169
    .line 170
    const/high16 v24, 0x800000

    .line 171
    .line 172
    goto :goto_9

    .line 173
    :cond_e
    const/high16 v24, 0x400000

    .line 174
    .line 175
    :goto_9
    or-int v8, v8, v24

    .line 176
    .line 177
    :cond_f
    const/high16 v24, 0x6000000

    .line 178
    .line 179
    and-int v25, v15, v24

    .line 180
    .line 181
    if-nez v25, :cond_10

    .line 182
    .line 183
    const/high16 v25, 0x2000000

    .line 184
    .line 185
    or-int v8, v8, v25

    .line 186
    .line 187
    :cond_10
    and-int/lit16 v12, v6, 0x200

    .line 188
    .line 189
    const/high16 v26, 0x30000000

    .line 190
    .line 191
    if-eqz v12, :cond_11

    .line 192
    .line 193
    or-int v8, v8, v26

    .line 194
    .line 195
    move-object/from16 v13, p7

    .line 196
    .line 197
    goto :goto_b

    .line 198
    :cond_11
    and-int v27, v15, v26

    .line 199
    .line 200
    move-object/from16 v13, p7

    .line 201
    .line 202
    if-nez v27, :cond_13

    .line 203
    .line 204
    invoke-virtual {v7, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v28

    .line 208
    if-eqz v28, :cond_12

    .line 209
    .line 210
    const/high16 v28, 0x20000000

    .line 211
    .line 212
    goto :goto_a

    .line 213
    :cond_12
    const/high16 v28, 0x10000000

    .line 214
    .line 215
    :goto_a
    or-int v8, v8, v28

    .line 216
    .line 217
    :cond_13
    :goto_b
    and-int/lit16 v10, v6, 0x400

    .line 218
    .line 219
    if-eqz v10, :cond_14

    .line 220
    .line 221
    or-int/lit8 v29, v2, 0x6

    .line 222
    .line 223
    move-object/from16 v0, p8

    .line 224
    .line 225
    goto :goto_d

    .line 226
    :cond_14
    and-int/lit8 v29, v2, 0x6

    .line 227
    .line 228
    move-object/from16 v0, p8

    .line 229
    .line 230
    if-nez v29, :cond_16

    .line 231
    .line 232
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 233
    .line 234
    .line 235
    move-result v29

    .line 236
    if-eqz v29, :cond_15

    .line 237
    .line 238
    const/16 v29, 0x4

    .line 239
    .line 240
    goto :goto_c

    .line 241
    :cond_15
    const/16 v29, 0x2

    .line 242
    .line 243
    :goto_c
    or-int v29, v2, v29

    .line 244
    .line 245
    goto :goto_d

    .line 246
    :cond_16
    move/from16 v29, v2

    .line 247
    .line 248
    :goto_d
    and-int/lit16 v0, v6, 0x800

    .line 249
    .line 250
    if-eqz v0, :cond_17

    .line 251
    .line 252
    or-int/lit8 v29, v29, 0x30

    .line 253
    .line 254
    move/from16 v30, v0

    .line 255
    .line 256
    :goto_e
    move/from16 v0, v29

    .line 257
    .line 258
    goto :goto_10

    .line 259
    :cond_17
    and-int/lit8 v30, v2, 0x30

    .line 260
    .line 261
    if-nez v30, :cond_19

    .line 262
    .line 263
    move/from16 v30, v0

    .line 264
    .line 265
    move-object/from16 v0, p9

    .line 266
    .line 267
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 268
    .line 269
    .line 270
    move-result v31

    .line 271
    if-eqz v31, :cond_18

    .line 272
    .line 273
    const/16 v19, 0x20

    .line 274
    .line 275
    goto :goto_f

    .line 276
    :cond_18
    const/16 v19, 0x10

    .line 277
    .line 278
    :goto_f
    or-int v29, v29, v19

    .line 279
    .line 280
    goto :goto_e

    .line 281
    :cond_19
    move/from16 v30, v0

    .line 282
    .line 283
    move-object/from16 v0, p9

    .line 284
    .line 285
    goto :goto_e

    .line 286
    :goto_10
    move/from16 p12, v8

    .line 287
    .line 288
    and-int/lit16 v8, v6, 0x1000

    .line 289
    .line 290
    if-eqz v8, :cond_1a

    .line 291
    .line 292
    or-int/lit16 v0, v0, 0x180

    .line 293
    .line 294
    move/from16 v16, v0

    .line 295
    .line 296
    move-object/from16 v0, p10

    .line 297
    .line 298
    goto :goto_11

    .line 299
    :cond_1a
    move/from16 v19, v0

    .line 300
    .line 301
    and-int/lit16 v0, v2, 0x180

    .line 302
    .line 303
    if-nez v0, :cond_1c

    .line 304
    .line 305
    move-object/from16 v0, p10

    .line 306
    .line 307
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result v29

    .line 311
    if-eqz v29, :cond_1b

    .line 312
    .line 313
    const/16 v16, 0x100

    .line 314
    .line 315
    :cond_1b
    or-int v16, v19, v16

    .line 316
    .line 317
    goto :goto_11

    .line 318
    :cond_1c
    move-object/from16 v0, p10

    .line 319
    .line 320
    move/from16 v16, v19

    .line 321
    .line 322
    :goto_11
    and-int/lit16 v0, v2, 0xc00

    .line 323
    .line 324
    if-nez v0, :cond_1e

    .line 325
    .line 326
    invoke-virtual {v7, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v0

    .line 330
    if-eqz v0, :cond_1d

    .line 331
    .line 332
    const/16 v18, 0x800

    .line 333
    .line 334
    :cond_1d
    or-int v16, v16, v18

    .line 335
    .line 336
    :cond_1e
    move/from16 v0, v16

    .line 337
    .line 338
    const v16, 0x12492493

    .line 339
    .line 340
    .line 341
    and-int v2, p12, v16

    .line 342
    .line 343
    const v6, 0x12492492

    .line 344
    .line 345
    .line 346
    const/16 v16, 0x1

    .line 347
    .line 348
    if-ne v2, v6, :cond_20

    .line 349
    .line 350
    and-int/lit16 v2, v0, 0x493

    .line 351
    .line 352
    const/16 v6, 0x492

    .line 353
    .line 354
    if-eq v2, v6, :cond_1f

    .line 355
    .line 356
    goto :goto_12

    .line 357
    :cond_1f
    const/4 v2, 0x0

    .line 358
    goto :goto_13

    .line 359
    :cond_20
    :goto_12
    move/from16 v2, v16

    .line 360
    .line 361
    :goto_13
    and-int/lit8 v6, p12, 0x1

    .line 362
    .line 363
    invoke-virtual {v7, v6, v2}, Ll2/t;->O(IZ)Z

    .line 364
    .line 365
    .line 366
    move-result v2

    .line 367
    if-eqz v2, :cond_57

    .line 368
    .line 369
    invoke-virtual {v7}, Ll2/t;->T()V

    .line 370
    .line 371
    .line 372
    and-int/lit8 v2, p13, 0x1

    .line 373
    .line 374
    const v6, -0xe000001

    .line 375
    .line 376
    .line 377
    const/16 v18, 0x0

    .line 378
    .line 379
    if-eqz v2, :cond_22

    .line 380
    .line 381
    invoke-virtual {v7}, Ll2/t;->y()Z

    .line 382
    .line 383
    .line 384
    move-result v2

    .line 385
    if-eqz v2, :cond_21

    .line 386
    .line 387
    goto :goto_14

    .line 388
    :cond_21
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 389
    .line 390
    .line 391
    and-int v2, p12, v6

    .line 392
    .line 393
    move-object/from16 v6, p8

    .line 394
    .line 395
    move-object/from16 v8, p10

    .line 396
    .line 397
    move-object v12, v13

    .line 398
    move-object/from16 v13, p9

    .line 399
    .line 400
    goto :goto_18

    .line 401
    :cond_22
    :goto_14
    and-int v2, p12, v6

    .line 402
    .line 403
    if-eqz v12, :cond_23

    .line 404
    .line 405
    move-object/from16 v13, v18

    .line 406
    .line 407
    :cond_23
    if-eqz v10, :cond_24

    .line 408
    .line 409
    move-object/from16 v6, v18

    .line 410
    .line 411
    goto :goto_15

    .line 412
    :cond_24
    move-object/from16 v6, p8

    .line 413
    .line 414
    :goto_15
    if-eqz v30, :cond_25

    .line 415
    .line 416
    move-object/from16 v10, v18

    .line 417
    .line 418
    goto :goto_16

    .line 419
    :cond_25
    move-object/from16 v10, p9

    .line 420
    .line 421
    :goto_16
    if-eqz v8, :cond_26

    .line 422
    .line 423
    move-object v12, v13

    .line 424
    move-object/from16 v8, v18

    .line 425
    .line 426
    :goto_17
    move-object v13, v10

    .line 427
    goto :goto_18

    .line 428
    :cond_26
    move-object/from16 v8, p10

    .line 429
    .line 430
    move-object v12, v13

    .line 431
    goto :goto_17

    .line 432
    :goto_18
    invoke-virtual {v7}, Ll2/t;->r()V

    .line 433
    .line 434
    .line 435
    shr-int/lit8 v19, v2, 0x3

    .line 436
    .line 437
    and-int/lit8 v10, v19, 0xe

    .line 438
    .line 439
    shr-int/lit8 v29, v0, 0x6

    .line 440
    .line 441
    and-int/lit8 v29, v29, 0x70

    .line 442
    .line 443
    or-int v29, v10, v29

    .line 444
    .line 445
    invoke-static {v14, v7}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 446
    .line 447
    .line 448
    move-result-object v15

    .line 449
    and-int/lit8 v30, v29, 0xe

    .line 450
    .line 451
    move/from16 v31, v0

    .line 452
    .line 453
    xor-int/lit8 v0, v30, 0x6

    .line 454
    .line 455
    move/from16 p7, v2

    .line 456
    .line 457
    const/4 v2, 0x4

    .line 458
    if-le v0, v2, :cond_27

    .line 459
    .line 460
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    if-nez v0, :cond_28

    .line 465
    .line 466
    :cond_27
    and-int/lit8 v0, v29, 0x6

    .line 467
    .line 468
    if-ne v0, v2, :cond_29

    .line 469
    .line 470
    :cond_28
    move/from16 v0, v16

    .line 471
    .line 472
    goto :goto_19

    .line 473
    :cond_29
    const/4 v0, 0x0

    .line 474
    :goto_19
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 475
    .line 476
    .line 477
    move-result-object v2

    .line 478
    move/from16 p8, v0

    .line 479
    .line 480
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 481
    .line 482
    if-nez p8, :cond_2b

    .line 483
    .line 484
    if-ne v2, v0, :cond_2a

    .line 485
    .line 486
    goto :goto_1a

    .line 487
    :cond_2a
    move/from16 p8, v10

    .line 488
    .line 489
    goto :goto_1b

    .line 490
    :cond_2b
    :goto_1a
    new-instance v2, Landroidx/compose/foundation/lazy/a;

    .line 491
    .line 492
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 493
    .line 494
    .line 495
    new-instance v9, Ll2/g1;

    .line 496
    .line 497
    move/from16 p8, v10

    .line 498
    .line 499
    const v10, 0x7fffffff

    .line 500
    .line 501
    .line 502
    invoke-direct {v9, v10}, Ll2/g1;-><init>(I)V

    .line 503
    .line 504
    .line 505
    iput-object v9, v2, Landroidx/compose/foundation/lazy/a;->a:Ll2/g1;

    .line 506
    .line 507
    new-instance v9, Ll2/g1;

    .line 508
    .line 509
    invoke-direct {v9, v10}, Ll2/g1;-><init>(I)V

    .line 510
    .line 511
    .line 512
    iput-object v9, v2, Landroidx/compose/foundation/lazy/a;->b:Ll2/g1;

    .line 513
    .line 514
    sget-object v9, Ll2/x0;->g:Ll2/x0;

    .line 515
    .line 516
    new-instance v10, Lio0/f;

    .line 517
    .line 518
    const/4 v11, 0x2

    .line 519
    invoke-direct {v10, v15, v11}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 520
    .line 521
    .line 522
    invoke-static {v10, v9}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 523
    .line 524
    .line 525
    move-result-object v10

    .line 526
    new-instance v11, Lc41/b;

    .line 527
    .line 528
    const/16 v15, 0x11

    .line 529
    .line 530
    invoke-direct {v11, v10, v3, v2, v15}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 531
    .line 532
    .line 533
    invoke-static {v11, v9}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 534
    .line 535
    .line 536
    move-result-object v36

    .line 537
    new-instance v32, La90/r;

    .line 538
    .line 539
    const/16 v33, 0x0

    .line 540
    .line 541
    const/16 v34, 0x14

    .line 542
    .line 543
    const-class v35, Ll2/t2;

    .line 544
    .line 545
    const-string v37, "value"

    .line 546
    .line 547
    const-string v38, "getValue()Ljava/lang/Object;"

    .line 548
    .line 549
    invoke-direct/range {v32 .. v38}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 550
    .line 551
    .line 552
    move-object/from16 v2, v32

    .line 553
    .line 554
    invoke-virtual {v7, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 555
    .line 556
    .line 557
    :goto_1b
    check-cast v2, Lhy0/u;

    .line 558
    .line 559
    shr-int/lit8 v9, p7, 0x9

    .line 560
    .line 561
    and-int/lit8 v10, v9, 0x70

    .line 562
    .line 563
    or-int v10, p8, v10

    .line 564
    .line 565
    and-int/lit8 v11, v10, 0xe

    .line 566
    .line 567
    xor-int/lit8 v11, v11, 0x6

    .line 568
    .line 569
    const/4 v15, 0x4

    .line 570
    if-le v11, v15, :cond_2c

    .line 571
    .line 572
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 573
    .line 574
    .line 575
    move-result v11

    .line 576
    if-nez v11, :cond_2d

    .line 577
    .line 578
    :cond_2c
    and-int/lit8 v11, v10, 0x6

    .line 579
    .line 580
    if-ne v11, v15, :cond_2e

    .line 581
    .line 582
    :cond_2d
    move/from16 v11, v16

    .line 583
    .line 584
    goto :goto_1c

    .line 585
    :cond_2e
    const/4 v11, 0x0

    .line 586
    :goto_1c
    and-int/lit8 v28, v10, 0x70

    .line 587
    .line 588
    xor-int/lit8 v15, v28, 0x30

    .line 589
    .line 590
    move-object/from16 p8, v2

    .line 591
    .line 592
    const/16 v2, 0x20

    .line 593
    .line 594
    if-le v15, v2, :cond_2f

    .line 595
    .line 596
    invoke-virtual {v7, v4}, Ll2/t;->h(Z)Z

    .line 597
    .line 598
    .line 599
    move-result v15

    .line 600
    if-nez v15, :cond_30

    .line 601
    .line 602
    :cond_2f
    and-int/lit8 v10, v10, 0x30

    .line 603
    .line 604
    if-ne v10, v2, :cond_31

    .line 605
    .line 606
    :cond_30
    move/from16 v2, v16

    .line 607
    .line 608
    goto :goto_1d

    .line 609
    :cond_31
    const/4 v2, 0x0

    .line 610
    :goto_1d
    or-int/2addr v2, v11

    .line 611
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v10

    .line 615
    if-nez v2, :cond_32

    .line 616
    .line 617
    if-ne v10, v0, :cond_33

    .line 618
    .line 619
    :cond_32
    new-instance v10, Lm1/b;

    .line 620
    .line 621
    const/4 v2, 0x0

    .line 622
    invoke-direct {v10, v3, v4, v2}, Lm1/b;-><init>(Lg1/q2;ZI)V

    .line 623
    .line 624
    .line 625
    invoke-virtual {v7, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 626
    .line 627
    .line 628
    :cond_33
    move-object v15, v10

    .line 629
    check-cast v15, Lo1/r0;

    .line 630
    .line 631
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 632
    .line 633
    .line 634
    move-result-object v2

    .line 635
    if-ne v2, v0, :cond_34

    .line 636
    .line 637
    invoke-static {v7}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 638
    .line 639
    .line 640
    move-result-object v2

    .line 641
    invoke-virtual {v7, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 642
    .line 643
    .line 644
    :cond_34
    check-cast v2, Lvy0/b0;

    .line 645
    .line 646
    sget-object v10, Lw3/h1;->g:Ll2/u2;

    .line 647
    .line 648
    invoke-virtual {v7, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 649
    .line 650
    .line 651
    move-result-object v10

    .line 652
    check-cast v10, Le3/w;

    .line 653
    .line 654
    sget-object v11, Lw3/h1;->v:Ll2/e0;

    .line 655
    .line 656
    invoke-virtual {v7, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 657
    .line 658
    .line 659
    move-result-object v11

    .line 660
    check-cast v11, Ljava/lang/Boolean;

    .line 661
    .line 662
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 663
    .line 664
    .line 665
    move-result v11

    .line 666
    if-nez v11, :cond_35

    .line 667
    .line 668
    sget-object v18, Lo1/d1;->a:Lo1/f0;

    .line 669
    .line 670
    :cond_35
    move-object/from16 v11, v18

    .line 671
    .line 672
    const v18, 0xfff0

    .line 673
    .line 674
    .line 675
    and-int v18, p7, v18

    .line 676
    .line 677
    const/high16 v28, 0x380000

    .line 678
    .line 679
    and-int v9, v9, v28

    .line 680
    .line 681
    or-int v9, v18, v9

    .line 682
    .line 683
    shl-int/lit8 v18, v31, 0x12

    .line 684
    .line 685
    const/high16 v30, 0x1c00000

    .line 686
    .line 687
    and-int v32, v18, v30

    .line 688
    .line 689
    or-int v9, v9, v32

    .line 690
    .line 691
    const/high16 v32, 0xe000000

    .line 692
    .line 693
    and-int v18, v18, v32

    .line 694
    .line 695
    or-int v9, v9, v18

    .line 696
    .line 697
    shl-int/lit8 v18, v31, 0x1b

    .line 698
    .line 699
    const/high16 v31, 0x70000000

    .line 700
    .line 701
    and-int v18, v18, v31

    .line 702
    .line 703
    or-int v9, v9, v18

    .line 704
    .line 705
    and-int/lit8 v18, v9, 0x70

    .line 706
    .line 707
    move-object/from16 p7, v2

    .line 708
    .line 709
    xor-int/lit8 v2, v18, 0x30

    .line 710
    .line 711
    const/16 v14, 0x20

    .line 712
    .line 713
    if-le v2, v14, :cond_36

    .line 714
    .line 715
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 716
    .line 717
    .line 718
    move-result v2

    .line 719
    if-nez v2, :cond_37

    .line 720
    .line 721
    :cond_36
    and-int/lit8 v2, v9, 0x30

    .line 722
    .line 723
    if-ne v2, v14, :cond_38

    .line 724
    .line 725
    :cond_37
    move/from16 v2, v16

    .line 726
    .line 727
    goto :goto_1e

    .line 728
    :cond_38
    const/4 v2, 0x0

    .line 729
    :goto_1e
    and-int/lit16 v14, v9, 0x380

    .line 730
    .line 731
    xor-int/lit16 v14, v14, 0x180

    .line 732
    .line 733
    move/from16 p9, v2

    .line 734
    .line 735
    const/16 v2, 0x100

    .line 736
    .line 737
    if-le v14, v2, :cond_39

    .line 738
    .line 739
    invoke-virtual {v7, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 740
    .line 741
    .line 742
    move-result v14

    .line 743
    if-nez v14, :cond_3a

    .line 744
    .line 745
    :cond_39
    and-int/lit16 v14, v9, 0x180

    .line 746
    .line 747
    if-ne v14, v2, :cond_3b

    .line 748
    .line 749
    :cond_3a
    move/from16 v2, v16

    .line 750
    .line 751
    goto :goto_1f

    .line 752
    :cond_3b
    const/4 v2, 0x0

    .line 753
    :goto_1f
    or-int v2, p9, v2

    .line 754
    .line 755
    and-int/lit16 v14, v9, 0x1c00

    .line 756
    .line 757
    xor-int/lit16 v14, v14, 0xc00

    .line 758
    .line 759
    move/from16 p9, v2

    .line 760
    .line 761
    const/16 v2, 0x800

    .line 762
    .line 763
    if-le v14, v2, :cond_3c

    .line 764
    .line 765
    const/4 v14, 0x0

    .line 766
    invoke-virtual {v7, v14}, Ll2/t;->h(Z)Z

    .line 767
    .line 768
    .line 769
    move-result v17

    .line 770
    if-nez v17, :cond_3d

    .line 771
    .line 772
    goto :goto_20

    .line 773
    :cond_3c
    const/4 v14, 0x0

    .line 774
    :goto_20
    and-int/lit16 v14, v9, 0xc00

    .line 775
    .line 776
    if-ne v14, v2, :cond_3e

    .line 777
    .line 778
    :cond_3d
    move/from16 v2, v16

    .line 779
    .line 780
    goto :goto_21

    .line 781
    :cond_3e
    const/4 v2, 0x0

    .line 782
    :goto_21
    or-int v2, p9, v2

    .line 783
    .line 784
    const v14, 0xe000

    .line 785
    .line 786
    .line 787
    and-int/2addr v14, v9

    .line 788
    xor-int/lit16 v14, v14, 0x6000

    .line 789
    .line 790
    move/from16 p9, v2

    .line 791
    .line 792
    const/16 v2, 0x4000

    .line 793
    .line 794
    if-le v14, v2, :cond_3f

    .line 795
    .line 796
    invoke-virtual {v7, v4}, Ll2/t;->h(Z)Z

    .line 797
    .line 798
    .line 799
    move-result v14

    .line 800
    if-nez v14, :cond_40

    .line 801
    .line 802
    :cond_3f
    and-int/lit16 v14, v9, 0x6000

    .line 803
    .line 804
    if-ne v14, v2, :cond_41

    .line 805
    .line 806
    :cond_40
    move/from16 v2, v16

    .line 807
    .line 808
    goto :goto_22

    .line 809
    :cond_41
    const/4 v2, 0x0

    .line 810
    :goto_22
    or-int v2, p9, v2

    .line 811
    .line 812
    const/4 v14, 0x0

    .line 813
    invoke-virtual {v7, v14}, Ll2/t;->e(I)Z

    .line 814
    .line 815
    .line 816
    move-result v17

    .line 817
    or-int v2, v2, v17

    .line 818
    .line 819
    and-int v14, v9, v28

    .line 820
    .line 821
    xor-int v14, v14, v21

    .line 822
    .line 823
    move/from16 p9, v2

    .line 824
    .line 825
    const/high16 v2, 0x100000

    .line 826
    .line 827
    if-le v14, v2, :cond_42

    .line 828
    .line 829
    invoke-virtual {v7, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 830
    .line 831
    .line 832
    move-result v14

    .line 833
    if-nez v14, :cond_43

    .line 834
    .line 835
    :cond_42
    and-int v14, v9, v21

    .line 836
    .line 837
    if-ne v14, v2, :cond_44

    .line 838
    .line 839
    :cond_43
    move/from16 v2, v16

    .line 840
    .line 841
    goto :goto_23

    .line 842
    :cond_44
    const/4 v2, 0x0

    .line 843
    :goto_23
    or-int v2, p9, v2

    .line 844
    .line 845
    and-int v14, v9, v30

    .line 846
    .line 847
    xor-int v14, v14, v22

    .line 848
    .line 849
    move/from16 p9, v2

    .line 850
    .line 851
    const/high16 v2, 0x800000

    .line 852
    .line 853
    if-le v14, v2, :cond_45

    .line 854
    .line 855
    invoke-virtual {v7, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 856
    .line 857
    .line 858
    move-result v14

    .line 859
    if-nez v14, :cond_46

    .line 860
    .line 861
    :cond_45
    and-int v14, v9, v22

    .line 862
    .line 863
    if-ne v14, v2, :cond_47

    .line 864
    .line 865
    :cond_46
    move/from16 v2, v16

    .line 866
    .line 867
    goto :goto_24

    .line 868
    :cond_47
    const/4 v2, 0x0

    .line 869
    :goto_24
    or-int v2, p9, v2

    .line 870
    .line 871
    and-int v14, v9, v32

    .line 872
    .line 873
    xor-int v14, v14, v24

    .line 874
    .line 875
    move/from16 p9, v2

    .line 876
    .line 877
    const/high16 v2, 0x4000000

    .line 878
    .line 879
    if-le v14, v2, :cond_48

    .line 880
    .line 881
    invoke-virtual {v7, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 882
    .line 883
    .line 884
    move-result v14

    .line 885
    if-nez v14, :cond_49

    .line 886
    .line 887
    :cond_48
    and-int v14, v9, v24

    .line 888
    .line 889
    if-ne v14, v2, :cond_4a

    .line 890
    .line 891
    :cond_49
    move/from16 v2, v16

    .line 892
    .line 893
    goto :goto_25

    .line 894
    :cond_4a
    const/4 v2, 0x0

    .line 895
    :goto_25
    or-int v2, p9, v2

    .line 896
    .line 897
    and-int v14, v9, v31

    .line 898
    .line 899
    xor-int v14, v14, v26

    .line 900
    .line 901
    move/from16 p9, v2

    .line 902
    .line 903
    const/high16 v2, 0x20000000

    .line 904
    .line 905
    if-le v14, v2, :cond_4b

    .line 906
    .line 907
    invoke-virtual {v7, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 908
    .line 909
    .line 910
    move-result v14

    .line 911
    if-nez v14, :cond_4c

    .line 912
    .line 913
    :cond_4b
    and-int v9, v9, v26

    .line 914
    .line 915
    if-ne v9, v2, :cond_4d

    .line 916
    .line 917
    :cond_4c
    move/from16 v2, v16

    .line 918
    .line 919
    goto :goto_26

    .line 920
    :cond_4d
    const/4 v2, 0x0

    .line 921
    :goto_26
    or-int v2, p9, v2

    .line 922
    .line 923
    invoke-virtual {v7, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 924
    .line 925
    .line 926
    move-result v9

    .line 927
    or-int/2addr v2, v9

    .line 928
    invoke-virtual {v7, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 929
    .line 930
    .line 931
    move-result v9

    .line 932
    or-int/2addr v2, v9

    .line 933
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 934
    .line 935
    .line 936
    move-result-object v9

    .line 937
    if-nez v2, :cond_4f

    .line 938
    .line 939
    if-ne v9, v0, :cond_4e

    .line 940
    .line 941
    goto :goto_27

    .line 942
    :cond_4e
    move-object/from16 v17, v6

    .line 943
    .line 944
    move-object v14, v7

    .line 945
    move-object/from16 v18, v8

    .line 946
    .line 947
    move-object/from16 p7, v15

    .line 948
    .line 949
    const/4 v15, 0x4

    .line 950
    move-object v8, v3

    .line 951
    move-object/from16 v3, p8

    .line 952
    .line 953
    goto :goto_28

    .line 954
    :cond_4f
    :goto_27
    new-instance v2, Lm1/j;

    .line 955
    .line 956
    move-object/from16 v9, p7

    .line 957
    .line 958
    move-object v14, v7

    .line 959
    move-object/from16 p7, v15

    .line 960
    .line 961
    const/4 v15, 0x4

    .line 962
    move-object v7, v6

    .line 963
    move-object/from16 v6, p8

    .line 964
    .line 965
    invoke-direct/range {v2 .. v13}, Lm1/j;-><init>(Lm1/t;ZLk1/z0;Lhy0/u;Lk1/i;Lk1/g;Lvy0/b0;Le3/w;Lo1/f0;Lx2/d;Lx2/i;)V

    .line 966
    .line 967
    .line 968
    move-object/from16 v17, v7

    .line 969
    .line 970
    move-object/from16 v18, v8

    .line 971
    .line 972
    move-object v8, v3

    .line 973
    move-object v3, v6

    .line 974
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 975
    .line 976
    .line 977
    move-object v9, v2

    .line 978
    :goto_28
    move-object/from16 v21, v9

    .line 979
    .line 980
    check-cast v21, Lo1/c0;

    .line 981
    .line 982
    if-eqz p3, :cond_50

    .line 983
    .line 984
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 985
    .line 986
    :goto_29
    move-object v4, v2

    .line 987
    goto :goto_2a

    .line 988
    :cond_50
    sget-object v2, Lg1/w1;->e:Lg1/w1;

    .line 989
    .line 990
    goto :goto_29

    .line 991
    :goto_2a
    if-eqz p5, :cond_56

    .line 992
    .line 993
    const v2, -0x7bcdd0a8

    .line 994
    .line 995
    .line 996
    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 997
    .line 998
    .line 999
    and-int/lit8 v2, v19, 0xe

    .line 1000
    .line 1001
    xor-int/lit8 v2, v2, 0x6

    .line 1002
    .line 1003
    if-le v2, v15, :cond_51

    .line 1004
    .line 1005
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1006
    .line 1007
    .line 1008
    move-result v2

    .line 1009
    if-nez v2, :cond_52

    .line 1010
    .line 1011
    :cond_51
    and-int/lit8 v2, v19, 0x6

    .line 1012
    .line 1013
    if-ne v2, v15, :cond_53

    .line 1014
    .line 1015
    :cond_52
    :goto_2b
    const/4 v2, 0x0

    .line 1016
    goto :goto_2c

    .line 1017
    :cond_53
    const/16 v16, 0x0

    .line 1018
    .line 1019
    goto :goto_2b

    .line 1020
    :goto_2c
    invoke-virtual {v14, v2}, Ll2/t;->e(I)Z

    .line 1021
    .line 1022
    .line 1023
    move-result v5

    .line 1024
    or-int v2, v16, v5

    .line 1025
    .line 1026
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v5

    .line 1030
    if-nez v2, :cond_54

    .line 1031
    .line 1032
    if-ne v5, v0, :cond_55

    .line 1033
    .line 1034
    :cond_54
    new-instance v5, Lm1/c;

    .line 1035
    .line 1036
    invoke-direct {v5, v8}, Lm1/c;-><init>(Lm1/t;)V

    .line 1037
    .line 1038
    .line 1039
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1040
    .line 1041
    .line 1042
    :cond_55
    check-cast v5, Lm1/c;

    .line 1043
    .line 1044
    iget-object v0, v8, Lm1/t;->o:Lg1/r;

    .line 1045
    .line 1046
    const/4 v6, 0x0

    .line 1047
    invoke-static {v5, v0, v6, v4}, Landroidx/compose/foundation/lazy/layout/a;->a(Lo1/o;Lg1/r;ZLg1/w1;)Lx2/s;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v0

    .line 1051
    const/4 v2, 0x0

    .line 1052
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 1053
    .line 1054
    .line 1055
    goto :goto_2d

    .line 1056
    :cond_56
    const/4 v2, 0x0

    .line 1057
    const/4 v6, 0x0

    .line 1058
    const v0, -0x7bc74591

    .line 1059
    .line 1060
    .line 1061
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 1062
    .line 1063
    .line 1064
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 1065
    .line 1066
    .line 1067
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 1068
    .line 1069
    :goto_2d
    iget-object v2, v8, Lm1/t;->l:Lm1/r;

    .line 1070
    .line 1071
    invoke-interface {v1, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v2

    .line 1075
    iget-object v5, v8, Lm1/t;->m:Lo1/d;

    .line 1076
    .line 1077
    invoke-interface {v2, v5}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 1078
    .line 1079
    .line 1080
    move-result-object v2

    .line 1081
    move-object v5, v4

    .line 1082
    move v7, v6

    .line 1083
    move/from16 v6, p5

    .line 1084
    .line 1085
    move-object/from16 v4, p7

    .line 1086
    .line 1087
    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/lazy/layout/a;->b(Lx2/s;Lhy0/u;Lo1/r0;Lg1/w1;ZZ)Lx2/s;

    .line 1088
    .line 1089
    .line 1090
    move-result-object v2

    .line 1091
    move-object v15, v3

    .line 1092
    move-object v4, v5

    .line 1093
    move/from16 v20, v7

    .line 1094
    .line 1095
    invoke-interface {v2, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v0

    .line 1099
    iget-object v2, v8, Lm1/t;->n:Landroidx/compose/foundation/lazy/layout/b;

    .line 1100
    .line 1101
    iget-object v2, v2, Landroidx/compose/foundation/lazy/layout/b;->k:Lx2/s;

    .line 1102
    .line 1103
    invoke-interface {v0, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 1104
    .line 1105
    .line 1106
    move-result-object v2

    .line 1107
    move-object v3, v8

    .line 1108
    iget-object v8, v3, Lm1/t;->g:Li1/l;

    .line 1109
    .line 1110
    const/4 v9, 0x0

    .line 1111
    const/4 v11, 0x0

    .line 1112
    move-object/from16 v7, p4

    .line 1113
    .line 1114
    move/from16 v5, p5

    .line 1115
    .line 1116
    move-object/from16 v10, p6

    .line 1117
    .line 1118
    move/from16 v6, v20

    .line 1119
    .line 1120
    invoke-static/range {v2 .. v11}, Landroidx/compose/foundation/a;->l(Lx2/s;Lg1/q2;Lg1/w1;ZZLg1/j1;Li1/l;ZLe1/j;Lp1/h;)Lx2/s;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v0

    .line 1124
    move-object v8, v3

    .line 1125
    iget-object v4, v8, Lm1/t;->p:Lo1/l0;

    .line 1126
    .line 1127
    const/4 v7, 0x0

    .line 1128
    move-object v3, v0

    .line 1129
    move-object v6, v14

    .line 1130
    move-object v2, v15

    .line 1131
    move-object/from16 v5, v21

    .line 1132
    .line 1133
    invoke-static/range {v2 .. v7}, Lo1/y;->a(Lay0/a;Lx2/s;Lo1/l0;Lo1/c0;Ll2/o;I)V

    .line 1134
    .line 1135
    .line 1136
    move-object v10, v13

    .line 1137
    move-object/from16 v9, v17

    .line 1138
    .line 1139
    move-object/from16 v11, v18

    .line 1140
    .line 1141
    goto :goto_2e

    .line 1142
    :cond_57
    move-object v8, v3

    .line 1143
    move-object v6, v7

    .line 1144
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 1145
    .line 1146
    .line 1147
    move-object/from16 v9, p8

    .line 1148
    .line 1149
    move-object/from16 v10, p9

    .line 1150
    .line 1151
    move-object/from16 v11, p10

    .line 1152
    .line 1153
    move-object v12, v13

    .line 1154
    :goto_2e
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v0

    .line 1158
    if-eqz v0, :cond_58

    .line 1159
    .line 1160
    move-object v2, v0

    .line 1161
    new-instance v0, Lco0/e;

    .line 1162
    .line 1163
    move-object/from16 v3, p2

    .line 1164
    .line 1165
    move/from16 v4, p3

    .line 1166
    .line 1167
    move-object/from16 v5, p4

    .line 1168
    .line 1169
    move/from16 v6, p5

    .line 1170
    .line 1171
    move-object/from16 v7, p6

    .line 1172
    .line 1173
    move/from16 v13, p13

    .line 1174
    .line 1175
    move/from16 v14, p14

    .line 1176
    .line 1177
    move/from16 v15, p15

    .line 1178
    .line 1179
    move-object/from16 v39, v2

    .line 1180
    .line 1181
    move-object v2, v8

    .line 1182
    move-object v8, v12

    .line 1183
    move-object/from16 v12, p11

    .line 1184
    .line 1185
    invoke-direct/range {v0 .. v15}, Lco0/e;-><init>(Lx2/s;Lm1/t;Lk1/z0;ZLg1/j1;ZLe1/j;Lx2/d;Lk1/i;Lx2/i;Lk1/g;Lay0/k;III)V

    .line 1186
    .line 1187
    .line 1188
    move-object/from16 v2, v39

    .line 1189
    .line 1190
    iput-object v0, v2, Ll2/u1;->d:Lay0/n;

    .line 1191
    .line 1192
    :cond_58
    return-void
.end method

.method public static final b(Lx2/s;Ll2/s1;Lt2/b;Ll2/o;I)V
    .locals 5

    .line 1
    sget-object v0, Ly1/h;->a:Lt2/b;

    .line 2
    .line 3
    check-cast p3, Ll2/t;

    .line 4
    .line 5
    const v1, -0x2a95dc91

    .line 6
    .line 7
    .line 8
    invoke-virtual {p3, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    and-int/lit8 v1, p4, 0x6

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v1, 0x2

    .line 24
    :goto_0
    or-int/2addr v1, p4

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move v1, p4

    .line 27
    :goto_1
    and-int/lit8 v2, p4, 0x30

    .line 28
    .line 29
    if-nez v2, :cond_3

    .line 30
    .line 31
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    const/16 v2, 0x20

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    const/16 v2, 0x10

    .line 41
    .line 42
    :goto_2
    or-int/2addr v1, v2

    .line 43
    :cond_3
    and-int/lit16 v2, p4, 0x180

    .line 44
    .line 45
    if-nez v2, :cond_5

    .line 46
    .line 47
    invoke-virtual {p3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-eqz v2, :cond_4

    .line 52
    .line 53
    const/16 v2, 0x100

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_4
    const/16 v2, 0x80

    .line 57
    .line 58
    :goto_3
    or-int/2addr v1, v2

    .line 59
    :cond_5
    and-int/lit16 v2, p4, 0xc00

    .line 60
    .line 61
    if-nez v2, :cond_7

    .line 62
    .line 63
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-eqz v2, :cond_6

    .line 68
    .line 69
    const/16 v2, 0x800

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_6
    const/16 v2, 0x400

    .line 73
    .line 74
    :goto_4
    or-int/2addr v1, v2

    .line 75
    :cond_7
    and-int/lit16 v2, v1, 0x493

    .line 76
    .line 77
    const/16 v3, 0x492

    .line 78
    .line 79
    if-eq v2, v3, :cond_8

    .line 80
    .line 81
    const/4 v2, 0x1

    .line 82
    goto :goto_5

    .line 83
    :cond_8
    const/4 v2, 0x0

    .line 84
    :goto_5
    and-int/lit8 v3, v1, 0x1

    .line 85
    .line 86
    invoke-virtual {p3, v3, v2}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-eqz v2, :cond_a

    .line 91
    .line 92
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 97
    .line 98
    if-ne v2, v3, :cond_9

    .line 99
    .line 100
    sget-object v2, Ll2/x0;->f:Ll2/x0;

    .line 101
    .line 102
    new-instance v3, Ll2/j1;

    .line 103
    .line 104
    const/4 v4, 0x0

    .line 105
    invoke-direct {v3, v4, v2}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p3, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    move-object v2, v3

    .line 112
    :cond_9
    check-cast v2, Ll2/b1;

    .line 113
    .line 114
    shr-int/lit8 v1, v1, 0x6

    .line 115
    .line 116
    and-int/lit8 v1, v1, 0xe

    .line 117
    .line 118
    invoke-static {v0, p3, v1}, Lb0/c;->c(Lt2/b;Ll2/o;I)La2/d;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-virtual {p1, v0}, Ll2/s1;->a(Ljava/lang/Object;)Ll2/t1;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    new-instance v3, La2/i;

    .line 127
    .line 128
    invoke-direct {v3, p0, v2, p2, v0}, La2/i;-><init>(Lx2/s;Ll2/b1;Lt2/b;La2/d;)V

    .line 129
    .line 130
    .line 131
    const v0, 0x1059082f

    .line 132
    .line 133
    .line 134
    invoke-static {v0, p3, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    const/16 v2, 0x38

    .line 139
    .line 140
    invoke-static {v1, v0, p3, v2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 141
    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_a
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 145
    .line 146
    .line 147
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 148
    .line 149
    .line 150
    move-result-object p3

    .line 151
    if-eqz p3, :cond_b

    .line 152
    .line 153
    new-instance v0, La2/f;

    .line 154
    .line 155
    invoke-direct {v0, p0, p1, p2, p4}, La2/f;-><init>(Lx2/s;Ll2/s1;Lt2/b;I)V

    .line 156
    .line 157
    .line 158
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 159
    .line 160
    :cond_b
    return-void
.end method

.method public static final c(Lt2/b;Ll2/o;I)La2/d;
    .locals 2

    .line 1
    and-int/lit8 v0, p2, 0xe

    .line 2
    .line 3
    xor-int/lit8 v0, v0, 0x6

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    if-le v0, v1, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    :cond_0
    and-int/lit8 p2, p2, 0x6

    .line 18
    .line 19
    if-ne p2, v1, :cond_2

    .line 20
    .line 21
    :cond_1
    const/4 p2, 0x1

    .line 22
    goto :goto_0

    .line 23
    :cond_2
    const/4 p2, 0x0

    .line 24
    :goto_0
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 31
    .line 32
    if-nez p2, :cond_3

    .line 33
    .line 34
    if-ne v0, v1, :cond_4

    .line 35
    .line 36
    :cond_3
    new-instance v0, La2/d;

    .line 37
    .line 38
    invoke-direct {v0, p0}, La2/d;-><init>(Lt2/b;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    :cond_4
    check-cast v0, La2/d;

    .line 45
    .line 46
    invoke-virtual {p1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    if-ne p2, v1, :cond_6

    .line 57
    .line 58
    :cond_5
    new-instance p2, La2/e;

    .line 59
    .line 60
    const/4 p0, 0x0

    .line 61
    invoke-direct {p2, v0, p0}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_6
    check-cast p2, Lay0/k;

    .line 68
    .line 69
    invoke-static {v0, p2, p1}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 70
    .line 71
    .line 72
    return-object v0
.end method

.method public static final d(Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;)Lbl0/a;
    .locals 8

    .line 1
    new-instance v0, Lbl0/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getStreet()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getHouseNumber()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getZipCode()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getCity()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getCountry()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getFormattedAddress()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getCountryCode()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    invoke-direct/range {v0 .. v7}, Lbl0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public static final e(Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Lbl0/m;)Ljava/util/List;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;->getParkingAreas()Ljava/util/List;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    if-eqz p0, :cond_8

    .line 7
    .line 8
    check-cast p0, Ljava/lang/Iterable;

    .line 9
    .line 10
    new-instance v1, Ljava/util/ArrayList;

    .line 11
    .line 12
    const/16 v2, 0xa

    .line 13
    .line 14
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_9

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Lcz/myskoda/api/bff_maps/v3/ParkingAreaDto;

    .line 36
    .line 37
    invoke-virtual {v3}, Lcz/myskoda/api/bff_maps/v3/ParkingAreaDto;->getType()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    if-eqz v4, :cond_7

    .line 42
    .line 43
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    const v6, 0x49b6570

    .line 48
    .line 49
    .line 50
    if-eq v5, v6, :cond_5

    .line 51
    .line 52
    const v6, 0x4b86ed1a    # 1.7685044E7f

    .line 53
    .line 54
    .line 55
    if-eq v5, v6, :cond_2

    .line 56
    .line 57
    const v6, 0x6bb01145

    .line 58
    .line 59
    .line 60
    if-ne v5, v6, :cond_7

    .line 61
    .line 62
    const-string v5, "LineString"

    .line 63
    .line 64
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    if-eqz v4, :cond_7

    .line 69
    .line 70
    invoke-virtual {v3}, Lcz/myskoda/api/bff_maps/v3/ParkingAreaDto;->getCoordinates()Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    if-eqz v3, :cond_1

    .line 75
    .line 76
    check-cast v3, Ljava/lang/Iterable;

    .line 77
    .line 78
    new-instance v4, Ljava/util/ArrayList;

    .line 79
    .line 80
    invoke-static {v3, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 85
    .line 86
    .line 87
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    if-eqz v5, :cond_0

    .line 96
    .line 97
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    check-cast v5, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 102
    .line 103
    invoke-static {v5}, Lb0/c;->f(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)Lxj0/f;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :catchall_0
    move-exception p0

    .line 112
    goto/16 :goto_4

    .line 113
    .line 114
    :cond_0
    new-instance v3, Lbl0/y;

    .line 115
    .line 116
    invoke-direct {v3, v4, p1}, Lbl0/y;-><init>(Ljava/util/ArrayList;Lbl0/m;)V

    .line 117
    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 121
    .line 122
    const-string p1, "missing line string coordinates"

    .line 123
    .line 124
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_2
    const-string v5, "Polygon"

    .line 129
    .line 130
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v4

    .line 134
    if-eqz v4, :cond_7

    .line 135
    .line 136
    invoke-virtual {v3}, Lcz/myskoda/api/bff_maps/v3/ParkingAreaDto;->getCoordinates()Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    if-eqz v3, :cond_4

    .line 141
    .line 142
    check-cast v3, Ljava/lang/Iterable;

    .line 143
    .line 144
    new-instance v4, Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-static {v3, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 147
    .line 148
    .line 149
    move-result v5

    .line 150
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 151
    .line 152
    .line 153
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 154
    .line 155
    .line 156
    move-result-object v3

    .line 157
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    if-eqz v5, :cond_3

    .line 162
    .line 163
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    check-cast v5, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 168
    .line 169
    invoke-static {v5}, Lb0/c;->f(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)Lxj0/f;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_3
    new-instance v3, Lbl0/a0;

    .line 178
    .line 179
    invoke-direct {v3, v4, p1}, Lbl0/a0;-><init>(Ljava/util/ArrayList;Lbl0/m;)V

    .line 180
    .line 181
    .line 182
    goto :goto_3

    .line 183
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 184
    .line 185
    const-string p1, "missing polygon coordinates"

    .line 186
    .line 187
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    throw p0

    .line 191
    :cond_5
    const-string v5, "Point"

    .line 192
    .line 193
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    if-eqz v4, :cond_7

    .line 198
    .line 199
    new-instance v4, Lbl0/z;

    .line 200
    .line 201
    invoke-virtual {v3}, Lcz/myskoda/api/bff_maps/v3/ParkingAreaDto;->getCoordinates()Ljava/util/List;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    if-eqz v3, :cond_6

    .line 206
    .line 207
    invoke-static {v3}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    check-cast v3, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 212
    .line 213
    if-eqz v3, :cond_6

    .line 214
    .line 215
    invoke-static {v3}, Lb0/c;->f(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)Lxj0/f;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    invoke-direct {v4, v3}, Lbl0/z;-><init>(Lxj0/f;)V

    .line 220
    .line 221
    .line 222
    move-object v3, v4

    .line 223
    :goto_3
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    goto/16 :goto_0

    .line 227
    .line 228
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 229
    .line 230
    const-string p1, "missing point coordinates"

    .line 231
    .line 232
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    throw p0

    .line 236
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 237
    .line 238
    invoke-virtual {v3}, Lcz/myskoda/api/bff_maps/v3/ParkingAreaDto;->getType()Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    new-instance v1, Ljava/lang/StringBuilder;

    .line 243
    .line 244
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 245
    .line 246
    .line 247
    const-string v2, "Unsupported Geometry type "

    .line 248
    .line 249
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object p1

    .line 259
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object p1

    .line 263
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 267
    :cond_8
    move-object v1, v0

    .line 268
    goto :goto_5

    .line 269
    :goto_4
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 270
    .line 271
    .line 272
    move-result-object v1

    .line 273
    :cond_9
    :goto_5
    instance-of p0, v1, Llx0/n;

    .line 274
    .line 275
    if-eqz p0, :cond_a

    .line 276
    .line 277
    goto :goto_6

    .line 278
    :cond_a
    move-object v0, v1

    .line 279
    :goto_6
    check-cast v0, Ljava/util/List;

    .line 280
    .line 281
    return-object v0
.end method

.method public static final f(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)Lxj0/f;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lxj0/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;->getLatitude()D

    .line 9
    .line 10
    .line 11
    move-result-wide v1

    .line 12
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;->getLongitude()D

    .line 13
    .line 14
    .line 15
    move-result-wide v3

    .line 16
    invoke-direct {v0, v1, v2, v3, v4}, Lxj0/f;-><init>(DD)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public static final g(Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;Z)Lbl0/c0;
    .locals 10

    .line 1
    new-instance v0, Lbl0/c0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getId()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getAddress()Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    const/4 v4, 0x0

    .line 16
    if-eqz v3, :cond_0

    .line 17
    .line 18
    invoke-static {v3}, Lb0/c;->d(Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;)Lbl0/a;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move-object v3, v4

    .line 24
    :goto_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getAddress()Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    if-eqz v5, :cond_1

    .line 29
    .line 30
    invoke-virtual {v5}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getFormattedAddress()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move-object v5, v4

    .line 36
    :goto_1
    if-nez v5, :cond_2

    .line 37
    .line 38
    const-string v5, ""

    .line 39
    .line 40
    :cond_2
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getLocation()Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    invoke-static {v6}, Lb0/c;->f(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)Lxj0/f;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    move-object v7, v4

    .line 49
    move-object v4, v5

    .line 50
    move-object v5, v6

    .line 51
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getOpenNow()Ljava/lang/Boolean;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDto;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    if-eqz v8, :cond_7

    .line 60
    .line 61
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->getGeometry()Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    if-eqz v8, :cond_7

    .line 66
    .line 67
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NearbyPlaceDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDto;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    if-eqz p0, :cond_5

    .line 72
    .line 73
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->getParkingType()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    if-eqz p0, :cond_5

    .line 78
    .line 79
    const-string v9, "LOCATION"

    .line 80
    .line 81
    invoke-virtual {p0, v9}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v9

    .line 85
    if-eqz v9, :cond_3

    .line 86
    .line 87
    sget-object p0, Lbl0/m;->d:Lbl0/m;

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_3
    const-string v9, "ZONE"

    .line 91
    .line 92
    invoke-virtual {p0, v9}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-eqz p0, :cond_4

    .line 97
    .line 98
    sget-object p0, Lbl0/m;->e:Lbl0/m;

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_4
    move-object p0, v7

    .line 102
    :goto_2
    if-nez p0, :cond_6

    .line 103
    .line 104
    :cond_5
    sget-object p0, Lbl0/m;->d:Lbl0/m;

    .line 105
    .line 106
    :cond_6
    invoke-static {v8, p0}, Lb0/c;->e(Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Lbl0/m;)Ljava/util/List;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    goto :goto_3

    .line 111
    :cond_7
    move-object p0, v7

    .line 112
    :goto_3
    if-nez p0, :cond_8

    .line 113
    .line 114
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 115
    .line 116
    :cond_8
    move-object v7, p0

    .line 117
    move v8, p1

    .line 118
    invoke-direct/range {v0 .. v8}, Lbl0/c0;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/lang/Boolean;Ljava/util/List;Z)V

    .line 119
    .line 120
    .line 121
    return-object v0
.end method
