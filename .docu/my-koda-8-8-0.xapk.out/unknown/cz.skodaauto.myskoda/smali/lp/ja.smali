.class public abstract Llp/ja;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/ArrayList;ZJLjava/util/List;JFZFLay0/k;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v3, p2

    .line 4
    .line 5
    move-wide/from16 v5, p5

    .line 6
    .line 7
    move-object/from16 v9, p10

    .line 8
    .line 9
    const/4 v11, 0x0

    .line 10
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 11
    .line 12
    .line 13
    move-result-object v12

    .line 14
    move-object/from16 v13, p11

    .line 15
    .line 16
    check-cast v13, Ll2/t;

    .line 17
    .line 18
    const v0, -0x32838d8

    .line 19
    .line 20
    .line 21
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    iget-object v14, v13, Ll2/t;->a:Leb/j0;

    .line 25
    .line 26
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    const/4 v0, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v0, 0x2

    .line 35
    :goto_0
    or-int v0, p12, v0

    .line 36
    .line 37
    invoke-virtual {v13, v3, v4}, Ll2/t;->f(J)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    const/16 v2, 0x100

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v2, 0x80

    .line 47
    .line 48
    :goto_1
    or-int/2addr v0, v2

    .line 49
    or-int/lit16 v0, v0, 0x6c00

    .line 50
    .line 51
    invoke-virtual {v13, v5, v6}, Ll2/t;->f(J)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-eqz v2, :cond_2

    .line 56
    .line 57
    const/high16 v2, 0x20000

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    const/high16 v2, 0x10000

    .line 61
    .line 62
    :goto_2
    or-int/2addr v0, v2

    .line 63
    const/high16 v2, 0xd80000

    .line 64
    .line 65
    or-int/2addr v0, v2

    .line 66
    move/from16 v2, p7

    .line 67
    .line 68
    invoke-virtual {v13, v2}, Ll2/t;->d(F)Z

    .line 69
    .line 70
    .line 71
    move-result v15

    .line 72
    if-eqz v15, :cond_3

    .line 73
    .line 74
    const/high16 v15, 0x4000000

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_3
    const/high16 v15, 0x2000000

    .line 78
    .line 79
    :goto_3
    or-int/2addr v0, v15

    .line 80
    const/high16 v15, 0x30000000

    .line 81
    .line 82
    or-int/2addr v0, v15

    .line 83
    move/from16 v15, p9

    .line 84
    .line 85
    invoke-virtual {v13, v15}, Ll2/t;->d(F)Z

    .line 86
    .line 87
    .line 88
    move-result v16

    .line 89
    move/from16 v17, v11

    .line 90
    .line 91
    if-eqz v16, :cond_4

    .line 92
    .line 93
    const/16 v16, 0x20

    .line 94
    .line 95
    goto :goto_4

    .line 96
    :cond_4
    const/16 v16, 0x10

    .line 97
    .line 98
    :goto_4
    const/16 v18, 0x6

    .line 99
    .line 100
    or-int v16, v18, v16

    .line 101
    .line 102
    invoke-virtual {v13, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v18

    .line 106
    if-eqz v18, :cond_5

    .line 107
    .line 108
    const/16 v18, 0x100

    .line 109
    .line 110
    goto :goto_5

    .line 111
    :cond_5
    const/16 v18, 0x80

    .line 112
    .line 113
    :goto_5
    or-int v11, v16, v18

    .line 114
    .line 115
    const v16, 0x12492493

    .line 116
    .line 117
    .line 118
    and-int v7, v0, v16

    .line 119
    .line 120
    const v10, 0x12492492

    .line 121
    .line 122
    .line 123
    const/4 v8, 0x1

    .line 124
    if-ne v7, v10, :cond_7

    .line 125
    .line 126
    and-int/lit16 v7, v11, 0x93

    .line 127
    .line 128
    const/16 v10, 0x92

    .line 129
    .line 130
    if-eq v7, v10, :cond_6

    .line 131
    .line 132
    goto :goto_6

    .line 133
    :cond_6
    move/from16 v7, v17

    .line 134
    .line 135
    goto :goto_7

    .line 136
    :cond_7
    :goto_6
    move v7, v8

    .line 137
    :goto_7
    and-int/lit8 v10, v0, 0x1

    .line 138
    .line 139
    invoke-virtual {v13, v10, v7}, Ll2/t;->O(IZ)Z

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    if-eqz v7, :cond_14

    .line 144
    .line 145
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 146
    .line 147
    .line 148
    move-result v7

    .line 149
    if-eqz v7, :cond_8

    .line 150
    .line 151
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 152
    .line 153
    .line 154
    move-result-object v11

    .line 155
    if-eqz v11, :cond_15

    .line 156
    .line 157
    new-instance v0, Luu/o1;

    .line 158
    .line 159
    move/from16 v10, p12

    .line 160
    .line 161
    move v7, v2

    .line 162
    move v8, v15

    .line 163
    move/from16 v2, p1

    .line 164
    .line 165
    invoke-direct/range {v0 .. v10}, Luu/o1;-><init>(Ljava/util/ArrayList;ZJJFFLay0/k;I)V

    .line 166
    .line 167
    .line 168
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 169
    .line 170
    return-void

    .line 171
    :cond_8
    move-object v2, v14

    .line 172
    check-cast v2, Luu/x;

    .line 173
    .line 174
    invoke-virtual {v13, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v3

    .line 178
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v4

    .line 182
    or-int/2addr v3, v4

    .line 183
    and-int/lit16 v4, v0, 0x380

    .line 184
    .line 185
    const/16 v5, 0x100

    .line 186
    .line 187
    if-ne v4, v5, :cond_9

    .line 188
    .line 189
    move v4, v8

    .line 190
    goto :goto_8

    .line 191
    :cond_9
    move/from16 v4, v17

    .line 192
    .line 193
    :goto_8
    or-int/2addr v3, v4

    .line 194
    sget-object v15, Lmx0/s;->d:Lmx0/s;

    .line 195
    .line 196
    invoke-virtual {v13, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    or-int/2addr v3, v4

    .line 201
    const/high16 v4, 0x70000

    .line 202
    .line 203
    and-int/2addr v4, v0

    .line 204
    const/high16 v5, 0x20000

    .line 205
    .line 206
    if-ne v4, v5, :cond_a

    .line 207
    .line 208
    move v4, v8

    .line 209
    goto :goto_9

    .line 210
    :cond_a
    move/from16 v4, v17

    .line 211
    .line 212
    :goto_9
    or-int/2addr v3, v4

    .line 213
    const/4 v4, 0x0

    .line 214
    invoke-virtual {v13, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v5

    .line 218
    or-int/2addr v3, v5

    .line 219
    const/high16 v5, 0xe000000

    .line 220
    .line 221
    and-int/2addr v0, v5

    .line 222
    const/high16 v5, 0x4000000

    .line 223
    .line 224
    if-ne v0, v5, :cond_b

    .line 225
    .line 226
    move v0, v8

    .line 227
    goto :goto_a

    .line 228
    :cond_b
    move/from16 v0, v17

    .line 229
    .line 230
    :goto_a
    or-int/2addr v0, v3

    .line 231
    and-int/lit8 v3, v11, 0x70

    .line 232
    .line 233
    const/16 v5, 0x20

    .line 234
    .line 235
    if-ne v3, v5, :cond_c

    .line 236
    .line 237
    move v3, v8

    .line 238
    goto :goto_b

    .line 239
    :cond_c
    move/from16 v3, v17

    .line 240
    .line 241
    :goto_b
    or-int/2addr v0, v3

    .line 242
    invoke-virtual {v13, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result v3

    .line 246
    or-int/2addr v0, v3

    .line 247
    and-int/lit16 v3, v11, 0x380

    .line 248
    .line 249
    const/16 v5, 0x100

    .line 250
    .line 251
    if-ne v3, v5, :cond_d

    .line 252
    .line 253
    move v3, v8

    .line 254
    goto :goto_c

    .line 255
    :cond_d
    move/from16 v3, v17

    .line 256
    .line 257
    :goto_c
    or-int/2addr v0, v3

    .line 258
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v3

    .line 262
    if-nez v0, :cond_f

    .line 263
    .line 264
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 265
    .line 266
    if-ne v3, v0, :cond_e

    .line 267
    .line 268
    goto :goto_d

    .line 269
    :cond_e
    move-wide/from16 v5, p5

    .line 270
    .line 271
    move-object/from16 v9, p10

    .line 272
    .line 273
    move-object v0, v3

    .line 274
    move-object v11, v4

    .line 275
    move/from16 p4, v8

    .line 276
    .line 277
    move-wide/from16 v3, p2

    .line 278
    .line 279
    goto :goto_e

    .line 280
    :cond_f
    :goto_d
    new-instance v0, Luu/p1;

    .line 281
    .line 282
    move-wide/from16 v5, p2

    .line 283
    .line 284
    move/from16 v9, p7

    .line 285
    .line 286
    move/from16 v10, p9

    .line 287
    .line 288
    move-object v3, v1

    .line 289
    move-object v1, v2

    .line 290
    move-object v11, v4

    .line 291
    move/from16 p4, v8

    .line 292
    .line 293
    move/from16 v4, p1

    .line 294
    .line 295
    move-wide/from16 v7, p5

    .line 296
    .line 297
    move-object/from16 v2, p10

    .line 298
    .line 299
    invoke-direct/range {v0 .. v10}, Luu/p1;-><init>(Luu/x;Lay0/k;Ljava/util/ArrayList;ZJJFF)V

    .line 300
    .line 301
    .line 302
    move-object v9, v2

    .line 303
    move-object v1, v3

    .line 304
    move-wide v3, v5

    .line 305
    move-wide v5, v7

    .line 306
    invoke-virtual {v13, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    :goto_e
    check-cast v0, Lay0/a;

    .line 310
    .line 311
    instance-of v2, v14, Luu/x;

    .line 312
    .line 313
    if-eqz v2, :cond_13

    .line 314
    .line 315
    invoke-virtual {v13}, Ll2/t;->W()V

    .line 316
    .line 317
    .line 318
    iget-boolean v2, v13, Ll2/t;->S:Z

    .line 319
    .line 320
    if-eqz v2, :cond_10

    .line 321
    .line 322
    invoke-virtual {v13, v0}, Ll2/t;->l(Lay0/a;)V

    .line 323
    .line 324
    .line 325
    goto :goto_f

    .line 326
    :cond_10
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 327
    .line 328
    .line 329
    :goto_f
    new-instance v0, Luu/f1;

    .line 330
    .line 331
    const/16 v2, 0x13

    .line 332
    .line 333
    invoke-direct {v0, v2}, Luu/f1;-><init>(I)V

    .line 334
    .line 335
    .line 336
    invoke-static {v0, v9, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 337
    .line 338
    .line 339
    new-instance v0, Luu/f1;

    .line 340
    .line 341
    const/16 v2, 0x14

    .line 342
    .line 343
    invoke-direct {v0, v2}, Luu/f1;-><init>(I)V

    .line 344
    .line 345
    .line 346
    invoke-static {v0, v1, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 347
    .line 348
    .line 349
    invoke-static/range {p1 .. p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    new-instance v2, Luu/f1;

    .line 354
    .line 355
    const/16 v7, 0x15

    .line 356
    .line 357
    invoke-direct {v2, v7}, Luu/f1;-><init>(I)V

    .line 358
    .line 359
    .line 360
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 361
    .line 362
    .line 363
    new-instance v0, Le3/s;

    .line 364
    .line 365
    invoke-direct {v0, v3, v4}, Le3/s;-><init>(J)V

    .line 366
    .line 367
    .line 368
    sget-object v2, Luu/l;->k:Luu/l;

    .line 369
    .line 370
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 371
    .line 372
    .line 373
    invoke-static/range {v17 .. v17}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    new-instance v2, Luu/f1;

    .line 378
    .line 379
    const/16 v7, 0xc

    .line 380
    .line 381
    invoke-direct {v2, v7}, Luu/f1;-><init>(I)V

    .line 382
    .line 383
    .line 384
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 385
    .line 386
    .line 387
    new-instance v0, Luu/f1;

    .line 388
    .line 389
    const/16 v2, 0xd

    .line 390
    .line 391
    invoke-direct {v0, v2}, Luu/f1;-><init>(I)V

    .line 392
    .line 393
    .line 394
    invoke-static {v0, v15, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 395
    .line 396
    .line 397
    new-instance v0, Le3/s;

    .line 398
    .line 399
    invoke-direct {v0, v5, v6}, Le3/s;-><init>(J)V

    .line 400
    .line 401
    .line 402
    sget-object v2, Luu/l;->l:Luu/l;

    .line 403
    .line 404
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 405
    .line 406
    .line 407
    new-instance v0, Luu/f1;

    .line 408
    .line 409
    const/16 v2, 0xe

    .line 410
    .line 411
    invoke-direct {v0, v2}, Luu/f1;-><init>(I)V

    .line 412
    .line 413
    .line 414
    iget-boolean v2, v13, Ll2/t;->S:Z

    .line 415
    .line 416
    if-nez v2, :cond_11

    .line 417
    .line 418
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v7

    .line 422
    invoke-static {v7, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 423
    .line 424
    .line 425
    move-result v7

    .line 426
    if-nez v7, :cond_12

    .line 427
    .line 428
    :cond_11
    invoke-virtual {v13, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    if-nez v2, :cond_12

    .line 432
    .line 433
    invoke-virtual {v13, v12, v0}, Ll2/t;->b(Ljava/lang/Object;Lay0/n;)V

    .line 434
    .line 435
    .line 436
    :cond_12
    new-instance v0, Luu/f1;

    .line 437
    .line 438
    const/16 v2, 0xf

    .line 439
    .line 440
    invoke-direct {v0, v2}, Luu/f1;-><init>(I)V

    .line 441
    .line 442
    .line 443
    invoke-static {v0, v11, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 444
    .line 445
    .line 446
    invoke-static/range {p7 .. p7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 447
    .line 448
    .line 449
    move-result-object v0

    .line 450
    new-instance v2, Luu/f1;

    .line 451
    .line 452
    const/16 v7, 0xb

    .line 453
    .line 454
    invoke-direct {v2, v7}, Luu/f1;-><init>(I)V

    .line 455
    .line 456
    .line 457
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 458
    .line 459
    .line 460
    new-instance v0, Luu/f1;

    .line 461
    .line 462
    const/16 v2, 0x10

    .line 463
    .line 464
    invoke-direct {v0, v2}, Luu/f1;-><init>(I)V

    .line 465
    .line 466
    .line 467
    invoke-static {v0, v11, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 468
    .line 469
    .line 470
    invoke-static/range {p4 .. p4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    new-instance v2, Luu/f1;

    .line 475
    .line 476
    const/16 v7, 0x11

    .line 477
    .line 478
    invoke-direct {v2, v7}, Luu/f1;-><init>(I)V

    .line 479
    .line 480
    .line 481
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 482
    .line 483
    .line 484
    invoke-static/range {p9 .. p9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    new-instance v2, Luu/f1;

    .line 489
    .line 490
    const/16 v7, 0x12

    .line 491
    .line 492
    invoke-direct {v2, v7}, Luu/f1;-><init>(I)V

    .line 493
    .line 494
    .line 495
    invoke-static {v2, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 496
    .line 497
    .line 498
    move/from16 v0, p4

    .line 499
    .line 500
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 501
    .line 502
    .line 503
    move v9, v0

    .line 504
    goto :goto_10

    .line 505
    :cond_13
    invoke-static {}, Ll2/b;->l()V

    .line 506
    .line 507
    .line 508
    throw v11

    .line 509
    :cond_14
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 510
    .line 511
    .line 512
    move-object/from16 v15, p4

    .line 513
    .line 514
    move/from16 v9, p8

    .line 515
    .line 516
    :goto_10
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 517
    .line 518
    .line 519
    move-result-object v13

    .line 520
    if-eqz v13, :cond_15

    .line 521
    .line 522
    new-instance v0, Luu/n1;

    .line 523
    .line 524
    move/from16 v2, p1

    .line 525
    .line 526
    move/from16 v8, p7

    .line 527
    .line 528
    move/from16 v10, p9

    .line 529
    .line 530
    move-object/from16 v11, p10

    .line 531
    .line 532
    move/from16 v12, p12

    .line 533
    .line 534
    move-wide v6, v5

    .line 535
    move-object v5, v15

    .line 536
    invoke-direct/range {v0 .. v12}, Luu/n1;-><init>(Ljava/util/ArrayList;ZJLjava/util/List;JFZFLay0/k;I)V

    .line 537
    .line 538
    .line 539
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 540
    .line 541
    :cond_15
    return-void
.end method
