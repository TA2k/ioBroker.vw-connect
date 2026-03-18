.class public abstract Lkp/x5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V
    .locals 48

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v0, p11

    .line 6
    .line 7
    move/from16 v3, p12

    .line 8
    .line 9
    const-string v4, "text"

    .line 10
    .line 11
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v4, "style"

    .line 15
    .line 16
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v4, p10

    .line 20
    .line 21
    check-cast v4, Ll2/t;

    .line 22
    .line 23
    const v5, 0x43f2dc2f

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v5, v0, 0x6

    .line 30
    .line 31
    if-nez v5, :cond_1

    .line 32
    .line 33
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_0

    .line 38
    .line 39
    const/4 v5, 0x4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v5, 0x2

    .line 42
    :goto_0
    or-int/2addr v5, v0

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v5, v0

    .line 45
    :goto_1
    and-int/lit8 v7, v0, 0x30

    .line 46
    .line 47
    if-nez v7, :cond_3

    .line 48
    .line 49
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v7

    .line 53
    if-eqz v7, :cond_2

    .line 54
    .line 55
    const/16 v7, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v7, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr v5, v7

    .line 61
    :cond_3
    and-int/lit8 v7, v3, 0x4

    .line 62
    .line 63
    if-eqz v7, :cond_5

    .line 64
    .line 65
    or-int/lit16 v5, v5, 0x180

    .line 66
    .line 67
    :cond_4
    move-object/from16 v8, p2

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_5
    and-int/lit16 v8, v0, 0x180

    .line 71
    .line 72
    if-nez v8, :cond_4

    .line 73
    .line 74
    move-object/from16 v8, p2

    .line 75
    .line 76
    invoke-virtual {v4, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v9

    .line 80
    if-eqz v9, :cond_6

    .line 81
    .line 82
    const/16 v9, 0x100

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_6
    const/16 v9, 0x80

    .line 86
    .line 87
    :goto_3
    or-int/2addr v5, v9

    .line 88
    :goto_4
    and-int/lit8 v9, v3, 0x8

    .line 89
    .line 90
    if-eqz v9, :cond_8

    .line 91
    .line 92
    or-int/lit16 v5, v5, 0xc00

    .line 93
    .line 94
    :cond_7
    move-object/from16 v10, p3

    .line 95
    .line 96
    goto :goto_6

    .line 97
    :cond_8
    and-int/lit16 v10, v0, 0xc00

    .line 98
    .line 99
    if-nez v10, :cond_7

    .line 100
    .line 101
    move-object/from16 v10, p3

    .line 102
    .line 103
    invoke-virtual {v4, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v11

    .line 107
    if-eqz v11, :cond_9

    .line 108
    .line 109
    const/16 v11, 0x800

    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_9
    const/16 v11, 0x400

    .line 113
    .line 114
    :goto_5
    or-int/2addr v5, v11

    .line 115
    :goto_6
    const v11, 0x1b6000

    .line 116
    .line 117
    .line 118
    or-int/2addr v5, v11

    .line 119
    const/high16 v11, 0xc00000

    .line 120
    .line 121
    and-int/2addr v11, v0

    .line 122
    if-nez v11, :cond_c

    .line 123
    .line 124
    and-int/lit16 v11, v3, 0x80

    .line 125
    .line 126
    if-nez v11, :cond_a

    .line 127
    .line 128
    move-wide/from16 v11, p7

    .line 129
    .line 130
    invoke-virtual {v4, v11, v12}, Ll2/t;->f(J)Z

    .line 131
    .line 132
    .line 133
    move-result v13

    .line 134
    if-eqz v13, :cond_b

    .line 135
    .line 136
    const/high16 v13, 0x800000

    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_a
    move-wide/from16 v11, p7

    .line 140
    .line 141
    :cond_b
    const/high16 v13, 0x400000

    .line 142
    .line 143
    :goto_7
    or-int/2addr v5, v13

    .line 144
    goto :goto_8

    .line 145
    :cond_c
    move-wide/from16 v11, p7

    .line 146
    .line 147
    :goto_8
    and-int/lit16 v13, v3, 0x100

    .line 148
    .line 149
    const/high16 v14, 0x6000000

    .line 150
    .line 151
    if-eqz v13, :cond_e

    .line 152
    .line 153
    or-int/2addr v5, v14

    .line 154
    :cond_d
    move-object/from16 v14, p9

    .line 155
    .line 156
    goto :goto_a

    .line 157
    :cond_e
    and-int/2addr v14, v0

    .line 158
    if-nez v14, :cond_d

    .line 159
    .line 160
    move-object/from16 v14, p9

    .line 161
    .line 162
    invoke-virtual {v4, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v15

    .line 166
    if-eqz v15, :cond_f

    .line 167
    .line 168
    const/high16 v15, 0x4000000

    .line 169
    .line 170
    goto :goto_9

    .line 171
    :cond_f
    const/high16 v15, 0x2000000

    .line 172
    .line 173
    :goto_9
    or-int/2addr v5, v15

    .line 174
    :goto_a
    const v15, 0x2492493

    .line 175
    .line 176
    .line 177
    and-int/2addr v15, v5

    .line 178
    const v6, 0x2492492

    .line 179
    .line 180
    .line 181
    move/from16 v16, v5

    .line 182
    .line 183
    if-eq v15, v6, :cond_10

    .line 184
    .line 185
    const/4 v6, 0x1

    .line 186
    goto :goto_b

    .line 187
    :cond_10
    const/4 v6, 0x0

    .line 188
    :goto_b
    and-int/lit8 v15, v16, 0x1

    .line 189
    .line 190
    invoke-virtual {v4, v15, v6}, Ll2/t;->O(IZ)Z

    .line 191
    .line 192
    .line 193
    move-result v6

    .line 194
    if-eqz v6, :cond_2b

    .line 195
    .line 196
    invoke-virtual {v4}, Ll2/t;->T()V

    .line 197
    .line 198
    .line 199
    and-int/lit8 v6, v0, 0x1

    .line 200
    .line 201
    const v15, -0x1c00001

    .line 202
    .line 203
    .line 204
    move/from16 v18, v6

    .line 205
    .line 206
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 207
    .line 208
    if-eqz v18, :cond_13

    .line 209
    .line 210
    invoke-virtual {v4}, Ll2/t;->y()Z

    .line 211
    .line 212
    .line 213
    move-result v18

    .line 214
    if-eqz v18, :cond_11

    .line 215
    .line 216
    goto :goto_c

    .line 217
    :cond_11
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 218
    .line 219
    .line 220
    and-int/lit16 v7, v3, 0x80

    .line 221
    .line 222
    if-eqz v7, :cond_12

    .line 223
    .line 224
    and-int v7, v16, v15

    .line 225
    .line 226
    move/from16 v19, p4

    .line 227
    .line 228
    move/from16 v20, p5

    .line 229
    .line 230
    move/from16 v22, p6

    .line 231
    .line 232
    move/from16 v25, v7

    .line 233
    .line 234
    move-object/from16 v18, v8

    .line 235
    .line 236
    move-object/from16 v21, v10

    .line 237
    .line 238
    move-wide/from16 v23, v11

    .line 239
    .line 240
    move-object v7, v14

    .line 241
    goto/16 :goto_11

    .line 242
    .line 243
    :cond_12
    move/from16 v19, p4

    .line 244
    .line 245
    move/from16 v20, p5

    .line 246
    .line 247
    move/from16 v22, p6

    .line 248
    .line 249
    move-object/from16 v18, v8

    .line 250
    .line 251
    move-object/from16 v21, v10

    .line 252
    .line 253
    move-wide/from16 v23, v11

    .line 254
    .line 255
    move-object v7, v14

    .line 256
    move/from16 v25, v16

    .line 257
    .line 258
    goto :goto_11

    .line 259
    :cond_13
    :goto_c
    if-eqz v7, :cond_14

    .line 260
    .line 261
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 262
    .line 263
    goto :goto_d

    .line 264
    :cond_14
    move-object v7, v8

    .line 265
    :goto_d
    if-eqz v9, :cond_16

    .line 266
    .line 267
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v8

    .line 271
    if-ne v8, v6, :cond_15

    .line 272
    .line 273
    new-instance v8, Ldj/a;

    .line 274
    .line 275
    const/16 v9, 0x18

    .line 276
    .line 277
    invoke-direct {v8, v9}, Ldj/a;-><init>(I)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 281
    .line 282
    .line 283
    :cond_15
    check-cast v8, Lay0/k;

    .line 284
    .line 285
    goto :goto_e

    .line 286
    :cond_16
    move-object v8, v10

    .line 287
    :goto_e
    and-int/lit16 v9, v3, 0x80

    .line 288
    .line 289
    if-eqz v9, :cond_17

    .line 290
    .line 291
    sget-object v9, Lh71/m;->a:Ll2/u2;

    .line 292
    .line 293
    invoke-virtual {v4, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v9

    .line 297
    check-cast v9, Lh71/l;

    .line 298
    .line 299
    iget-object v9, v9, Lh71/l;->e:Lh71/k;

    .line 300
    .line 301
    iget-wide v9, v9, Lh71/k;->c:J

    .line 302
    .line 303
    and-int v11, v16, v15

    .line 304
    .line 305
    goto :goto_f

    .line 306
    :cond_17
    move-wide v9, v11

    .line 307
    move/from16 v11, v16

    .line 308
    .line 309
    :goto_f
    const v12, 0x7fffffff

    .line 310
    .line 311
    .line 312
    if-eqz v13, :cond_18

    .line 313
    .line 314
    const/4 v13, 0x0

    .line 315
    move-object/from16 v18, v7

    .line 316
    .line 317
    move-object/from16 v21, v8

    .line 318
    .line 319
    move-wide/from16 v23, v9

    .line 320
    .line 321
    move/from16 v25, v11

    .line 322
    .line 323
    move/from16 v22, v12

    .line 324
    .line 325
    move-object v7, v13

    .line 326
    :goto_10
    const/16 v19, 0x1

    .line 327
    .line 328
    const/16 v20, 0x1

    .line 329
    .line 330
    goto :goto_11

    .line 331
    :cond_18
    move-object/from16 v18, v7

    .line 332
    .line 333
    move-object/from16 v21, v8

    .line 334
    .line 335
    move-wide/from16 v23, v9

    .line 336
    .line 337
    move/from16 v25, v11

    .line 338
    .line 339
    move/from16 v22, v12

    .line 340
    .line 341
    move-object v7, v14

    .line 342
    goto :goto_10

    .line 343
    :goto_11
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 344
    .line 345
    .line 346
    sget-object v8, Lh71/m;->a:Ll2/u2;

    .line 347
    .line 348
    invoke-virtual {v4, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v8

    .line 352
    check-cast v8, Lh71/l;

    .line 353
    .line 354
    iget-object v8, v8, Lh71/l;->e:Lh71/k;

    .line 355
    .line 356
    iget-wide v8, v8, Lh71/k;->h:J

    .line 357
    .line 358
    and-int/lit8 v10, v25, 0xe

    .line 359
    .line 360
    const/4 v11, 0x4

    .line 361
    if-ne v10, v11, :cond_19

    .line 362
    .line 363
    const/4 v10, 0x1

    .line 364
    goto :goto_12

    .line 365
    :cond_19
    const/4 v10, 0x0

    .line 366
    :goto_12
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v11

    .line 370
    if-nez v10, :cond_1a

    .line 371
    .line 372
    if-ne v11, v6, :cond_1e

    .line 373
    .line 374
    :cond_1a
    const/16 v10, 0x3f

    .line 375
    .line 376
    invoke-static {v1, v10}, Landroid/text/Html;->fromHtml(Ljava/lang/String;I)Landroid/text/Spanned;

    .line 377
    .line 378
    .line 379
    move-result-object v10

    .line 380
    new-instance v11, Lg4/d;

    .line 381
    .line 382
    invoke-direct {v11}, Lg4/d;-><init>()V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v10}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 386
    .line 387
    .line 388
    move-result-object v12

    .line 389
    invoke-virtual {v11, v12}, Lg4/d;->d(Ljava/lang/String;)V

    .line 390
    .line 391
    .line 392
    invoke-interface {v10}, Ljava/lang/CharSequence;->length()I

    .line 393
    .line 394
    .line 395
    move-result v12

    .line 396
    const-class v13, Ljava/lang/Object;

    .line 397
    .line 398
    const/4 v14, 0x0

    .line 399
    invoke-interface {v10, v14, v12, v13}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v12

    .line 403
    const-string v13, "getSpans(...)"

    .line 404
    .line 405
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 406
    .line 407
    .line 408
    array-length v13, v12

    .line 409
    move v15, v14

    .line 410
    move/from16 v16, v15

    .line 411
    .line 412
    :goto_13
    if-ge v15, v13, :cond_1d

    .line 413
    .line 414
    aget-object v14, v12, v15

    .line 415
    .line 416
    invoke-interface {v10, v14}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 417
    .line 418
    .line 419
    move-result v5

    .line 420
    invoke-interface {v10, v14}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 421
    .line 422
    .line 423
    move-result v0

    .line 424
    instance-of v1, v14, Landroid/text/style/StyleSpan;

    .line 425
    .line 426
    if-eqz v1, :cond_1c

    .line 427
    .line 428
    check-cast v14, Landroid/text/style/StyleSpan;

    .line 429
    .line 430
    invoke-virtual {v14}, Landroid/text/style/StyleSpan;->getStyle()I

    .line 431
    .line 432
    .line 433
    move-result v1

    .line 434
    const/4 v14, 0x1

    .line 435
    if-ne v1, v14, :cond_1b

    .line 436
    .line 437
    new-instance v26, Lg4/g0;

    .line 438
    .line 439
    sget-object v31, Lk4/x;->n:Lk4/x;

    .line 440
    .line 441
    const/16 v44, 0x0

    .line 442
    .line 443
    const v45, 0xfffb

    .line 444
    .line 445
    .line 446
    const-wide/16 v27, 0x0

    .line 447
    .line 448
    const-wide/16 v29, 0x0

    .line 449
    .line 450
    const/16 v32, 0x0

    .line 451
    .line 452
    const/16 v33, 0x0

    .line 453
    .line 454
    const/16 v34, 0x0

    .line 455
    .line 456
    const/16 v35, 0x0

    .line 457
    .line 458
    const-wide/16 v36, 0x0

    .line 459
    .line 460
    const/16 v38, 0x0

    .line 461
    .line 462
    const/16 v39, 0x0

    .line 463
    .line 464
    const/16 v40, 0x0

    .line 465
    .line 466
    const-wide/16 v41, 0x0

    .line 467
    .line 468
    const/16 v43, 0x0

    .line 469
    .line 470
    invoke-direct/range {v26 .. v45}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 471
    .line 472
    .line 473
    move-object/from16 v1, v26

    .line 474
    .line 475
    invoke-virtual {v11, v1, v5, v0}, Lg4/d;->b(Lg4/g0;II)V

    .line 476
    .line 477
    .line 478
    :cond_1b
    move-wide/from16 v27, v8

    .line 479
    .line 480
    goto :goto_14

    .line 481
    :cond_1c
    instance-of v1, v14, Landroid/text/style/URLSpan;

    .line 482
    .line 483
    if-eqz v1, :cond_1b

    .line 484
    .line 485
    check-cast v14, Landroid/text/style/URLSpan;

    .line 486
    .line 487
    invoke-virtual {v14}, Landroid/text/style/URLSpan;->getURL()Ljava/lang/String;

    .line 488
    .line 489
    .line 490
    move-result-object v1

    .line 491
    const-string v2, "getURL(...)"

    .line 492
    .line 493
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 494
    .line 495
    .line 496
    invoke-virtual {v14}, Landroid/text/style/URLSpan;->getURL()Ljava/lang/String;

    .line 497
    .line 498
    .line 499
    move-result-object v14

    .line 500
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 501
    .line 502
    .line 503
    invoke-virtual {v11, v14, v1, v5, v0}, Lg4/d;->a(Ljava/lang/String;Ljava/lang/String;II)V

    .line 504
    .line 505
    .line 506
    new-instance v26, Lg4/g0;

    .line 507
    .line 508
    const/16 v44, 0x0

    .line 509
    .line 510
    const v45, 0xeffe

    .line 511
    .line 512
    .line 513
    const-wide/16 v29, 0x0

    .line 514
    .line 515
    const/16 v31, 0x0

    .line 516
    .line 517
    const/16 v32, 0x0

    .line 518
    .line 519
    const/16 v33, 0x0

    .line 520
    .line 521
    const/16 v34, 0x0

    .line 522
    .line 523
    const/16 v35, 0x0

    .line 524
    .line 525
    const-wide/16 v36, 0x0

    .line 526
    .line 527
    const/16 v38, 0x0

    .line 528
    .line 529
    const/16 v39, 0x0

    .line 530
    .line 531
    const/16 v40, 0x0

    .line 532
    .line 533
    const-wide/16 v41, 0x0

    .line 534
    .line 535
    sget-object v43, Lr4/l;->c:Lr4/l;

    .line 536
    .line 537
    move-wide/from16 v27, v8

    .line 538
    .line 539
    invoke-direct/range {v26 .. v45}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 540
    .line 541
    .line 542
    move-object/from16 v1, v26

    .line 543
    .line 544
    invoke-virtual {v11, v1, v5, v0}, Lg4/d;->b(Lg4/g0;II)V

    .line 545
    .line 546
    .line 547
    const/16 v16, 0x1

    .line 548
    .line 549
    :goto_14
    add-int/lit8 v15, v15, 0x1

    .line 550
    .line 551
    move-object/from16 v1, p0

    .line 552
    .line 553
    move-object/from16 v2, p1

    .line 554
    .line 555
    move/from16 v0, p11

    .line 556
    .line 557
    move-wide/from16 v8, v27

    .line 558
    .line 559
    const/4 v14, 0x0

    .line 560
    goto/16 :goto_13

    .line 561
    .line 562
    :cond_1d
    invoke-virtual {v11}, Lg4/d;->j()Lg4/g;

    .line 563
    .line 564
    .line 565
    move-result-object v0

    .line 566
    invoke-static/range {v16 .. v16}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 567
    .line 568
    .line 569
    move-result-object v1

    .line 570
    new-instance v11, Llx0/l;

    .line 571
    .line 572
    invoke-direct {v11, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 573
    .line 574
    .line 575
    invoke-virtual {v4, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 576
    .line 577
    .line 578
    :cond_1e
    check-cast v11, Llx0/l;

    .line 579
    .line 580
    iget-object v0, v11, Llx0/l;->d:Ljava/lang/Object;

    .line 581
    .line 582
    check-cast v0, Lg4/g;

    .line 583
    .line 584
    iget-object v1, v11, Llx0/l;->e:Ljava/lang/Object;

    .line 585
    .line 586
    check-cast v1, Ljava/lang/Boolean;

    .line 587
    .line 588
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 589
    .line 590
    .line 591
    move-result v1

    .line 592
    sget-object v2, Lc71/e;->a:Ll2/e0;

    .line 593
    .line 594
    invoke-virtual {v4, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 595
    .line 596
    .line 597
    move-result-object v2

    .line 598
    check-cast v2, Lc71/d;

    .line 599
    .line 600
    const-wide/16 v8, 0x10

    .line 601
    .line 602
    if-eqz v1, :cond_25

    .line 603
    .line 604
    const v1, 0x43047ffe    # 132.49997f

    .line 605
    .line 606
    .line 607
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 608
    .line 609
    .line 610
    cmp-long v1, v23, v8

    .line 611
    .line 612
    if-nez v1, :cond_1f

    .line 613
    .line 614
    if-eqz v7, :cond_1f

    .line 615
    .line 616
    iget v11, v7, Lr4/k;->a:I

    .line 617
    .line 618
    const/4 v15, 0x0

    .line 619
    const v16, 0xff7fff

    .line 620
    .line 621
    .line 622
    move-object v13, v4

    .line 623
    const-wide/16 v3, 0x0

    .line 624
    .line 625
    move-object v1, v6

    .line 626
    const-wide/16 v5, 0x0

    .line 627
    .line 628
    move-object v14, v7

    .line 629
    const/4 v7, 0x0

    .line 630
    const/4 v8, 0x0

    .line 631
    const-wide/16 v9, 0x0

    .line 632
    .line 633
    move-object/from16 v26, v13

    .line 634
    .line 635
    const-wide/16 v12, 0x0

    .line 636
    .line 637
    move-object/from16 v27, v14

    .line 638
    .line 639
    const/4 v14, 0x0

    .line 640
    move-object/from16 p2, v2

    .line 641
    .line 642
    move-object/from16 v2, p1

    .line 643
    .line 644
    invoke-static/range {v2 .. v16}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 645
    .line 646
    .line 647
    move-result-object v3

    .line 648
    move-object/from16 v47, p2

    .line 649
    .line 650
    move-object/from16 v17, v1

    .line 651
    .line 652
    move-object v7, v3

    .line 653
    move-object/from16 v1, v26

    .line 654
    .line 655
    move-object/from16 v46, v27

    .line 656
    .line 657
    goto/16 :goto_17

    .line 658
    .line 659
    :cond_1f
    move-object v3, v2

    .line 660
    move-object/from16 v26, v4

    .line 661
    .line 662
    move-object v2, v7

    .line 663
    move v4, v1

    .line 664
    move-object v1, v6

    .line 665
    if-nez v4, :cond_20

    .line 666
    .line 667
    move-object/from16 v7, p1

    .line 668
    .line 669
    move-object/from16 v17, v1

    .line 670
    .line 671
    move-object/from16 v46, v2

    .line 672
    .line 673
    move-object/from16 v47, v3

    .line 674
    .line 675
    move-object/from16 v1, v26

    .line 676
    .line 677
    goto :goto_17

    .line 678
    :cond_20
    if-nez v4, :cond_22

    .line 679
    .line 680
    :cond_21
    move-object/from16 v17, v1

    .line 681
    .line 682
    move-object/from16 v46, v2

    .line 683
    .line 684
    move-object/from16 v47, v3

    .line 685
    .line 686
    move-wide/from16 v3, v23

    .line 687
    .line 688
    move-object/from16 v1, v26

    .line 689
    .line 690
    goto :goto_16

    .line 691
    :cond_22
    if-eqz v2, :cond_21

    .line 692
    .line 693
    iget v11, v2, Lr4/k;->a:I

    .line 694
    .line 695
    const/4 v15, 0x0

    .line 696
    const v16, 0xff7ffe

    .line 697
    .line 698
    .line 699
    const-wide/16 v5, 0x0

    .line 700
    .line 701
    const/4 v7, 0x0

    .line 702
    const/4 v8, 0x0

    .line 703
    const-wide/16 v9, 0x0

    .line 704
    .line 705
    const-wide/16 v12, 0x0

    .line 706
    .line 707
    const/4 v14, 0x0

    .line 708
    move-object/from16 v17, v1

    .line 709
    .line 710
    move-object/from16 v46, v2

    .line 711
    .line 712
    move-object/from16 v47, v3

    .line 713
    .line 714
    move-wide/from16 v3, v23

    .line 715
    .line 716
    move-object/from16 v1, v26

    .line 717
    .line 718
    move-object/from16 v2, p1

    .line 719
    .line 720
    invoke-static/range {v2 .. v16}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 721
    .line 722
    .line 723
    move-result-object v5

    .line 724
    :goto_15
    move-object v7, v5

    .line 725
    goto :goto_17

    .line 726
    :goto_16
    const/4 v15, 0x0

    .line 727
    const v16, 0xfffffe

    .line 728
    .line 729
    .line 730
    const-wide/16 v5, 0x0

    .line 731
    .line 732
    const/4 v7, 0x0

    .line 733
    const/4 v8, 0x0

    .line 734
    const-wide/16 v9, 0x0

    .line 735
    .line 736
    const/4 v11, 0x0

    .line 737
    const-wide/16 v12, 0x0

    .line 738
    .line 739
    const/4 v14, 0x0

    .line 740
    move-object/from16 v2, p1

    .line 741
    .line 742
    invoke-static/range {v2 .. v16}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 743
    .line 744
    .line 745
    move-result-object v5

    .line 746
    move-wide/from16 v23, v3

    .line 747
    .line 748
    goto :goto_15

    .line 749
    :goto_17
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 750
    .line 751
    .line 752
    move-result v2

    .line 753
    move-object/from16 v3, v47

    .line 754
    .line 755
    invoke-virtual {v1, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 756
    .line 757
    .line 758
    move-result v4

    .line 759
    or-int/2addr v2, v4

    .line 760
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v4

    .line 764
    if-nez v2, :cond_23

    .line 765
    .line 766
    move-object/from16 v2, v17

    .line 767
    .line 768
    if-ne v4, v2, :cond_24

    .line 769
    .line 770
    :cond_23
    new-instance v4, Laa/z;

    .line 771
    .line 772
    const/16 v2, 0x1a

    .line 773
    .line 774
    invoke-direct {v4, v2, v0, v3}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 775
    .line 776
    .line 777
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 778
    .line 779
    .line 780
    :cond_24
    move-object v12, v4

    .line 781
    check-cast v12, Lay0/k;

    .line 782
    .line 783
    shr-int/lit8 v2, v25, 0x3

    .line 784
    .line 785
    and-int/lit8 v3, v2, 0x70

    .line 786
    .line 787
    shr-int/lit8 v4, v25, 0x6

    .line 788
    .line 789
    and-int/lit16 v4, v4, 0x1c00

    .line 790
    .line 791
    or-int/2addr v3, v4

    .line 792
    const v4, 0xe000

    .line 793
    .line 794
    .line 795
    and-int v4, v25, v4

    .line 796
    .line 797
    or-int/2addr v3, v4

    .line 798
    const/high16 v4, 0x70000

    .line 799
    .line 800
    and-int/2addr v2, v4

    .line 801
    or-int/2addr v2, v3

    .line 802
    shl-int/lit8 v3, v25, 0x9

    .line 803
    .line 804
    const/high16 v4, 0x380000

    .line 805
    .line 806
    and-int/2addr v3, v4

    .line 807
    or-int v14, v2, v3

    .line 808
    .line 809
    move-object v5, v0

    .line 810
    move-object v13, v1

    .line 811
    move-object/from16 v6, v18

    .line 812
    .line 813
    move/from16 v9, v19

    .line 814
    .line 815
    move/from16 v8, v20

    .line 816
    .line 817
    move-object/from16 v11, v21

    .line 818
    .line 819
    move/from16 v10, v22

    .line 820
    .line 821
    invoke-static/range {v5 .. v14}, Lt1/l0;->e(Lg4/g;Lx2/s;Lg4/p0;ZIILay0/k;Lay0/k;Ll2/o;I)V

    .line 822
    .line 823
    .line 824
    move-object v0, v6

    .line 825
    move/from16 v18, v8

    .line 826
    .line 827
    move/from16 v17, v9

    .line 828
    .line 829
    move/from16 v19, v10

    .line 830
    .line 831
    const/4 v2, 0x0

    .line 832
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 833
    .line 834
    .line 835
    move/from16 v16, v17

    .line 836
    .line 837
    move/from16 v17, v18

    .line 838
    .line 839
    move/from16 v18, v19

    .line 840
    .line 841
    move-wide/from16 v3, v23

    .line 842
    .line 843
    move-object/from16 v0, v46

    .line 844
    .line 845
    goto/16 :goto_1e

    .line 846
    .line 847
    :cond_25
    move/from16 v1, v20

    .line 848
    .line 849
    move-object/from16 v20, v0

    .line 850
    .line 851
    move-object/from16 v0, v18

    .line 852
    .line 853
    move/from16 v18, v1

    .line 854
    .line 855
    move-object v1, v4

    .line 856
    move-object/from16 v46, v7

    .line 857
    .line 858
    move/from16 v17, v19

    .line 859
    .line 860
    move/from16 v19, v22

    .line 861
    .line 862
    const/4 v2, 0x0

    .line 863
    const v3, 0x43129304

    .line 864
    .line 865
    .line 866
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 867
    .line 868
    .line 869
    cmp-long v3, v23, v8

    .line 870
    .line 871
    if-nez v3, :cond_27

    .line 872
    .line 873
    move-object/from16 v4, v46

    .line 874
    .line 875
    if-eqz v4, :cond_26

    .line 876
    .line 877
    iget v11, v4, Lr4/k;->a:I

    .line 878
    .line 879
    const/4 v15, 0x0

    .line 880
    const v16, 0xff7fff

    .line 881
    .line 882
    .line 883
    move-object/from16 v27, v4

    .line 884
    .line 885
    const-wide/16 v3, 0x0

    .line 886
    .line 887
    const-wide/16 v5, 0x0

    .line 888
    .line 889
    const/4 v7, 0x0

    .line 890
    const/4 v8, 0x0

    .line 891
    const-wide/16 v9, 0x0

    .line 892
    .line 893
    const-wide/16 v12, 0x0

    .line 894
    .line 895
    const/4 v14, 0x0

    .line 896
    move-object/from16 p2, v0

    .line 897
    .line 898
    move-object/from16 v26, v1

    .line 899
    .line 900
    move v1, v2

    .line 901
    move-object/from16 v0, v27

    .line 902
    .line 903
    move-object/from16 v2, p1

    .line 904
    .line 905
    invoke-static/range {v2 .. v16}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 906
    .line 907
    .line 908
    move-result-object v3

    .line 909
    move-object/from16 v22, v3

    .line 910
    .line 911
    :goto_18
    move-wide/from16 v3, v23

    .line 912
    .line 913
    goto :goto_1d

    .line 914
    :cond_26
    move-object/from16 p2, v0

    .line 915
    .line 916
    move-object v0, v4

    .line 917
    :goto_19
    move-object/from16 v26, v1

    .line 918
    .line 919
    move v1, v2

    .line 920
    goto :goto_1a

    .line 921
    :cond_27
    move-object/from16 p2, v0

    .line 922
    .line 923
    move-object/from16 v0, v46

    .line 924
    .line 925
    goto :goto_19

    .line 926
    :goto_1a
    if-nez v3, :cond_28

    .line 927
    .line 928
    move-object/from16 v22, p1

    .line 929
    .line 930
    goto :goto_18

    .line 931
    :cond_28
    if-nez v3, :cond_2a

    .line 932
    .line 933
    :cond_29
    move-wide/from16 v3, v23

    .line 934
    .line 935
    goto :goto_1c

    .line 936
    :cond_2a
    if-eqz v0, :cond_29

    .line 937
    .line 938
    iget v11, v0, Lr4/k;->a:I

    .line 939
    .line 940
    const/4 v15, 0x0

    .line 941
    const v16, 0xff7ffe

    .line 942
    .line 943
    .line 944
    const-wide/16 v5, 0x0

    .line 945
    .line 946
    const/4 v7, 0x0

    .line 947
    const/4 v8, 0x0

    .line 948
    const-wide/16 v9, 0x0

    .line 949
    .line 950
    const-wide/16 v12, 0x0

    .line 951
    .line 952
    const/4 v14, 0x0

    .line 953
    move-object/from16 v2, p1

    .line 954
    .line 955
    move-wide/from16 v3, v23

    .line 956
    .line 957
    invoke-static/range {v2 .. v16}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 958
    .line 959
    .line 960
    move-result-object v5

    .line 961
    :goto_1b
    move-object/from16 v22, v5

    .line 962
    .line 963
    goto :goto_1d

    .line 964
    :goto_1c
    const/4 v15, 0x0

    .line 965
    const v16, 0xfffffe

    .line 966
    .line 967
    .line 968
    const-wide/16 v5, 0x0

    .line 969
    .line 970
    const/4 v7, 0x0

    .line 971
    const/4 v8, 0x0

    .line 972
    const-wide/16 v9, 0x0

    .line 973
    .line 974
    const/4 v11, 0x0

    .line 975
    const-wide/16 v12, 0x0

    .line 976
    .line 977
    const/4 v14, 0x0

    .line 978
    move-object/from16 v2, p1

    .line 979
    .line 980
    invoke-static/range {v2 .. v16}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 981
    .line 982
    .line 983
    move-result-object v5

    .line 984
    goto :goto_1b

    .line 985
    :goto_1d
    shr-int/lit8 v2, v25, 0x3

    .line 986
    .line 987
    and-int/lit8 v24, v2, 0x70

    .line 988
    .line 989
    shr-int/lit8 v2, v25, 0x6

    .line 990
    .line 991
    const v5, 0xff80

    .line 992
    .line 993
    .line 994
    and-int/2addr v2, v5

    .line 995
    shl-int/lit8 v5, v25, 0xc

    .line 996
    .line 997
    const/high16 v6, 0x1c00000

    .line 998
    .line 999
    and-int/2addr v5, v6

    .line 1000
    or-int v25, v2, v5

    .line 1001
    .line 1002
    move-object/from16 v13, v26

    .line 1003
    .line 1004
    const v26, 0x18ffc

    .line 1005
    .line 1006
    .line 1007
    const-wide/16 v7, 0x0

    .line 1008
    .line 1009
    const-wide/16 v9, 0x0

    .line 1010
    .line 1011
    const-wide/16 v11, 0x0

    .line 1012
    .line 1013
    move-object/from16 v23, v13

    .line 1014
    .line 1015
    const/4 v13, 0x0

    .line 1016
    const-wide/16 v14, 0x0

    .line 1017
    .line 1018
    move/from16 v16, v17

    .line 1019
    .line 1020
    move/from16 v17, v18

    .line 1021
    .line 1022
    move/from16 v18, v19

    .line 1023
    .line 1024
    const/16 v19, 0x0

    .line 1025
    .line 1026
    move-object/from16 v5, v20

    .line 1027
    .line 1028
    const/16 v20, 0x0

    .line 1029
    .line 1030
    move-object/from16 v6, p2

    .line 1031
    .line 1032
    invoke-static/range {v5 .. v26}, Lh2/rb;->c(Lg4/g;Lx2/s;JJJLr4/k;JIZIILjava/util/Map;Lay0/k;Lg4/p0;Ll2/o;III)V

    .line 1033
    .line 1034
    .line 1035
    move-object/from16 v13, v23

    .line 1036
    .line 1037
    invoke-virtual {v13, v1}, Ll2/t;->q(Z)V

    .line 1038
    .line 1039
    .line 1040
    :goto_1e
    move-object v10, v0

    .line 1041
    move-wide v8, v3

    .line 1042
    move-object v3, v6

    .line 1043
    move/from16 v5, v16

    .line 1044
    .line 1045
    move/from16 v6, v17

    .line 1046
    .line 1047
    move/from16 v7, v18

    .line 1048
    .line 1049
    move-object/from16 v4, v21

    .line 1050
    .line 1051
    goto :goto_1f

    .line 1052
    :cond_2b
    move-object v13, v4

    .line 1053
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1054
    .line 1055
    .line 1056
    move/from16 v5, p4

    .line 1057
    .line 1058
    move/from16 v6, p5

    .line 1059
    .line 1060
    move/from16 v7, p6

    .line 1061
    .line 1062
    move-object v3, v8

    .line 1063
    move-object v4, v10

    .line 1064
    move-wide v8, v11

    .line 1065
    move-object v10, v14

    .line 1066
    :goto_1f
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v13

    .line 1070
    if-eqz v13, :cond_2c

    .line 1071
    .line 1072
    new-instance v0, Le71/r;

    .line 1073
    .line 1074
    move-object/from16 v1, p0

    .line 1075
    .line 1076
    move-object/from16 v2, p1

    .line 1077
    .line 1078
    move/from16 v11, p11

    .line 1079
    .line 1080
    move/from16 v12, p12

    .line 1081
    .line 1082
    invoke-direct/range {v0 .. v12}, Le71/r;-><init>(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;II)V

    .line 1083
    .line 1084
    .line 1085
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 1086
    .line 1087
    :cond_2c
    return-void
.end method

.method public static final b(Lql0/j;Ll2/o;II)V
    .locals 23

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    const-string v0, "<this>"

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v8, 0x1

    .line 9
    and-int/lit8 v0, p3, 0x1

    .line 10
    .line 11
    const/4 v9, 0x0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    move v10, v9

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v10, v8

    .line 17
    :goto_0
    and-int/lit8 v0, p2, 0xe

    .line 18
    .line 19
    xor-int/lit8 v11, v0, 0x6

    .line 20
    .line 21
    const/4 v12, 0x4

    .line 22
    if-le v11, v12, :cond_2

    .line 23
    .line 24
    move-object/from16 v0, p1

    .line 25
    .line 26
    check-cast v0, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v0, v8

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    :goto_1
    move v0, v9

    .line 38
    :goto_2
    move-object/from16 v13, p1

    .line 39
    .line 40
    check-cast v13, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 47
    .line 48
    if-nez v0, :cond_3

    .line 49
    .line 50
    if-ne v1, v14, :cond_4

    .line 51
    .line 52
    :cond_3
    new-instance v0, Lr40/b;

    .line 53
    .line 54
    const/4 v6, 0x0

    .line 55
    const/16 v7, 0x12

    .line 56
    .line 57
    const/4 v1, 0x0

    .line 58
    const-class v3, Lql0/j;

    .line 59
    .line 60
    const-string v4, "onActive"

    .line 61
    .line 62
    const-string v5, "onActive()V"

    .line 63
    .line 64
    invoke-direct/range {v0 .. v7}, Lr40/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v13, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    move-object v1, v0

    .line 71
    :cond_4
    check-cast v1, Lhy0/g;

    .line 72
    .line 73
    move-object v15, v1

    .line 74
    check-cast v15, Lay0/a;

    .line 75
    .line 76
    if-le v11, v12, :cond_6

    .line 77
    .line 78
    invoke-virtual {v13, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-nez v0, :cond_5

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_5
    move v0, v8

    .line 86
    goto :goto_4

    .line 87
    :cond_6
    :goto_3
    move v0, v9

    .line 88
    :goto_4
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    if-nez v0, :cond_7

    .line 93
    .line 94
    if-ne v1, v14, :cond_8

    .line 95
    .line 96
    :cond_7
    new-instance v0, Lr40/b;

    .line 97
    .line 98
    const/4 v6, 0x0

    .line 99
    const/16 v7, 0x13

    .line 100
    .line 101
    const/4 v1, 0x0

    .line 102
    const-class v3, Lql0/j;

    .line 103
    .line 104
    const-string v4, "onInactive"

    .line 105
    .line 106
    const-string v5, "onInactive()V"

    .line 107
    .line 108
    invoke-direct/range {v0 .. v7}, Lr40/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v13, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    move-object v1, v0

    .line 115
    :cond_8
    check-cast v1, Lhy0/g;

    .line 116
    .line 117
    move-object/from16 v18, v1

    .line 118
    .line 119
    check-cast v18, Lay0/a;

    .line 120
    .line 121
    and-int/lit8 v0, p2, 0x70

    .line 122
    .line 123
    xor-int/lit8 v0, v0, 0x30

    .line 124
    .line 125
    const/16 v1, 0x20

    .line 126
    .line 127
    if-le v0, v1, :cond_9

    .line 128
    .line 129
    invoke-virtual {v13, v10}, Ll2/t;->h(Z)Z

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    if-nez v0, :cond_a

    .line 134
    .line 135
    :cond_9
    and-int/lit8 v0, p2, 0x30

    .line 136
    .line 137
    if-ne v0, v1, :cond_b

    .line 138
    .line 139
    :cond_a
    move v0, v8

    .line 140
    goto :goto_5

    .line 141
    :cond_b
    move v0, v9

    .line 142
    :goto_5
    if-le v11, v12, :cond_c

    .line 143
    .line 144
    invoke-virtual {v13, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-nez v1, :cond_d

    .line 149
    .line 150
    :cond_c
    move v8, v9

    .line 151
    :cond_d
    or-int/2addr v0, v8

    .line 152
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    if-nez v0, :cond_e

    .line 157
    .line 158
    if-ne v1, v14, :cond_f

    .line 159
    .line 160
    :cond_e
    new-instance v1, Lc/d;

    .line 161
    .line 162
    const/16 v0, 0xa

    .line 163
    .line 164
    invoke-direct {v1, v10, v2, v0}, Lc/d;-><init>(ZLjava/lang/Object;I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v13, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    :cond_f
    move-object/from16 v19, v1

    .line 171
    .line 172
    check-cast v19, Lay0/a;

    .line 173
    .line 174
    const/16 v21, 0x0

    .line 175
    .line 176
    const/16 v22, 0x5b

    .line 177
    .line 178
    move-object/from16 v20, v13

    .line 179
    .line 180
    const/4 v13, 0x0

    .line 181
    const/4 v14, 0x0

    .line 182
    const/16 v16, 0x0

    .line 183
    .line 184
    const/16 v17, 0x0

    .line 185
    .line 186
    invoke-static/range {v13 .. v22}, Lxf0/i0;->z(Landroidx/lifecycle/x;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 187
    .line 188
    .line 189
    return-void
.end method
