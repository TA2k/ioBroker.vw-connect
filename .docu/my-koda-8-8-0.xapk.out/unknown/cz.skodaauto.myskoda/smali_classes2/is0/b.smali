.class public abstract Lis0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(IJLa7/a2;Lay0/n;Ll2/o;)V
    .locals 21

    .line 1
    move-wide/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move-object/from16 v9, p5

    .line 6
    .line 7
    check-cast v9, Ll2/t;

    .line 8
    .line 9
    const v0, 0x5af55f46

    .line 10
    .line 11
    .line 12
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v9, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v1, 0x2

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v1

    .line 25
    :goto_0
    or-int v0, p0, v0

    .line 26
    .line 27
    invoke-virtual {v9, v2, v3}, Ll2/t;->f(J)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_1

    .line 32
    .line 33
    const/16 v5, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v5, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v0, v5

    .line 39
    move-object/from16 v5, p4

    .line 40
    .line 41
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_2

    .line 46
    .line 47
    const/16 v6, 0x100

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v6, 0x80

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v6

    .line 53
    and-int/lit16 v6, v0, 0x93

    .line 54
    .line 55
    const/16 v7, 0x92

    .line 56
    .line 57
    if-ne v6, v7, :cond_4

    .line 58
    .line 59
    invoke-virtual {v9}, Ll2/t;->A()Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-nez v6, :cond_3

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_11

    .line 70
    .line 71
    :cond_4
    :goto_3
    instance-of v6, v4, La7/z1;

    .line 72
    .line 73
    const/16 v7, 0xa

    .line 74
    .line 75
    const/4 v8, 0x0

    .line 76
    if-eqz v6, :cond_5

    .line 77
    .line 78
    const v1, -0x45f2ce04

    .line 79
    .line 80
    .line 81
    invoke-virtual {v9, v1}, Ll2/t;->Z(I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 85
    .line 86
    .line 87
    new-instance v1, Lt4/h;

    .line 88
    .line 89
    invoke-direct {v1, v2, v3}, Lt4/h;-><init>(J)V

    .line 90
    .line 91
    .line 92
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    check-cast v1, Ljava/util/Collection;

    .line 97
    .line 98
    goto/16 :goto_f

    .line 99
    .line 100
    :cond_5
    instance-of v6, v4, La7/x1;

    .line 101
    .line 102
    const/16 v10, 0x1f

    .line 103
    .line 104
    if-eqz v6, :cond_f

    .line 105
    .line 106
    const v1, -0x45f2c76c

    .line 107
    .line 108
    .line 109
    invoke-virtual {v9, v1}, Ll2/t;->Z(I)V

    .line 110
    .line 111
    .line 112
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 113
    .line 114
    if-lt v1, v10, :cond_d

    .line 115
    .line 116
    const v1, -0x7865729c

    .line 117
    .line 118
    .line 119
    invoke-virtual {v9, v1}, Ll2/t;->Z(I)V

    .line 120
    .line 121
    .line 122
    sget-object v1, La7/x;->a:Ll2/e0;

    .line 123
    .line 124
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    check-cast v1, Landroid/os/Bundle;

    .line 129
    .line 130
    const v6, -0x45f2ba68

    .line 131
    .line 132
    .line 133
    invoke-virtual {v9, v6}, Ll2/t;->Z(I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v9, v2, v3}, Ll2/t;->f(J)Z

    .line 137
    .line 138
    .line 139
    move-result v6

    .line 140
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v10

    .line 144
    if-nez v6, :cond_6

    .line 145
    .line 146
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 147
    .line 148
    if-ne v10, v6, :cond_7

    .line 149
    .line 150
    :cond_6
    new-instance v10, La7/u1;

    .line 151
    .line 152
    invoke-direct {v10, v2, v3}, La7/u1;-><init>(J)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_7
    check-cast v10, Lay0/a;

    .line 159
    .line 160
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 161
    .line 162
    .line 163
    const-string v6, "appWidgetSizes"

    .line 164
    .line 165
    invoke-virtual {v1, v6}, Landroid/os/Bundle;->getParcelableArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 166
    .line 167
    .line 168
    move-result-object v6

    .line 169
    if-eqz v6, :cond_9

    .line 170
    .line 171
    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    .line 172
    .line 173
    .line 174
    move-result v11

    .line 175
    if-eqz v11, :cond_8

    .line 176
    .line 177
    goto :goto_5

    .line 178
    :cond_8
    new-instance v1, Ljava/util/ArrayList;

    .line 179
    .line 180
    invoke-static {v6, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 181
    .line 182
    .line 183
    move-result v10

    .line 184
    invoke-direct {v1, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 185
    .line 186
    .line 187
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 188
    .line 189
    .line 190
    move-result-object v6

    .line 191
    :goto_4
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 192
    .line 193
    .line 194
    move-result v10

    .line 195
    if-eqz v10, :cond_c

    .line 196
    .line 197
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v10

    .line 201
    check-cast v10, Landroid/util/SizeF;

    .line 202
    .line 203
    invoke-virtual {v10}, Landroid/util/SizeF;->getWidth()F

    .line 204
    .line 205
    .line 206
    move-result v11

    .line 207
    invoke-virtual {v10}, Landroid/util/SizeF;->getHeight()F

    .line 208
    .line 209
    .line 210
    move-result v10

    .line 211
    invoke-static {v11, v10}, Lkp/c9;->a(FF)J

    .line 212
    .line 213
    .line 214
    move-result-wide v10

    .line 215
    new-instance v12, Lt4/h;

    .line 216
    .line 217
    invoke-direct {v12, v10, v11}, Lt4/h;-><init>(J)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v1, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_9
    :goto_5
    const-string v6, "appWidgetMinHeight"

    .line 225
    .line 226
    invoke-virtual {v1, v6, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 227
    .line 228
    .line 229
    move-result v6

    .line 230
    const-string v11, "appWidgetMaxHeight"

    .line 231
    .line 232
    invoke-virtual {v1, v11, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 233
    .line 234
    .line 235
    move-result v11

    .line 236
    const-string v12, "appWidgetMinWidth"

    .line 237
    .line 238
    invoke-virtual {v1, v12, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 239
    .line 240
    .line 241
    move-result v12

    .line 242
    const-string v13, "appWidgetMaxWidth"

    .line 243
    .line 244
    invoke-virtual {v1, v13, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    if-eqz v6, :cond_b

    .line 249
    .line 250
    if-eqz v11, :cond_b

    .line 251
    .line 252
    if-eqz v12, :cond_b

    .line 253
    .line 254
    if-nez v1, :cond_a

    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_a
    int-to-float v10, v12

    .line 258
    int-to-float v11, v11

    .line 259
    invoke-static {v10, v11}, Lkp/c9;->a(FF)J

    .line 260
    .line 261
    .line 262
    move-result-wide v10

    .line 263
    new-instance v12, Lt4/h;

    .line 264
    .line 265
    invoke-direct {v12, v10, v11}, Lt4/h;-><init>(J)V

    .line 266
    .line 267
    .line 268
    int-to-float v1, v1

    .line 269
    int-to-float v6, v6

    .line 270
    invoke-static {v1, v6}, Lkp/c9;->a(FF)J

    .line 271
    .line 272
    .line 273
    move-result-wide v10

    .line 274
    new-instance v1, Lt4/h;

    .line 275
    .line 276
    invoke-direct {v1, v10, v11}, Lt4/h;-><init>(J)V

    .line 277
    .line 278
    .line 279
    filled-new-array {v12, v1}, [Lt4/h;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 284
    .line 285
    .line 286
    move-result-object v1

    .line 287
    goto :goto_7

    .line 288
    :cond_b
    :goto_6
    invoke-interface {v10}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 293
    .line 294
    .line 295
    move-result-object v1

    .line 296
    :cond_c
    :goto_7
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 297
    .line 298
    .line 299
    goto :goto_8

    .line 300
    :cond_d
    const v1, -0x78641c47

    .line 301
    .line 302
    .line 303
    invoke-virtual {v9, v1}, Ll2/t;->Z(I)V

    .line 304
    .line 305
    .line 306
    sget-object v1, La7/x;->a:Ll2/e0;

    .line 307
    .line 308
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v1

    .line 312
    check-cast v1, Landroid/os/Bundle;

    .line 313
    .line 314
    invoke-static {v1}, Lcy0/a;->g(Landroid/os/Bundle;)Ljava/util/List;

    .line 315
    .line 316
    .line 317
    move-result-object v1

    .line 318
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 319
    .line 320
    .line 321
    move-result v6

    .line 322
    if-eqz v6, :cond_e

    .line 323
    .line 324
    new-instance v1, Lt4/h;

    .line 325
    .line 326
    invoke-direct {v1, v2, v3}, Lt4/h;-><init>(J)V

    .line 327
    .line 328
    .line 329
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    :cond_e
    check-cast v1, Ljava/util/List;

    .line 334
    .line 335
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 336
    .line 337
    .line 338
    :goto_8
    invoke-virtual {v9, v8}, Ll2/t;->q(Z)V

    .line 339
    .line 340
    .line 341
    check-cast v1, Ljava/util/Collection;

    .line 342
    .line 343
    goto/16 :goto_f

    .line 344
    .line 345
    :cond_f
    instance-of v6, v4, La7/y1;

    .line 346
    .line 347
    if-eqz v6, :cond_1f

    .line 348
    .line 349
    const v6, -0x78619584

    .line 350
    .line 351
    .line 352
    invoke-virtual {v9, v6}, Ll2/t;->Z(I)V

    .line 353
    .line 354
    .line 355
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 356
    .line 357
    if-lt v6, v10, :cond_10

    .line 358
    .line 359
    move-object v1, v4

    .line 360
    check-cast v1, La7/y1;

    .line 361
    .line 362
    iget-object v1, v1, La7/y1;->a:Ljava/util/Set;

    .line 363
    .line 364
    check-cast v1, Ljava/util/Collection;

    .line 365
    .line 366
    move v2, v8

    .line 367
    goto/16 :goto_e

    .line 368
    .line 369
    :cond_10
    move-object v6, v4

    .line 370
    check-cast v6, La7/y1;

    .line 371
    .line 372
    iget-object v6, v6, La7/y1;->a:Ljava/util/Set;

    .line 373
    .line 374
    check-cast v6, Ljava/util/Collection;

    .line 375
    .line 376
    check-cast v6, Ljava/lang/Iterable;

    .line 377
    .line 378
    new-array v1, v1, [Lay0/k;

    .line 379
    .line 380
    sget-object v10, La7/s;->g:La7/s;

    .line 381
    .line 382
    aput-object v10, v1, v8

    .line 383
    .line 384
    sget-object v10, La7/s;->h:La7/s;

    .line 385
    .line 386
    const/4 v11, 0x1

    .line 387
    aput-object v10, v1, v11

    .line 388
    .line 389
    invoke-static {v1}, Ljp/vc;->b([Lay0/k;)Ld4/a0;

    .line 390
    .line 391
    .line 392
    move-result-object v1

    .line 393
    invoke-static {v6, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    invoke-interface {v1, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v1

    .line 401
    check-cast v1, Lt4/h;

    .line 402
    .line 403
    iget-wide v12, v1, Lt4/h;->a:J

    .line 404
    .line 405
    sget-object v1, La7/x;->a:Ll2/e0;

    .line 406
    .line 407
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    check-cast v1, Landroid/os/Bundle;

    .line 412
    .line 413
    invoke-static {v1}, Lcy0/a;->g(Landroid/os/Bundle;)Ljava/util/List;

    .line 414
    .line 415
    .line 416
    move-result-object v1

    .line 417
    new-instance v10, Ljava/util/ArrayList;

    .line 418
    .line 419
    invoke-static {v1, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 420
    .line 421
    .line 422
    move-result v14

    .line 423
    invoke-direct {v10, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 424
    .line 425
    .line 426
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 427
    .line 428
    .line 429
    move-result-object v1

    .line 430
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 431
    .line 432
    .line 433
    move-result v14

    .line 434
    if-eqz v14, :cond_1b

    .line 435
    .line 436
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v14

    .line 440
    check-cast v14, Lt4/h;

    .line 441
    .line 442
    iget-wide v14, v14, Lt4/h;->a:J

    .line 443
    .line 444
    new-instance v7, Ljava/util/ArrayList;

    .line 445
    .line 446
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 447
    .line 448
    .line 449
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 450
    .line 451
    .line 452
    move-result-object v16

    .line 453
    :goto_a
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->hasNext()Z

    .line 454
    .line 455
    .line 456
    move-result v17

    .line 457
    const/16 v18, 0x0

    .line 458
    .line 459
    if-eqz v17, :cond_14

    .line 460
    .line 461
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object v17

    .line 465
    move-object/from16 v8, v17

    .line 466
    .line 467
    check-cast v8, Lt4/h;

    .line 468
    .line 469
    move-wide/from16 v19, v12

    .line 470
    .line 471
    iget-wide v11, v8, Lt4/h;->a:J

    .line 472
    .line 473
    invoke-static {v14, v15}, Lt4/h;->c(J)F

    .line 474
    .line 475
    .line 476
    move-result v8

    .line 477
    move-object v3, v1

    .line 478
    float-to-double v1, v8

    .line 479
    invoke-static {v1, v2}, Ljava/lang/Math;->ceil(D)D

    .line 480
    .line 481
    .line 482
    move-result-wide v1

    .line 483
    double-to-float v1, v1

    .line 484
    const/4 v2, 0x1

    .line 485
    int-to-float v8, v2

    .line 486
    add-float/2addr v1, v8

    .line 487
    invoke-static {v11, v12}, Lt4/h;->c(J)F

    .line 488
    .line 489
    .line 490
    move-result v13

    .line 491
    cmpl-float v1, v1, v13

    .line 492
    .line 493
    if-lez v1, :cond_11

    .line 494
    .line 495
    invoke-static {v14, v15}, Lt4/h;->b(J)F

    .line 496
    .line 497
    .line 498
    move-result v1

    .line 499
    move-object v13, v3

    .line 500
    float-to-double v2, v1

    .line 501
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 502
    .line 503
    .line 504
    move-result-wide v1

    .line 505
    double-to-float v1, v1

    .line 506
    add-float/2addr v1, v8

    .line 507
    invoke-static {v11, v12}, Lt4/h;->b(J)F

    .line 508
    .line 509
    .line 510
    move-result v2

    .line 511
    cmpl-float v1, v1, v2

    .line 512
    .line 513
    if-lez v1, :cond_12

    .line 514
    .line 515
    new-instance v1, Lt4/h;

    .line 516
    .line 517
    invoke-direct {v1, v11, v12}, Lt4/h;-><init>(J)V

    .line 518
    .line 519
    .line 520
    invoke-static {v14, v15}, Lt4/h;->c(J)F

    .line 521
    .line 522
    .line 523
    move-result v2

    .line 524
    invoke-static {v11, v12}, Lt4/h;->c(J)F

    .line 525
    .line 526
    .line 527
    move-result v3

    .line 528
    sub-float/2addr v2, v3

    .line 529
    invoke-static {v14, v15}, Lt4/h;->b(J)F

    .line 530
    .line 531
    .line 532
    move-result v3

    .line 533
    invoke-static {v11, v12}, Lt4/h;->b(J)F

    .line 534
    .line 535
    .line 536
    move-result v8

    .line 537
    sub-float/2addr v3, v8

    .line 538
    mul-float/2addr v2, v2

    .line 539
    mul-float/2addr v3, v3

    .line 540
    add-float/2addr v3, v2

    .line 541
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 542
    .line 543
    .line 544
    move-result-object v2

    .line 545
    new-instance v3, Llx0/l;

    .line 546
    .line 547
    invoke-direct {v3, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 548
    .line 549
    .line 550
    goto :goto_b

    .line 551
    :cond_11
    move-object v13, v3

    .line 552
    :cond_12
    move-object/from16 v3, v18

    .line 553
    .line 554
    :goto_b
    if-eqz v3, :cond_13

    .line 555
    .line 556
    invoke-virtual {v7, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 557
    .line 558
    .line 559
    :cond_13
    move-wide/from16 v2, p1

    .line 560
    .line 561
    move-object v1, v13

    .line 562
    move-wide/from16 v12, v19

    .line 563
    .line 564
    const/4 v8, 0x0

    .line 565
    const/4 v11, 0x1

    .line 566
    goto :goto_a

    .line 567
    :cond_14
    move-wide/from16 v19, v12

    .line 568
    .line 569
    move-object v13, v1

    .line 570
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 571
    .line 572
    .line 573
    move-result-object v1

    .line 574
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 575
    .line 576
    .line 577
    move-result v2

    .line 578
    if-nez v2, :cond_15

    .line 579
    .line 580
    move-object/from16 v2, v18

    .line 581
    .line 582
    goto :goto_c

    .line 583
    :cond_15
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 584
    .line 585
    .line 586
    move-result-object v2

    .line 587
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 588
    .line 589
    .line 590
    move-result v3

    .line 591
    if-nez v3, :cond_16

    .line 592
    .line 593
    goto :goto_c

    .line 594
    :cond_16
    move-object v3, v2

    .line 595
    check-cast v3, Llx0/l;

    .line 596
    .line 597
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v3, Ljava/lang/Number;

    .line 600
    .line 601
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 602
    .line 603
    .line 604
    move-result v3

    .line 605
    :cond_17
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    move-result-object v7

    .line 609
    move-object v8, v7

    .line 610
    check-cast v8, Llx0/l;

    .line 611
    .line 612
    iget-object v8, v8, Llx0/l;->e:Ljava/lang/Object;

    .line 613
    .line 614
    check-cast v8, Ljava/lang/Number;

    .line 615
    .line 616
    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    .line 617
    .line 618
    .line 619
    move-result v8

    .line 620
    invoke-static {v3, v8}, Ljava/lang/Float;->compare(FF)I

    .line 621
    .line 622
    .line 623
    move-result v11

    .line 624
    if-lez v11, :cond_18

    .line 625
    .line 626
    move-object v2, v7

    .line 627
    move v3, v8

    .line 628
    :cond_18
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 629
    .line 630
    .line 631
    move-result v7

    .line 632
    if-nez v7, :cond_17

    .line 633
    .line 634
    :goto_c
    check-cast v2, Llx0/l;

    .line 635
    .line 636
    if-eqz v2, :cond_19

    .line 637
    .line 638
    iget-object v1, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 639
    .line 640
    move-object/from16 v18, v1

    .line 641
    .line 642
    check-cast v18, Lt4/h;

    .line 643
    .line 644
    :cond_19
    move-object/from16 v1, v18

    .line 645
    .line 646
    if-eqz v1, :cond_1a

    .line 647
    .line 648
    iget-wide v1, v1, Lt4/h;->a:J

    .line 649
    .line 650
    goto :goto_d

    .line 651
    :cond_1a
    move-wide/from16 v1, v19

    .line 652
    .line 653
    :goto_d
    new-instance v3, Lt4/h;

    .line 654
    .line 655
    invoke-direct {v3, v1, v2}, Lt4/h;-><init>(J)V

    .line 656
    .line 657
    .line 658
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 659
    .line 660
    .line 661
    move-wide/from16 v2, p1

    .line 662
    .line 663
    move-object v1, v13

    .line 664
    move-wide/from16 v12, v19

    .line 665
    .line 666
    const/16 v7, 0xa

    .line 667
    .line 668
    const/4 v8, 0x0

    .line 669
    const/4 v11, 0x1

    .line 670
    goto/16 :goto_9

    .line 671
    .line 672
    :cond_1b
    move-wide/from16 v19, v12

    .line 673
    .line 674
    invoke-virtual {v10}, Ljava/util/ArrayList;->isEmpty()Z

    .line 675
    .line 676
    .line 677
    move-result v1

    .line 678
    if-eqz v1, :cond_1c

    .line 679
    .line 680
    new-instance v1, Lt4/h;

    .line 681
    .line 682
    move-wide/from16 v2, v19

    .line 683
    .line 684
    invoke-direct {v1, v2, v3}, Lt4/h;-><init>(J)V

    .line 685
    .line 686
    .line 687
    new-instance v6, Lt4/h;

    .line 688
    .line 689
    invoke-direct {v6, v2, v3}, Lt4/h;-><init>(J)V

    .line 690
    .line 691
    .line 692
    filled-new-array {v1, v6}, [Lt4/h;

    .line 693
    .line 694
    .line 695
    move-result-object v1

    .line 696
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 697
    .line 698
    .line 699
    move-result-object v10

    .line 700
    :cond_1c
    check-cast v10, Ljava/util/Collection;

    .line 701
    .line 702
    move-object v1, v10

    .line 703
    const/4 v2, 0x0

    .line 704
    :goto_e
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 705
    .line 706
    .line 707
    :goto_f
    check-cast v1, Ljava/lang/Iterable;

    .line 708
    .line 709
    invoke-static {v1}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    .line 710
    .line 711
    .line 712
    move-result-object v1

    .line 713
    check-cast v1, Ljava/lang/Iterable;

    .line 714
    .line 715
    new-instance v2, Ljava/util/ArrayList;

    .line 716
    .line 717
    const/16 v3, 0xa

    .line 718
    .line 719
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 720
    .line 721
    .line 722
    move-result v3

    .line 723
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 724
    .line 725
    .line 726
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 727
    .line 728
    .line 729
    move-result-object v1

    .line 730
    :goto_10
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 731
    .line 732
    .line 733
    move-result v3

    .line 734
    if-eqz v3, :cond_1d

    .line 735
    .line 736
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 737
    .line 738
    .line 739
    move-result-object v3

    .line 740
    check-cast v3, Lt4/h;

    .line 741
    .line 742
    iget-wide v6, v3, Lt4/h;->a:J

    .line 743
    .line 744
    shl-int/lit8 v3, v0, 0x3

    .line 745
    .line 746
    and-int/lit8 v3, v3, 0x70

    .line 747
    .line 748
    and-int/lit16 v8, v0, 0x380

    .line 749
    .line 750
    or-int/2addr v3, v8

    .line 751
    move-object v8, v5

    .line 752
    move-wide v5, v6

    .line 753
    move-object v7, v4

    .line 754
    move v4, v3

    .line 755
    invoke-static/range {v4 .. v9}, Lis0/b;->b(IJLa7/a2;Lay0/n;Ll2/o;)V

    .line 756
    .line 757
    .line 758
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 759
    .line 760
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 761
    .line 762
    .line 763
    move-object/from16 v4, p3

    .line 764
    .line 765
    move-object/from16 v5, p4

    .line 766
    .line 767
    goto :goto_10

    .line 768
    :cond_1d
    :goto_11
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 769
    .line 770
    .line 771
    move-result-object v6

    .line 772
    if-eqz v6, :cond_1e

    .line 773
    .line 774
    new-instance v0, La7/t1;

    .line 775
    .line 776
    move/from16 v1, p0

    .line 777
    .line 778
    move-wide/from16 v2, p1

    .line 779
    .line 780
    move-object/from16 v4, p3

    .line 781
    .line 782
    move-object/from16 v5, p4

    .line 783
    .line 784
    invoke-direct/range {v0 .. v5}, La7/t1;-><init>(IJLa7/a2;Lay0/n;)V

    .line 785
    .line 786
    .line 787
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 788
    .line 789
    :cond_1e
    return-void

    .line 790
    :cond_1f
    const v0, -0x45f46993

    .line 791
    .line 792
    .line 793
    invoke-virtual {v9, v0}, Ll2/t;->Z(I)V

    .line 794
    .line 795
    .line 796
    const/4 v2, 0x0

    .line 797
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 798
    .line 799
    .line 800
    new-instance v0, La8/r0;

    .line 801
    .line 802
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 803
    .line 804
    .line 805
    throw v0
.end method

.method public static final b(IJLa7/a2;Lay0/n;Ll2/o;)V
    .locals 6

    .line 1
    check-cast p5, Ll2/t;

    .line 2
    .line 3
    const v0, -0x336c667

    .line 4
    .line 5
    .line 6
    invoke-virtual {p5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p5, p1, p2}, Ll2/t;->f(J)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p0

    .line 19
    and-int/lit8 v1, p0, 0x30

    .line 20
    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    and-int/lit8 v1, p0, 0x40

    .line 24
    .line 25
    invoke-virtual {p5, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    const/16 v1, 0x20

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const/16 v1, 0x10

    .line 35
    .line 36
    :goto_1
    or-int/2addr v0, v1

    .line 37
    :cond_2
    invoke-virtual {p5, p4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    const/16 v1, 0x100

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_3
    const/16 v1, 0x80

    .line 47
    .line 48
    :goto_2
    or-int/2addr v0, v1

    .line 49
    and-int/lit16 v0, v0, 0x93

    .line 50
    .line 51
    const/16 v1, 0x92

    .line 52
    .line 53
    if-ne v0, v1, :cond_5

    .line 54
    .line 55
    invoke-virtual {p5}, Ll2/t;->A()Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-nez v0, :cond_4

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_4
    invoke-virtual {p5}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    goto :goto_4

    .line 66
    :cond_5
    :goto_3
    sget-object v0, Ly6/k;->a:Ll2/u2;

    .line 67
    .line 68
    new-instance v1, Lt4/h;

    .line 69
    .line 70
    invoke-direct {v1, p1, p2}, Lt4/h;-><init>(J)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    filled-new-array {v0}, [Ll2/t1;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    new-instance v1, La7/t1;

    .line 82
    .line 83
    invoke-direct {v1, p4, p1, p2, p3}, La7/t1;-><init>(Lay0/n;JLa7/a2;)V

    .line 84
    .line 85
    .line 86
    const v2, -0x481c5327

    .line 87
    .line 88
    .line 89
    invoke-static {v2, p5, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    const/16 v2, 0x30

    .line 94
    .line 95
    invoke-static {v0, v1, p5, v2}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 96
    .line 97
    .line 98
    :goto_4
    invoke-virtual {p5}, Ll2/t;->s()Ll2/u1;

    .line 99
    .line 100
    .line 101
    move-result-object p5

    .line 102
    if-eqz p5, :cond_6

    .line 103
    .line 104
    new-instance v0, La7/w1;

    .line 105
    .line 106
    move v1, p0

    .line 107
    move-wide v2, p1

    .line 108
    move-object v4, p3

    .line 109
    move-object v5, p4

    .line 110
    invoke-direct/range {v0 .. v5}, La7/w1;-><init>(IJLa7/a2;Lay0/n;)V

    .line 111
    .line 112
    .line 113
    iput-object v0, p5, Ll2/u1;->d:Lay0/n;

    .line 114
    .line 115
    :cond_6
    return-void
.end method

.method public static final c(Ljava/util/Collection;)Ljava/util/ArrayList;
    .locals 2

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lio/opentelemetry/sdk/trace/data/SpanData;

    .line 29
    .line 30
    invoke-interface {v1}, Lio/opentelemetry/sdk/trace/data/SpanData;->getSpanId()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    return-object v0
.end method

.method public static final d(Lqr0/i;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;
    .locals 2

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    iget-wide v0, p0, Lqr0/i;->a:D

    .line 4
    .line 5
    invoke-static {v0, v1, p1}, Lkp/i6;->d(DLqr0/s;)D

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const/4 p0, 0x1

    .line 10
    invoke-static {p0, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    :cond_0
    sget-object p0, Lqr0/s;->d:Lqr0/s;

    .line 15
    .line 16
    if-ne p1, p0, :cond_2

    .line 17
    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    invoke-static {p1}, Lkp/i6;->c(Lqr0/s;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    sget-object p0, Lqr0/t;->e:Lqr0/t;

    .line 26
    .line 27
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    goto :goto_0

    .line 32
    :cond_2
    invoke-static {p1}, Lkp/i6;->c(Lqr0/s;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    :goto_0
    const-string p1, " "

    .line 37
    .line 38
    invoke-static {p2, p1, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public static final e(Lqr0/g;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;
    .locals 2

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    iget-wide v0, p0, Lqr0/g;->a:D

    .line 4
    .line 5
    invoke-static {v0, v1, p1}, Lkp/g6;->d(DLqr0/s;)D

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    const/4 p0, 0x1

    .line 10
    invoke-static {p0, v0, v1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    :cond_0
    sget-object p0, Lqr0/s;->d:Lqr0/s;

    .line 15
    .line 16
    if-ne p1, p0, :cond_2

    .line 17
    .line 18
    if-eqz p3, :cond_1

    .line 19
    .line 20
    invoke-static {p1}, Lkp/g6;->c(Lqr0/s;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    sget-object p0, Lqr0/o;->f:Lqr0/o;

    .line 26
    .line 27
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    goto :goto_0

    .line 32
    :cond_2
    invoke-static {p1}, Lkp/g6;->c(Lqr0/s;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    :goto_0
    const-string p1, " "

    .line 37
    .line 38
    invoke-static {p2, p1, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
