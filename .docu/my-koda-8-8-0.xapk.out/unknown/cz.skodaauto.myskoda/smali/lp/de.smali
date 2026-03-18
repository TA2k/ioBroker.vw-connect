.class public abstract Llp/de;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroidx/compose/foundation/lazy/a;Lx21/y;Ljava/lang/Integer;Lx2/s;ZLx2/s;Lt2/b;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move/from16 v0, p8

    .line 8
    .line 9
    const-string v4, "<this>"

    .line 10
    .line 11
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    move-object/from16 v8, p7

    .line 15
    .line 16
    check-cast v8, Ll2/t;

    .line 17
    .line 18
    const v4, 0x14a43791

    .line 19
    .line 20
    .line 21
    invoke-virtual {v8, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v0, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    if-eqz v4, :cond_0

    .line 33
    .line 34
    const/4 v4, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v4, 0x2

    .line 37
    :goto_0
    or-int/2addr v4, v0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v4, v0

    .line 40
    :goto_1
    and-int/lit8 v5, v0, 0x30

    .line 41
    .line 42
    const/16 v6, 0x20

    .line 43
    .line 44
    if-nez v5, :cond_3

    .line 45
    .line 46
    invoke-virtual {v8, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    if-eqz v5, :cond_2

    .line 51
    .line 52
    move v5, v6

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/16 v5, 0x10

    .line 55
    .line 56
    :goto_2
    or-int/2addr v4, v5

    .line 57
    :cond_3
    and-int/lit16 v5, v0, 0x180

    .line 58
    .line 59
    if-nez v5, :cond_5

    .line 60
    .line 61
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    if-eqz v5, :cond_4

    .line 66
    .line 67
    const/16 v5, 0x100

    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_4
    const/16 v5, 0x80

    .line 71
    .line 72
    :goto_3
    or-int/2addr v4, v5

    .line 73
    :cond_5
    or-int/lit16 v5, v4, 0x6c00

    .line 74
    .line 75
    const/high16 v7, 0x30000

    .line 76
    .line 77
    and-int/2addr v7, v0

    .line 78
    if-nez v7, :cond_6

    .line 79
    .line 80
    const v5, 0x16c00

    .line 81
    .line 82
    .line 83
    or-int/2addr v5, v4

    .line 84
    :cond_6
    const/high16 v4, 0x180000

    .line 85
    .line 86
    and-int/2addr v4, v0

    .line 87
    move-object/from16 v7, p6

    .line 88
    .line 89
    if-nez v4, :cond_8

    .line 90
    .line 91
    invoke-virtual {v8, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    if-eqz v4, :cond_7

    .line 96
    .line 97
    const/high16 v4, 0x100000

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_7
    const/high16 v4, 0x80000

    .line 101
    .line 102
    :goto_4
    or-int/2addr v5, v4

    .line 103
    :cond_8
    const v4, 0x92493

    .line 104
    .line 105
    .line 106
    and-int/2addr v4, v5

    .line 107
    const v9, 0x92492

    .line 108
    .line 109
    .line 110
    if-ne v4, v9, :cond_a

    .line 111
    .line 112
    invoke-virtual {v8}, Ll2/t;->A()Z

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    if-nez v4, :cond_9

    .line 117
    .line 118
    goto :goto_5

    .line 119
    :cond_9
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 120
    .line 121
    .line 122
    move-object/from16 v4, p3

    .line 123
    .line 124
    move/from16 v5, p4

    .line 125
    .line 126
    move-object/from16 v6, p5

    .line 127
    .line 128
    goto/16 :goto_10

    .line 129
    .line 130
    :cond_a
    :goto_5
    invoke-virtual {v8}, Ll2/t;->T()V

    .line 131
    .line 132
    .line 133
    and-int/lit8 v4, v0, 0x1

    .line 134
    .line 135
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 136
    .line 137
    const v10, -0x70001

    .line 138
    .line 139
    .line 140
    if-eqz v4, :cond_c

    .line 141
    .line 142
    invoke-virtual {v8}, Ll2/t;->y()Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-eqz v4, :cond_b

    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_b
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 150
    .line 151
    .line 152
    and-int v4, v5, v10

    .line 153
    .line 154
    move-object/from16 v10, p3

    .line 155
    .line 156
    move/from16 v5, p4

    .line 157
    .line 158
    move-object/from16 v12, p5

    .line 159
    .line 160
    goto :goto_7

    .line 161
    :cond_c
    :goto_6
    invoke-static {v1, v9}, Landroidx/compose/foundation/lazy/a;->a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;

    .line 162
    .line 163
    .line 164
    move-result-object v4

    .line 165
    and-int/2addr v5, v10

    .line 166
    move-object v12, v4

    .line 167
    move v4, v5

    .line 168
    move-object v10, v9

    .line 169
    const/4 v5, 0x1

    .line 170
    :goto_7
    invoke-virtual {v8}, Ll2/t;->r()V

    .line 171
    .line 172
    .line 173
    const v13, -0x631e8484

    .line 174
    .line 175
    .line 176
    invoke-virtual {v8, v13}, Ll2/t;->Y(I)V

    .line 177
    .line 178
    .line 179
    and-int/lit8 v13, v4, 0x70

    .line 180
    .line 181
    const/4 v14, 0x0

    .line 182
    if-ne v13, v6, :cond_d

    .line 183
    .line 184
    const/4 v15, 0x1

    .line 185
    goto :goto_8

    .line 186
    :cond_d
    move v15, v14

    .line 187
    :goto_8
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v6

    .line 191
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 192
    .line 193
    if-nez v15, :cond_e

    .line 194
    .line 195
    if-ne v6, v11, :cond_f

    .line 196
    .line 197
    :cond_e
    new-instance v6, Lx21/n;

    .line 198
    .line 199
    const/4 v15, 0x4

    .line 200
    invoke-direct {v6, v2, v15}, Lx21/n;-><init>(Lx21/y;I)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    :cond_f
    check-cast v6, Lay0/a;

    .line 207
    .line 208
    invoke-virtual {v8, v14}, Ll2/t;->q(Z)V

    .line 209
    .line 210
    .line 211
    invoke-static {v6}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 212
    .line 213
    .line 214
    move-result-object v6

    .line 215
    new-instance v15, La4/b;

    .line 216
    .line 217
    const/16 v14, 0xe

    .line 218
    .line 219
    invoke-direct {v15, v14, v3, v2}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    invoke-static {v15}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 223
    .line 224
    .line 225
    move-result-object v14

    .line 226
    invoke-virtual {v14}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v15

    .line 230
    check-cast v15, Ljava/lang/Boolean;

    .line 231
    .line 232
    invoke-virtual {v15}, Ljava/lang/Boolean;->booleanValue()Z

    .line 233
    .line 234
    .line 235
    move-result v15

    .line 236
    const/high16 v0, 0x3f800000    # 1.0f

    .line 237
    .line 238
    if-eqz v15, :cond_18

    .line 239
    .line 240
    const v15, -0xb03e01

    .line 241
    .line 242
    .line 243
    invoke-virtual {v8, v15}, Ll2/t;->Y(I)V

    .line 244
    .line 245
    .line 246
    invoke-static {v9, v0}, Lx2/a;->d(Lx2/s;F)Lx2/s;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    invoke-virtual {v6}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v6

    .line 254
    check-cast v6, Lg1/w1;

    .line 255
    .line 256
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 257
    .line 258
    .line 259
    move-result v6

    .line 260
    if-eqz v6, :cond_14

    .line 261
    .line 262
    const/4 v15, 0x1

    .line 263
    if-ne v6, v15, :cond_13

    .line 264
    .line 265
    const v6, -0x631e51da

    .line 266
    .line 267
    .line 268
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 269
    .line 270
    .line 271
    const v6, -0x631e5028

    .line 272
    .line 273
    .line 274
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 275
    .line 276
    .line 277
    const/16 v6, 0x20

    .line 278
    .line 279
    if-ne v13, v6, :cond_10

    .line 280
    .line 281
    const/16 v16, 0x1

    .line 282
    .line 283
    goto :goto_9

    .line 284
    :cond_10
    const/16 v16, 0x0

    .line 285
    .line 286
    :goto_9
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v6

    .line 290
    if-nez v16, :cond_11

    .line 291
    .line 292
    if-ne v6, v11, :cond_12

    .line 293
    .line 294
    :cond_11
    new-instance v6, Lx21/u;

    .line 295
    .line 296
    const/4 v11, 0x1

    .line 297
    invoke-direct {v6, v2, v11}, Lx21/u;-><init>(Lx21/y;I)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    :cond_12
    check-cast v6, Lay0/k;

    .line 304
    .line 305
    const/4 v11, 0x0

    .line 306
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 307
    .line 308
    .line 309
    invoke-static {v9, v6}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 310
    .line 311
    .line 312
    move-result-object v6

    .line 313
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 314
    .line 315
    .line 316
    goto :goto_b

    .line 317
    :cond_13
    const v6, -0x6325ea39

    .line 318
    .line 319
    .line 320
    const/4 v11, 0x0

    .line 321
    invoke-static {v6, v8, v11}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    throw v0

    .line 326
    :cond_14
    const v6, -0x631e645a

    .line 327
    .line 328
    .line 329
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 330
    .line 331
    .line 332
    const v6, -0x631e62a8

    .line 333
    .line 334
    .line 335
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 336
    .line 337
    .line 338
    const/16 v6, 0x20

    .line 339
    .line 340
    if-ne v13, v6, :cond_15

    .line 341
    .line 342
    const/16 v16, 0x1

    .line 343
    .line 344
    goto :goto_a

    .line 345
    :cond_15
    const/16 v16, 0x0

    .line 346
    .line 347
    :goto_a
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v6

    .line 351
    if-nez v16, :cond_16

    .line 352
    .line 353
    if-ne v6, v11, :cond_17

    .line 354
    .line 355
    :cond_16
    new-instance v6, Lx21/u;

    .line 356
    .line 357
    const/4 v11, 0x0

    .line 358
    invoke-direct {v6, v2, v11}, Lx21/u;-><init>(Lx21/y;I)V

    .line 359
    .line 360
    .line 361
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 362
    .line 363
    .line 364
    :cond_17
    check-cast v6, Lay0/k;

    .line 365
    .line 366
    const/4 v11, 0x0

    .line 367
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 368
    .line 369
    .line 370
    invoke-static {v9, v6}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 371
    .line 372
    .line 373
    move-result-object v6

    .line 374
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 375
    .line 376
    .line 377
    :goto_b
    invoke-interface {v0, v6}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 378
    .line 379
    .line 380
    move-result-object v0

    .line 381
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 382
    .line 383
    .line 384
    goto/16 :goto_f

    .line 385
    .line 386
    :cond_18
    iget-object v15, v2, Lx21/y;->s:Ll2/j1;

    .line 387
    .line 388
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v15

    .line 392
    invoke-virtual {v3, v15}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    move-result v15

    .line 396
    if-eqz v15, :cond_21

    .line 397
    .line 398
    const v15, -0xa9441d

    .line 399
    .line 400
    .line 401
    invoke-virtual {v8, v15}, Ll2/t;->Y(I)V

    .line 402
    .line 403
    .line 404
    invoke-static {v9, v0}, Lx2/a;->d(Lx2/s;F)Lx2/s;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    invoke-virtual {v6}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v6

    .line 412
    check-cast v6, Lg1/w1;

    .line 413
    .line 414
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 415
    .line 416
    .line 417
    move-result v6

    .line 418
    if-eqz v6, :cond_1d

    .line 419
    .line 420
    const/4 v15, 0x1

    .line 421
    if-ne v6, v15, :cond_1c

    .line 422
    .line 423
    const v6, -0x631e168c

    .line 424
    .line 425
    .line 426
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 427
    .line 428
    .line 429
    const v6, -0x631e14da

    .line 430
    .line 431
    .line 432
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 433
    .line 434
    .line 435
    const/16 v6, 0x20

    .line 436
    .line 437
    if-ne v13, v6, :cond_19

    .line 438
    .line 439
    goto :goto_c

    .line 440
    :cond_19
    const/4 v15, 0x0

    .line 441
    :goto_c
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    move-result-object v6

    .line 445
    if-nez v15, :cond_1a

    .line 446
    .line 447
    if-ne v6, v11, :cond_1b

    .line 448
    .line 449
    :cond_1a
    new-instance v6, Lx21/u;

    .line 450
    .line 451
    const/4 v11, 0x3

    .line 452
    invoke-direct {v6, v2, v11}, Lx21/u;-><init>(Lx21/y;I)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 456
    .line 457
    .line 458
    :cond_1b
    check-cast v6, Lay0/k;

    .line 459
    .line 460
    const/4 v11, 0x0

    .line 461
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 462
    .line 463
    .line 464
    invoke-static {v9, v6}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 465
    .line 466
    .line 467
    move-result-object v6

    .line 468
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 469
    .line 470
    .line 471
    goto :goto_e

    .line 472
    :cond_1c
    const v6, -0x6325ea39

    .line 473
    .line 474
    .line 475
    const/4 v11, 0x0

    .line 476
    invoke-static {v6, v8, v11}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    throw v0

    .line 481
    :cond_1d
    const/4 v15, 0x1

    .line 482
    const v6, -0x631e2acc

    .line 483
    .line 484
    .line 485
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 486
    .line 487
    .line 488
    const v6, -0x631e291a

    .line 489
    .line 490
    .line 491
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 492
    .line 493
    .line 494
    const/16 v6, 0x20

    .line 495
    .line 496
    if-ne v13, v6, :cond_1e

    .line 497
    .line 498
    goto :goto_d

    .line 499
    :cond_1e
    const/4 v15, 0x0

    .line 500
    :goto_d
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v6

    .line 504
    if-nez v15, :cond_1f

    .line 505
    .line 506
    if-ne v6, v11, :cond_20

    .line 507
    .line 508
    :cond_1f
    new-instance v6, Lx21/u;

    .line 509
    .line 510
    const/4 v11, 0x2

    .line 511
    invoke-direct {v6, v2, v11}, Lx21/u;-><init>(Lx21/y;I)V

    .line 512
    .line 513
    .line 514
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    :cond_20
    check-cast v6, Lay0/k;

    .line 518
    .line 519
    const/4 v11, 0x0

    .line 520
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 521
    .line 522
    .line 523
    invoke-static {v9, v6}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 524
    .line 525
    .line 526
    move-result-object v6

    .line 527
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 528
    .line 529
    .line 530
    :goto_e
    invoke-interface {v0, v6}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 531
    .line 532
    .line 533
    move-result-object v0

    .line 534
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 535
    .line 536
    .line 537
    goto :goto_f

    .line 538
    :cond_21
    const/4 v11, 0x0

    .line 539
    const v0, -0xa2b4e8

    .line 540
    .line 541
    .line 542
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 543
    .line 544
    .line 545
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 546
    .line 547
    .line 548
    move-object v0, v12

    .line 549
    :goto_f
    invoke-interface {v10, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 550
    .line 551
    .line 552
    move-result-object v0

    .line 553
    invoke-virtual {v14}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    move-result-object v6

    .line 557
    check-cast v6, Ljava/lang/Boolean;

    .line 558
    .line 559
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 560
    .line 561
    .line 562
    move-result v6

    .line 563
    shr-int/lit8 v4, v4, 0x3

    .line 564
    .line 565
    const v9, 0x71c7e

    .line 566
    .line 567
    .line 568
    and-int/2addr v9, v4

    .line 569
    move-object v4, v0

    .line 570
    invoke-static/range {v2 .. v9}, Llp/ce;->a(Lx21/y;Ljava/lang/Integer;Lx2/s;ZZLt2/b;Ll2/o;I)V

    .line 571
    .line 572
    .line 573
    move-object v4, v10

    .line 574
    move-object v6, v12

    .line 575
    :goto_10
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 576
    .line 577
    .line 578
    move-result-object v9

    .line 579
    if-eqz v9, :cond_22

    .line 580
    .line 581
    new-instance v0, Lx21/t;

    .line 582
    .line 583
    move-object/from16 v2, p1

    .line 584
    .line 585
    move-object/from16 v3, p2

    .line 586
    .line 587
    move-object/from16 v7, p6

    .line 588
    .line 589
    move/from16 v8, p8

    .line 590
    .line 591
    invoke-direct/range {v0 .. v8}, Lx21/t;-><init>(Landroidx/compose/foundation/lazy/a;Lx21/y;Ljava/lang/Integer;Lx2/s;ZLx2/s;Lt2/b;I)V

    .line 592
    .line 593
    .line 594
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 595
    .line 596
    :cond_22
    return-void
.end method

.method public static varargs b([I)Ljava/util/List;
    .locals 3

    .line 1
    array-length v0, p0

    .line 2
    if-nez v0, :cond_0

    .line 3
    .line 4
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    new-instance v0, Lkr/b;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    array-length v2, p0

    .line 11
    invoke-direct {v0, v1, v2, p0}, Lkr/b;-><init>(II[I)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static c(J)I
    .locals 3

    .line 1
    long-to-int v0, p0

    .line 2
    int-to-long v1, v0

    .line 3
    cmp-long v1, v1, p0

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v1, 0x0

    .line 10
    :goto_0
    const-string v2, "Out of range: %s"

    .line 11
    .line 12
    invoke-static {p0, p1, v2, v1}, Lkp/i9;->b(JLjava/lang/String;Z)V

    .line 13
    .line 14
    .line 15
    return v0
.end method

.method public static d(BBBB)I
    .locals 0

    .line 1
    shl-int/lit8 p0, p0, 0x18

    .line 2
    .line 3
    and-int/lit16 p1, p1, 0xff

    .line 4
    .line 5
    shl-int/lit8 p1, p1, 0x10

    .line 6
    .line 7
    or-int/2addr p0, p1

    .line 8
    and-int/lit16 p1, p2, 0xff

    .line 9
    .line 10
    shl-int/lit8 p1, p1, 0x8

    .line 11
    .line 12
    or-int/2addr p0, p1

    .line 13
    and-int/lit16 p1, p3, 0xff

    .line 14
    .line 15
    or-int/2addr p0, p1

    .line 16
    return p0
.end method

.method public static e(J)I
    .locals 2

    .line 1
    const-wide/32 v0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    cmp-long v0, p0, v0

    .line 5
    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    const p0, 0x7fffffff

    .line 9
    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    const-wide/32 v0, -0x80000000

    .line 13
    .line 14
    .line 15
    cmp-long v0, p0, v0

    .line 16
    .line 17
    if-gez v0, :cond_1

    .line 18
    .line 19
    const/high16 p0, -0x80000000

    .line 20
    .line 21
    return p0

    .line 22
    :cond_1
    long-to-int p0, p0

    .line 23
    return p0
.end method

.method public static f(Ljava/util/Collection;)[I
    .locals 4

    .line 1
    instance-of v0, p0, Lkr/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lkr/b;

    .line 6
    .line 7
    iget-object v0, p0, Lkr/b;->d:[I

    .line 8
    .line 9
    iget v1, p0, Lkr/b;->e:I

    .line 10
    .line 11
    iget p0, p0, Lkr/b;->f:I

    .line 12
    .line 13
    invoke-static {v0, v1, p0}, Ljava/util/Arrays;->copyOfRange([III)[I

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    invoke-interface {p0}, Ljava/util/Collection;->toArray()[Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    array-length v0, p0

    .line 23
    new-array v1, v0, [I

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    :goto_0
    if-ge v2, v0, :cond_1

    .line 27
    .line 28
    aget-object v3, p0, v2

    .line 29
    .line 30
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    check-cast v3, Ljava/lang/Number;

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    aput v3, v1, v2

    .line 40
    .line 41
    add-int/lit8 v2, v2, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    return-object v1
.end method

.method public static g(Ljava/lang/String;)Ljava/lang/Integer;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    :goto_0
    const/4 v0, 0x0

    .line 13
    const/16 v16, 0x0

    .line 14
    .line 15
    goto/16 :goto_6

    .line 16
    .line 17
    :cond_0
    const/4 v1, 0x0

    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/16 v4, 0x2d

    .line 23
    .line 24
    if-ne v3, v4, :cond_1

    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    :cond_1
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-ne v1, v3, :cond_2

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    add-int/lit8 v3, v1, 0x1

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    const/4 v5, -0x1

    .line 41
    const/16 v6, 0x80

    .line 42
    .line 43
    if-ge v4, v6, :cond_3

    .line 44
    .line 45
    sget-object v7, Lkr/c;->a:[B

    .line 46
    .line 47
    aget-byte v4, v7, v4

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    sget-object v4, Lkr/c;->a:[B

    .line 51
    .line 52
    move v4, v5

    .line 53
    :goto_1
    if-ltz v4, :cond_6

    .line 54
    .line 55
    const/16 v7, 0xa

    .line 56
    .line 57
    if-lt v4, v7, :cond_4

    .line 58
    .line 59
    goto :goto_4

    .line 60
    :cond_4
    neg-int v4, v4

    .line 61
    int-to-long v8, v4

    .line 62
    int-to-long v10, v7

    .line 63
    const-wide/high16 v12, -0x8000000000000000L

    .line 64
    .line 65
    div-long v14, v12, v10

    .line 66
    .line 67
    :goto_2
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-ge v3, v4, :cond_9

    .line 72
    .line 73
    add-int/lit8 v4, v3, 0x1

    .line 74
    .line 75
    invoke-virtual {v0, v3}, Ljava/lang/String;->charAt(I)C

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-ge v3, v6, :cond_5

    .line 80
    .line 81
    sget-object v16, Lkr/c;->a:[B

    .line 82
    .line 83
    aget-byte v3, v16, v3

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_5
    sget-object v3, Lkr/c;->a:[B

    .line 87
    .line 88
    move v3, v5

    .line 89
    :goto_3
    if-ltz v3, :cond_6

    .line 90
    .line 91
    if-ge v3, v7, :cond_6

    .line 92
    .line 93
    cmp-long v16, v8, v14

    .line 94
    .line 95
    if-gez v16, :cond_7

    .line 96
    .line 97
    :cond_6
    :goto_4
    const/16 v16, 0x0

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_7
    mul-long/2addr v8, v10

    .line 101
    const/16 v16, 0x0

    .line 102
    .line 103
    int-to-long v2, v3

    .line 104
    add-long v17, v2, v12

    .line 105
    .line 106
    cmp-long v17, v8, v17

    .line 107
    .line 108
    if-gez v17, :cond_8

    .line 109
    .line 110
    :goto_5
    move-object/from16 v0, v16

    .line 111
    .line 112
    goto :goto_6

    .line 113
    :cond_8
    sub-long/2addr v8, v2

    .line 114
    move v3, v4

    .line 115
    goto :goto_2

    .line 116
    :cond_9
    const/16 v16, 0x0

    .line 117
    .line 118
    if-eqz v1, :cond_a

    .line 119
    .line 120
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    goto :goto_6

    .line 125
    :cond_a
    cmp-long v0, v8, v12

    .line 126
    .line 127
    if-nez v0, :cond_b

    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_b
    neg-long v0, v8

    .line 131
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    :goto_6
    if-eqz v0, :cond_d

    .line 136
    .line 137
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 138
    .line 139
    .line 140
    move-result-wide v1

    .line 141
    invoke-virtual {v0}, Ljava/lang/Long;->intValue()I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    int-to-long v3, v3

    .line 146
    cmp-long v1, v1, v3

    .line 147
    .line 148
    if-eqz v1, :cond_c

    .line 149
    .line 150
    goto :goto_7

    .line 151
    :cond_c
    invoke-virtual {v0}, Ljava/lang/Long;->intValue()I

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    return-object v0

    .line 160
    :cond_d
    :goto_7
    return-object v16
.end method
