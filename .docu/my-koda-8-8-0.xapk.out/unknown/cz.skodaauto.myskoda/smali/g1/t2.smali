.class public final Lg1/t2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lg1/u2;


# direct methods
.method public constructor <init>(Lg1/u2;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg1/t2;->a:Lg1/u2;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(IJ)J
    .locals 19

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    move-wide/from16 v2, p2

    .line 6
    .line 7
    iget-object v1, v1, Lg1/t2;->a:Lg1/u2;

    .line 8
    .line 9
    iput v0, v1, Lg1/u2;->j:I

    .line 10
    .line 11
    iget-object v4, v1, Lg1/u2;->b:Le1/j;

    .line 12
    .line 13
    if-eqz v4, :cond_36

    .line 14
    .line 15
    iget-object v5, v1, Lg1/u2;->a:Lg1/q2;

    .line 16
    .line 17
    invoke-interface {v5}, Lg1/q2;->d()Z

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    if-nez v5, :cond_0

    .line 22
    .line 23
    iget-object v5, v1, Lg1/u2;->a:Lg1/q2;

    .line 24
    .line 25
    invoke-interface {v5}, Lg1/q2;->b()Z

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    if-eqz v5, :cond_36

    .line 30
    .line 31
    :cond_0
    iget v0, v1, Lg1/u2;->j:I

    .line 32
    .line 33
    iget-object v1, v1, Lg1/u2;->m:Le81/w;

    .line 34
    .line 35
    iget-object v5, v4, Le1/j;->c:Le1/f0;

    .line 36
    .line 37
    iget-wide v6, v4, Le1/j;->g:J

    .line 38
    .line 39
    invoke-static {v6, v7}, Ld3/e;->e(J)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-eqz v6, :cond_1

    .line 44
    .line 45
    new-instance v0, Ld3/b;

    .line 46
    .line 47
    invoke-direct {v0, v2, v3}, Ld3/b;-><init>(J)V

    .line 48
    .line 49
    .line 50
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    check-cast v0, Ld3/b;

    .line 55
    .line 56
    iget-wide v0, v0, Ld3/b;->a:J

    .line 57
    .line 58
    goto/16 :goto_17

    .line 59
    .line 60
    :cond_1
    iget-boolean v6, v4, Le1/j;->f:Z

    .line 61
    .line 62
    const-wide/16 v7, 0x0

    .line 63
    .line 64
    const/4 v9, 0x1

    .line 65
    if-nez v6, :cond_6

    .line 66
    .line 67
    iget-object v6, v5, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 68
    .line 69
    invoke-static {v6}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    if-eqz v6, :cond_2

    .line 74
    .line 75
    invoke-virtual {v4, v7, v8}, Le1/j;->f(J)F

    .line 76
    .line 77
    .line 78
    :cond_2
    iget-object v6, v5, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 79
    .line 80
    invoke-static {v6}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    if-eqz v6, :cond_3

    .line 85
    .line 86
    invoke-virtual {v4, v7, v8}, Le1/j;->g(J)F

    .line 87
    .line 88
    .line 89
    :cond_3
    iget-object v6, v5, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 90
    .line 91
    invoke-static {v6}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    if-eqz v6, :cond_4

    .line 96
    .line 97
    invoke-virtual {v4, v7, v8}, Le1/j;->h(J)F

    .line 98
    .line 99
    .line 100
    :cond_4
    iget-object v6, v5, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 101
    .line 102
    invoke-static {v6}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 103
    .line 104
    .line 105
    move-result v6

    .line 106
    if-eqz v6, :cond_5

    .line 107
    .line 108
    invoke-virtual {v4, v7, v8}, Le1/j;->e(J)F

    .line 109
    .line 110
    .line 111
    :cond_5
    iput-boolean v9, v4, Le1/j;->f:Z

    .line 112
    .line 113
    :cond_6
    sget v6, Le1/l;->a:I

    .line 114
    .line 115
    const/4 v6, 0x2

    .line 116
    if-ne v0, v6, :cond_7

    .line 117
    .line 118
    const/high16 v6, 0x40800000    # 4.0f

    .line 119
    .line 120
    goto :goto_0

    .line 121
    :cond_7
    const/high16 v6, 0x3f800000    # 1.0f

    .line 122
    .line 123
    :goto_0
    invoke-static {v2, v3, v6}, Ld3/b;->i(JF)J

    .line 124
    .line 125
    .line 126
    move-result-wide v10

    .line 127
    const-wide v12, 0xffffffffL

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    and-long v14, v2, v12

    .line 133
    .line 134
    long-to-int v14, v14

    .line 135
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 136
    .line 137
    .line 138
    move-result v15

    .line 139
    const/16 v16, 0x0

    .line 140
    .line 141
    cmpg-float v15, v15, v16

    .line 142
    .line 143
    if-nez v15, :cond_9

    .line 144
    .line 145
    move-wide/from16 p0, v12

    .line 146
    .line 147
    :cond_8
    move/from16 v12, v16

    .line 148
    .line 149
    goto/16 :goto_1

    .line 150
    .line 151
    :cond_9
    iget-object v15, v5, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 152
    .line 153
    invoke-static {v15}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 154
    .line 155
    .line 156
    move-result v15

    .line 157
    if-eqz v15, :cond_c

    .line 158
    .line 159
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 160
    .line 161
    .line 162
    move-result v15

    .line 163
    cmpg-float v15, v15, v16

    .line 164
    .line 165
    if-gez v15, :cond_c

    .line 166
    .line 167
    invoke-virtual {v4, v10, v11}, Le1/j;->h(J)F

    .line 168
    .line 169
    .line 170
    move-result v15

    .line 171
    move-wide/from16 p0, v12

    .line 172
    .line 173
    iget-object v12, v5, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 174
    .line 175
    invoke-static {v12}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 176
    .line 177
    .line 178
    move-result v12

    .line 179
    if-nez v12, :cond_a

    .line 180
    .line 181
    invoke-virtual {v5}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 182
    .line 183
    .line 184
    move-result-object v12

    .line 185
    invoke-virtual {v12}, Landroid/widget/EdgeEffect;->finish()V

    .line 186
    .line 187
    .line 188
    :cond_a
    and-long v12, v10, p0

    .line 189
    .line 190
    long-to-int v12, v12

    .line 191
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 192
    .line 193
    .line 194
    move-result v12

    .line 195
    cmpg-float v12, v15, v12

    .line 196
    .line 197
    if-nez v12, :cond_b

    .line 198
    .line 199
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 200
    .line 201
    .line 202
    move-result v12

    .line 203
    goto :goto_1

    .line 204
    :cond_b
    div-float v12, v15, v6

    .line 205
    .line 206
    goto :goto_1

    .line 207
    :cond_c
    move-wide/from16 p0, v12

    .line 208
    .line 209
    iget-object v12, v5, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 210
    .line 211
    invoke-static {v12}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 212
    .line 213
    .line 214
    move-result v12

    .line 215
    if-eqz v12, :cond_8

    .line 216
    .line 217
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 218
    .line 219
    .line 220
    move-result v12

    .line 221
    cmpl-float v12, v12, v16

    .line 222
    .line 223
    if-lez v12, :cond_8

    .line 224
    .line 225
    invoke-virtual {v4, v10, v11}, Le1/j;->e(J)F

    .line 226
    .line 227
    .line 228
    move-result v12

    .line 229
    iget-object v13, v5, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 230
    .line 231
    invoke-static {v13}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 232
    .line 233
    .line 234
    move-result v13

    .line 235
    if-nez v13, :cond_d

    .line 236
    .line 237
    invoke-virtual {v5}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 238
    .line 239
    .line 240
    move-result-object v13

    .line 241
    invoke-virtual {v13}, Landroid/widget/EdgeEffect;->finish()V

    .line 242
    .line 243
    .line 244
    :cond_d
    and-long v7, v10, p0

    .line 245
    .line 246
    long-to-int v7, v7

    .line 247
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 248
    .line 249
    .line 250
    move-result v7

    .line 251
    cmpg-float v7, v12, v7

    .line 252
    .line 253
    if-nez v7, :cond_e

    .line 254
    .line 255
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 256
    .line 257
    .line 258
    move-result v12

    .line 259
    goto :goto_1

    .line 260
    :cond_e
    div-float/2addr v12, v6

    .line 261
    :goto_1
    const/16 v13, 0x20

    .line 262
    .line 263
    shr-long v7, v2, v13

    .line 264
    .line 265
    long-to-int v7, v7

    .line 266
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 267
    .line 268
    .line 269
    move-result v8

    .line 270
    cmpg-float v8, v8, v16

    .line 271
    .line 272
    if-nez v8, :cond_10

    .line 273
    .line 274
    :cond_f
    move/from16 v6, v16

    .line 275
    .line 276
    goto :goto_2

    .line 277
    :cond_10
    iget-object v8, v5, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 278
    .line 279
    invoke-static {v8}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 280
    .line 281
    .line 282
    move-result v8

    .line 283
    if-eqz v8, :cond_13

    .line 284
    .line 285
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 286
    .line 287
    .line 288
    move-result v8

    .line 289
    cmpg-float v8, v8, v16

    .line 290
    .line 291
    if-gez v8, :cond_13

    .line 292
    .line 293
    invoke-virtual {v4, v10, v11}, Le1/j;->f(J)F

    .line 294
    .line 295
    .line 296
    move-result v8

    .line 297
    iget-object v15, v5, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 298
    .line 299
    invoke-static {v15}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 300
    .line 301
    .line 302
    move-result v15

    .line 303
    if-nez v15, :cond_11

    .line 304
    .line 305
    invoke-virtual {v5}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 306
    .line 307
    .line 308
    move-result-object v15

    .line 309
    invoke-virtual {v15}, Landroid/widget/EdgeEffect;->finish()V

    .line 310
    .line 311
    .line 312
    :cond_11
    shr-long/2addr v10, v13

    .line 313
    long-to-int v10, v10

    .line 314
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 315
    .line 316
    .line 317
    move-result v10

    .line 318
    cmpg-float v10, v8, v10

    .line 319
    .line 320
    if-nez v10, :cond_12

    .line 321
    .line 322
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 323
    .line 324
    .line 325
    move-result v6

    .line 326
    goto :goto_2

    .line 327
    :cond_12
    div-float v6, v8, v6

    .line 328
    .line 329
    goto :goto_2

    .line 330
    :cond_13
    iget-object v8, v5, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 331
    .line 332
    invoke-static {v8}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 333
    .line 334
    .line 335
    move-result v8

    .line 336
    if-eqz v8, :cond_f

    .line 337
    .line 338
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 339
    .line 340
    .line 341
    move-result v8

    .line 342
    cmpl-float v8, v8, v16

    .line 343
    .line 344
    if-lez v8, :cond_f

    .line 345
    .line 346
    invoke-virtual {v4, v10, v11}, Le1/j;->g(J)F

    .line 347
    .line 348
    .line 349
    move-result v8

    .line 350
    iget-object v15, v5, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 351
    .line 352
    invoke-static {v15}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 353
    .line 354
    .line 355
    move-result v15

    .line 356
    if-nez v15, :cond_14

    .line 357
    .line 358
    invoke-virtual {v5}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 359
    .line 360
    .line 361
    move-result-object v15

    .line 362
    invoke-virtual {v15}, Landroid/widget/EdgeEffect;->finish()V

    .line 363
    .line 364
    .line 365
    :cond_14
    shr-long/2addr v10, v13

    .line 366
    long-to-int v10, v10

    .line 367
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 368
    .line 369
    .line 370
    move-result v10

    .line 371
    cmpg-float v10, v8, v10

    .line 372
    .line 373
    if-nez v10, :cond_12

    .line 374
    .line 375
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 376
    .line 377
    .line 378
    move-result v6

    .line 379
    :goto_2
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 380
    .line 381
    .line 382
    move-result v6

    .line 383
    int-to-long v10, v6

    .line 384
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 385
    .line 386
    .line 387
    move-result v6

    .line 388
    move v12, v13

    .line 389
    move v8, v14

    .line 390
    int-to-long v13, v6

    .line 391
    shl-long/2addr v10, v12

    .line 392
    and-long v13, v13, p0

    .line 393
    .line 394
    or-long/2addr v10, v13

    .line 395
    const-wide/16 v13, 0x0

    .line 396
    .line 397
    invoke-static {v10, v11, v13, v14}, Ld3/b;->c(JJ)Z

    .line 398
    .line 399
    .line 400
    move-result v6

    .line 401
    if-nez v6, :cond_15

    .line 402
    .line 403
    invoke-virtual {v4}, Le1/j;->d()V

    .line 404
    .line 405
    .line 406
    :cond_15
    invoke-static {v2, v3, v10, v11}, Ld3/b;->g(JJ)J

    .line 407
    .line 408
    .line 409
    move-result-wide v2

    .line 410
    new-instance v6, Ld3/b;

    .line 411
    .line 412
    invoke-direct {v6, v2, v3}, Ld3/b;-><init>(J)V

    .line 413
    .line 414
    .line 415
    invoke-interface {v1, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v1

    .line 419
    check-cast v1, Ld3/b;

    .line 420
    .line 421
    iget-wide v13, v1, Ld3/b;->a:J

    .line 422
    .line 423
    move-wide/from16 v17, v10

    .line 424
    .line 425
    invoke-static {v2, v3, v13, v14}, Ld3/b;->g(JJ)J

    .line 426
    .line 427
    .line 428
    move-result-wide v9

    .line 429
    move v6, v12

    .line 430
    move-wide/from16 p2, v13

    .line 431
    .line 432
    shr-long v12, v2, v6

    .line 433
    .line 434
    long-to-int v11, v12

    .line 435
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 436
    .line 437
    .line 438
    move-result v11

    .line 439
    cmpg-float v11, v11, v16

    .line 440
    .line 441
    if-nez v11, :cond_16

    .line 442
    .line 443
    and-long v11, v2, p0

    .line 444
    .line 445
    long-to-int v11, v11

    .line 446
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 447
    .line 448
    .line 449
    move-result v11

    .line 450
    cmpg-float v11, v11, v16

    .line 451
    .line 452
    if-nez v11, :cond_16

    .line 453
    .line 454
    goto :goto_3

    .line 455
    :cond_16
    shr-long v11, p2, v6

    .line 456
    .line 457
    long-to-int v11, v11

    .line 458
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 459
    .line 460
    .line 461
    move-result v11

    .line 462
    cmpg-float v11, v11, v16

    .line 463
    .line 464
    if-nez v11, :cond_17

    .line 465
    .line 466
    and-long v11, p2, p0

    .line 467
    .line 468
    long-to-int v11, v11

    .line 469
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 470
    .line 471
    .line 472
    move-result v11

    .line 473
    cmpg-float v11, v11, v16

    .line 474
    .line 475
    if-nez v11, :cond_17

    .line 476
    .line 477
    goto :goto_3

    .line 478
    :cond_17
    iget-object v11, v5, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 479
    .line 480
    invoke-static {v11}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 481
    .line 482
    .line 483
    move-result v11

    .line 484
    if-nez v11, :cond_18

    .line 485
    .line 486
    iget-object v11, v5, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 487
    .line 488
    invoke-static {v11}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 489
    .line 490
    .line 491
    move-result v11

    .line 492
    if-nez v11, :cond_18

    .line 493
    .line 494
    iget-object v11, v5, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 495
    .line 496
    invoke-static {v11}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 497
    .line 498
    .line 499
    move-result v11

    .line 500
    if-nez v11, :cond_18

    .line 501
    .line 502
    iget-object v11, v5, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 503
    .line 504
    invoke-static {v11}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 505
    .line 506
    .line 507
    move-result v11

    .line 508
    if-eqz v11, :cond_19

    .line 509
    .line 510
    :cond_18
    invoke-virtual {v4}, Le1/j;->a()V

    .line 511
    .line 512
    .line 513
    :cond_19
    :goto_3
    const/4 v11, 0x0

    .line 514
    const/4 v1, 0x1

    .line 515
    if-ne v0, v1, :cond_1f

    .line 516
    .line 517
    shr-long v12, v9, v6

    .line 518
    .line 519
    long-to-int v0, v12

    .line 520
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 521
    .line 522
    .line 523
    move-result v6

    .line 524
    const/high16 v12, 0x3f000000    # 0.5f

    .line 525
    .line 526
    cmpl-float v6, v6, v12

    .line 527
    .line 528
    const/high16 v13, -0x41000000    # -0.5f

    .line 529
    .line 530
    if-lez v6, :cond_1a

    .line 531
    .line 532
    invoke-virtual {v4, v9, v10}, Le1/j;->f(J)F

    .line 533
    .line 534
    .line 535
    :goto_4
    move v0, v1

    .line 536
    goto :goto_5

    .line 537
    :cond_1a
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 538
    .line 539
    .line 540
    move-result v0

    .line 541
    cmpg-float v0, v0, v13

    .line 542
    .line 543
    if-gez v0, :cond_1b

    .line 544
    .line 545
    invoke-virtual {v4, v9, v10}, Le1/j;->g(J)F

    .line 546
    .line 547
    .line 548
    goto :goto_4

    .line 549
    :cond_1b
    move v0, v11

    .line 550
    :goto_5
    and-long v14, v9, p0

    .line 551
    .line 552
    long-to-int v6, v14

    .line 553
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 554
    .line 555
    .line 556
    move-result v14

    .line 557
    cmpl-float v12, v14, v12

    .line 558
    .line 559
    if-lez v12, :cond_1c

    .line 560
    .line 561
    invoke-virtual {v4, v9, v10}, Le1/j;->h(J)F

    .line 562
    .line 563
    .line 564
    :goto_6
    move v6, v1

    .line 565
    goto :goto_7

    .line 566
    :cond_1c
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 567
    .line 568
    .line 569
    move-result v6

    .line 570
    cmpg-float v6, v6, v13

    .line 571
    .line 572
    if-gez v6, :cond_1d

    .line 573
    .line 574
    invoke-virtual {v4, v9, v10}, Le1/j;->e(J)F

    .line 575
    .line 576
    .line 577
    goto :goto_6

    .line 578
    :cond_1d
    move v6, v11

    .line 579
    :goto_7
    if-nez v0, :cond_1e

    .line 580
    .line 581
    if-eqz v6, :cond_1f

    .line 582
    .line 583
    :cond_1e
    move v0, v1

    .line 584
    :goto_8
    const-wide/16 v13, 0x0

    .line 585
    .line 586
    goto :goto_9

    .line 587
    :cond_1f
    move v0, v11

    .line 588
    goto :goto_8

    .line 589
    :goto_9
    invoke-static {v2, v3, v13, v14}, Ld3/b;->c(JJ)Z

    .line 590
    .line 591
    .line 592
    move-result v2

    .line 593
    if-nez v2, :cond_34

    .line 594
    .line 595
    iget-object v2, v5, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 596
    .line 597
    invoke-static {v2}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 598
    .line 599
    .line 600
    move-result v2

    .line 601
    if-eqz v2, :cond_22

    .line 602
    .line 603
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 604
    .line 605
    .line 606
    move-result v2

    .line 607
    cmpg-float v2, v2, v16

    .line 608
    .line 609
    if-gez v2, :cond_22

    .line 610
    .line 611
    invoke-virtual {v5}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 612
    .line 613
    .line 614
    move-result-object v2

    .line 615
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 616
    .line 617
    .line 618
    move-result v3

    .line 619
    instance-of v6, v2, Le1/i0;

    .line 620
    .line 621
    if-eqz v6, :cond_20

    .line 622
    .line 623
    check-cast v2, Le1/i0;

    .line 624
    .line 625
    iget v6, v2, Le1/i0;->b:F

    .line 626
    .line 627
    add-float/2addr v6, v3

    .line 628
    iput v6, v2, Le1/i0;->b:F

    .line 629
    .line 630
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    .line 631
    .line 632
    .line 633
    move-result v3

    .line 634
    iget v6, v2, Le1/i0;->a:F

    .line 635
    .line 636
    cmpl-float v3, v3, v6

    .line 637
    .line 638
    if-lez v3, :cond_21

    .line 639
    .line 640
    invoke-virtual {v2}, Le1/i0;->onRelease()V

    .line 641
    .line 642
    .line 643
    goto :goto_a

    .line 644
    :cond_20
    invoke-virtual {v2}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 645
    .line 646
    .line 647
    :cond_21
    :goto_a
    iget-object v2, v5, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 648
    .line 649
    invoke-static {v2}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 650
    .line 651
    .line 652
    move-result v2

    .line 653
    goto :goto_b

    .line 654
    :cond_22
    move v2, v11

    .line 655
    :goto_b
    iget-object v3, v5, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 656
    .line 657
    invoke-static {v3}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 658
    .line 659
    .line 660
    move-result v3

    .line 661
    if-eqz v3, :cond_27

    .line 662
    .line 663
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 664
    .line 665
    .line 666
    move-result v3

    .line 667
    cmpl-float v3, v3, v16

    .line 668
    .line 669
    if-lez v3, :cond_27

    .line 670
    .line 671
    invoke-virtual {v5}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 672
    .line 673
    .line 674
    move-result-object v3

    .line 675
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 676
    .line 677
    .line 678
    move-result v6

    .line 679
    instance-of v7, v3, Le1/i0;

    .line 680
    .line 681
    if-eqz v7, :cond_23

    .line 682
    .line 683
    check-cast v3, Le1/i0;

    .line 684
    .line 685
    iget v7, v3, Le1/i0;->b:F

    .line 686
    .line 687
    add-float/2addr v7, v6

    .line 688
    iput v7, v3, Le1/i0;->b:F

    .line 689
    .line 690
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 691
    .line 692
    .line 693
    move-result v6

    .line 694
    iget v7, v3, Le1/i0;->a:F

    .line 695
    .line 696
    cmpl-float v6, v6, v7

    .line 697
    .line 698
    if-lez v6, :cond_24

    .line 699
    .line 700
    invoke-virtual {v3}, Le1/i0;->onRelease()V

    .line 701
    .line 702
    .line 703
    goto :goto_c

    .line 704
    :cond_23
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 705
    .line 706
    .line 707
    :cond_24
    :goto_c
    if-nez v2, :cond_26

    .line 708
    .line 709
    iget-object v2, v5, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 710
    .line 711
    invoke-static {v2}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 712
    .line 713
    .line 714
    move-result v2

    .line 715
    if-eqz v2, :cond_25

    .line 716
    .line 717
    goto :goto_d

    .line 718
    :cond_25
    move v2, v11

    .line 719
    goto :goto_e

    .line 720
    :cond_26
    :goto_d
    move v2, v1

    .line 721
    :cond_27
    :goto_e
    iget-object v3, v5, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 722
    .line 723
    invoke-static {v3}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 724
    .line 725
    .line 726
    move-result v3

    .line 727
    if-eqz v3, :cond_2c

    .line 728
    .line 729
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 730
    .line 731
    .line 732
    move-result v3

    .line 733
    cmpg-float v3, v3, v16

    .line 734
    .line 735
    if-gez v3, :cond_2c

    .line 736
    .line 737
    invoke-virtual {v5}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 738
    .line 739
    .line 740
    move-result-object v3

    .line 741
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 742
    .line 743
    .line 744
    move-result v6

    .line 745
    instance-of v7, v3, Le1/i0;

    .line 746
    .line 747
    if-eqz v7, :cond_28

    .line 748
    .line 749
    check-cast v3, Le1/i0;

    .line 750
    .line 751
    iget v7, v3, Le1/i0;->b:F

    .line 752
    .line 753
    add-float/2addr v7, v6

    .line 754
    iput v7, v3, Le1/i0;->b:F

    .line 755
    .line 756
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 757
    .line 758
    .line 759
    move-result v6

    .line 760
    iget v7, v3, Le1/i0;->a:F

    .line 761
    .line 762
    cmpl-float v6, v6, v7

    .line 763
    .line 764
    if-lez v6, :cond_29

    .line 765
    .line 766
    invoke-virtual {v3}, Le1/i0;->onRelease()V

    .line 767
    .line 768
    .line 769
    goto :goto_f

    .line 770
    :cond_28
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 771
    .line 772
    .line 773
    :cond_29
    :goto_f
    if-nez v2, :cond_2b

    .line 774
    .line 775
    iget-object v2, v5, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 776
    .line 777
    invoke-static {v2}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 778
    .line 779
    .line 780
    move-result v2

    .line 781
    if-eqz v2, :cond_2a

    .line 782
    .line 783
    goto :goto_10

    .line 784
    :cond_2a
    move v2, v11

    .line 785
    goto :goto_11

    .line 786
    :cond_2b
    :goto_10
    move v2, v1

    .line 787
    :cond_2c
    :goto_11
    iget-object v3, v5, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 788
    .line 789
    invoke-static {v3}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 790
    .line 791
    .line 792
    move-result v3

    .line 793
    if-eqz v3, :cond_31

    .line 794
    .line 795
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 796
    .line 797
    .line 798
    move-result v3

    .line 799
    cmpl-float v3, v3, v16

    .line 800
    .line 801
    if-lez v3, :cond_31

    .line 802
    .line 803
    invoke-virtual {v5}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 804
    .line 805
    .line 806
    move-result-object v3

    .line 807
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 808
    .line 809
    .line 810
    move-result v6

    .line 811
    instance-of v7, v3, Le1/i0;

    .line 812
    .line 813
    if-eqz v7, :cond_2d

    .line 814
    .line 815
    check-cast v3, Le1/i0;

    .line 816
    .line 817
    iget v7, v3, Le1/i0;->b:F

    .line 818
    .line 819
    add-float/2addr v7, v6

    .line 820
    iput v7, v3, Le1/i0;->b:F

    .line 821
    .line 822
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 823
    .line 824
    .line 825
    move-result v6

    .line 826
    iget v7, v3, Le1/i0;->a:F

    .line 827
    .line 828
    cmpl-float v6, v6, v7

    .line 829
    .line 830
    if-lez v6, :cond_2e

    .line 831
    .line 832
    invoke-virtual {v3}, Le1/i0;->onRelease()V

    .line 833
    .line 834
    .line 835
    goto :goto_12

    .line 836
    :cond_2d
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 837
    .line 838
    .line 839
    :cond_2e
    :goto_12
    if-nez v2, :cond_30

    .line 840
    .line 841
    iget-object v2, v5, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 842
    .line 843
    invoke-static {v2}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 844
    .line 845
    .line 846
    move-result v2

    .line 847
    if-eqz v2, :cond_2f

    .line 848
    .line 849
    goto :goto_13

    .line 850
    :cond_2f
    move v2, v11

    .line 851
    goto :goto_14

    .line 852
    :cond_30
    :goto_13
    move v2, v1

    .line 853
    :cond_31
    :goto_14
    if-nez v2, :cond_33

    .line 854
    .line 855
    if-eqz v0, :cond_32

    .line 856
    .line 857
    goto :goto_15

    .line 858
    :cond_32
    move v9, v11

    .line 859
    goto :goto_16

    .line 860
    :cond_33
    :goto_15
    move v9, v1

    .line 861
    :goto_16
    move v0, v9

    .line 862
    :cond_34
    if-eqz v0, :cond_35

    .line 863
    .line 864
    invoke-virtual {v4}, Le1/j;->d()V

    .line 865
    .line 866
    .line 867
    :cond_35
    move-wide/from16 v2, p2

    .line 868
    .line 869
    move-wide/from16 v0, v17

    .line 870
    .line 871
    invoke-static {v0, v1, v2, v3}, Ld3/b;->h(JJ)J

    .line 872
    .line 873
    .line 874
    move-result-wide v0

    .line 875
    :goto_17
    return-wide v0

    .line 876
    :cond_36
    iget-object v4, v1, Lg1/u2;->k:Lg1/e2;

    .line 877
    .line 878
    invoke-virtual {v1, v4, v2, v3, v0}, Lg1/u2;->c(Lg1/e2;JI)J

    .line 879
    .line 880
    .line 881
    move-result-wide v0

    .line 882
    return-wide v0
.end method
