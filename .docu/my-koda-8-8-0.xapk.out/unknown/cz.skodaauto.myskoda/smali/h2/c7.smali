.class public abstract Lh2/c7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    int-to-float v0, v0

    .line 3
    sput v0, Lh2/c7;->a:F

    .line 4
    .line 5
    return-void
.end method

.method public static final a(Ll4/v;Lay0/k;Lx2/s;ZLg4/p0;Lay0/n;Lay0/n;Lay0/n;ZLl4/d0;Lt1/o0;Lt1/n0;ZIILe3/n0;Lh2/eb;Ll2/o;I)V
    .locals 38

    .line 1
    move/from16 v3, p8

    .line 2
    .line 3
    move-object/from16 v4, p16

    .line 4
    .line 5
    move/from16 v0, p18

    .line 6
    .line 7
    move-object/from16 v1, p17

    .line 8
    .line 9
    check-cast v1, Ll2/t;

    .line 10
    .line 11
    const v2, 0x7a9fbaf5

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v2, v0, 0x6

    .line 18
    .line 19
    move-object/from16 v5, p0

    .line 20
    .line 21
    if-nez v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {v1, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    const/4 v2, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v2, 0x2

    .line 32
    :goto_0
    or-int/2addr v2, v0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v2, v0

    .line 35
    :goto_1
    and-int/lit8 v6, v0, 0x30

    .line 36
    .line 37
    if-nez v6, :cond_3

    .line 38
    .line 39
    move-object/from16 v6, p1

    .line 40
    .line 41
    invoke-virtual {v1, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    if-eqz v7, :cond_2

    .line 46
    .line 47
    const/16 v7, 0x20

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v7, 0x10

    .line 51
    .line 52
    :goto_2
    or-int/2addr v2, v7

    .line 53
    goto :goto_3

    .line 54
    :cond_3
    move-object/from16 v6, p1

    .line 55
    .line 56
    :goto_3
    and-int/lit16 v7, v0, 0x180

    .line 57
    .line 58
    const/16 v8, 0x80

    .line 59
    .line 60
    const/16 v9, 0x100

    .line 61
    .line 62
    if-nez v7, :cond_5

    .line 63
    .line 64
    move-object/from16 v7, p2

    .line 65
    .line 66
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v10

    .line 70
    if-eqz v10, :cond_4

    .line 71
    .line 72
    move v10, v9

    .line 73
    goto :goto_4

    .line 74
    :cond_4
    move v10, v8

    .line 75
    :goto_4
    or-int/2addr v2, v10

    .line 76
    goto :goto_5

    .line 77
    :cond_5
    move-object/from16 v7, p2

    .line 78
    .line 79
    :goto_5
    or-int/lit16 v10, v2, 0x6c00

    .line 80
    .line 81
    const/high16 v11, 0x30000

    .line 82
    .line 83
    and-int/2addr v11, v0

    .line 84
    if-nez v11, :cond_6

    .line 85
    .line 86
    const v10, 0x16c00

    .line 87
    .line 88
    .line 89
    or-int/2addr v10, v2

    .line 90
    :cond_6
    const/high16 v2, 0x180000

    .line 91
    .line 92
    and-int/2addr v2, v0

    .line 93
    if-nez v2, :cond_8

    .line 94
    .line 95
    move-object/from16 v2, p5

    .line 96
    .line 97
    invoke-virtual {v1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v11

    .line 101
    if-eqz v11, :cond_7

    .line 102
    .line 103
    const/high16 v11, 0x100000

    .line 104
    .line 105
    goto :goto_6

    .line 106
    :cond_7
    const/high16 v11, 0x80000

    .line 107
    .line 108
    :goto_6
    or-int/2addr v10, v11

    .line 109
    goto :goto_7

    .line 110
    :cond_8
    move-object/from16 v2, p5

    .line 111
    .line 112
    :goto_7
    const/high16 v11, 0xc00000

    .line 113
    .line 114
    and-int/2addr v11, v0

    .line 115
    if-nez v11, :cond_a

    .line 116
    .line 117
    move-object/from16 v11, p6

    .line 118
    .line 119
    invoke-virtual {v1, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v12

    .line 123
    if-eqz v12, :cond_9

    .line 124
    .line 125
    const/high16 v12, 0x800000

    .line 126
    .line 127
    goto :goto_8

    .line 128
    :cond_9
    const/high16 v12, 0x400000

    .line 129
    .line 130
    :goto_8
    or-int/2addr v10, v12

    .line 131
    goto :goto_9

    .line 132
    :cond_a
    move-object/from16 v11, p6

    .line 133
    .line 134
    :goto_9
    const/high16 v12, 0x36000000

    .line 135
    .line 136
    or-int/2addr v10, v12

    .line 137
    invoke-virtual {v1, v3}, Ll2/t;->h(Z)Z

    .line 138
    .line 139
    .line 140
    move-result v12

    .line 141
    if-eqz v12, :cond_b

    .line 142
    .line 143
    const/16 v12, 0x800

    .line 144
    .line 145
    goto :goto_a

    .line 146
    :cond_b
    const/16 v12, 0x400

    .line 147
    .line 148
    :goto_a
    const v13, 0xc301b6

    .line 149
    .line 150
    .line 151
    or-int/2addr v12, v13

    .line 152
    move-object/from16 v14, p9

    .line 153
    .line 154
    invoke-virtual {v1, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v13

    .line 158
    if-eqz v13, :cond_c

    .line 159
    .line 160
    const/16 v13, 0x4000

    .line 161
    .line 162
    goto :goto_b

    .line 163
    :cond_c
    const/16 v13, 0x2000

    .line 164
    .line 165
    :goto_b
    or-int/2addr v12, v13

    .line 166
    const/high16 v13, 0x32180000

    .line 167
    .line 168
    or-int/2addr v12, v13

    .line 169
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v13

    .line 173
    if-eqz v13, :cond_d

    .line 174
    .line 175
    move v8, v9

    .line 176
    :cond_d
    const/16 v9, 0x16

    .line 177
    .line 178
    or-int/2addr v8, v9

    .line 179
    const v9, 0x12492493

    .line 180
    .line 181
    .line 182
    and-int v13, v10, v9

    .line 183
    .line 184
    const v15, 0x12492492

    .line 185
    .line 186
    .line 187
    move/from16 p17, v9

    .line 188
    .line 189
    const/16 v16, 0x1

    .line 190
    .line 191
    if-ne v13, v15, :cond_f

    .line 192
    .line 193
    and-int v12, v12, p17

    .line 194
    .line 195
    if-ne v12, v15, :cond_f

    .line 196
    .line 197
    and-int/lit16 v8, v8, 0x93

    .line 198
    .line 199
    const/16 v12, 0x92

    .line 200
    .line 201
    if-eq v8, v12, :cond_e

    .line 202
    .line 203
    goto :goto_c

    .line 204
    :cond_e
    const/4 v8, 0x0

    .line 205
    goto :goto_d

    .line 206
    :cond_f
    :goto_c
    move/from16 v8, v16

    .line 207
    .line 208
    :goto_d
    and-int/lit8 v10, v10, 0x1

    .line 209
    .line 210
    invoke-virtual {v1, v10, v8}, Ll2/t;->O(IZ)Z

    .line 211
    .line 212
    .line 213
    move-result v8

    .line 214
    if-eqz v8, :cond_18

    .line 215
    .line 216
    invoke-virtual {v1}, Ll2/t;->T()V

    .line 217
    .line 218
    .line 219
    and-int/lit8 v8, v0, 0x1

    .line 220
    .line 221
    if-eqz v8, :cond_11

    .line 222
    .line 223
    invoke-virtual {v1}, Ll2/t;->y()Z

    .line 224
    .line 225
    .line 226
    move-result v8

    .line 227
    if-eqz v8, :cond_10

    .line 228
    .line 229
    goto :goto_e

    .line 230
    :cond_10
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 231
    .line 232
    .line 233
    move/from16 v16, p3

    .line 234
    .line 235
    move-object/from16 v8, p4

    .line 236
    .line 237
    move-object/from16 v10, p11

    .line 238
    .line 239
    move/from16 v12, p13

    .line 240
    .line 241
    move/from16 v13, p14

    .line 242
    .line 243
    move-object/from16 v18, p15

    .line 244
    .line 245
    goto :goto_10

    .line 246
    :cond_11
    :goto_e
    sget-object v8, Lh2/rb;->a:Ll2/e0;

    .line 247
    .line 248
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v8

    .line 252
    check-cast v8, Lg4/p0;

    .line 253
    .line 254
    sget-object v10, Lt1/n0;->g:Lt1/n0;

    .line 255
    .line 256
    if-eqz p12, :cond_12

    .line 257
    .line 258
    move/from16 v12, v16

    .line 259
    .line 260
    goto :goto_f

    .line 261
    :cond_12
    const v12, 0x7fffffff

    .line 262
    .line 263
    .line 264
    :goto_f
    sget-object v13, Lh2/v6;->a:Lh2/v6;

    .line 265
    .line 266
    sget-object v13, Lk2/z;->b:Lk2/f0;

    .line 267
    .line 268
    invoke-static {v13, v1}, Lh2/i8;->b(Lk2/f0;Ll2/o;)Le3/n0;

    .line 269
    .line 270
    .line 271
    move-result-object v13

    .line 272
    move-object/from16 v18, v13

    .line 273
    .line 274
    move/from16 v13, v16

    .line 275
    .line 276
    :goto_10
    invoke-virtual {v1}, Ll2/t;->r()V

    .line 277
    .line 278
    .line 279
    const v15, -0x1defba1a

    .line 280
    .line 281
    .line 282
    invoke-virtual {v1, v15}, Ll2/t;->Y(I)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v15

    .line 289
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 290
    .line 291
    if-ne v15, v9, :cond_13

    .line 292
    .line 293
    invoke-static {v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 294
    .line 295
    .line 296
    move-result-object v15

    .line 297
    :cond_13
    check-cast v15, Li1/l;

    .line 298
    .line 299
    const/4 v9, 0x0

    .line 300
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 301
    .line 302
    .line 303
    const v9, 0x519d82ef

    .line 304
    .line 305
    .line 306
    invoke-virtual {v1, v9}, Ll2/t;->Y(I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v8}, Lg4/p0;->b()J

    .line 310
    .line 311
    .line 312
    move-result-wide v19

    .line 313
    const-wide/16 v21, 0x10

    .line 314
    .line 315
    cmp-long v9, v19, v21

    .line 316
    .line 317
    if-eqz v9, :cond_14

    .line 318
    .line 319
    :goto_11
    move-wide/from16 v22, v19

    .line 320
    .line 321
    const/4 v9, 0x0

    .line 322
    goto :goto_13

    .line 323
    :cond_14
    const/4 v9, 0x0

    .line 324
    invoke-static {v15, v1, v9}, Llp/n1;->b(Li1/l;Ll2/o;I)Ll2/b1;

    .line 325
    .line 326
    .line 327
    move-result-object v17

    .line 328
    invoke-interface/range {v17 .. v17}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v9

    .line 332
    check-cast v9, Ljava/lang/Boolean;

    .line 333
    .line 334
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 335
    .line 336
    .line 337
    move-result v9

    .line 338
    if-nez v16, :cond_15

    .line 339
    .line 340
    iget-wide v2, v4, Lh2/eb;->c:J

    .line 341
    .line 342
    :goto_12
    move-wide/from16 v19, v2

    .line 343
    .line 344
    goto :goto_11

    .line 345
    :cond_15
    if-eqz p8, :cond_16

    .line 346
    .line 347
    iget-wide v2, v4, Lh2/eb;->d:J

    .line 348
    .line 349
    goto :goto_12

    .line 350
    :cond_16
    if-eqz v9, :cond_17

    .line 351
    .line 352
    iget-wide v2, v4, Lh2/eb;->a:J

    .line 353
    .line 354
    goto :goto_12

    .line 355
    :cond_17
    iget-wide v2, v4, Lh2/eb;->b:J

    .line 356
    .line 357
    goto :goto_12

    .line 358
    :goto_13
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 359
    .line 360
    .line 361
    new-instance v21, Lg4/p0;

    .line 362
    .line 363
    const-wide/16 v32, 0x0

    .line 364
    .line 365
    const v34, 0xfffffe

    .line 366
    .line 367
    .line 368
    const-wide/16 v24, 0x0

    .line 369
    .line 370
    const/16 v26, 0x0

    .line 371
    .line 372
    const/16 v27, 0x0

    .line 373
    .line 374
    const/16 v28, 0x0

    .line 375
    .line 376
    const-wide/16 v29, 0x0

    .line 377
    .line 378
    const/16 v31, 0x0

    .line 379
    .line 380
    invoke-direct/range {v21 .. v34}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 381
    .line 382
    .line 383
    move-object/from16 v2, v21

    .line 384
    .line 385
    invoke-virtual {v8, v2}, Lg4/p0;->d(Lg4/p0;)Lg4/p0;

    .line 386
    .line 387
    .line 388
    move-result-object v2

    .line 389
    sget-object v3, Le2/e1;->a:Ll2/e0;

    .line 390
    .line 391
    iget-object v9, v4, Lh2/eb;->k:Le2/d1;

    .line 392
    .line 393
    invoke-virtual {v3, v9}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 394
    .line 395
    .line 396
    move-result-object v3

    .line 397
    new-instance v0, Lh2/b7;

    .line 398
    .line 399
    move-object/from16 v17, p7

    .line 400
    .line 401
    move-object/from16 v9, p10

    .line 402
    .line 403
    move-object/from16 v35, v1

    .line 404
    .line 405
    move-object/from16 v36, v3

    .line 406
    .line 407
    move-object v1, v7

    .line 408
    move-object/from16 v19, v8

    .line 409
    .line 410
    move/from16 v7, v16

    .line 411
    .line 412
    move/from16 v3, p8

    .line 413
    .line 414
    move-object v8, v2

    .line 415
    move-object/from16 v16, v11

    .line 416
    .line 417
    move-object/from16 v2, p5

    .line 418
    .line 419
    move/from16 v11, p12

    .line 420
    .line 421
    invoke-direct/range {v0 .. v18}, Lh2/b7;-><init>(Lx2/s;Lay0/n;ZLh2/eb;Ll4/v;Lay0/k;ZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Li1/l;Lay0/n;Lay0/n;Le3/n0;)V

    .line 422
    .line 423
    .line 424
    const v1, -0x7cd4204b

    .line 425
    .line 426
    .line 427
    move-object/from16 v2, v35

    .line 428
    .line 429
    invoke-static {v1, v2, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    const/16 v1, 0x38

    .line 434
    .line 435
    move-object/from16 v3, v36

    .line 436
    .line 437
    invoke-static {v3, v0, v2, v1}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 438
    .line 439
    .line 440
    move v4, v7

    .line 441
    move v14, v12

    .line 442
    move v15, v13

    .line 443
    move-object/from16 v16, v18

    .line 444
    .line 445
    move-object/from16 v5, v19

    .line 446
    .line 447
    move-object v12, v10

    .line 448
    goto :goto_14

    .line 449
    :cond_18
    move-object v2, v1

    .line 450
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 451
    .line 452
    .line 453
    move/from16 v4, p3

    .line 454
    .line 455
    move-object/from16 v5, p4

    .line 456
    .line 457
    move-object/from16 v12, p11

    .line 458
    .line 459
    move/from16 v14, p13

    .line 460
    .line 461
    move/from16 v15, p14

    .line 462
    .line 463
    move-object/from16 v16, p15

    .line 464
    .line 465
    :goto_14
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 466
    .line 467
    .line 468
    move-result-object v0

    .line 469
    if-eqz v0, :cond_19

    .line 470
    .line 471
    move-object v1, v0

    .line 472
    new-instance v0, Lh2/w6;

    .line 473
    .line 474
    move-object/from16 v2, p1

    .line 475
    .line 476
    move-object/from16 v3, p2

    .line 477
    .line 478
    move-object/from16 v6, p5

    .line 479
    .line 480
    move-object/from16 v7, p6

    .line 481
    .line 482
    move-object/from16 v8, p7

    .line 483
    .line 484
    move/from16 v9, p8

    .line 485
    .line 486
    move-object/from16 v10, p9

    .line 487
    .line 488
    move-object/from16 v11, p10

    .line 489
    .line 490
    move/from16 v13, p12

    .line 491
    .line 492
    move-object/from16 v17, p16

    .line 493
    .line 494
    move/from16 v18, p18

    .line 495
    .line 496
    move-object/from16 v37, v1

    .line 497
    .line 498
    move-object/from16 v1, p0

    .line 499
    .line 500
    invoke-direct/range {v0 .. v18}, Lh2/w6;-><init>(Ll4/v;Lay0/k;Lx2/s;ZLg4/p0;Lay0/n;Lay0/n;Lay0/n;ZLl4/d0;Lt1/o0;Lt1/n0;ZIILe3/n0;Lh2/eb;I)V

    .line 501
    .line 502
    .line 503
    move-object/from16 v1, v37

    .line 504
    .line 505
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    .line 506
    .line 507
    :cond_19
    return-void
.end method

.method public static final b(Lay0/n;Lay0/o;Lay0/n;Lay0/n;Lay0/n;Lay0/n;Lay0/n;ZLh2/nb;Li2/g1;Lay0/k;Lt2/b;Lay0/n;Lk1/z0;Ll2/o;II)V
    .locals 33

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v10, p9

    move-object/from16 v0, p11

    move-object/from16 v15, p12

    move-object/from16 v13, p13

    move/from16 v8, p15

    move/from16 v9, p16

    .line 1
    sget-object v11, Lx2/c;->h:Lx2/j;

    sget-object v12, Lx2/c;->d:Lx2/j;

    move-object/from16 v14, p14

    check-cast v14, Ll2/t;

    move-object/from16 v16, v11

    const v11, 0x2cec89be

    invoke-virtual {v14, v11}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v11, v8, 0x6

    move/from16 p14, v11

    sget-object v11, Lx2/p;->b:Lx2/p;

    move-object/from16 v17, v12

    if-nez p14, :cond_1

    invoke-virtual {v14, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_0

    const/16 v19, 0x4

    goto :goto_0

    :cond_0
    const/16 v19, 0x2

    :goto_0
    or-int v19, v8, v19

    goto :goto_1

    :cond_1
    move/from16 v19, v8

    :goto_1
    and-int/lit8 v20, v8, 0x30

    const/16 v21, 0x10

    if-nez v20, :cond_3

    invoke-virtual {v14, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_2

    const/16 v20, 0x20

    goto :goto_2

    :cond_2
    move/from16 v20, v21

    :goto_2
    or-int v19, v19, v20

    :cond_3
    and-int/lit16 v12, v8, 0x180

    const/16 v22, 0x80

    const/16 v23, 0x100

    if-nez v12, :cond_5

    invoke-virtual {v14, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_4

    move/from16 v12, v23

    goto :goto_3

    :cond_4
    move/from16 v12, v22

    :goto_3
    or-int v19, v19, v12

    :cond_5
    and-int/lit16 v12, v8, 0xc00

    const/16 v24, 0x400

    const/16 v25, 0x800

    if-nez v12, :cond_7

    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_6

    move/from16 v12, v25

    goto :goto_4

    :cond_6
    move/from16 v12, v24

    :goto_4
    or-int v19, v19, v12

    :cond_7
    and-int/lit16 v12, v8, 0x6000

    const/16 v26, 0x2000

    if-nez v12, :cond_9

    invoke-virtual {v14, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_8

    const/16 v12, 0x4000

    goto :goto_5

    :cond_8
    move/from16 v12, v26

    :goto_5
    or-int v19, v19, v12

    :cond_9
    const/high16 v12, 0x30000

    and-int v12, p15, v12

    if-nez v12, :cond_b

    invoke-virtual {v14, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_a

    const/high16 v12, 0x20000

    goto :goto_6

    :cond_a
    const/high16 v12, 0x10000

    :goto_6
    or-int v19, v19, v12

    :cond_b
    const/high16 v12, 0x180000

    and-int v12, p15, v12

    if-nez v12, :cond_d

    invoke-virtual {v14, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_c

    const/high16 v12, 0x100000

    goto :goto_7

    :cond_c
    const/high16 v12, 0x80000

    :goto_7
    or-int v19, v19, v12

    :cond_d
    const/high16 v12, 0xc00000

    and-int v12, p15, v12

    if-nez v12, :cond_f

    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_e

    const/high16 v12, 0x800000

    goto :goto_8

    :cond_e
    const/high16 v12, 0x400000

    :goto_8
    or-int v19, v19, v12

    :cond_f
    const/high16 v12, 0x6000000

    and-int v12, p15, v12

    if-nez v12, :cond_11

    move/from16 v12, p7

    invoke-virtual {v14, v12}, Ll2/t;->h(Z)Z

    move-result v28

    if-eqz v28, :cond_10

    const/high16 v28, 0x4000000

    goto :goto_9

    :cond_10
    const/high16 v28, 0x2000000

    :goto_9
    or-int v19, v19, v28

    goto :goto_a

    :cond_11
    move/from16 v12, p7

    :goto_a
    const/high16 v28, 0x30000000

    and-int v28, p15, v28

    move-object/from16 v8, p8

    if-nez v28, :cond_13

    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_12

    const/high16 v30, 0x20000000

    goto :goto_b

    :cond_12
    const/high16 v30, 0x10000000

    :goto_b
    or-int v19, v19, v30

    :cond_13
    and-int/lit8 v30, v9, 0x6

    if-nez v30, :cond_16

    and-int/lit8 v30, v9, 0x8

    if-nez v30, :cond_14

    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v30

    goto :goto_c

    :cond_14
    invoke-virtual {v14, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v30

    :goto_c
    if-eqz v30, :cond_15

    const/16 v30, 0x4

    goto :goto_d

    :cond_15
    const/16 v30, 0x2

    :goto_d
    or-int v30, v9, v30

    goto :goto_e

    :cond_16
    move/from16 v30, v9

    :goto_e
    and-int/lit8 v31, v9, 0x30

    move-object/from16 v8, p10

    if-nez v31, :cond_18

    invoke-virtual {v14, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v31

    if-eqz v31, :cond_17

    const/16 v21, 0x20

    :cond_17
    or-int v30, v30, v21

    :cond_18
    and-int/lit16 v8, v9, 0x180

    if-nez v8, :cond_1a

    invoke-virtual {v14, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_19

    move/from16 v22, v23

    :cond_19
    or-int v30, v30, v22

    :cond_1a
    and-int/lit16 v8, v9, 0xc00

    if-nez v8, :cond_1c

    invoke-virtual {v14, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_1b

    move/from16 v24, v25

    :cond_1b
    or-int v30, v30, v24

    :cond_1c
    and-int/lit16 v8, v9, 0x6000

    if-nez v8, :cond_1e

    invoke-virtual {v14, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_1d

    const/16 v26, 0x4000

    :cond_1d
    or-int v30, v30, v26

    :cond_1e
    move/from16 v8, v30

    const v21, 0x12492493

    and-int v9, v19, v21

    move-object/from16 v21, v11

    const v11, 0x12492492

    if-ne v9, v11, :cond_20

    and-int/lit16 v9, v8, 0x2493

    const/16 v11, 0x2492

    if-eq v9, v11, :cond_1f

    goto :goto_f

    :cond_1f
    const/4 v9, 0x0

    goto :goto_10

    :cond_20
    :goto_f
    const/4 v9, 0x1

    :goto_10
    and-int/lit8 v11, v19, 0x1

    invoke-virtual {v14, v11, v9}, Ll2/t;->O(IZ)Z

    move-result v9

    if-eqz v9, :cond_51

    .line 2
    invoke-static {v14}, Li2/h1;->e(Ll2/o;)F

    move-result v9

    and-int/lit8 v11, v8, 0x70

    const/16 v15, 0x20

    if-ne v11, v15, :cond_21

    const/4 v11, 0x1

    goto :goto_11

    :cond_21
    const/4 v11, 0x0

    :goto_11
    const/high16 v15, 0xe000000

    and-int v15, v19, v15

    move/from16 v20, v8

    const/high16 v8, 0x4000000

    if-ne v15, v8, :cond_22

    const/4 v8, 0x1

    goto :goto_12

    :cond_22
    const/4 v8, 0x0

    :goto_12
    or-int/2addr v8, v11

    const/high16 v11, 0x70000000

    and-int v11, v19, v11

    const/high16 v15, 0x20000000

    if-ne v11, v15, :cond_23

    const/4 v11, 0x1

    goto :goto_13

    :cond_23
    const/4 v11, 0x0

    :goto_13
    or-int/2addr v8, v11

    and-int/lit8 v15, v20, 0xe

    const/4 v11, 0x4

    if-eq v15, v11, :cond_25

    and-int/lit8 v18, v20, 0x8

    if-eqz v18, :cond_24

    .line 3
    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_24

    goto :goto_14

    :cond_24
    const/16 v18, 0x0

    goto :goto_15

    :cond_25
    :goto_14
    const/16 v18, 0x1

    :goto_15
    or-int v8, v8, v18

    const v18, 0xe000

    and-int v11, v20, v18

    move/from16 v18, v8

    const/16 v8, 0x4000

    if-ne v11, v8, :cond_26

    const/4 v8, 0x1

    goto :goto_16

    :cond_26
    const/4 v8, 0x0

    :goto_16
    or-int v8, v18, v8

    .line 4
    invoke-virtual {v14, v9}, Ll2/t;->d(F)Z

    move-result v11

    or-int/2addr v8, v11

    .line 5
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v11

    .line 6
    sget-object v3, Ll2/n;->a:Ll2/x0;

    if-nez v8, :cond_28

    if-ne v11, v3, :cond_27

    goto :goto_17

    :cond_27
    move-object/from16 p14, v3

    move-object v1, v14

    move-object/from16 v3, v16

    move-object/from16 v2, v21

    const/4 v7, 0x2

    move v14, v9

    move/from16 v16, v15

    move-object/from16 v15, v17

    goto :goto_18

    .line 7
    :cond_28
    :goto_17
    new-instance v8, Lh2/e7;

    move/from16 p14, v12

    move-object v12, v10

    move/from16 v10, p14

    move-object/from16 v11, p8

    move-object/from16 p14, v3

    move-object v1, v14

    move-object/from16 v3, v16

    move-object/from16 v2, v21

    const/4 v7, 0x2

    move v14, v9

    move/from16 v16, v15

    move-object/from16 v15, v17

    move-object/from16 v9, p10

    invoke-direct/range {v8 .. v14}, Lh2/e7;-><init>(Lay0/k;ZLh2/nb;Li2/g1;Lk1/z0;F)V

    .line 8
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    move-object v11, v8

    .line 9
    :goto_18
    check-cast v11, Lh2/e7;

    .line 10
    sget-object v8, Lw3/h1;->n:Ll2/u2;

    .line 11
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v8

    .line 12
    check-cast v8, Lt4/m;

    move-object v12, v8

    .line 13
    iget-wide v7, v1, Ll2/t;->T:J

    .line 14
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    move-result v7

    .line 15
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v8

    .line 16
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v9

    .line 17
    sget-object v18, Lv3/k;->m1:Lv3/j;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 v18, v12

    .line 18
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 19
    invoke-virtual {v1}, Ll2/t;->c0()V

    move/from16 v21, v14

    .line 20
    iget-boolean v14, v1, Ll2/t;->S:Z

    if-eqz v14, :cond_29

    .line 21
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_19

    .line 22
    :cond_29
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 23
    :goto_19
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 24
    invoke-static {v14, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 25
    sget-object v11, Lv3/j;->f:Lv3/h;

    .line 26
    invoke-static {v11, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 27
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 28
    iget-boolean v10, v1, Ll2/t;->S:Z

    if-nez v10, :cond_2a

    .line 29
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v10, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_2b

    .line 30
    :cond_2a
    invoke-static {v7, v1, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 31
    :cond_2b
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 32
    invoke-static {v6, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v7, v20, 0x6

    and-int/lit8 v7, v7, 0xe

    .line 33
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-virtual {v0, v1, v7}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    if-eqz v4, :cond_2f

    const v7, 0x7fe3b06d

    .line 34
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 35
    const-string v7, "Leading"

    invoke-static {v2, v7}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v7

    .line 36
    sget-object v9, Landroidx/compose/material3/MinimumInteractiveModifier;->b:Landroidx/compose/material3/MinimumInteractiveModifier;

    invoke-interface {v7, v9}, Lx2/s;->g(Lx2/s;)Lx2/s;

    move-result-object v7

    const/4 v9, 0x0

    .line 37
    invoke-static {v3, v9}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v10

    move-object/from16 v24, v2

    move-object v9, v3

    .line 38
    iget-wide v2, v1, Ll2/t;->T:J

    .line 39
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    move-result v2

    .line 40
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v3

    .line 41
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v7

    .line 42
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 43
    iget-boolean v0, v1, Ll2/t;->S:Z

    if-eqz v0, :cond_2c

    .line 44
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_1a

    .line 45
    :cond_2c
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 46
    :goto_1a
    invoke-static {v14, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 47
    invoke-static {v11, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 48
    iget-boolean v0, v1, Ll2/t;->S:Z

    if-nez v0, :cond_2d

    .line 49
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2e

    .line 50
    :cond_2d
    invoke-static {v2, v1, v2, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 51
    :cond_2e
    invoke-static {v6, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v19, 0xc

    and-int/lit8 v0, v0, 0xe

    const/4 v2, 0x1

    const/4 v3, 0x0

    .line 52
    invoke-static {v0, v4, v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    goto :goto_1b

    :cond_2f
    move-object/from16 v24, v2

    move-object v9, v3

    const/4 v3, 0x0

    const v0, 0x7fe7716d

    .line 53
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 54
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    :goto_1b
    if-eqz v5, :cond_33

    const v0, 0x7fe8184b

    .line 55
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 56
    const-string v0, "Trailing"

    move-object/from16 v2, v24

    invoke-static {v2, v0}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v0

    .line 57
    sget-object v7, Landroidx/compose/material3/MinimumInteractiveModifier;->b:Landroidx/compose/material3/MinimumInteractiveModifier;

    invoke-interface {v0, v7}, Lx2/s;->g(Lx2/s;)Lx2/s;

    move-result-object v0

    .line 58
    invoke-static {v9, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v7

    .line 59
    iget-wide v9, v1, Ll2/t;->T:J

    .line 60
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    move-result v3

    .line 61
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v9

    .line 62
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 63
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 64
    iget-boolean v10, v1, Ll2/t;->S:Z

    if-eqz v10, :cond_30

    .line 65
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_1c

    .line 66
    :cond_30
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 67
    :goto_1c
    invoke-static {v14, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 68
    invoke-static {v11, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 69
    iget-boolean v7, v1, Ll2/t;->S:Z

    if-nez v7, :cond_31

    .line 70
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_32

    .line 71
    :cond_31
    invoke-static {v3, v1, v3, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 72
    :cond_32
    invoke-static {v6, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v19, 0xf

    and-int/lit8 v0, v0, 0xe

    const/4 v3, 0x1

    const/4 v9, 0x0

    .line 73
    invoke-static {v0, v5, v1, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    :goto_1d
    move-object/from16 v0, v18

    goto :goto_1e

    :cond_33
    move v9, v3

    move-object/from16 v2, v24

    const v0, 0x7febe0cd

    .line 74
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 75
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    goto :goto_1d

    .line 76
    :goto_1e
    invoke-static {v13, v0}, Landroidx/compose/foundation/layout/a;->f(Lk1/z0;Lt4/m;)F

    move-result v3

    .line 77
    invoke-static {v13, v0}, Landroidx/compose/foundation/layout/a;->e(Lk1/z0;Lt4/m;)F

    move-result v0

    if-eqz v4, :cond_34

    sub-float v3, v3, v21

    int-to-float v7, v9

    cmpg-float v10, v3, v7

    if-gez v10, :cond_34

    move v3, v7

    :cond_34
    move/from16 v25, v3

    if-eqz v5, :cond_35

    sub-float v0, v0, v21

    int-to-float v3, v9

    cmpg-float v7, v0, v3

    if-gez v7, :cond_35

    move v0, v3

    :cond_35
    const/4 v3, 0x0

    const/4 v7, 0x3

    if-eqz p5, :cond_39

    const v9, 0x7ff69eb8

    .line 78
    invoke-virtual {v1, v9}, Ll2/t;->Y(I)V

    .line 79
    const-string v9, "Prefix"

    invoke-static {v2, v9}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v9

    .line 80
    sget v10, Li2/h1;->d:F

    move/from16 v18, v0

    const/4 v0, 0x2

    invoke-static {v9, v10, v3, v0}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    move-result-object v10

    .line 81
    invoke-static {v10, v7}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    move-result-object v24

    .line 82
    sget v27, Li2/h1;->c:F

    const/16 v28, 0x0

    const/16 v29, 0xa

    const/16 v26, 0x0

    invoke-static/range {v24 .. v29}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    move-result-object v0

    const/4 v10, 0x0

    .line 83
    invoke-static {v15, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v9

    .line 84
    iget-wide v3, v1, Ll2/t;->T:J

    .line 85
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    move-result v3

    .line 86
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v4

    .line 87
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 88
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 89
    iget-boolean v10, v1, Ll2/t;->S:Z

    if-eqz v10, :cond_36

    .line 90
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_1f

    .line 91
    :cond_36
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 92
    :goto_1f
    invoke-static {v14, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 93
    invoke-static {v11, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 94
    iget-boolean v4, v1, Ll2/t;->S:Z

    if-nez v4, :cond_37

    .line 95
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_38

    .line 96
    :cond_37
    invoke-static {v3, v1, v3, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 97
    :cond_38
    invoke-static {v6, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v19, 0x12

    and-int/lit8 v0, v0, 0xe

    move-object/from16 v3, p5

    const/4 v4, 0x1

    const/4 v9, 0x0

    .line 98
    invoke-static {v0, v3, v1, v4, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    goto :goto_20

    :cond_39
    move-object/from16 v3, p5

    move/from16 v18, v0

    const/4 v9, 0x0

    const v0, 0x7ffb9ecd

    .line 99
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 100
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    :goto_20
    if-eqz p6, :cond_3d

    const v0, 0x7ffc47ba

    .line 101
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 102
    const-string v0, "Suffix"

    invoke-static {v2, v0}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v0

    .line 103
    sget v4, Li2/h1;->d:F

    const/4 v9, 0x2

    const/4 v10, 0x0

    invoke-static {v0, v4, v10, v9}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    move-result-object v0

    .line 104
    invoke-static {v0, v7}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    move-result-object v26

    .line 105
    sget v27, Li2/h1;->c:F

    const/16 v30, 0x0

    const/16 v31, 0xa

    const/16 v28, 0x0

    move/from16 v29, v18

    invoke-static/range {v26 .. v31}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    move-result-object v0

    const/4 v4, 0x0

    .line 106
    invoke-static {v15, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v9

    move-object v4, v8

    .line 107
    iget-wide v7, v1, Ll2/t;->T:J

    .line 108
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    move-result v7

    .line 109
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v8

    .line 110
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 111
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 112
    iget-boolean v10, v1, Ll2/t;->S:Z

    if-eqz v10, :cond_3a

    .line 113
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_21

    .line 114
    :cond_3a
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 115
    :goto_21
    invoke-static {v14, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    invoke-static {v11, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    iget-boolean v8, v1, Ll2/t;->S:Z

    if-nez v8, :cond_3b

    .line 118
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_3c

    .line 119
    :cond_3b
    invoke-static {v7, v1, v7, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 120
    :cond_3c
    invoke-static {v6, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v19, 0x15

    and-int/lit8 v0, v0, 0xe

    move-object/from16 v7, p6

    const/4 v8, 0x1

    const/4 v9, 0x0

    .line 121
    invoke-static {v0, v7, v1, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    goto :goto_22

    :cond_3d
    move-object/from16 v7, p6

    move-object v4, v8

    const/4 v9, 0x0

    const v0, -0x7ffebfb3

    .line 122
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 123
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 124
    :goto_22
    sget v0, Li2/h1;->d:F

    move/from16 v23, v9

    const/4 v9, 0x2

    const/4 v10, 0x0

    invoke-static {v2, v0, v10, v9}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    move-result-object v0

    move/from16 v9, v23

    const/4 v8, 0x3

    .line 125
    invoke-static {v0, v8}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    move-result-object v26

    if-nez v3, :cond_3e

    move/from16 v27, v25

    goto :goto_23

    :cond_3e
    int-to-float v0, v9

    move/from16 v27, v0

    :goto_23
    if-nez v7, :cond_3f

    move/from16 v29, v18

    goto :goto_24

    :cond_3f
    int-to-float v0, v9

    move/from16 v29, v0

    :goto_24
    const/16 v30, 0x0

    const/16 v31, 0xa

    const/16 v28, 0x0

    .line 126
    invoke-static/range {v26 .. v31}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    move-result-object v0

    if-eqz p1, :cond_40

    const v8, -0x7ff91a72

    .line 127
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 128
    const-string v8, "Hint"

    invoke-static {v2, v8}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v8

    invoke-interface {v8, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    move-result-object v8

    shr-int/lit8 v9, v19, 0x3

    and-int/lit8 v9, v9, 0x70

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    move-object/from16 v10, p1

    invoke-interface {v10, v8, v1, v9}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v9, 0x0

    .line 129
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    goto :goto_25

    :cond_40
    move-object/from16 v10, p1

    const/4 v9, 0x0

    const v8, -0x7ff7b5d3

    .line 130
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 131
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 132
    :goto_25
    const-string v8, "TextField"

    invoke-static {v2, v8}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v8

    invoke-interface {v8, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    move-result-object v0

    const/4 v8, 0x1

    .line 133
    invoke-static {v15, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v9

    .line 134
    iget-wide v7, v1, Ll2/t;->T:J

    .line 135
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    move-result v7

    .line 136
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v8

    .line 137
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 138
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 139
    iget-boolean v3, v1, Ll2/t;->S:Z

    if-eqz v3, :cond_41

    .line 140
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_26

    .line 141
    :cond_41
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 142
    :goto_26
    invoke-static {v14, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    invoke-static {v11, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    iget-boolean v3, v1, Ll2/t;->S:Z

    if-nez v3, :cond_42

    .line 145
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_43

    .line 146
    :cond_42
    invoke-static {v7, v1, v7, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 147
    :cond_43
    invoke-static {v6, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v19, 0x3

    and-int/lit8 v0, v0, 0xe

    const/4 v8, 0x1

    move-object/from16 v3, p0

    .line 148
    invoke-static {v0, v3, v1, v8}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    if-eqz p2, :cond_4c

    const v0, -0x7fedc0ae

    .line 149
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    move/from16 v0, v16

    const/4 v7, 0x4

    if-eq v0, v7, :cond_46

    and-int/lit8 v0, v20, 0x8

    if-eqz v0, :cond_44

    move-object/from16 v0, p9

    .line 150
    invoke-virtual {v1, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_45

    goto :goto_27

    :cond_44
    move-object/from16 v0, p9

    :cond_45
    const/4 v7, 0x0

    goto :goto_28

    :cond_46
    move-object/from16 v0, p9

    :goto_27
    const/4 v7, 0x1

    .line 151
    :goto_28
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_47

    move-object/from16 v7, p14

    if-ne v8, v7, :cond_48

    .line 152
    :cond_47
    new-instance v8, Lh2/x6;

    const/4 v7, 0x0

    invoke-direct {v8, v0, v7}, Lh2/x6;-><init>(Li2/g1;I)V

    .line 153
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    :cond_48
    check-cast v8, Lay0/a;

    .line 155
    new-instance v7, La71/k;

    const/16 v9, 0x8

    invoke-direct {v7, v8, v9}, La71/k;-><init>(Lay0/a;I)V

    invoke-static {v2, v7}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    move-result-object v7

    const/4 v8, 0x3

    .line 156
    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    move-result-object v7

    .line 157
    const-string v8, "Label"

    invoke-static {v7, v8}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v7

    .line 158
    invoke-interface {v7, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    move-result-object v7

    const/4 v9, 0x0

    .line 159
    invoke-static {v15, v9}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v8

    .line 160
    iget-wide v9, v1, Ll2/t;->T:J

    .line 161
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    move-result v9

    .line 162
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v10

    .line 163
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v7

    .line 164
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 165
    iget-boolean v0, v1, Ll2/t;->S:Z

    if-eqz v0, :cond_49

    .line 166
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_29

    .line 167
    :cond_49
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 168
    :goto_29
    invoke-static {v14, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 169
    invoke-static {v11, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 170
    iget-boolean v0, v1, Ll2/t;->S:Z

    if-nez v0, :cond_4a

    .line 171
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_4b

    .line 172
    :cond_4a
    invoke-static {v9, v1, v9, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 173
    :cond_4b
    invoke-static {v6, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v19, 0x9

    and-int/lit8 v0, v0, 0xe

    move-object/from16 v7, p2

    const/4 v8, 0x1

    const/4 v9, 0x0

    .line 174
    invoke-static {v0, v7, v1, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    goto :goto_2a

    :cond_4c
    move-object/from16 v7, p2

    const/4 v9, 0x0

    const v0, -0x7fe7b9d3

    .line 175
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 176
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    :goto_2a
    if-eqz p12, :cond_50

    const v0, -0x7fe6fc50

    .line 177
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 178
    const-string v0, "Supporting"

    invoke-static {v2, v0}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    move-result-object v0

    .line 179
    sget v2, Li2/h1;->f:F

    const/4 v9, 0x2

    const/4 v10, 0x0

    invoke-static {v0, v2, v10, v9}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    move-result-object v0

    const/4 v8, 0x3

    .line 180
    invoke-static {v0, v8}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    move-result-object v0

    .line 181
    invoke-static {}, Lh2/hb;->h()Lk1/a1;

    move-result-object v2

    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    move-result-object v0

    const/4 v9, 0x0

    .line 182
    invoke-static {v15, v9}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v2

    .line 183
    iget-wide v8, v1, Ll2/t;->T:J

    .line 184
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    move-result v8

    .line 185
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    move-result-object v9

    .line 186
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 187
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 188
    iget-boolean v10, v1, Ll2/t;->S:Z

    if-eqz v10, :cond_4d

    .line 189
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    goto :goto_2b

    .line 190
    :cond_4d
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 191
    :goto_2b
    invoke-static {v14, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 192
    invoke-static {v11, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 193
    iget-boolean v2, v1, Ll2/t;->S:Z

    if-nez v2, :cond_4e

    .line 194
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_4f

    .line 195
    :cond_4e
    invoke-static {v8, v1, v8, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 196
    :cond_4f
    invoke-static {v6, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v20, 0x9

    and-int/lit8 v0, v0, 0xe

    move-object/from16 v15, p12

    const/4 v8, 0x1

    const/4 v9, 0x0

    .line 197
    invoke-static {v0, v15, v1, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    goto :goto_2c

    :cond_50
    move-object/from16 v15, p12

    const/4 v8, 0x1

    const/4 v9, 0x0

    const v0, -0x7fe1de33

    .line 198
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 199
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 200
    :goto_2c
    invoke-virtual {v1, v8}, Ll2/t;->q(Z)V

    goto :goto_2d

    :cond_51
    move-object/from16 v15, p12

    move-object v7, v3

    move-object v3, v1

    move-object v1, v14

    .line 201
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 202
    :goto_2d
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_52

    move-object v1, v0

    new-instance v0, Lh2/y6;

    move-object/from16 v2, p1

    move-object/from16 v4, p3

    move-object/from16 v6, p5

    move/from16 v8, p7

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move/from16 v16, p16

    move-object/from16 v32, v1

    move-object v1, v3

    move-object v3, v7

    move-object v14, v13

    move-object v13, v15

    move-object/from16 v7, p6

    move/from16 v15, p15

    invoke-direct/range {v0 .. v16}, Lh2/y6;-><init>(Lay0/n;Lay0/o;Lay0/n;Lay0/n;Lay0/n;Lay0/n;Lay0/n;ZLh2/nb;Li2/g1;Lay0/k;Lt2/b;Lay0/n;Lk1/z0;II)V

    move-object/from16 v1, v32

    .line 203
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_52
    return-void
.end method
