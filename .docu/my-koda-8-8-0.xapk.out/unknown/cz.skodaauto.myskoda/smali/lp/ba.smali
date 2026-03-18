.class public abstract Llp/ba;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcom/google/android/gms/maps/model/LatLng;JDJFZFLay0/k;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-wide/from16 v4, p1

    .line 4
    .line 5
    move-wide/from16 v6, p5

    .line 6
    .line 7
    move/from16 v12, p12

    .line 8
    .line 9
    move-object/from16 v13, p11

    .line 10
    .line 11
    check-cast v13, Ll2/t;

    .line 12
    .line 13
    const v0, 0x8505f66

    .line 14
    .line 15
    .line 16
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    iget-object v14, v13, Ll2/t;->a:Leb/j0;

    .line 20
    .line 21
    and-int/lit8 v0, v12, 0x6

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {v13, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    move v0, v1

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v0, 0x2

    .line 35
    :goto_0
    or-int/2addr v0, v12

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v0, v12

    .line 38
    :goto_1
    or-int/lit8 v0, v0, 0x30

    .line 39
    .line 40
    and-int/lit16 v2, v12, 0x180

    .line 41
    .line 42
    if-nez v2, :cond_3

    .line 43
    .line 44
    invoke-virtual {v13, v4, v5}, Ll2/t;->f(J)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    const/16 v2, 0x100

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v2, 0x80

    .line 54
    .line 55
    :goto_2
    or-int/2addr v0, v2

    .line 56
    :cond_3
    and-int/lit16 v2, v12, 0xc00

    .line 57
    .line 58
    if-nez v2, :cond_5

    .line 59
    .line 60
    invoke-virtual {v13}, Ll2/t;->D()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    instance-of v10, v2, Ljava/lang/Double;

    .line 65
    .line 66
    if-eqz v10, :cond_4

    .line 67
    .line 68
    check-cast v2, Ljava/lang/Number;

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 71
    .line 72
    .line 73
    move-result-wide v10

    .line 74
    cmpg-double v2, p3, v10

    .line 75
    .line 76
    if-nez v2, :cond_4

    .line 77
    .line 78
    const/16 v2, 0x400

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_4
    invoke-static/range {p3 .. p4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-virtual {v13, v2}, Ll2/t;->k0(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    const/16 v2, 0x800

    .line 89
    .line 90
    :goto_3
    or-int/2addr v0, v2

    .line 91
    :cond_5
    and-int/lit16 v2, v12, 0x6000

    .line 92
    .line 93
    if-nez v2, :cond_7

    .line 94
    .line 95
    invoke-virtual {v13, v6, v7}, Ll2/t;->f(J)Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_6

    .line 100
    .line 101
    const/16 v2, 0x4000

    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_6
    const/16 v2, 0x2000

    .line 105
    .line 106
    :goto_4
    or-int/2addr v0, v2

    .line 107
    :cond_7
    const/high16 v2, 0x30000

    .line 108
    .line 109
    or-int/2addr v0, v2

    .line 110
    const/high16 v2, 0x180000

    .line 111
    .line 112
    and-int/2addr v2, v12

    .line 113
    if-nez v2, :cond_9

    .line 114
    .line 115
    move/from16 v2, p7

    .line 116
    .line 117
    invoke-virtual {v13, v2}, Ll2/t;->d(F)Z

    .line 118
    .line 119
    .line 120
    move-result v15

    .line 121
    if-eqz v15, :cond_8

    .line 122
    .line 123
    const/high16 v15, 0x100000

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_8
    const/high16 v15, 0x80000

    .line 127
    .line 128
    :goto_5
    or-int/2addr v0, v15

    .line 129
    goto :goto_6

    .line 130
    :cond_9
    move/from16 v2, p7

    .line 131
    .line 132
    :goto_6
    const/high16 v15, 0x6c00000

    .line 133
    .line 134
    or-int/2addr v0, v15

    .line 135
    const/high16 v15, 0x30000000

    .line 136
    .line 137
    and-int/2addr v15, v12

    .line 138
    if-nez v15, :cond_b

    .line 139
    .line 140
    move/from16 v15, p9

    .line 141
    .line 142
    invoke-virtual {v13, v15}, Ll2/t;->d(F)Z

    .line 143
    .line 144
    .line 145
    move-result v16

    .line 146
    if-eqz v16, :cond_a

    .line 147
    .line 148
    const/high16 v16, 0x20000000

    .line 149
    .line 150
    goto :goto_7

    .line 151
    :cond_a
    const/high16 v16, 0x10000000

    .line 152
    .line 153
    :goto_7
    or-int v0, v0, v16

    .line 154
    .line 155
    goto :goto_8

    .line 156
    :cond_b
    move/from16 v15, p9

    .line 157
    .line 158
    :goto_8
    const v16, 0x12492493

    .line 159
    .line 160
    .line 161
    and-int v11, v0, v16

    .line 162
    .line 163
    const v10, 0x12492492

    .line 164
    .line 165
    .line 166
    const/16 v17, 0x0

    .line 167
    .line 168
    if-ne v11, v10, :cond_c

    .line 169
    .line 170
    move/from16 v10, v17

    .line 171
    .line 172
    goto :goto_9

    .line 173
    :cond_c
    const/4 v10, 0x1

    .line 174
    :goto_9
    and-int/lit8 v11, v0, 0x1

    .line 175
    .line 176
    invoke-virtual {v13, v11, v10}, Ll2/t;->O(IZ)Z

    .line 177
    .line 178
    .line 179
    move-result v10

    .line 180
    if-eqz v10, :cond_1b

    .line 181
    .line 182
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 187
    .line 188
    if-ne v10, v11, :cond_d

    .line 189
    .line 190
    new-instance v10, Lu2/d;

    .line 191
    .line 192
    const/16 v9, 0x1d

    .line 193
    .line 194
    invoke-direct {v10, v9}, Lu2/d;-><init>(I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v13, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    :cond_d
    move-object v9, v10

    .line 201
    check-cast v9, Lay0/k;

    .line 202
    .line 203
    instance-of v10, v14, Luu/x;

    .line 204
    .line 205
    if-eqz v10, :cond_e

    .line 206
    .line 207
    move-object v10, v14

    .line 208
    check-cast v10, Luu/x;

    .line 209
    .line 210
    goto :goto_a

    .line 211
    :cond_e
    const/4 v10, 0x0

    .line 212
    :goto_a
    invoke-virtual {v13, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v20

    .line 216
    and-int/lit8 v8, v0, 0xe

    .line 217
    .line 218
    if-ne v8, v1, :cond_f

    .line 219
    .line 220
    const/4 v1, 0x1

    .line 221
    goto :goto_b

    .line 222
    :cond_f
    move/from16 v1, v17

    .line 223
    .line 224
    :goto_b
    or-int v1, v20, v1

    .line 225
    .line 226
    and-int/lit8 v8, v0, 0x70

    .line 227
    .line 228
    move/from16 p10, v1

    .line 229
    .line 230
    const/16 v1, 0x20

    .line 231
    .line 232
    if-ne v8, v1, :cond_10

    .line 233
    .line 234
    const/4 v1, 0x1

    .line 235
    goto :goto_c

    .line 236
    :cond_10
    move/from16 v1, v17

    .line 237
    .line 238
    :goto_c
    or-int v1, p10, v1

    .line 239
    .line 240
    and-int/lit16 v8, v0, 0x380

    .line 241
    .line 242
    move/from16 p10, v1

    .line 243
    .line 244
    const/16 v1, 0x100

    .line 245
    .line 246
    if-ne v8, v1, :cond_11

    .line 247
    .line 248
    const/4 v1, 0x1

    .line 249
    goto :goto_d

    .line 250
    :cond_11
    move/from16 v1, v17

    .line 251
    .line 252
    :goto_d
    or-int v1, p10, v1

    .line 253
    .line 254
    and-int/lit16 v8, v0, 0x1c00

    .line 255
    .line 256
    move/from16 v19, v0

    .line 257
    .line 258
    const/16 v0, 0x800

    .line 259
    .line 260
    if-ne v8, v0, :cond_12

    .line 261
    .line 262
    const/4 v0, 0x1

    .line 263
    goto :goto_e

    .line 264
    :cond_12
    move/from16 v0, v17

    .line 265
    .line 266
    :goto_e
    or-int/2addr v0, v1

    .line 267
    const v1, 0xe000

    .line 268
    .line 269
    .line 270
    and-int v1, v19, v1

    .line 271
    .line 272
    const/16 v8, 0x4000

    .line 273
    .line 274
    if-ne v1, v8, :cond_13

    .line 275
    .line 276
    const/4 v1, 0x1

    .line 277
    goto :goto_f

    .line 278
    :cond_13
    move/from16 v1, v17

    .line 279
    .line 280
    :goto_f
    or-int/2addr v0, v1

    .line 281
    const/4 v1, 0x0

    .line 282
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    move-result v8

    .line 286
    or-int/2addr v0, v8

    .line 287
    const/high16 v1, 0x380000

    .line 288
    .line 289
    and-int v1, v19, v1

    .line 290
    .line 291
    const/high16 v8, 0x100000

    .line 292
    .line 293
    if-ne v1, v8, :cond_14

    .line 294
    .line 295
    const/4 v1, 0x1

    .line 296
    goto :goto_10

    .line 297
    :cond_14
    move/from16 v1, v17

    .line 298
    .line 299
    :goto_10
    or-int/2addr v0, v1

    .line 300
    const/high16 v1, 0xe000000

    .line 301
    .line 302
    and-int v1, v19, v1

    .line 303
    .line 304
    const/high16 v8, 0x4000000

    .line 305
    .line 306
    if-ne v1, v8, :cond_15

    .line 307
    .line 308
    const/4 v1, 0x1

    .line 309
    goto :goto_11

    .line 310
    :cond_15
    move/from16 v1, v17

    .line 311
    .line 312
    :goto_11
    or-int/2addr v0, v1

    .line 313
    const/high16 v1, 0x70000000

    .line 314
    .line 315
    and-int v1, v19, v1

    .line 316
    .line 317
    const/high16 v8, 0x20000000

    .line 318
    .line 319
    if-ne v1, v8, :cond_16

    .line 320
    .line 321
    const/4 v1, 0x1

    .line 322
    goto :goto_12

    .line 323
    :cond_16
    move/from16 v1, v17

    .line 324
    .line 325
    :goto_12
    or-int/2addr v0, v1

    .line 326
    const/4 v1, 0x0

    .line 327
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v8

    .line 331
    or-int/2addr v0, v8

    .line 332
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v8

    .line 336
    if-nez v0, :cond_18

    .line 337
    .line 338
    if-ne v8, v11, :cond_17

    .line 339
    .line 340
    goto :goto_13

    .line 341
    :cond_17
    move-object v15, v1

    .line 342
    move-object v2, v9

    .line 343
    const/16 v18, 0x1

    .line 344
    .line 345
    goto :goto_14

    .line 346
    :cond_18
    :goto_13
    new-instance v0, Luu/k;

    .line 347
    .line 348
    move v11, v15

    .line 349
    const/16 v18, 0x1

    .line 350
    .line 351
    move-object v15, v1

    .line 352
    move-object v1, v10

    .line 353
    move v10, v2

    .line 354
    move-object v2, v9

    .line 355
    move-wide v8, v6

    .line 356
    move-wide/from16 v6, p3

    .line 357
    .line 358
    invoke-direct/range {v0 .. v11}, Luu/k;-><init>(Luu/x;Lay0/k;Lcom/google/android/gms/maps/model/LatLng;JDJFF)V

    .line 359
    .line 360
    .line 361
    move-wide v6, v8

    .line 362
    invoke-virtual {v13, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    move-object v8, v0

    .line 366
    :goto_14
    check-cast v8, Lay0/a;

    .line 367
    .line 368
    instance-of v0, v14, Luu/x;

    .line 369
    .line 370
    if-eqz v0, :cond_1a

    .line 371
    .line 372
    invoke-virtual {v13}, Ll2/t;->W()V

    .line 373
    .line 374
    .line 375
    iget-boolean v0, v13, Ll2/t;->S:Z

    .line 376
    .line 377
    if-eqz v0, :cond_19

    .line 378
    .line 379
    invoke-virtual {v13, v8}, Ll2/t;->l(Lay0/a;)V

    .line 380
    .line 381
    .line 382
    goto :goto_15

    .line 383
    :cond_19
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 384
    .line 385
    .line 386
    :goto_15
    new-instance v0, Luu/i;

    .line 387
    .line 388
    const/4 v1, 0x3

    .line 389
    const/4 v8, 0x0

    .line 390
    invoke-direct {v0, v8, v1}, Luu/i;-><init>(BI)V

    .line 391
    .line 392
    .line 393
    invoke-static {v0, v2, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 394
    .line 395
    .line 396
    new-instance v0, Luu/i;

    .line 397
    .line 398
    const/4 v1, 0x4

    .line 399
    invoke-direct {v0, v8, v1}, Luu/i;-><init>(BI)V

    .line 400
    .line 401
    .line 402
    invoke-static {v0, v3, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 403
    .line 404
    .line 405
    invoke-static/range {v17 .. v17}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 406
    .line 407
    .line 408
    move-result-object v0

    .line 409
    new-instance v1, Luu/i;

    .line 410
    .line 411
    const/4 v8, 0x5

    .line 412
    const/4 v9, 0x0

    .line 413
    invoke-direct {v1, v9, v8}, Luu/i;-><init>(BI)V

    .line 414
    .line 415
    .line 416
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 417
    .line 418
    .line 419
    new-instance v0, Le3/s;

    .line 420
    .line 421
    invoke-direct {v0, v4, v5}, Le3/s;-><init>(J)V

    .line 422
    .line 423
    .line 424
    sget-object v1, Luu/l;->e:Luu/l;

    .line 425
    .line 426
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 427
    .line 428
    .line 429
    invoke-static/range {p3 .. p4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    new-instance v1, Luu/i;

    .line 434
    .line 435
    const/4 v8, 0x6

    .line 436
    invoke-direct {v1, v9, v8}, Luu/i;-><init>(BI)V

    .line 437
    .line 438
    .line 439
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 440
    .line 441
    .line 442
    new-instance v0, Le3/s;

    .line 443
    .line 444
    invoke-direct {v0, v6, v7}, Le3/s;-><init>(J)V

    .line 445
    .line 446
    .line 447
    sget-object v1, Luu/l;->f:Luu/l;

    .line 448
    .line 449
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 450
    .line 451
    .line 452
    new-instance v0, Luu/i;

    .line 453
    .line 454
    const/4 v1, 0x7

    .line 455
    const/4 v8, 0x0

    .line 456
    invoke-direct {v0, v8, v1}, Luu/i;-><init>(BI)V

    .line 457
    .line 458
    .line 459
    invoke-static {v0, v15, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 460
    .line 461
    .line 462
    invoke-static/range {p7 .. p7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 463
    .line 464
    .line 465
    move-result-object v0

    .line 466
    new-instance v1, Luu/i;

    .line 467
    .line 468
    const/16 v8, 0x8

    .line 469
    .line 470
    invoke-direct {v1, v9, v8}, Luu/i;-><init>(BI)V

    .line 471
    .line 472
    .line 473
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 474
    .line 475
    .line 476
    new-instance v0, Luu/i;

    .line 477
    .line 478
    const/4 v1, 0x0

    .line 479
    const/4 v8, 0x0

    .line 480
    invoke-direct {v0, v8, v1}, Luu/i;-><init>(BI)V

    .line 481
    .line 482
    .line 483
    invoke-static {v0, v15, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 484
    .line 485
    .line 486
    invoke-static/range {v18 .. v18}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    new-instance v1, Luu/i;

    .line 491
    .line 492
    const/4 v8, 0x1

    .line 493
    invoke-direct {v1, v9, v8}, Luu/i;-><init>(BI)V

    .line 494
    .line 495
    .line 496
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 497
    .line 498
    .line 499
    invoke-static/range {p9 .. p9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    new-instance v1, Luu/i;

    .line 504
    .line 505
    const/4 v8, 0x2

    .line 506
    invoke-direct {v1, v9, v8}, Luu/i;-><init>(BI)V

    .line 507
    .line 508
    .line 509
    invoke-static {v1, v0, v13}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 510
    .line 511
    .line 512
    move/from16 v0, v18

    .line 513
    .line 514
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 515
    .line 516
    .line 517
    move v9, v0

    .line 518
    move-object v11, v2

    .line 519
    goto :goto_16

    .line 520
    :cond_1a
    invoke-static {}, Ll2/b;->l()V

    .line 521
    .line 522
    .line 523
    throw v15

    .line 524
    :cond_1b
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 525
    .line 526
    .line 527
    move/from16 v9, p8

    .line 528
    .line 529
    move-object/from16 v11, p10

    .line 530
    .line 531
    :goto_16
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 532
    .line 533
    .line 534
    move-result-object v13

    .line 535
    if-eqz v13, :cond_1c

    .line 536
    .line 537
    new-instance v0, Luu/j;

    .line 538
    .line 539
    move/from16 v8, p7

    .line 540
    .line 541
    move/from16 v10, p9

    .line 542
    .line 543
    move-object v1, v3

    .line 544
    move-wide v2, v4

    .line 545
    move-wide/from16 v4, p3

    .line 546
    .line 547
    invoke-direct/range {v0 .. v12}, Luu/j;-><init>(Lcom/google/android/gms/maps/model/LatLng;JDJFZFLay0/k;I)V

    .line 548
    .line 549
    .line 550
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 551
    .line 552
    :cond_1c
    return-void
.end method

.method public static final b(Lcz/myskoda/api/bff/v1/TodoDto;)Lla0/a;
    .locals 10

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/TodoDto;->getTitleKey()Ljava/lang/String;

    move-result-object v1

    .line 2
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v2

    const v3, 0x7f1202bd

    sparse-switch v2, :sswitch_data_0

    goto/16 :goto_1

    :sswitch_0
    const-string v2, "todo_detail_addcare_title_sl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    goto/16 :goto_1

    :cond_0
    const v1, 0x7f121328

    :goto_0
    move v5, v1

    goto/16 :goto_2

    :sswitch_1
    const-string v2, "todo_detail_addcare_title_sk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    goto/16 :goto_1

    :cond_1
    const v1, 0x7f121327

    goto :goto_0

    :sswitch_2
    const-string v2, "todo_detail_addcare_title_pl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    goto/16 :goto_1

    :cond_2
    const v1, 0x7f121326

    goto :goto_0

    :sswitch_3
    const-string v2, "todo_detail_addcare_title_lu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    goto/16 :goto_1

    :cond_3
    const v1, 0x7f121325

    goto :goto_0

    :sswitch_4
    const-string v2, "todo_detail_addcare_title_gb"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    goto/16 :goto_1

    :cond_4
    const v1, 0x7f121323

    goto :goto_0

    :sswitch_5
    const-string v2, "todo_detail_addcare_title_fr"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5

    goto/16 :goto_1

    :cond_5
    const v1, 0x7f121322

    goto :goto_0

    :sswitch_6
    const-string v2, "todo_detail_addcare_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_6

    goto/16 :goto_1

    :cond_6
    const v1, 0x7f121321

    goto :goto_0

    :sswitch_7
    const-string v2, "todo_detail_addcare_title_de"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_7

    goto/16 :goto_1

    :cond_7
    const v1, 0x7f121320

    goto :goto_0

    :sswitch_8
    const-string v2, "todo_detail_addcare_title_cz"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_8

    goto/16 :goto_1

    :cond_8
    const v1, 0x7f12131f

    goto :goto_0

    :sswitch_9
    const-string v2, "todo_detail_addcare_title_ch"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_9

    goto/16 :goto_1

    :cond_9
    const v1, 0x7f12131e

    goto/16 :goto_0

    :sswitch_a
    const-string v2, "todo_detail_addcare_title_ba"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_a

    goto/16 :goto_1

    :cond_a
    const v1, 0x7f12131d

    goto/16 :goto_0

    :sswitch_b
    const-string v2, "todo_detail_hassle_title_general"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_b

    goto/16 :goto_1

    :cond_b
    const v1, 0x7f1213cc

    goto/16 :goto_0

    :sswitch_c
    const-string v2, "todo_detail_hassle_title_sl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_c

    goto/16 :goto_1

    :cond_c
    const v1, 0x7f1213d4

    goto/16 :goto_0

    :sswitch_d
    const-string v2, "todo_detail_hassle_title_sk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_d

    goto/16 :goto_1

    :cond_d
    const v1, 0x7f1213d3

    goto/16 :goto_0

    :sswitch_e
    const-string v2, "todo_detail_hassle_title_se"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_e

    goto/16 :goto_1

    :cond_e
    const v1, 0x7f1213d2

    goto/16 :goto_0

    :sswitch_f
    const-string v2, "todo_detail_hassle_title_pt"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_f

    goto/16 :goto_1

    :cond_f
    const v1, 0x7f1213d1

    goto/16 :goto_0

    :sswitch_10
    const-string v2, "todo_detail_hassle_title_pl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_10

    goto/16 :goto_1

    :cond_10
    const v1, 0x7f1213d0

    goto/16 :goto_0

    :sswitch_11
    const-string v2, "todo_detail_hassle_title_lu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_11

    goto/16 :goto_1

    :cond_11
    const v1, 0x7f1213cf

    goto/16 :goto_0

    :sswitch_12
    const-string v2, "todo_detail_hassle_title_is"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_12

    goto/16 :goto_1

    :cond_12
    const v1, 0x7f1213ce

    goto/16 :goto_0

    :sswitch_13
    const-string v2, "todo_detail_hassle_title_ie"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_13

    goto/16 :goto_1

    :cond_13
    const v1, 0x7f1213cd

    goto/16 :goto_0

    :sswitch_14
    const-string v2, "todo_detail_hassle_title_gb"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_14

    goto/16 :goto_1

    :cond_14
    const v1, 0x7f1213cb

    goto/16 :goto_0

    :sswitch_15
    const-string v2, "todo_detail_hassle_title_fr"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_15

    goto/16 :goto_1

    :cond_15
    const v1, 0x7f1213ca

    goto/16 :goto_0

    :sswitch_16
    const-string v2, "todo_detail_hassle_title_fi"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_16

    goto/16 :goto_1

    :cond_16
    const v1, 0x7f1213c9

    goto/16 :goto_0

    :sswitch_17
    const-string v2, "todo_detail_hassle_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_17

    goto/16 :goto_1

    :cond_17
    const v1, 0x7f1213c8    # 1.9417E38f

    goto/16 :goto_0

    :sswitch_18
    const-string v2, "todo_detail_hassle_title_dk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_18

    goto/16 :goto_1

    :cond_18
    const v1, 0x7f1213c7

    goto/16 :goto_0

    :sswitch_19
    const-string v2, "todo_detail_hassle_title_de"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_19

    goto/16 :goto_1

    :cond_19
    const v1, 0x7f1213c6

    goto/16 :goto_0

    :sswitch_1a
    const-string v2, "todo_detail_hassle_title_cz"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1a

    goto/16 :goto_1

    :cond_1a
    const v1, 0x7f1213c5

    goto/16 :goto_0

    :sswitch_1b
    const-string v2, "todo_detail_hassle_title_ch"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1b

    goto/16 :goto_1

    :cond_1b
    const v1, 0x7f1213c4

    goto/16 :goto_0

    :sswitch_1c
    const-string v2, "todo_detail_hassle_title_ba"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1c

    goto/16 :goto_1

    :cond_1c
    const v1, 0x7f1213c3

    goto/16 :goto_0

    :sswitch_1d
    const-string v2, "todo_detail_hassle_title_at"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1d

    goto/16 :goto_1

    :cond_1d
    const v1, 0x7f1213c2

    goto/16 :goto_0

    :sswitch_1e
    const-string v2, "todo_detail_financing_title_ie"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1e

    goto/16 :goto_1

    :cond_1e
    const v1, 0x7f121392

    goto/16 :goto_0

    :sswitch_1f
    const-string v2, "todo_detail_financing_title_dk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1f

    goto/16 :goto_1

    :cond_1f
    const v1, 0x7f121391

    goto/16 :goto_0

    :sswitch_20
    const-string v2, "todo_detail_carexchange_title_ie"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_20

    goto/16 :goto_1

    :cond_20
    const v1, 0x7f121336

    goto/16 :goto_0

    :sswitch_21
    const-string v2, "todo_detail_warranty_title_fi"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_21

    goto/16 :goto_1

    :cond_21
    const v1, 0x7f121447

    goto/16 :goto_0

    :sswitch_22
    const-string v2, "todo_detail_warranty_title_at"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_22

    goto/16 :goto_1

    :cond_22
    const v1, 0x7f121446

    goto/16 :goto_0

    :sswitch_23
    const-string v2, "todo_detail_insurance_title_general"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_23

    goto/16 :goto_1

    :cond_23
    const v1, 0x7f1213fe

    goto/16 :goto_0

    :sswitch_24
    const-string v2, "todo_detail_connectivity_title_sl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_24

    goto/16 :goto_1

    :cond_24
    const v1, 0x7f121378

    goto/16 :goto_0

    :sswitch_25
    const-string v2, "todo_detail_connectivity_title_sk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_25

    goto/16 :goto_1

    :cond_25
    const v1, 0x7f121377

    goto/16 :goto_0

    :sswitch_26
    const-string v2, "todo_detail_connectivity_title_se"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_26

    goto/16 :goto_1

    :cond_26
    const v1, 0x7f121376

    goto/16 :goto_0

    :sswitch_27
    const-string v2, "todo_detail_connectivity_title_pt"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_27

    goto/16 :goto_1

    :cond_27
    const v1, 0x7f121375

    goto/16 :goto_0

    :sswitch_28
    const-string v2, "todo_detail_connectivity_title_pl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_28

    goto/16 :goto_1

    :cond_28
    const v1, 0x7f121374

    goto/16 :goto_0

    :sswitch_29
    const-string v2, "todo_detail_connectivity_title_nl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_29

    goto/16 :goto_1

    :cond_29
    const v1, 0x7f121373

    goto/16 :goto_0

    :sswitch_2a
    const-string v2, "todo_detail_connectivity_title_lu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2a

    goto/16 :goto_1

    :cond_2a
    const v1, 0x7f121372

    goto/16 :goto_0

    :sswitch_2b
    const-string v2, "todo_detail_connectivity_title_is"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2b

    goto/16 :goto_1

    :cond_2b
    const v1, 0x7f121371

    goto/16 :goto_0

    :sswitch_2c
    const-string v2, "todo_detail_connectivity_title_ie"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2c

    goto/16 :goto_1

    :cond_2c
    const v1, 0x7f121370

    goto/16 :goto_0

    :sswitch_2d
    const-string v2, "todo_detail_connectivity_title_gb"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2d

    goto/16 :goto_1

    :cond_2d
    const v1, 0x7f12136e

    goto/16 :goto_0

    :sswitch_2e
    const-string v2, "todo_detail_connectivity_title_fr"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2e

    goto/16 :goto_1

    :cond_2e
    const v1, 0x7f12136d

    goto/16 :goto_0

    :sswitch_2f
    const-string v2, "todo_detail_connectivity_title_fi"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2f

    goto/16 :goto_1

    :cond_2f
    const v1, 0x7f12136c

    goto/16 :goto_0

    :sswitch_30
    const-string v2, "todo_detail_connectivity_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_30

    goto/16 :goto_1

    :cond_30
    const v1, 0x7f12136b

    goto/16 :goto_0

    :sswitch_31
    const-string v2, "todo_detail_connectivity_title_dk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_31

    goto/16 :goto_1

    :cond_31
    const v1, 0x7f12136a

    goto/16 :goto_0

    :sswitch_32
    const-string v2, "todo_detail_connectivity_title_de"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_32

    goto/16 :goto_1

    :cond_32
    const v1, 0x7f121369

    goto/16 :goto_0

    :sswitch_33
    const-string v2, "todo_detail_connectivity_title_cz"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_33

    goto/16 :goto_1

    :cond_33
    const v1, 0x7f121368

    goto/16 :goto_0

    :sswitch_34
    const-string v2, "todo_detail_connectivity_title_ch"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_34

    goto/16 :goto_1

    :cond_34
    const v1, 0x7f121367

    goto/16 :goto_0

    :sswitch_35
    const-string v2, "todo_detail_connectivity_title_ba"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_35

    goto/16 :goto_1

    :cond_35
    const v1, 0x7f121366

    goto/16 :goto_0

    :sswitch_36
    const-string v2, "todo_detail_connectivity_title_at"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_36

    goto/16 :goto_1

    :cond_36
    const v1, 0x7f121365

    goto/16 :goto_0

    :sswitch_37
    const-string v2, "todo_detail_insurance_title_sl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_37

    goto/16 :goto_1

    :cond_37
    const v1, 0x7f121403

    goto/16 :goto_0

    :sswitch_38
    const-string v2, "todo_detail_insurance_title_sk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_38

    goto/16 :goto_1

    :cond_38
    const v1, 0x7f121402

    goto/16 :goto_0

    :sswitch_39
    const-string v2, "todo_detail_insurance_title_se"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_39

    goto/16 :goto_1

    :cond_39
    const v1, 0x7f121401

    goto/16 :goto_0

    :sswitch_3a
    const-string v2, "todo_detail_insurance_title_pl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3a

    goto/16 :goto_1

    :cond_3a
    const v1, 0x7f121400

    goto/16 :goto_0

    :sswitch_3b
    const-string v2, "todo_detail_insurance_title_nl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3b

    goto/16 :goto_1

    :cond_3b
    const v1, 0x7f1213ff

    goto/16 :goto_0

    :sswitch_3c
    const-string v2, "todo_detail_insurance_title_gb"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3c

    goto/16 :goto_1

    :cond_3c
    const v1, 0x7f1213fd

    goto/16 :goto_0

    :sswitch_3d
    const-string v2, "todo_detail_insurance_title_fr"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3d

    goto/16 :goto_1

    :cond_3d
    const v1, 0x7f1213fc

    goto/16 :goto_0

    :sswitch_3e
    const-string v2, "todo_detail_insurance_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3e

    goto/16 :goto_1

    :cond_3e
    const v1, 0x7f1213fb

    goto/16 :goto_0

    :sswitch_3f
    const-string v2, "todo_detail_insurance_title_dk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3f

    goto/16 :goto_1

    :cond_3f
    const v1, 0x7f1213fa

    goto/16 :goto_0

    :sswitch_40
    const-string v2, "todo_detail_insurance_title_de"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_40

    goto/16 :goto_1

    :cond_40
    const v1, 0x7f1213f9

    goto/16 :goto_0

    :sswitch_41
    const-string v2, "todo_detail_insurance_title_cz"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_41

    goto/16 :goto_1

    :cond_41
    const v1, 0x7f1213f8

    goto/16 :goto_0

    :sswitch_42
    const-string v2, "todo_detail_insurance_title_ch"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_42

    goto/16 :goto_1

    :cond_42
    const v1, 0x7f1213f7

    goto/16 :goto_0

    :sswitch_43
    const-string v2, "todo_detail_insurance_title_at"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_43

    goto/16 :goto_1

    :cond_43
    const v1, 0x7f1213f6

    goto/16 :goto_0

    :sswitch_44
    const-string v2, "todo_detail_connectivity_title_general"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_44

    goto/16 :goto_1

    :cond_44
    const v1, 0x7f12136f

    goto/16 :goto_0

    :sswitch_45
    const-string v2, "todo_detail_gettoknow_title_lu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_45

    goto/16 :goto_1

    :cond_45
    const v1, 0x7f121398

    goto/16 :goto_0

    :sswitch_46
    const-string v2, "todo_detail_gettoknow_title_ie"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_46

    goto/16 :goto_1

    :cond_46
    const v1, 0x7f121397

    goto/16 :goto_0

    :sswitch_47
    const-string v2, "todo_detail_clubskoda_title_fr"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_47

    goto/16 :goto_1

    :cond_47
    const v1, 0x7f121339

    goto/16 :goto_0

    :sswitch_48
    const-string v2, "todo_detail_roadside_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_48

    goto/16 :goto_1

    :cond_48
    const v1, 0x7f121423

    goto/16 :goto_0

    :sswitch_49
    const-string v2, "todo_detail_registration_title_general"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_49

    goto/16 :goto_1

    :cond_49
    const v1, 0x7f12141f

    goto/16 :goto_0

    :sswitch_4a
    const-string v2, "todo_detail_accessories_title_se"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4a

    goto/16 :goto_1

    :cond_4a
    const v1, 0x7f1212ff

    goto/16 :goto_0

    :sswitch_4b
    const-string v2, "todo_detail_accessories_title_nl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4b

    goto/16 :goto_1

    :cond_4b
    const v1, 0x7f1212fe

    goto/16 :goto_0

    :sswitch_4c
    const-string v2, "todo_detail_accessories_title_lu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4c

    goto/16 :goto_1

    :cond_4c
    const v1, 0x7f1212fd

    goto/16 :goto_0

    :sswitch_4d
    const-string v2, "todo_detail_accessories_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4d

    goto/16 :goto_1

    :cond_4d
    const v1, 0x7f1212fc

    goto/16 :goto_0

    :sswitch_4e
    const-string v2, "todo_detail_accessories_title_dk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4e

    goto/16 :goto_1

    :cond_4e
    const v1, 0x7f1212fb

    goto/16 :goto_0

    :sswitch_4f
    const-string v2, "todo_detail_accessories_title_cz"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4f

    goto/16 :goto_1

    :cond_4f
    const v1, 0x7f1212fa

    goto/16 :goto_0

    :sswitch_50
    const-string v2, "todo_detail_svc_maintenance_title_se"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_50

    goto/16 :goto_1

    :cond_50
    const v1, 0x7f121438

    goto/16 :goto_0

    :sswitch_51
    const-string v2, "todo_detail_svc_maintenance_title_pt"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_51

    goto/16 :goto_1

    :cond_51
    const v1, 0x7f121437

    goto/16 :goto_0

    :sswitch_52
    const-string v2, "todo_detail_svc_maintenance_title_pl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_52

    goto/16 :goto_1

    :cond_52
    const v1, 0x7f121436

    goto/16 :goto_0

    :sswitch_53
    const-string v2, "todo_detail_svc_maintenance_title_fi"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_53

    goto/16 :goto_1

    :cond_53
    const v1, 0x7f121435

    goto/16 :goto_0

    :sswitch_54
    const-string v2, "todo_detail_svc_maintenance_title_dk"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_54

    goto/16 :goto_1

    :cond_54
    const v1, 0x7f121434

    goto/16 :goto_0

    :sswitch_55
    const-string v2, "todo_detail_svc_maintenance_title_cz"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_55

    goto :goto_1

    :cond_55
    const v1, 0x7f121433

    goto/16 :goto_0

    :sswitch_56
    const-string v2, "todo_detail_registration_title_lu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_56

    goto :goto_1

    :cond_56
    const v1, 0x7f121420

    goto/16 :goto_0

    :sswitch_57
    const-string v2, "todo_detail_registration_title_fr"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_57

    goto :goto_1

    :cond_57
    const v1, 0x7f12141e

    goto/16 :goto_0

    :sswitch_58
    const-string v2, "todo_detail_registration_title_de"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_58

    goto :goto_1

    :cond_58
    const v1, 0x7f12141d

    goto/16 :goto_0

    :sswitch_59
    const-string v2, "todo_detail_electricdriving_title_nl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_59

    goto :goto_1

    :cond_59
    const v1, 0x7f12138a    # 1.9416874E38f

    goto/16 :goto_0

    :sswitch_5a
    const-string v2, "todo_detail_addcare_title_general"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5a

    goto :goto_1

    :cond_5a
    const v1, 0x7f121324

    goto/16 :goto_0

    :sswitch_5b
    const-string v2, "todo_detail_svccatalogue_title_es"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5b

    goto :goto_1

    :cond_5b
    const v1, 0x7f121440

    goto/16 :goto_0

    :sswitch_5c
    const-string v2, "todo_detail_newsletter_title_nl"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5c

    :goto_1
    move v5, v3

    goto :goto_2

    :cond_5c
    const v1, 0x7f121413

    goto/16 :goto_0

    .line 4
    :goto_2
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/TodoDto;->getBodyKey()Ljava/lang/String;

    move-result-object v1

    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v0

    sparse-switch v0, :sswitch_data_1

    goto/16 :goto_4

    :sswitch_5d
    const-string v0, "todo_detail_clubskoda_ice_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_5d

    goto/16 :goto_4

    :cond_5d
    const v3, 0x7f121338

    :goto_3
    move v6, v3

    goto/16 :goto_5

    :sswitch_5e
    const-string v0, "todo_detail_warranty_ice_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_5e

    goto/16 :goto_4

    :cond_5e
    const v3, 0x7f121445

    goto :goto_3

    :sswitch_5f
    const-string v0, "todo_detail_warranty_ice_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_5f

    goto/16 :goto_4

    :cond_5f
    const v3, 0x7f121444

    goto :goto_3

    :sswitch_60
    const-string v0, "todo_detail_hassle_bev_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_60

    goto/16 :goto_4

    :cond_60
    const v3, 0x7f1213ad

    goto :goto_3

    :sswitch_61
    const-string v0, "todo_detail_hassle_bev_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_61

    goto/16 :goto_4

    :cond_61
    const v3, 0x7f1213ac

    goto :goto_3

    :sswitch_62
    const-string v0, "todo_detail_hassle_bev_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_62

    goto/16 :goto_4

    :cond_62
    const v3, 0x7f1213ab

    goto :goto_3

    :sswitch_63
    const-string v0, "todo_detail_hassle_bev_body_pt"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_63

    goto/16 :goto_4

    :cond_63
    const v3, 0x7f1213aa

    goto :goto_3

    :sswitch_64
    const-string v0, "todo_detail_hassle_bev_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_64

    goto/16 :goto_4

    :cond_64
    const v3, 0x7f1213a9

    goto :goto_3

    :sswitch_65
    const-string v0, "todo_detail_hassle_bev_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_65

    goto/16 :goto_4

    :cond_65
    const v3, 0x7f1213a8

    goto :goto_3

    :sswitch_66
    const-string v0, "todo_detail_hassle_bev_body_is"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_66

    goto/16 :goto_4

    :cond_66
    const v3, 0x7f1213a7

    goto/16 :goto_3

    :sswitch_67
    const-string v0, "todo_detail_hassle_bev_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_67

    goto/16 :goto_4

    :cond_67
    const v3, 0x7f1213a6

    goto/16 :goto_3

    :sswitch_68
    const-string v0, "todo_detail_hassle_bev_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_68

    goto/16 :goto_4

    :cond_68
    const v3, 0x7f1213a4

    goto/16 :goto_3

    :sswitch_69
    const-string v0, "todo_detail_hassle_bev_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_69

    goto/16 :goto_4

    :cond_69
    const v3, 0x7f1213a3

    goto/16 :goto_3

    :sswitch_6a
    const-string v0, "todo_detail_hassle_bev_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6a

    goto/16 :goto_4

    :cond_6a
    const v3, 0x7f1213a2

    goto/16 :goto_3

    :sswitch_6b
    const-string v0, "todo_detail_hassle_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6b

    goto/16 :goto_4

    :cond_6b
    const v3, 0x7f1213a1

    goto/16 :goto_3

    :sswitch_6c
    const-string v0, "todo_detail_hassle_bev_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6c

    goto/16 :goto_4

    :cond_6c
    const v3, 0x7f1213a0

    goto/16 :goto_3

    :sswitch_6d
    const-string v0, "todo_detail_hassle_bev_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6d

    goto/16 :goto_4

    :cond_6d
    const v3, 0x7f12139f

    goto/16 :goto_3

    :sswitch_6e
    const-string v0, "todo_detail_hassle_bev_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6e

    goto/16 :goto_4

    :cond_6e
    const v3, 0x7f12139e

    goto/16 :goto_3

    :sswitch_6f
    const-string v0, "todo_detail_hassle_bev_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6f

    goto/16 :goto_4

    :cond_6f
    const v3, 0x7f12139d

    goto/16 :goto_3

    :sswitch_70
    const-string v0, "todo_detail_hassle_bev_body_ba"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_70

    goto/16 :goto_4

    :cond_70
    const v3, 0x7f12139c

    goto/16 :goto_3

    :sswitch_71
    const-string v0, "todo_detail_hassle_bev_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_71

    goto/16 :goto_4

    :cond_71
    const v3, 0x7f12139b

    goto/16 :goto_3

    :sswitch_72
    const-string v0, "todo_detail_registration_ice_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_72

    goto/16 :goto_4

    :cond_72
    const v3, 0x7f12141b

    goto/16 :goto_3

    :sswitch_73
    const-string v0, "todo_detail_svc_maintenance_bev_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_73

    goto/16 :goto_4

    :cond_73
    const v3, 0x7f12142b

    goto/16 :goto_3

    :sswitch_74
    const-string v0, "todo_detail_svc_maintenance_bev_body_pt"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_74

    goto/16 :goto_4

    :cond_74
    const v3, 0x7f12142a

    goto/16 :goto_3

    :sswitch_75
    const-string v0, "todo_detail_svc_maintenance_bev_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_75

    goto/16 :goto_4

    :cond_75
    const v3, 0x7f121429

    goto/16 :goto_3

    :sswitch_76
    const-string v0, "todo_detail_svc_maintenance_bev_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_76

    goto/16 :goto_4

    :cond_76
    const v3, 0x7f121428

    goto/16 :goto_3

    :sswitch_77
    const-string v0, "todo_detail_svc_maintenance_bev_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_77

    goto/16 :goto_4

    :cond_77
    const v3, 0x7f121427

    goto/16 :goto_3

    :sswitch_78
    const-string v0, "todo_detail_svc_maintenance_bev_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_78

    goto/16 :goto_4

    :cond_78
    const v3, 0x7f121426

    goto/16 :goto_3

    :sswitch_79
    const-string v0, "todo_detail_connectivity_ice_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_79

    goto/16 :goto_4

    :cond_79
    const v3, 0x7f12135b

    goto/16 :goto_3

    :sswitch_7a
    const-string v0, "todo_detail_accessories_bev_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7a

    goto/16 :goto_4

    :cond_7a
    const v3, 0x7f1212f3

    goto/16 :goto_3

    :sswitch_7b
    const-string v0, "todo_detail_accessories_bev_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7b

    goto/16 :goto_4

    :cond_7b
    const v3, 0x7f1212f2

    goto/16 :goto_3

    :sswitch_7c
    const-string v0, "todo_detail_accessories_bev_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7c

    goto/16 :goto_4

    :cond_7c
    const v3, 0x7f1212f1

    goto/16 :goto_3

    :sswitch_7d
    const-string v0, "todo_detail_accessories_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7d

    goto/16 :goto_4

    :cond_7d
    const v3, 0x7f1212f0

    goto/16 :goto_3

    :sswitch_7e
    const-string v0, "todo_detail_accessories_bev_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7e

    goto/16 :goto_4

    :cond_7e
    const v3, 0x7f1212ef

    goto/16 :goto_3

    :sswitch_7f
    const-string v0, "todo_detail_accessories_bev_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7f

    goto/16 :goto_4

    :cond_7f
    const v3, 0x7f1212ee

    goto/16 :goto_3

    :sswitch_80
    const-string v0, "todo_detail_connectivity_ice_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_80

    goto/16 :goto_4

    :cond_80
    const v3, 0x7f121364

    goto/16 :goto_3

    :sswitch_81
    const-string v0, "todo_detail_connectivity_ice_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_81

    goto/16 :goto_4

    :cond_81
    const v3, 0x7f121363

    goto/16 :goto_3

    :sswitch_82
    const-string v0, "todo_detail_connectivity_ice_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_82

    goto/16 :goto_4

    :cond_82
    const v3, 0x7f121362

    goto/16 :goto_3

    :sswitch_83
    const-string v0, "todo_detail_connectivity_ice_body_pt"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_83

    goto/16 :goto_4

    :cond_83
    const v3, 0x7f121361

    goto/16 :goto_3

    :sswitch_84
    const-string v0, "todo_detail_connectivity_ice_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_84

    goto/16 :goto_4

    :cond_84
    const v3, 0x7f121360

    goto/16 :goto_3

    :sswitch_85
    const-string v0, "todo_detail_connectivity_ice_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_85

    goto/16 :goto_4

    :cond_85
    const v3, 0x7f12135f

    goto/16 :goto_3

    :sswitch_86
    const-string v0, "todo_detail_connectivity_ice_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_86

    goto/16 :goto_4

    :cond_86
    const v3, 0x7f12135e

    goto/16 :goto_3

    :sswitch_87
    const-string v0, "todo_detail_connectivity_ice_body_is"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_87

    goto/16 :goto_4

    :cond_87
    const v3, 0x7f12135d

    goto/16 :goto_3

    :sswitch_88
    const-string v0, "todo_detail_connectivity_ice_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_88

    goto/16 :goto_4

    :cond_88
    const v3, 0x7f12135c

    goto/16 :goto_3

    :sswitch_89
    const-string v0, "todo_detail_connectivity_ice_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_89

    goto/16 :goto_4

    :cond_89
    const v3, 0x7f12135a

    goto/16 :goto_3

    :sswitch_8a
    const-string v0, "todo_detail_connectivity_ice_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8a

    goto/16 :goto_4

    :cond_8a
    const v3, 0x7f121359

    goto/16 :goto_3

    :sswitch_8b
    const-string v0, "todo_detail_connectivity_ice_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8b

    goto/16 :goto_4

    :cond_8b
    const v3, 0x7f121358

    goto/16 :goto_3

    :sswitch_8c
    const-string v0, "todo_detail_connectivity_ice_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8c

    goto/16 :goto_4

    :cond_8c
    const v3, 0x7f121357

    goto/16 :goto_3

    :sswitch_8d
    const-string v0, "todo_detail_connectivity_ice_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8d

    goto/16 :goto_4

    :cond_8d
    const v3, 0x7f121356

    goto/16 :goto_3

    :sswitch_8e
    const-string v0, "todo_detail_connectivity_ice_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8e

    goto/16 :goto_4

    :cond_8e
    const v3, 0x7f121355

    goto/16 :goto_3

    :sswitch_8f
    const-string v0, "todo_detail_connectivity_ice_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8f

    goto/16 :goto_4

    :cond_8f
    const v3, 0x7f121354

    goto/16 :goto_3

    :sswitch_90
    const-string v0, "todo_detail_connectivity_ice_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_90

    goto/16 :goto_4

    :cond_90
    const v3, 0x7f121353

    goto/16 :goto_3

    :sswitch_91
    const-string v0, "todo_detail_connectivity_ice_body_ba"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_91

    goto/16 :goto_4

    :cond_91
    const v3, 0x7f121352

    goto/16 :goto_3

    :sswitch_92
    const-string v0, "todo_detail_connectivity_ice_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_92

    goto/16 :goto_4

    :cond_92
    const v3, 0x7f121351

    goto/16 :goto_3

    :sswitch_93
    const-string v0, "todo_detail_svccatalogue_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_93

    goto/16 :goto_4

    :cond_93
    const v3, 0x7f12143e

    goto/16 :goto_3

    :sswitch_94
    const-string v0, "todo_detail_financing_ice_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_94

    goto/16 :goto_4

    :cond_94
    const v3, 0x7f12138f

    goto/16 :goto_3

    :sswitch_95
    const-string v0, "todo_detail_financing_ice_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_95

    goto/16 :goto_4

    :cond_95
    const v3, 0x7f12138e

    goto/16 :goto_3

    :sswitch_96
    const-string v0, "todo_detail_addcare_ice_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_96

    goto/16 :goto_4

    :cond_96
    const v3, 0x7f121318

    goto/16 :goto_3

    :sswitch_97
    const-string v0, "todo_detail_clubskoda_bev_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_97

    goto/16 :goto_4

    :cond_97
    const v3, 0x7f121337

    goto/16 :goto_3

    :sswitch_98
    const-string v0, "todo_detail_insurance_ice_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_98

    goto/16 :goto_4

    :cond_98
    const v3, 0x7f1213f0

    goto/16 :goto_3

    :sswitch_99
    const-string v0, "todo_detail_registration_ice_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_99

    goto/16 :goto_4

    :cond_99
    const v3, 0x7f12141c

    goto/16 :goto_3

    :sswitch_9a
    const-string v0, "todo_detail_registration_ice_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9a

    goto/16 :goto_4

    :cond_9a
    const v3, 0x7f12141a

    goto/16 :goto_3

    :sswitch_9b
    const-string v0, "todo_detail_registration_ice_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9b

    goto/16 :goto_4

    :cond_9b
    const v3, 0x7f121419

    goto/16 :goto_3

    :sswitch_9c
    const-string v0, "todo_detail_warranty_bev_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9c

    goto/16 :goto_4

    :cond_9c
    const v3, 0x7f121443

    goto/16 :goto_3

    :sswitch_9d
    const-string v0, "todo_detail_warranty_bev_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9d

    goto/16 :goto_4

    :cond_9d
    const v3, 0x7f121442

    goto/16 :goto_3

    :sswitch_9e
    const-string v0, "todo_detail_electricdriving_bev_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9e

    goto/16 :goto_4

    :cond_9e
    const v3, 0x7f121387

    goto/16 :goto_3

    :sswitch_9f
    const-string v0, "todo_detail_roadside_ice_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9f

    goto/16 :goto_4

    :cond_9f
    const v3, 0x7f121422

    goto/16 :goto_3

    :sswitch_a0
    const-string v0, "todo_detail_connectivity_bev_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a0

    goto/16 :goto_4

    :cond_a0
    const v3, 0x7f12134f

    goto/16 :goto_3

    :sswitch_a1
    const-string v0, "todo_detail_connectivity_bev_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a1

    goto/16 :goto_4

    :cond_a1
    const v3, 0x7f12134e

    goto/16 :goto_3

    :sswitch_a2
    const-string v0, "todo_detail_connectivity_bev_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a2

    goto/16 :goto_4

    :cond_a2
    const v3, 0x7f12134d

    goto/16 :goto_3

    :sswitch_a3
    const-string v0, "todo_detail_connectivity_bev_body_pt"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a3

    goto/16 :goto_4

    :cond_a3
    const v3, 0x7f12134c

    goto/16 :goto_3

    :sswitch_a4
    const-string v0, "todo_detail_connectivity_bev_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a4

    goto/16 :goto_4

    :cond_a4
    const v3, 0x7f12134b

    goto/16 :goto_3

    :sswitch_a5
    const-string v0, "todo_detail_connectivity_bev_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a5

    goto/16 :goto_4

    :cond_a5
    const v3, 0x7f12134a

    goto/16 :goto_3

    :sswitch_a6
    const-string v0, "todo_detail_connectivity_bev_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a6

    goto/16 :goto_4

    :cond_a6
    const v3, 0x7f121349

    goto/16 :goto_3

    :sswitch_a7
    const-string v0, "todo_detail_connectivity_bev_body_is"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a7

    goto/16 :goto_4

    :cond_a7
    const v3, 0x7f121348

    goto/16 :goto_3

    :sswitch_a8
    const-string v0, "todo_detail_connectivity_bev_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a8

    goto/16 :goto_4

    :cond_a8
    const v3, 0x7f121347

    goto/16 :goto_3

    :sswitch_a9
    const-string v0, "todo_detail_connectivity_bev_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a9

    goto/16 :goto_4

    :cond_a9
    const v3, 0x7f121345

    goto/16 :goto_3

    :sswitch_aa
    const-string v0, "todo_detail_connectivity_bev_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_aa

    goto/16 :goto_4

    :cond_aa
    const v3, 0x7f121344

    goto/16 :goto_3

    :sswitch_ab
    const-string v0, "todo_detail_connectivity_bev_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ab

    goto/16 :goto_4

    :cond_ab
    const v3, 0x7f121343    # 1.941673E38f

    goto/16 :goto_3

    :sswitch_ac
    const-string v0, "todo_detail_connectivity_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ac

    goto/16 :goto_4

    :cond_ac
    const v3, 0x7f121342

    goto/16 :goto_3

    :sswitch_ad
    const-string v0, "todo_detail_connectivity_bev_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ad

    goto/16 :goto_4

    :cond_ad
    const v3, 0x7f121341

    goto/16 :goto_3

    :sswitch_ae
    const-string v0, "todo_detail_connectivity_bev_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ae

    goto/16 :goto_4

    :cond_ae
    const v3, 0x7f121340

    goto/16 :goto_3

    :sswitch_af
    const-string v0, "todo_detail_connectivity_bev_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_af

    goto/16 :goto_4

    :cond_af
    const v3, 0x7f12133f

    goto/16 :goto_3

    :sswitch_b0
    const-string v0, "todo_detail_connectivity_bev_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b0

    goto/16 :goto_4

    :cond_b0
    const v3, 0x7f12133e

    goto/16 :goto_3

    :sswitch_b1
    const-string v0, "todo_detail_connectivity_bev_body_ba"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b1

    goto/16 :goto_4

    :cond_b1
    const v3, 0x7f12133d

    goto/16 :goto_3

    :sswitch_b2
    const-string v0, "todo_detail_connectivity_bev_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b2

    goto/16 :goto_4

    :cond_b2
    const v3, 0x7f12133c

    goto/16 :goto_3

    :sswitch_b3
    const-string v0, "todo_detail_newsletter_ice_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b3

    goto/16 :goto_4

    :cond_b3
    const v3, 0x7f121412

    goto/16 :goto_3

    :sswitch_b4
    const-string v0, "todo_detail_gettoknow_ice_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b4

    goto/16 :goto_4

    :cond_b4
    const v3, 0x7f121396

    goto/16 :goto_3

    :sswitch_b5
    const-string v0, "todo_detail_gettoknow_ice_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b5

    goto/16 :goto_4

    :cond_b5
    const v3, 0x7f121395

    goto/16 :goto_3

    :sswitch_b6
    const-string v0, "todo_detail_insurance_ice_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b6

    goto/16 :goto_4

    :cond_b6
    const v3, 0x7f1213f5

    goto/16 :goto_3

    :sswitch_b7
    const-string v0, "todo_detail_insurance_ice_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b7

    goto/16 :goto_4

    :cond_b7
    const v3, 0x7f1213f4

    goto/16 :goto_3

    :sswitch_b8
    const-string v0, "todo_detail_insurance_ice_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b8

    goto/16 :goto_4

    :cond_b8
    const v3, 0x7f1213f3

    goto/16 :goto_3

    :sswitch_b9
    const-string v0, "todo_detail_insurance_ice_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b9

    goto/16 :goto_4

    :cond_b9
    const v3, 0x7f1213f2

    goto/16 :goto_3

    :sswitch_ba
    const-string v0, "todo_detail_insurance_ice_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ba

    goto/16 :goto_4

    :cond_ba
    const v3, 0x7f1213f1

    goto/16 :goto_3

    :sswitch_bb
    const-string v0, "todo_detail_insurance_ice_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_bb

    goto/16 :goto_4

    :cond_bb
    const v3, 0x7f1213ef

    goto/16 :goto_3

    :sswitch_bc
    const-string v0, "todo_detail_insurance_ice_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_bc

    goto/16 :goto_4

    :cond_bc
    const v3, 0x7f1213ee

    goto/16 :goto_3

    :sswitch_bd
    const-string v0, "todo_detail_insurance_ice_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_bd

    goto/16 :goto_4

    :cond_bd
    const v3, 0x7f1213ed

    goto/16 :goto_3

    :sswitch_be
    const-string v0, "todo_detail_insurance_ice_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_be

    goto/16 :goto_4

    :cond_be
    const v3, 0x7f1213ec

    goto/16 :goto_3

    :sswitch_bf
    const-string v0, "todo_detail_insurance_ice_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_bf

    goto/16 :goto_4

    :cond_bf
    const v3, 0x7f1213eb

    goto/16 :goto_3

    :sswitch_c0
    const-string v0, "todo_detail_insurance_ice_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c0

    goto/16 :goto_4

    :cond_c0
    const v3, 0x7f1213ea

    goto/16 :goto_3

    :sswitch_c1
    const-string v0, "todo_detail_insurance_ice_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c1

    goto/16 :goto_4

    :cond_c1
    const v3, 0x7f1213e9

    goto/16 :goto_3

    :sswitch_c2
    const-string v0, "todo_detail_insurance_ice_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c2

    goto/16 :goto_4

    :cond_c2
    const v3, 0x7f1213e8

    goto/16 :goto_3

    :sswitch_c3
    const-string v0, "todo_detail_carexchange_ice_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c3

    goto/16 :goto_4

    :cond_c3
    const v3, 0x7f121335

    goto/16 :goto_3

    :sswitch_c4
    const-string v0, "todo_detail_registration_bev_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c4

    goto/16 :goto_4

    :cond_c4
    const v3, 0x7f121417

    goto/16 :goto_3

    :sswitch_c5
    const-string v0, "todo_detail_addcare_ice_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c5

    goto/16 :goto_4

    :cond_c5
    const v3, 0x7f12131c

    goto/16 :goto_3

    :sswitch_c6
    const-string v0, "todo_detail_addcare_ice_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c6

    goto/16 :goto_4

    :cond_c6
    const v3, 0x7f12131b

    goto/16 :goto_3

    :sswitch_c7
    const-string v0, "todo_detail_addcare_ice_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c7

    goto/16 :goto_4

    :cond_c7
    const v3, 0x7f12131a

    goto/16 :goto_3

    :sswitch_c8
    const-string v0, "todo_detail_addcare_ice_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c8

    goto/16 :goto_4

    :cond_c8
    const v3, 0x7f121319

    goto/16 :goto_3

    :sswitch_c9
    const-string v0, "todo_detail_addcare_ice_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c9

    goto/16 :goto_4

    :cond_c9
    const v3, 0x7f121317

    goto/16 :goto_3

    :sswitch_ca
    const-string v0, "todo_detail_addcare_ice_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ca

    goto/16 :goto_4

    :cond_ca
    const v3, 0x7f121316

    goto/16 :goto_3

    :sswitch_cb
    const-string v0, "todo_detail_addcare_ice_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_cb

    goto/16 :goto_4

    :cond_cb
    const v3, 0x7f121315

    goto/16 :goto_3

    :sswitch_cc
    const-string v0, "todo_detail_addcare_ice_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_cc

    goto/16 :goto_4

    :cond_cc
    const v3, 0x7f121314

    goto/16 :goto_3

    :sswitch_cd
    const-string v0, "todo_detail_addcare_ice_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_cd

    goto/16 :goto_4

    :cond_cd
    const v3, 0x7f121313

    goto/16 :goto_3

    :sswitch_ce
    const-string v0, "todo_detail_addcare_ice_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ce

    goto/16 :goto_4

    :cond_ce
    const v3, 0x7f121312

    goto/16 :goto_3

    :sswitch_cf
    const-string v0, "todo_detail_addcare_ice_body_ba"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_cf

    goto/16 :goto_4

    :cond_cf
    const v3, 0x7f121311

    goto/16 :goto_3

    :sswitch_d0
    const-string v0, "todo_detail_financing_bev_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d0

    goto/16 :goto_4

    :cond_d0
    const v3, 0x7f12138c

    goto/16 :goto_3

    :sswitch_d1
    const-string v0, "todo_detail_financing_bev_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d1

    goto/16 :goto_4

    :cond_d1
    const v3, 0x7f12138b

    goto/16 :goto_3

    :sswitch_d2
    const-string v0, "todo_detail_connectivity_bev_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d2

    goto/16 :goto_4

    :cond_d2
    const v3, 0x7f121346

    goto/16 :goto_3

    :sswitch_d3
    const-string v0, "todo_detail_registration_bev_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d3

    goto/16 :goto_4

    :cond_d3
    const v3, 0x7f121418

    goto/16 :goto_3

    :sswitch_d4
    const-string v0, "todo_detail_registration_bev_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d4

    goto/16 :goto_4

    :cond_d4
    const v3, 0x7f121416

    goto/16 :goto_3

    :sswitch_d5
    const-string v0, "todo_detail_registration_bev_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d5

    goto/16 :goto_4

    :cond_d5
    const v3, 0x7f121415

    goto/16 :goto_3

    :sswitch_d6
    const-string v0, "todo_detail_addcare_bev_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d6

    goto/16 :goto_4

    :cond_d6
    const v3, 0x7f12130c

    goto/16 :goto_3

    :sswitch_d7
    const-string v0, "todo_detail_roadside_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d7

    goto/16 :goto_4

    :cond_d7
    const v3, 0x7f121421

    goto/16 :goto_3

    :sswitch_d8
    const-string v0, "todo_detail_svc_maintenance_ice_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d8

    goto/16 :goto_4

    :cond_d8
    const v3, 0x7f121431

    goto/16 :goto_3

    :sswitch_d9
    const-string v0, "todo_detail_svc_maintenance_ice_body_pt"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d9

    goto/16 :goto_4

    :cond_d9
    const v3, 0x7f121430

    goto/16 :goto_3

    :sswitch_da
    const-string v0, "todo_detail_svc_maintenance_ice_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_da

    goto/16 :goto_4

    :cond_da
    const v3, 0x7f12142f

    goto/16 :goto_3

    :sswitch_db
    const-string v0, "todo_detail_svc_maintenance_ice_body_fi"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_db

    goto/16 :goto_4

    :cond_db
    const v3, 0x7f12142e

    goto/16 :goto_3

    :sswitch_dc
    const-string v0, "todo_detail_svc_maintenance_ice_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_dc

    goto/16 :goto_4

    :cond_dc
    const v3, 0x7f12142d

    goto/16 :goto_3

    :sswitch_dd
    const-string v0, "todo_detail_svc_maintenance_ice_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_dd

    goto/16 :goto_4

    :cond_dd
    const v3, 0x7f12142c

    goto/16 :goto_3

    :sswitch_de
    const-string v0, "todo_detail_newsletter_bev_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_de

    goto/16 :goto_4

    :cond_de
    const v3, 0x7f121411

    goto/16 :goto_3

    :sswitch_df
    const-string v0, "todo_detail_insurance_bev_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_df

    goto/16 :goto_4

    :cond_df
    const v3, 0x7f1213e2

    goto/16 :goto_3

    :sswitch_e0
    const-string v0, "todo_detail_accessories_ice_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e0

    goto/16 :goto_4

    :cond_e0
    const v3, 0x7f1212f9

    goto/16 :goto_3

    :sswitch_e1
    const-string v0, "todo_detail_accessories_ice_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e1

    goto/16 :goto_4

    :cond_e1
    const v3, 0x7f1212f8

    goto/16 :goto_3

    :sswitch_e2
    const-string v0, "todo_detail_accessories_ice_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e2

    goto/16 :goto_4

    :cond_e2
    const v3, 0x7f1212f7

    goto/16 :goto_3

    :sswitch_e3
    const-string v0, "todo_detail_accessories_ice_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e3

    goto/16 :goto_4

    :cond_e3
    const v3, 0x7f1212f6

    goto/16 :goto_3

    :sswitch_e4
    const-string v0, "todo_detail_accessories_ice_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e4

    goto/16 :goto_4

    :cond_e4
    const v3, 0x7f1212f5

    goto/16 :goto_3

    :sswitch_e5
    const-string v0, "todo_detail_accessories_ice_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e5

    goto/16 :goto_4

    :cond_e5
    const v3, 0x7f1212f4

    goto/16 :goto_3

    :sswitch_e6
    const-string v0, "todo_detail_gettoknow_bev_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e6

    goto/16 :goto_4

    :cond_e6
    const v3, 0x7f121394

    goto/16 :goto_3

    :sswitch_e7
    const-string v0, "todo_detail_gettoknow_bev_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e7

    goto/16 :goto_4

    :cond_e7
    const v3, 0x7f121393

    goto/16 :goto_3

    :sswitch_e8
    const-string v0, "todo_detail_insurance_bev_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e8

    goto/16 :goto_4

    :cond_e8
    const v3, 0x7f1213e7

    goto/16 :goto_3

    :sswitch_e9
    const-string v0, "todo_detail_insurance_bev_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e9

    goto/16 :goto_4

    :cond_e9
    const v3, 0x7f1213e6

    goto/16 :goto_3

    :sswitch_ea
    const-string v0, "todo_detail_insurance_bev_body_se"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ea

    goto/16 :goto_4

    :cond_ea
    const v3, 0x7f1213e5

    goto/16 :goto_3

    :sswitch_eb
    const-string v0, "todo_detail_insurance_bev_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_eb

    goto/16 :goto_4

    :cond_eb
    const v3, 0x7f1213e4

    goto/16 :goto_3

    :sswitch_ec
    const-string v0, "todo_detail_insurance_bev_body_nl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ec

    goto/16 :goto_4

    :cond_ec
    const v3, 0x7f1213e3

    goto/16 :goto_3

    :sswitch_ed
    const-string v0, "todo_detail_insurance_bev_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ed

    goto/16 :goto_4

    :cond_ed
    const v3, 0x7f1213e1

    goto/16 :goto_3

    :sswitch_ee
    const-string v0, "todo_detail_insurance_bev_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ee

    goto/16 :goto_4

    :cond_ee
    const v3, 0x7f1213e0

    goto/16 :goto_3

    :sswitch_ef
    const-string v0, "todo_detail_insurance_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ef

    goto/16 :goto_4

    :cond_ef
    const v3, 0x7f1213df

    goto/16 :goto_3

    :sswitch_f0
    const-string v0, "todo_detail_insurance_bev_body_dk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f0

    goto/16 :goto_4

    :cond_f0
    const v3, 0x7f1213de

    goto/16 :goto_3

    :sswitch_f1
    const-string v0, "todo_detail_insurance_bev_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f1

    goto/16 :goto_4

    :cond_f1
    const v3, 0x7f1213dd

    goto/16 :goto_3

    :sswitch_f2
    const-string v0, "todo_detail_insurance_bev_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f2

    goto/16 :goto_4

    :cond_f2
    const v3, 0x7f1213dc

    goto/16 :goto_3

    :sswitch_f3
    const-string v0, "todo_detail_insurance_bev_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f3

    goto/16 :goto_4

    :cond_f3
    const v3, 0x7f1213db

    goto/16 :goto_3

    :sswitch_f4
    const-string v0, "todo_detail_insurance_bev_body_at"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f4

    goto/16 :goto_4

    :cond_f4
    const v3, 0x7f1213da

    goto/16 :goto_3

    :sswitch_f5
    const-string v0, "todo_detail_carexchange_bev_body_ie"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f5

    goto/16 :goto_4

    :cond_f5
    const v3, 0x7f121334

    goto/16 :goto_3

    :sswitch_f6
    const-string v0, "todo_detail_hassle_bev_body_general"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f6

    goto/16 :goto_4

    :cond_f6
    const v3, 0x7f1213a5

    goto/16 :goto_3

    :sswitch_f7
    const-string v0, "todo_detail_addcare_bev_body_sl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f7

    goto/16 :goto_4

    :cond_f7
    const v3, 0x7f121310

    goto/16 :goto_3

    :sswitch_f8
    const-string v0, "todo_detail_addcare_bev_body_sk"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f8

    goto/16 :goto_4

    :cond_f8
    const v3, 0x7f12130f

    goto/16 :goto_3

    :sswitch_f9
    const-string v0, "todo_detail_addcare_bev_body_pl"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_f9

    goto/16 :goto_4

    :cond_f9
    const v3, 0x7f12130e

    goto/16 :goto_3

    :sswitch_fa
    const-string v0, "todo_detail_addcare_bev_body_lu"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_fa

    goto/16 :goto_4

    :cond_fa
    const v3, 0x7f12130d

    goto/16 :goto_3

    :sswitch_fb
    const-string v0, "todo_detail_addcare_bev_body_gb"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_fb

    goto :goto_4

    :cond_fb
    const v3, 0x7f12130b

    goto/16 :goto_3

    :sswitch_fc
    const-string v0, "todo_detail_addcare_bev_body_fr"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_fc

    goto :goto_4

    :cond_fc
    const v3, 0x7f12130a

    goto/16 :goto_3

    :sswitch_fd
    const-string v0, "todo_detail_addcare_bev_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_fd

    goto :goto_4

    :cond_fd
    const v3, 0x7f121309

    goto/16 :goto_3

    :sswitch_fe
    const-string v0, "todo_detail_addcare_bev_body_de"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_fe

    goto :goto_4

    :cond_fe
    const v3, 0x7f121308

    goto/16 :goto_3

    :sswitch_ff
    const-string v0, "todo_detail_addcare_bev_body_cz"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_ff

    goto :goto_4

    :cond_ff
    const v3, 0x7f121307

    goto/16 :goto_3

    :sswitch_100
    const-string v0, "todo_detail_addcare_bev_body_ch"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_100

    goto :goto_4

    :cond_100
    const v3, 0x7f121306

    goto/16 :goto_3

    :sswitch_101
    const-string v0, "todo_detail_addcare_bev_body_ba"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_101

    goto :goto_4

    :cond_101
    const v3, 0x7f121305

    goto/16 :goto_3

    :sswitch_102
    const-string v0, "todo_detail_svccatalogue_ice_body_es"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_102

    :goto_4
    goto/16 :goto_3

    :cond_102
    const v3, 0x7f12143f

    goto/16 :goto_3

    .line 7
    :goto_5
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/TodoDto;->getTitleKey()Ljava/lang/String;

    move-result-object v7

    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/TodoDto;->getBodyKey()Ljava/lang/String;

    move-result-object v8

    .line 9
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/TodoDto;->getUrlKeys()Ljava/util/List;

    move-result-object p0

    if-eqz p0, :cond_104

    check-cast p0, Ljava/lang/Iterable;

    .line 10
    new-instance v0, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 11
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_6
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_103

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    .line 12
    check-cast v1, Ljava/lang/String;

    .line 13
    invoke-static {v1}, Llp/ba;->c(Ljava/lang/String;)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_103
    :goto_7
    move-object v9, v0

    goto :goto_8

    :cond_104
    const/4 v0, 0x0

    goto :goto_7

    .line 15
    :goto_8
    new-instance v4, Lla0/a;

    invoke-direct/range {v4 .. v9}, Lla0/a;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;)V

    return-object v4

    :sswitch_data_0
    .sparse-switch
        -0x56c95b8a -> :sswitch_5c
        -0x54c796aa -> :sswitch_5b
        -0x454fd061 -> :sswitch_5a
        -0x435ac231 -> :sswitch_59
        -0x30e3bf87 -> :sswitch_58
        -0x30e3bf3c -> :sswitch_57
        -0x30e3be7f -> :sswitch_56
        -0x219487e2 -> :sswitch_55
        -0x219487d2 -> :sswitch_54
        -0x21948796 -> :sswitch_53
        -0x2194865d -> :sswitch_52
        -0x21948655 -> :sswitch_51
        -0x21948607 -> :sswitch_50
        -0x1cdf1d5e -> :sswitch_4f
        -0x1cdf1d4e -> :sswitch_4e
        -0x1cdf1d27 -> :sswitch_4d
        -0x1cdf1c4c -> :sswitch_4c
        -0x1cdf1c17 -> :sswitch_4b
        -0x1cdf1b83 -> :sswitch_4a
        -0x14097010 -> :sswitch_49
        -0x8969fd8 -> :sswitch_48
        0x574f649 -> :sswitch_47
        0x27eda2db -> :sswitch_46
        0x27eda348 -> :sswitch_45
        0x29a97c6e -> :sswitch_44
        0x2bec8734 -> :sswitch_43
        0x2bec8766 -> :sswitch_42
        0x2bec8778 -> :sswitch_41
        0x2bec8782 -> :sswitch_40
        0x2bec8788 -> :sswitch_3f
        0x2bec87af -> :sswitch_3e
        0x2bec87cd -> :sswitch_3d
        0x2bec87dc -> :sswitch_3c
        0x2bec88bf -> :sswitch_3b
        0x2bec88fd -> :sswitch_3a
        0x2bec8953 -> :sswitch_39
        0x2bec8959 -> :sswitch_38
        0x2bec895a -> :sswitch_37
        0x384afced -> :sswitch_36
        0x384afcf9 -> :sswitch_35
        0x384afd1f -> :sswitch_34
        0x384afd31 -> :sswitch_33
        0x384afd3b -> :sswitch_32
        0x384afd41 -> :sswitch_31
        0x384afd68 -> :sswitch_30
        0x384afd7d -> :sswitch_2f
        0x384afd86 -> :sswitch_2e
        0x384afd95 -> :sswitch_2d
        0x384afdd6 -> :sswitch_2c
        0x384afde4 -> :sswitch_2b
        0x384afe43 -> :sswitch_2a
        0x384afe78 -> :sswitch_29
        0x384afeb6 -> :sswitch_28
        0x384afebe -> :sswitch_27
        0x384aff0c -> :sswitch_26
        0x384aff12 -> :sswitch_25
        0x384aff13 -> :sswitch_24
        0x48964687 -> :sswitch_23
        0x4bbd70c8 -> :sswitch_22
        0x4bbd7158 -> :sswitch_21
        0x56383c60 -> :sswitch_20
        0x5b6524eb -> :sswitch_1f
        0x5b652580 -> :sswitch_1e
        0x713e44f2 -> :sswitch_1d
        0x713e44fe -> :sswitch_1c
        0x713e4524 -> :sswitch_1b
        0x713e4536 -> :sswitch_1a
        0x713e4540 -> :sswitch_19
        0x713e4546 -> :sswitch_18
        0x713e456d -> :sswitch_17
        0x713e4582 -> :sswitch_16
        0x713e458b -> :sswitch_15
        0x713e459a -> :sswitch_14
        0x713e45db -> :sswitch_13
        0x713e45e9 -> :sswitch_12
        0x713e4648 -> :sswitch_11
        0x713e46bb -> :sswitch_10
        0x713e46c3 -> :sswitch_f
        0x713e4711 -> :sswitch_e
        0x713e4717 -> :sswitch_d
        0x713e4718 -> :sswitch_c
        0x760b6f89 -> :sswitch_b
        0x7edb4f28 -> :sswitch_a
        0x7edb4f4e -> :sswitch_9
        0x7edb4f60 -> :sswitch_8
        0x7edb4f6a -> :sswitch_7
        0x7edb4f97 -> :sswitch_6
        0x7edb4fb5 -> :sswitch_5
        0x7edb4fc4 -> :sswitch_4
        0x7edb5072 -> :sswitch_3
        0x7edb50e5 -> :sswitch_2
        0x7edb5141 -> :sswitch_1
        0x7edb5142 -> :sswitch_0
    .end sparse-switch

    :sswitch_data_1
    .sparse-switch
        -0x7fc3224a -> :sswitch_102
        -0x771cde92 -> :sswitch_101
        -0x771cde6c -> :sswitch_100
        -0x771cde5a -> :sswitch_ff
        -0x771cde50 -> :sswitch_fe
        -0x771cde23 -> :sswitch_fd
        -0x771cde05 -> :sswitch_fc
        -0x771cddf6 -> :sswitch_fb
        -0x771cdd48 -> :sswitch_fa
        -0x771cdcd5 -> :sswitch_f9
        -0x771cdc79 -> :sswitch_f8
        -0x771cdc78 -> :sswitch_f7
        -0x71fe6711 -> :sswitch_f6
        -0x7087ebf0 -> :sswitch_f5
        -0x704e2db6 -> :sswitch_f4
        -0x704e2d84 -> :sswitch_f3
        -0x704e2d72 -> :sswitch_f2
        -0x704e2d68 -> :sswitch_f1
        -0x704e2d62 -> :sswitch_f0
        -0x704e2d3b -> :sswitch_ef
        -0x704e2d1d -> :sswitch_ee
        -0x704e2d0e -> :sswitch_ed
        -0x704e2c2b -> :sswitch_ec
        -0x704e2bed -> :sswitch_eb
        -0x704e2b97 -> :sswitch_ea
        -0x704e2b91 -> :sswitch_e9
        -0x704e2b90 -> :sswitch_e8
        -0x6bc7284b -> :sswitch_e7
        -0x6bc727de -> :sswitch_e6
        -0x696eaee4 -> :sswitch_e5
        -0x696eaed4 -> :sswitch_e4
        -0x696eaead -> :sswitch_e3
        -0x696eadd2 -> :sswitch_e2
        -0x696ead9d -> :sswitch_e1
        -0x696ead09 -> :sswitch_e0
        -0x670d86cf -> :sswitch_df
        -0x5d3ef742 -> :sswitch_de
        -0x5d0505e0 -> :sswitch_dd
        -0x5d0505d0 -> :sswitch_dc
        -0x5d050594 -> :sswitch_db
        -0x5d05045b -> :sswitch_da
        -0x5d050453 -> :sswitch_d9
        -0x5d050405 -> :sswitch_d8
        -0x5ae30454 -> :sswitch_d7
        -0x51d126e7 -> :sswitch_d6
        -0x41c89dbf -> :sswitch_d5
        -0x41c89d74 -> :sswitch_d4
        -0x41c89cb7 -> :sswitch_d3
        -0x2c7fda16 -> :sswitch_d2
        -0x2b3ae9a5 -> :sswitch_d1
        -0x2b3ae910 -> :sswitch_d0
        -0x25fa3c9a -> :sswitch_cf
        -0x25fa3c74 -> :sswitch_ce
        -0x25fa3c62 -> :sswitch_cd
        -0x25fa3c58 -> :sswitch_cc
        -0x25fa3c2b -> :sswitch_cb
        -0x25fa3c0d -> :sswitch_ca
        -0x25fa3bfe -> :sswitch_c9
        -0x25fa3b50 -> :sswitch_c8
        -0x25fa3add -> :sswitch_c7
        -0x25fa3a81 -> :sswitch_c6
        -0x25fa3a80 -> :sswitch_c5
        -0x250eb4d8 -> :sswitch_c4
        -0x1f6549f8 -> :sswitch_c3
        -0x1f2b8bbe -> :sswitch_c2
        -0x1f2b8b8c -> :sswitch_c1
        -0x1f2b8b7a -> :sswitch_c0
        -0x1f2b8b70 -> :sswitch_bf
        -0x1f2b8b6a -> :sswitch_be
        -0x1f2b8b43 -> :sswitch_bd
        -0x1f2b8b25 -> :sswitch_bc
        -0x1f2b8b16 -> :sswitch_bb
        -0x1f2b8a33 -> :sswitch_ba
        -0x1f2b89f5 -> :sswitch_b9
        -0x1f2b899f -> :sswitch_b8
        -0x1f2b8999 -> :sswitch_b7
        -0x1f2b8998 -> :sswitch_b6
        -0x1aa48653 -> :sswitch_b5
        -0x1aa485e6 -> :sswitch_b4
        -0xc1c554a -> :sswitch_b3
        -0xbe8aa0f -> :sswitch_b2
        -0xbe8aa03 -> :sswitch_b1
        -0xbe8a9dd -> :sswitch_b0
        -0xbe8a9cb -> :sswitch_af
        -0xbe8a9c1 -> :sswitch_ae
        -0xbe8a9bb -> :sswitch_ad
        -0xbe8a994 -> :sswitch_ac
        -0xbe8a97f -> :sswitch_ab
        -0xbe8a976 -> :sswitch_aa
        -0xbe8a967 -> :sswitch_a9
        -0xbe8a926 -> :sswitch_a8
        -0xbe8a918 -> :sswitch_a7
        -0xbe8a8b9 -> :sswitch_a6
        -0xbe8a884 -> :sswitch_a5
        -0xbe8a846 -> :sswitch_a4
        -0xbe8a83e -> :sswitch_a3
        -0xbe8a7f0 -> :sswitch_a2
        -0xbe8a7ea -> :sswitch_a1
        -0xbe8a7e9 -> :sswitch_a0
        -0x9c0625c -> :sswitch_9f
        -0x9b7bb3b -> :sswitch_9e
        0x80f9036 -> :sswitch_9d
        0x80f90c6 -> :sswitch_9c
        0xf5a0439 -> :sswitch_9b
        0xf5a0484 -> :sswitch_9a
        0xf5a0541 -> :sswitch_99
        0x107e5239 -> :sswitch_98
        0x1b6302e7 -> :sswitch_97
        0x25bab221 -> :sswitch_96
        0x25e7b853 -> :sswitch_95
        0x25e7b8e8 -> :sswitch_94
        0x2f1a3bbe -> :sswitch_93
        0x4539f7e9 -> :sswitch_92
        0x4539f7f5 -> :sswitch_91
        0x4539f81b -> :sswitch_90
        0x4539f82d -> :sswitch_8f
        0x4539f837 -> :sswitch_8e
        0x4539f83d -> :sswitch_8d
        0x4539f864 -> :sswitch_8c
        0x4539f879 -> :sswitch_8b
        0x4539f882 -> :sswitch_8a
        0x4539f891 -> :sswitch_89
        0x4539f8d2 -> :sswitch_88
        0x4539f8e0 -> :sswitch_87
        0x4539f93f -> :sswitch_86
        0x4539f974 -> :sswitch_85
        0x4539f9b2 -> :sswitch_84
        0x4539f9ba -> :sswitch_83
        0x4539fa08 -> :sswitch_82
        0x4539fa0e -> :sswitch_81
        0x4539fa0f -> :sswitch_80
        0x456eaf24 -> :sswitch_7f
        0x456eaf34 -> :sswitch_7e
        0x456eaf5b -> :sswitch_7d
        0x456eb036 -> :sswitch_7c
        0x456eb06b -> :sswitch_7b
        0x456eb0ff -> :sswitch_7a
        0x4b0bfef2 -> :sswitch_79
        0x51d85828 -> :sswitch_78
        0x51d85838 -> :sswitch_77
        0x51d85874 -> :sswitch_76
        0x51d859ad -> :sswitch_75
        0x51d859b5 -> :sswitch_74
        0x51d85a03 -> :sswitch_73
        0x527d2430 -> :sswitch_72
        0x530153cc -> :sswitch_71
        0x530153d8 -> :sswitch_70
        0x530153fe -> :sswitch_6f
        0x53015410 -> :sswitch_6e
        0x5301541a -> :sswitch_6d
        0x53015420 -> :sswitch_6c
        0x53015447 -> :sswitch_6b
        0x5301545c -> :sswitch_6a
        0x53015465 -> :sswitch_69
        0x53015474 -> :sswitch_68
        0x530154b5 -> :sswitch_67
        0x530154c3 -> :sswitch_66
        0x53015522 -> :sswitch_65
        0x53015595 -> :sswitch_64
        0x5301559d -> :sswitch_63
        0x530155eb -> :sswitch_62
        0x530155f1 -> :sswitch_61
        0x530155f2 -> :sswitch_60
        0x5932322e -> :sswitch_5f
        0x593232be -> :sswitch_5e
        0x6c85a4df -> :sswitch_5d
    .end sparse-switch
.end method

.method public static final c(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    sparse-switch v0, :sswitch_data_0

    .line 11
    .line 12
    .line 13
    goto/16 :goto_0

    .line 14
    .line 15
    :sswitch_0
    const-string v0, "todo_detail_gettoknow_url_lu"

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_0
    const p0, 0x7f12139a

    .line 26
    .line 27
    .line 28
    return p0

    .line 29
    :sswitch_1
    const-string v0, "todo_detail_gettoknow_url_ie"

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-nez p0, :cond_1

    .line 36
    .line 37
    goto/16 :goto_0

    .line 38
    .line 39
    :cond_1
    const p0, 0x7f121399

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :sswitch_2
    const-string v0, "todo_detail_insurance_url_sl"

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-nez p0, :cond_2

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :cond_2
    const p0, 0x7f121410

    .line 54
    .line 55
    .line 56
    return p0

    .line 57
    :sswitch_3
    const-string v0, "todo_detail_insurance_url_sk"

    .line 58
    .line 59
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-nez p0, :cond_3

    .line 64
    .line 65
    goto/16 :goto_0

    .line 66
    .line 67
    :cond_3
    const p0, 0x7f12140f

    .line 68
    .line 69
    .line 70
    return p0

    .line 71
    :sswitch_4
    const-string v0, "todo_detail_insurance_url_se"

    .line 72
    .line 73
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    if-nez p0, :cond_4

    .line 78
    .line 79
    goto/16 :goto_0

    .line 80
    .line 81
    :cond_4
    const p0, 0x7f12140e

    .line 82
    .line 83
    .line 84
    return p0

    .line 85
    :sswitch_5
    const-string v0, "todo_detail_insurance_url_pl"

    .line 86
    .line 87
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-nez p0, :cond_5

    .line 92
    .line 93
    goto/16 :goto_0

    .line 94
    .line 95
    :cond_5
    const p0, 0x7f12140d

    .line 96
    .line 97
    .line 98
    return p0

    .line 99
    :sswitch_6
    const-string v0, "todo_detail_insurance_url_nl"

    .line 100
    .line 101
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    if-nez p0, :cond_6

    .line 106
    .line 107
    goto/16 :goto_0

    .line 108
    .line 109
    :cond_6
    const p0, 0x7f12140c

    .line 110
    .line 111
    .line 112
    return p0

    .line 113
    :sswitch_7
    const-string v0, "todo_detail_insurance_url_gb"

    .line 114
    .line 115
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-nez p0, :cond_7

    .line 120
    .line 121
    goto/16 :goto_0

    .line 122
    .line 123
    :cond_7
    const p0, 0x7f12140a

    .line 124
    .line 125
    .line 126
    return p0

    .line 127
    :sswitch_8
    const-string v0, "todo_detail_insurance_url_fr"

    .line 128
    .line 129
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    if-nez p0, :cond_8

    .line 134
    .line 135
    goto/16 :goto_0

    .line 136
    .line 137
    :cond_8
    const p0, 0x7f121409

    .line 138
    .line 139
    .line 140
    return p0

    .line 141
    :sswitch_9
    const-string v0, "todo_detail_insurance_url_es"

    .line 142
    .line 143
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p0

    .line 147
    if-nez p0, :cond_9

    .line 148
    .line 149
    goto/16 :goto_0

    .line 150
    .line 151
    :cond_9
    const p0, 0x7f121408

    .line 152
    .line 153
    .line 154
    return p0

    .line 155
    :sswitch_a
    const-string v0, "todo_detail_insurance_url_dk"

    .line 156
    .line 157
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result p0

    .line 161
    if-nez p0, :cond_a

    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :cond_a
    const p0, 0x7f121407

    .line 166
    .line 167
    .line 168
    return p0

    .line 169
    :sswitch_b
    const-string v0, "todo_detail_insurance_url_de"

    .line 170
    .line 171
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result p0

    .line 175
    if-nez p0, :cond_b

    .line 176
    .line 177
    goto/16 :goto_0

    .line 178
    .line 179
    :cond_b
    const p0, 0x7f121406

    .line 180
    .line 181
    .line 182
    return p0

    .line 183
    :sswitch_c
    const-string v0, "todo_detail_insurance_url_cz"

    .line 184
    .line 185
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    if-nez p0, :cond_c

    .line 190
    .line 191
    goto/16 :goto_0

    .line 192
    .line 193
    :cond_c
    const p0, 0x7f121405

    .line 194
    .line 195
    .line 196
    return p0

    .line 197
    :sswitch_d
    const-string v0, "todo_detail_insurance_url_ch"

    .line 198
    .line 199
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    if-nez p0, :cond_d

    .line 204
    .line 205
    goto/16 :goto_0

    .line 206
    .line 207
    :cond_d
    const p0, 0x7f121404

    .line 208
    .line 209
    .line 210
    return p0

    .line 211
    :sswitch_e
    const-string v0, "todo_detail_hassle_charger_url_general"

    .line 212
    .line 213
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result p0

    .line 217
    if-nez p0, :cond_e

    .line 218
    .line 219
    goto/16 :goto_0

    .line 220
    .line 221
    :cond_e
    const p0, 0x7f1213b4

    .line 222
    .line 223
    .line 224
    return p0

    .line 225
    :sswitch_f
    const-string v0, "todo_detail_newsletter_url_nl"

    .line 226
    .line 227
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result p0

    .line 231
    if-nez p0, :cond_f

    .line 232
    .line 233
    goto/16 :goto_0

    .line 234
    .line 235
    :cond_f
    const p0, 0x7f121414

    .line 236
    .line 237
    .line 238
    return p0

    .line 239
    :sswitch_10
    const-string v0, "todo_detail_hassle_ohme_url_gb"

    .line 240
    .line 241
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    if-nez p0, :cond_10

    .line 246
    .line 247
    goto/16 :goto_0

    .line 248
    .line 249
    :cond_10
    const p0, 0x7f1213b8

    .line 250
    .line 251
    .line 252
    return p0

    .line 253
    :sswitch_11
    const-string v0, "todo_detail_clubskoda_url_fr"

    .line 254
    .line 255
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-result p0

    .line 259
    if-nez p0, :cond_11

    .line 260
    .line 261
    goto/16 :goto_0

    .line 262
    .line 263
    :cond_11
    const p0, 0x7f12133a

    .line 264
    .line 265
    .line 266
    return p0

    .line 267
    :sswitch_12
    const-string v0, "todo_detail_hassle_general_url_fi"

    .line 268
    .line 269
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result p0

    .line 273
    if-nez p0, :cond_12

    .line 274
    .line 275
    goto/16 :goto_0

    .line 276
    .line 277
    :cond_12
    const p0, 0x7f1213b6

    .line 278
    .line 279
    .line 280
    return p0

    .line 281
    :sswitch_13
    const-string v0, "todo_detail_connectivity_availability_url_ch"

    .line 282
    .line 283
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result p0

    .line 287
    if-nez p0, :cond_13

    .line 288
    .line 289
    goto/16 :goto_0

    .line 290
    .line 291
    :cond_13
    const p0, 0x7f12133b

    .line 292
    .line 293
    .line 294
    return p0

    .line 295
    :sswitch_14
    const-string v0, "todo_detail_financing_calculator_url_dk"

    .line 296
    .line 297
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 298
    .line 299
    .line 300
    move-result p0

    .line 301
    if-nez p0, :cond_14

    .line 302
    .line 303
    goto/16 :goto_0

    .line 304
    .line 305
    :cond_14
    const p0, 0x7f12138d

    .line 306
    .line 307
    .line 308
    return p0

    .line 309
    :sswitch_15
    const-string v0, "todo_detail_insurance_url_general"

    .line 310
    .line 311
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result p0

    .line 315
    if-nez p0, :cond_15

    .line 316
    .line 317
    goto/16 :goto_0

    .line 318
    .line 319
    :cond_15
    const p0, 0x7f12140b

    .line 320
    .line 321
    .line 322
    return p0

    .line 323
    :sswitch_16
    const-string v0, "todo_detail_electricdriving_email_url_nl"

    .line 324
    .line 325
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result p0

    .line 329
    if-nez p0, :cond_16

    .line 330
    .line 331
    goto/16 :goto_0

    .line 332
    .line 333
    :cond_16
    const p0, 0x7f121388

    .line 334
    .line 335
    .line 336
    return p0

    .line 337
    :sswitch_17
    const-string v0, "todo_detail_hassle_powerpass_url_lu"

    .line 338
    .line 339
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    move-result p0

    .line 343
    if-nez p0, :cond_17

    .line 344
    .line 345
    goto/16 :goto_0

    .line 346
    .line 347
    :cond_17
    const p0, 0x7f1213c1

    .line 348
    .line 349
    .line 350
    return p0

    .line 351
    :sswitch_18
    const-string v0, "todo_detail_hassle_powerpass_url_ie"

    .line 352
    .line 353
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    move-result p0

    .line 357
    if-nez p0, :cond_18

    .line 358
    .line 359
    goto/16 :goto_0

    .line 360
    .line 361
    :cond_18
    const p0, 0x7f1213c0

    .line 362
    .line 363
    .line 364
    return p0

    .line 365
    :sswitch_19
    const-string v0, "todo_detail_hassle_powerpass_url_fr"

    .line 366
    .line 367
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 368
    .line 369
    .line 370
    move-result p0

    .line 371
    if-nez p0, :cond_19

    .line 372
    .line 373
    goto/16 :goto_0

    .line 374
    .line 375
    :cond_19
    const p0, 0x7f1213be

    .line 376
    .line 377
    .line 378
    return p0

    .line 379
    :sswitch_1a
    const-string v0, "todo_detail_hassle_powerpass_url_fi"

    .line 380
    .line 381
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    move-result p0

    .line 385
    if-nez p0, :cond_1a

    .line 386
    .line 387
    goto/16 :goto_0

    .line 388
    .line 389
    :cond_1a
    const p0, 0x7f1213bd

    .line 390
    .line 391
    .line 392
    return p0

    .line 393
    :sswitch_1b
    const-string v0, "todo_detail_hassle_powerpass_url_es"

    .line 394
    .line 395
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 396
    .line 397
    .line 398
    move-result p0

    .line 399
    if-nez p0, :cond_1b

    .line 400
    .line 401
    goto/16 :goto_0

    .line 402
    .line 403
    :cond_1b
    const p0, 0x7f1213bc

    .line 404
    .line 405
    .line 406
    return p0

    .line 407
    :sswitch_1c
    const-string v0, "todo_detail_hassle_powerpass_url_dk"

    .line 408
    .line 409
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 410
    .line 411
    .line 412
    move-result p0

    .line 413
    if-nez p0, :cond_1c

    .line 414
    .line 415
    goto/16 :goto_0

    .line 416
    .line 417
    :cond_1c
    const p0, 0x7f1213bb

    .line 418
    .line 419
    .line 420
    return p0

    .line 421
    :sswitch_1d
    const-string v0, "todo_detail_hassle_powerpass_url_de"

    .line 422
    .line 423
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    move-result p0

    .line 427
    if-nez p0, :cond_1d

    .line 428
    .line 429
    goto/16 :goto_0

    .line 430
    .line 431
    :cond_1d
    const p0, 0x7f1213ba

    .line 432
    .line 433
    .line 434
    return p0

    .line 435
    :sswitch_1e
    const-string v0, "todo_detail_hassle_powerpass_url_cz"

    .line 436
    .line 437
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    move-result p0

    .line 441
    if-nez p0, :cond_1e

    .line 442
    .line 443
    goto/16 :goto_0

    .line 444
    .line 445
    :cond_1e
    const p0, 0x7f1213b9

    .line 446
    .line 447
    .line 448
    return p0

    .line 449
    :sswitch_1f
    const-string v0, "todo_detail_addcare_url_general"

    .line 450
    .line 451
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 452
    .line 453
    .line 454
    move-result p0

    .line 455
    if-nez p0, :cond_1f

    .line 456
    .line 457
    goto/16 :goto_0

    .line 458
    .line 459
    :cond_1f
    const p0, 0x7f12132f

    .line 460
    .line 461
    .line 462
    return p0

    .line 463
    :sswitch_20
    const-string v0, "todo_detail_connectivity_url_sl"

    .line 464
    .line 465
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 466
    .line 467
    .line 468
    move-result p0

    .line 469
    if-nez p0, :cond_20

    .line 470
    .line 471
    goto/16 :goto_0

    .line 472
    .line 473
    :cond_20
    const p0, 0x7f121386

    .line 474
    .line 475
    .line 476
    return p0

    .line 477
    :sswitch_21
    const-string v0, "todo_detail_connectivity_url_sk"

    .line 478
    .line 479
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 480
    .line 481
    .line 482
    move-result p0

    .line 483
    if-nez p0, :cond_21

    .line 484
    .line 485
    goto/16 :goto_0

    .line 486
    .line 487
    :cond_21
    const p0, 0x7f121385

    .line 488
    .line 489
    .line 490
    return p0

    .line 491
    :sswitch_22
    const-string v0, "todo_detail_connectivity_url_se"

    .line 492
    .line 493
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 494
    .line 495
    .line 496
    move-result p0

    .line 497
    if-nez p0, :cond_22

    .line 498
    .line 499
    goto/16 :goto_0

    .line 500
    .line 501
    :cond_22
    const p0, 0x7f121384

    .line 502
    .line 503
    .line 504
    return p0

    .line 505
    :sswitch_23
    const-string v0, "todo_detail_connectivity_url_pt"

    .line 506
    .line 507
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 508
    .line 509
    .line 510
    move-result p0

    .line 511
    if-nez p0, :cond_23

    .line 512
    .line 513
    goto/16 :goto_0

    .line 514
    .line 515
    :cond_23
    const p0, 0x7f121383

    .line 516
    .line 517
    .line 518
    return p0

    .line 519
    :sswitch_24
    const-string v0, "todo_detail_connectivity_url_pl"

    .line 520
    .line 521
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 522
    .line 523
    .line 524
    move-result p0

    .line 525
    if-nez p0, :cond_24

    .line 526
    .line 527
    goto/16 :goto_0

    .line 528
    .line 529
    :cond_24
    const p0, 0x7f121382

    .line 530
    .line 531
    .line 532
    return p0

    .line 533
    :sswitch_25
    const-string v0, "todo_detail_connectivity_url_nl"

    .line 534
    .line 535
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 536
    .line 537
    .line 538
    move-result p0

    .line 539
    if-nez p0, :cond_25

    .line 540
    .line 541
    goto/16 :goto_0

    .line 542
    .line 543
    :cond_25
    const p0, 0x7f121381

    .line 544
    .line 545
    .line 546
    return p0

    .line 547
    :sswitch_26
    const-string v0, "todo_detail_connectivity_url_ie"

    .line 548
    .line 549
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 550
    .line 551
    .line 552
    move-result p0

    .line 553
    if-nez p0, :cond_26

    .line 554
    .line 555
    goto/16 :goto_0

    .line 556
    .line 557
    :cond_26
    const p0, 0x7f121380

    .line 558
    .line 559
    .line 560
    return p0

    .line 561
    :sswitch_27
    const-string v0, "todo_detail_connectivity_url_es"

    .line 562
    .line 563
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 564
    .line 565
    .line 566
    move-result p0

    .line 567
    if-nez p0, :cond_27

    .line 568
    .line 569
    goto/16 :goto_0

    .line 570
    .line 571
    :cond_27
    const p0, 0x7f12137e

    .line 572
    .line 573
    .line 574
    return p0

    .line 575
    :sswitch_28
    const-string v0, "todo_detail_connectivity_url_dk"

    .line 576
    .line 577
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 578
    .line 579
    .line 580
    move-result p0

    .line 581
    if-nez p0, :cond_28

    .line 582
    .line 583
    goto/16 :goto_0

    .line 584
    .line 585
    :cond_28
    const p0, 0x7f12137d

    .line 586
    .line 587
    .line 588
    return p0

    .line 589
    :sswitch_29
    const-string v0, "todo_detail_connectivity_url_de"

    .line 590
    .line 591
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 592
    .line 593
    .line 594
    move-result p0

    .line 595
    if-nez p0, :cond_29

    .line 596
    .line 597
    goto/16 :goto_0

    .line 598
    .line 599
    :cond_29
    const p0, 0x7f12137c

    .line 600
    .line 601
    .line 602
    return p0

    .line 603
    :sswitch_2a
    const-string v0, "todo_detail_connectivity_url_cz"

    .line 604
    .line 605
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 606
    .line 607
    .line 608
    move-result p0

    .line 609
    if-nez p0, :cond_2a

    .line 610
    .line 611
    goto/16 :goto_0

    .line 612
    .line 613
    :cond_2a
    const p0, 0x7f12137b

    .line 614
    .line 615
    .line 616
    return p0

    .line 617
    :sswitch_2b
    const-string v0, "todo_detail_connectivity_url_ba"

    .line 618
    .line 619
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 620
    .line 621
    .line 622
    move-result p0

    .line 623
    if-nez p0, :cond_2b

    .line 624
    .line 625
    goto/16 :goto_0

    .line 626
    .line 627
    :cond_2b
    const p0, 0x7f12137a

    .line 628
    .line 629
    .line 630
    return p0

    .line 631
    :sswitch_2c
    const-string v0, "todo_detail_connectivity_url_at"

    .line 632
    .line 633
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 634
    .line 635
    .line 636
    move-result p0

    .line 637
    if-nez p0, :cond_2c

    .line 638
    .line 639
    goto/16 :goto_0

    .line 640
    .line 641
    :cond_2c
    const p0, 0x7f121379

    .line 642
    .line 643
    .line 644
    return p0

    .line 645
    :sswitch_2d
    const-string v0, "todo_detail_financing_offers_url_dk"

    .line 646
    .line 647
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 648
    .line 649
    .line 650
    move-result p0

    .line 651
    if-nez p0, :cond_2d

    .line 652
    .line 653
    goto/16 :goto_0

    .line 654
    .line 655
    :cond_2d
    const p0, 0x7f121390

    .line 656
    .line 657
    .line 658
    return p0

    .line 659
    :sswitch_2e
    const-string v0, "todo_detail_accessories_url_se"

    .line 660
    .line 661
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 662
    .line 663
    .line 664
    move-result p0

    .line 665
    if-nez p0, :cond_2e

    .line 666
    .line 667
    goto/16 :goto_0

    .line 668
    .line 669
    :cond_2e
    const p0, 0x7f121304

    .line 670
    .line 671
    .line 672
    return p0

    .line 673
    :sswitch_2f
    const-string v0, "todo_detail_accessories_url_nl"

    .line 674
    .line 675
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 676
    .line 677
    .line 678
    move-result p0

    .line 679
    if-nez p0, :cond_2f

    .line 680
    .line 681
    goto/16 :goto_0

    .line 682
    .line 683
    :cond_2f
    const p0, 0x7f121303

    .line 684
    .line 685
    .line 686
    return p0

    .line 687
    :sswitch_30
    const-string v0, "todo_detail_accessories_url_es"

    .line 688
    .line 689
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 690
    .line 691
    .line 692
    move-result p0

    .line 693
    if-nez p0, :cond_30

    .line 694
    .line 695
    goto/16 :goto_0

    .line 696
    .line 697
    :cond_30
    const p0, 0x7f121302

    .line 698
    .line 699
    .line 700
    return p0

    .line 701
    :sswitch_31
    const-string v0, "todo_detail_accessories_url_dk"

    .line 702
    .line 703
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 704
    .line 705
    .line 706
    move-result p0

    .line 707
    if-nez p0, :cond_31

    .line 708
    .line 709
    goto/16 :goto_0

    .line 710
    .line 711
    :cond_31
    const p0, 0x7f121301

    .line 712
    .line 713
    .line 714
    return p0

    .line 715
    :sswitch_32
    const-string v0, "todo_detail_accessories_url_cz"

    .line 716
    .line 717
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 718
    .line 719
    .line 720
    move-result p0

    .line 721
    if-nez p0, :cond_32

    .line 722
    .line 723
    goto/16 :goto_0

    .line 724
    .line 725
    :cond_32
    const p0, 0x7f121300

    .line 726
    .line 727
    .line 728
    return p0

    .line 729
    :sswitch_33
    const-string v0, "todo_detail_svc_maintenance_url_se"

    .line 730
    .line 731
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 732
    .line 733
    .line 734
    move-result p0

    .line 735
    if-nez p0, :cond_33

    .line 736
    .line 737
    goto/16 :goto_0

    .line 738
    .line 739
    :cond_33
    const p0, 0x7f12143d

    .line 740
    .line 741
    .line 742
    return p0

    .line 743
    :sswitch_34
    const-string v0, "todo_detail_svc_maintenance_url_pt"

    .line 744
    .line 745
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 746
    .line 747
    .line 748
    move-result p0

    .line 749
    if-nez p0, :cond_34

    .line 750
    .line 751
    goto/16 :goto_0

    .line 752
    .line 753
    :cond_34
    const p0, 0x7f12143c

    .line 754
    .line 755
    .line 756
    return p0

    .line 757
    :sswitch_35
    const-string v0, "todo_detail_svc_maintenance_url_pl"

    .line 758
    .line 759
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 760
    .line 761
    .line 762
    move-result p0

    .line 763
    if-nez p0, :cond_35

    .line 764
    .line 765
    goto/16 :goto_0

    .line 766
    .line 767
    :cond_35
    const p0, 0x7f12143b

    .line 768
    .line 769
    .line 770
    return p0

    .line 771
    :sswitch_36
    const-string v0, "todo_detail_svc_maintenance_url_dk"

    .line 772
    .line 773
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 774
    .line 775
    .line 776
    move-result p0

    .line 777
    if-nez p0, :cond_36

    .line 778
    .line 779
    goto/16 :goto_0

    .line 780
    .line 781
    :cond_36
    const p0, 0x7f12143a

    .line 782
    .line 783
    .line 784
    return p0

    .line 785
    :sswitch_37
    const-string v0, "todo_detail_svc_maintenance_url_cz"

    .line 786
    .line 787
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 788
    .line 789
    .line 790
    move-result p0

    .line 791
    if-nez p0, :cond_37

    .line 792
    .line 793
    goto/16 :goto_0

    .line 794
    .line 795
    :cond_37
    const p0, 0x7f121439

    .line 796
    .line 797
    .line 798
    return p0

    .line 799
    :sswitch_38
    const-string v0, "todo_detail_warranty_url_fi"

    .line 800
    .line 801
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 802
    .line 803
    .line 804
    move-result p0

    .line 805
    if-nez p0, :cond_38

    .line 806
    .line 807
    goto/16 :goto_0

    .line 808
    .line 809
    :cond_38
    const p0, 0x7f121448

    .line 810
    .line 811
    .line 812
    return p0

    .line 813
    :sswitch_39
    const-string v0, "todo_detail_hassle_url_sl"

    .line 814
    .line 815
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 816
    .line 817
    .line 818
    move-result p0

    .line 819
    if-nez p0, :cond_39

    .line 820
    .line 821
    goto/16 :goto_0

    .line 822
    .line 823
    :cond_39
    const p0, 0x7f1213d8

    .line 824
    .line 825
    .line 826
    return p0

    .line 827
    :sswitch_3a
    const-string v0, "todo_detail_hassle_url_se"

    .line 828
    .line 829
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 830
    .line 831
    .line 832
    move-result p0

    .line 833
    if-nez p0, :cond_3a

    .line 834
    .line 835
    goto/16 :goto_0

    .line 836
    .line 837
    :cond_3a
    const p0, 0x7f1213d7

    .line 838
    .line 839
    .line 840
    return p0

    .line 841
    :sswitch_3b
    const-string v0, "todo_detail_hassle_url_pt"

    .line 842
    .line 843
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 844
    .line 845
    .line 846
    move-result p0

    .line 847
    if-nez p0, :cond_3b

    .line 848
    .line 849
    goto/16 :goto_0

    .line 850
    .line 851
    :cond_3b
    const p0, 0x7f1213d6

    .line 852
    .line 853
    .line 854
    return p0

    .line 855
    :sswitch_3c
    const-string v0, "todo_detail_hassle_url_is"

    .line 856
    .line 857
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 858
    .line 859
    .line 860
    move-result p0

    .line 861
    if-nez p0, :cond_3c

    .line 862
    .line 863
    goto/16 :goto_0

    .line 864
    .line 865
    :cond_3c
    const p0, 0x7f1213d5

    .line 866
    .line 867
    .line 868
    return p0

    .line 869
    :sswitch_3d
    const-string v0, "todo_detail_connectivity_connect_url_ch"

    .line 870
    .line 871
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 872
    .line 873
    .line 874
    move-result p0

    .line 875
    if-nez p0, :cond_3d

    .line 876
    .line 877
    goto/16 :goto_0

    .line 878
    .line 879
    :cond_3d
    const p0, 0x7f121350

    .line 880
    .line 881
    .line 882
    return p0

    .line 883
    :sswitch_3e
    const-string v0, "todo_detail_electricdriving_phone_url_nl"

    .line 884
    .line 885
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 886
    .line 887
    .line 888
    move-result p0

    .line 889
    if-nez p0, :cond_3e

    .line 890
    .line 891
    goto/16 :goto_0

    .line 892
    .line 893
    :cond_3e
    const p0, 0x7f121389

    .line 894
    .line 895
    .line 896
    return p0

    .line 897
    :sswitch_3f
    const-string v0, "todo_detail_svc_maintenance_partners_url_fi"

    .line 898
    .line 899
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 900
    .line 901
    .line 902
    move-result p0

    .line 903
    if-nez p0, :cond_3f

    .line 904
    .line 905
    goto/16 :goto_0

    .line 906
    .line 907
    :cond_3f
    const p0, 0x7f121432

    .line 908
    .line 909
    .line 910
    return p0

    .line 911
    :sswitch_40
    const-string v0, "todo_detail_hassle_octopus_url_gb"

    .line 912
    .line 913
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 914
    .line 915
    .line 916
    move-result p0

    .line 917
    if-nez p0, :cond_40

    .line 918
    .line 919
    goto/16 :goto_0

    .line 920
    .line 921
    :cond_40
    const p0, 0x7f1213b7

    .line 922
    .line 923
    .line 924
    return p0

    .line 925
    :sswitch_41
    const-string v0, "todo_detail_hassle_charger_url_lu"

    .line 926
    .line 927
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 928
    .line 929
    .line 930
    move-result p0

    .line 931
    if-nez p0, :cond_41

    .line 932
    .line 933
    goto/16 :goto_0

    .line 934
    .line 935
    :cond_41
    const p0, 0x7f1213b5

    .line 936
    .line 937
    .line 938
    return p0

    .line 939
    :sswitch_42
    const-string v0, "todo_detail_hassle_charger_url_fi"

    .line 940
    .line 941
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 942
    .line 943
    .line 944
    move-result p0

    .line 945
    if-nez p0, :cond_42

    .line 946
    .line 947
    goto/16 :goto_0

    .line 948
    .line 949
    :cond_42
    const p0, 0x7f1213b3

    .line 950
    .line 951
    .line 952
    return p0

    .line 953
    :sswitch_43
    const-string v0, "todo_detail_hassle_charger_url_es"

    .line 954
    .line 955
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 956
    .line 957
    .line 958
    move-result p0

    .line 959
    if-nez p0, :cond_43

    .line 960
    .line 961
    goto/16 :goto_0

    .line 962
    .line 963
    :cond_43
    const p0, 0x7f1213b2

    .line 964
    .line 965
    .line 966
    return p0

    .line 967
    :sswitch_44
    const-string v0, "todo_detail_hassle_charger_url_dk"

    .line 968
    .line 969
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 970
    .line 971
    .line 972
    move-result p0

    .line 973
    if-nez p0, :cond_44

    .line 974
    .line 975
    goto/16 :goto_0

    .line 976
    .line 977
    :cond_44
    const p0, 0x7f1213b1

    .line 978
    .line 979
    .line 980
    return p0

    .line 981
    :sswitch_45
    const-string v0, "todo_detail_hassle_charger_url_de"

    .line 982
    .line 983
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 984
    .line 985
    .line 986
    move-result p0

    .line 987
    if-nez p0, :cond_45

    .line 988
    .line 989
    goto/16 :goto_0

    .line 990
    .line 991
    :cond_45
    const p0, 0x7f1213b0

    .line 992
    .line 993
    .line 994
    return p0

    .line 995
    :sswitch_46
    const-string v0, "todo_detail_hassle_charger_url_cz"

    .line 996
    .line 997
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 998
    .line 999
    .line 1000
    move-result p0

    .line 1001
    if-nez p0, :cond_46

    .line 1002
    .line 1003
    goto/16 :goto_0

    .line 1004
    .line 1005
    :cond_46
    const p0, 0x7f1213af

    .line 1006
    .line 1007
    .line 1008
    return p0

    .line 1009
    :sswitch_47
    const-string v0, "todo_detail_hassle_powerpass_url_general"

    .line 1010
    .line 1011
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1012
    .line 1013
    .line 1014
    move-result p0

    .line 1015
    if-nez p0, :cond_47

    .line 1016
    .line 1017
    goto/16 :goto_0

    .line 1018
    .line 1019
    :cond_47
    const p0, 0x7f1213bf

    .line 1020
    .line 1021
    .line 1022
    return p0

    .line 1023
    :sswitch_48
    const-string v0, "todo_detail_roadside_url_es"

    .line 1024
    .line 1025
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1026
    .line 1027
    .line 1028
    move-result p0

    .line 1029
    if-nez p0, :cond_48

    .line 1030
    .line 1031
    goto/16 :goto_0

    .line 1032
    .line 1033
    :cond_48
    const p0, 0x7f121424

    .line 1034
    .line 1035
    .line 1036
    return p0

    .line 1037
    :sswitch_49
    const-string v0, "todo_detail_svccatalogue_url_es"

    .line 1038
    .line 1039
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1040
    .line 1041
    .line 1042
    move-result p0

    .line 1043
    if-nez p0, :cond_49

    .line 1044
    .line 1045
    goto/16 :goto_0

    .line 1046
    .line 1047
    :cond_49
    const p0, 0x7f121441

    .line 1048
    .line 1049
    .line 1050
    return p0

    .line 1051
    :sswitch_4a
    const-string v0, "todo_detail_hassle_chargee_url_cz"

    .line 1052
    .line 1053
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1054
    .line 1055
    .line 1056
    move-result p0

    .line 1057
    if-nez p0, :cond_4a

    .line 1058
    .line 1059
    goto/16 :goto_0

    .line 1060
    .line 1061
    :cond_4a
    const p0, 0x7f1213ae

    .line 1062
    .line 1063
    .line 1064
    return p0

    .line 1065
    :sswitch_4b
    const-string v0, "todo_detail_addcare_url_sl"

    .line 1066
    .line 1067
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1068
    .line 1069
    .line 1070
    move-result p0

    .line 1071
    if-nez p0, :cond_4b

    .line 1072
    .line 1073
    goto/16 :goto_0

    .line 1074
    .line 1075
    :cond_4b
    const p0, 0x7f121332

    .line 1076
    .line 1077
    .line 1078
    return p0

    .line 1079
    :sswitch_4c
    const-string v0, "todo_detail_addcare_url_sk"

    .line 1080
    .line 1081
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1082
    .line 1083
    .line 1084
    move-result p0

    .line 1085
    if-nez p0, :cond_4c

    .line 1086
    .line 1087
    goto/16 :goto_0

    .line 1088
    .line 1089
    :cond_4c
    const p0, 0x7f121331

    .line 1090
    .line 1091
    .line 1092
    return p0

    .line 1093
    :sswitch_4d
    const-string v0, "todo_detail_addcare_url_pl"

    .line 1094
    .line 1095
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1096
    .line 1097
    .line 1098
    move-result p0

    .line 1099
    if-nez p0, :cond_4d

    .line 1100
    .line 1101
    goto/16 :goto_0

    .line 1102
    .line 1103
    :cond_4d
    const p0, 0x7f121330

    .line 1104
    .line 1105
    .line 1106
    return p0

    .line 1107
    :sswitch_4e
    const-string v0, "todo_detail_addcare_url_gb"

    .line 1108
    .line 1109
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1110
    .line 1111
    .line 1112
    move-result p0

    .line 1113
    if-nez p0, :cond_4e

    .line 1114
    .line 1115
    goto :goto_0

    .line 1116
    :cond_4e
    const p0, 0x7f12132e

    .line 1117
    .line 1118
    .line 1119
    return p0

    .line 1120
    :sswitch_4f
    const-string v0, "todo_detail_addcare_url_fr"

    .line 1121
    .line 1122
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1123
    .line 1124
    .line 1125
    move-result p0

    .line 1126
    if-nez p0, :cond_4f

    .line 1127
    .line 1128
    goto :goto_0

    .line 1129
    :cond_4f
    const p0, 0x7f12132d

    .line 1130
    .line 1131
    .line 1132
    return p0

    .line 1133
    :sswitch_50
    const-string v0, "todo_detail_addcare_url_de"

    .line 1134
    .line 1135
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1136
    .line 1137
    .line 1138
    move-result p0

    .line 1139
    if-nez p0, :cond_50

    .line 1140
    .line 1141
    goto :goto_0

    .line 1142
    :cond_50
    const p0, 0x7f12132c

    .line 1143
    .line 1144
    .line 1145
    return p0

    .line 1146
    :sswitch_51
    const-string v0, "todo_detail_addcare_url_cz"

    .line 1147
    .line 1148
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1149
    .line 1150
    .line 1151
    move-result p0

    .line 1152
    if-nez p0, :cond_51

    .line 1153
    .line 1154
    goto :goto_0

    .line 1155
    :cond_51
    const p0, 0x7f12132b

    .line 1156
    .line 1157
    .line 1158
    return p0

    .line 1159
    :sswitch_52
    const-string v0, "todo_detail_addcare_url_ch"

    .line 1160
    .line 1161
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1162
    .line 1163
    .line 1164
    move-result p0

    .line 1165
    if-nez p0, :cond_52

    .line 1166
    .line 1167
    goto :goto_0

    .line 1168
    :cond_52
    const p0, 0x7f12132a

    .line 1169
    .line 1170
    .line 1171
    return p0

    .line 1172
    :sswitch_53
    const-string v0, "todo_detail_addcare_url_ba"

    .line 1173
    .line 1174
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1175
    .line 1176
    .line 1177
    move-result p0

    .line 1178
    if-nez p0, :cond_53

    .line 1179
    .line 1180
    goto :goto_0

    .line 1181
    :cond_53
    const p0, 0x7f121329

    .line 1182
    .line 1183
    .line 1184
    return p0

    .line 1185
    :sswitch_54
    const-string v0, "todo_detail_svc_maintenance_agreement_url_fi"

    .line 1186
    .line 1187
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1188
    .line 1189
    .line 1190
    move-result p0

    .line 1191
    if-nez p0, :cond_54

    .line 1192
    .line 1193
    goto :goto_0

    .line 1194
    :cond_54
    const p0, 0x7f121425

    .line 1195
    .line 1196
    .line 1197
    return p0

    .line 1198
    :sswitch_55
    const-string v0, "todo_detail_connectivity_url_general"

    .line 1199
    .line 1200
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1201
    .line 1202
    .line 1203
    move-result p0

    .line 1204
    if-nez p0, :cond_55

    .line 1205
    .line 1206
    :goto_0
    const p0, 0x7f1202bd

    .line 1207
    .line 1208
    .line 1209
    return p0

    .line 1210
    :cond_55
    const p0, 0x7f12137f

    .line 1211
    .line 1212
    .line 1213
    return p0

    .line 1214
    nop

    .line 1215
    :sswitch_data_0
    .sparse-switch
        -0x69ee303b -> :sswitch_55
        -0x67eaca38 -> :sswitch_54
        -0x665f3ecf -> :sswitch_53
        -0x665f3ea9 -> :sswitch_52
        -0x665f3e97 -> :sswitch_51
        -0x665f3e8d -> :sswitch_50
        -0x665f3e42 -> :sswitch_4f
        -0x665f3e33 -> :sswitch_4e
        -0x665f3d12 -> :sswitch_4d
        -0x665f3cb6 -> :sswitch_4c
        -0x665f3cb5 -> :sswitch_4b
        -0x5601e373 -> :sswitch_4a
        -0x5258c0e1 -> :sswitch_49
        -0x47143d8f -> :sswitch_48
        -0x2fc1ec89 -> :sswitch_47
        -0xf929c20 -> :sswitch_46
        -0xf929c16 -> :sswitch_45
        -0xf929c10 -> :sswitch_44
        -0xf929be9 -> :sswitch_43
        -0xf929bd4 -> :sswitch_42
        -0xf929b0e -> :sswitch_41
        -0xb7e03fd -> :sswitch_40
        0x4f92747 -> :sswitch_3f
        0x50b2249 -> :sswitch_3e
        0x53f555d -> :sswitch_3d
        0xed33572 -> :sswitch_3c
        0xed3364c -> :sswitch_3b
        0xed3369a -> :sswitch_3a
        0xed336a1 -> :sswitch_39
        0x11b75e61 -> :sswitch_38
        0x140001a7 -> :sswitch_37
        0x140001b7 -> :sswitch_36
        0x1400032c -> :sswitch_35
        0x14000334 -> :sswitch_34
        0x14000382 -> :sswitch_33
        0x15563d2b -> :sswitch_32
        0x15563d3b -> :sswitch_31
        0x15563d62 -> :sswitch_30
        0x15563e72 -> :sswitch_2f
        0x15563f06 -> :sswitch_2e
        0x1d27ba02 -> :sswitch_2d
        0x2413af36 -> :sswitch_2c
        0x2413af42 -> :sswitch_2b
        0x2413af7a -> :sswitch_2a
        0x2413af84 -> :sswitch_29
        0x2413af8a -> :sswitch_28
        0x2413afb1 -> :sswitch_27
        0x2413b01f -> :sswitch_26
        0x2413b0c1 -> :sswitch_25
        0x2413b0ff -> :sswitch_24
        0x2413b107 -> :sswitch_23
        0x2413b155 -> :sswitch_22
        0x2413b15b -> :sswitch_21
        0x2413b15c -> :sswitch_20
        0x2add9b36 -> :sswitch_1f
        0x2af46488 -> :sswitch_1e
        0x2af46492 -> :sswitch_1d
        0x2af46498 -> :sswitch_1c
        0x2af464bf -> :sswitch_1b
        0x2af464d4 -> :sswitch_1a
        0x2af464dd -> :sswitch_19
        0x2af4652d -> :sswitch_18
        0x2af4659a -> :sswitch_17
        0x2eae645b -> :sswitch_16
        0x31ac4c1e -> :sswitch_15
        0x31aee8b7 -> :sswitch_14
        0x375f7946 -> :sswitch_13
        0x3f92dc42 -> :sswitch_12
        0x45dafd52 -> :sswitch_11
        0x64a3a401 -> :sswitch_10
        0x6f0cbe3f -> :sswitch_f
        0x6fb6eb1f -> :sswitch_e
        0x71511f6f -> :sswitch_d
        0x71511f81 -> :sswitch_c
        0x71511f8b -> :sswitch_b
        0x71511f91 -> :sswitch_a
        0x71511fb8 -> :sswitch_9
        0x71511fd6 -> :sswitch_8
        0x71511fe5 -> :sswitch_7
        0x715120c8 -> :sswitch_6
        0x71512106 -> :sswitch_5
        0x7151215c -> :sswitch_4
        0x71512162 -> :sswitch_3
        0x71512163 -> :sswitch_2
        0x73b5d264 -> :sswitch_1
        0x73b5d2d1 -> :sswitch_0
    .end sparse-switch
.end method
