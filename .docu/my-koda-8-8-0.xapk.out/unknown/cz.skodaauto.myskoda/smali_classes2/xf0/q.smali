.class public abstract Lxf0/q;
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
    sput-object v0, Lxf0/q;->a:Lgy0/j;

    .line 11
    .line 12
    new-instance v0, Lgy0/j;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lxf0/q;->b:Lgy0/j;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZLjava/lang/Integer;Lay0/a;Lay0/a;Ll2/o;II)V
    .locals 35

    .line 1
    move/from16 v5, p4

    .line 2
    .line 3
    move-wide/from16 v6, p5

    .line 4
    .line 5
    move/from16 v8, p7

    .line 6
    .line 7
    move/from16 v9, p8

    .line 8
    .line 9
    move-object/from16 v0, p9

    .line 10
    .line 11
    move/from16 v1, p13

    .line 12
    .line 13
    move-object/from16 v12, p12

    .line 14
    .line 15
    check-cast v12, Ll2/t;

    .line 16
    .line 17
    const v2, -0x4674fec8

    .line 18
    .line 19
    .line 20
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v2, v1, 0x6

    .line 24
    .line 25
    const/4 v3, 0x4

    .line 26
    if-nez v2, :cond_1

    .line 27
    .line 28
    move-object/from16 v2, p0

    .line 29
    .line 30
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v10

    .line 34
    if-eqz v10, :cond_0

    .line 35
    .line 36
    move v10, v3

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v10, 0x2

    .line 39
    :goto_0
    or-int/2addr v10, v1

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move-object/from16 v2, p0

    .line 42
    .line 43
    move v10, v1

    .line 44
    :goto_1
    and-int/lit8 v11, v1, 0x30

    .line 45
    .line 46
    if-nez v11, :cond_3

    .line 47
    .line 48
    move-object/from16 v11, p1

    .line 49
    .line 50
    invoke-virtual {v12, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v13

    .line 54
    if-eqz v13, :cond_2

    .line 55
    .line 56
    const/16 v13, 0x20

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_2
    const/16 v13, 0x10

    .line 60
    .line 61
    :goto_2
    or-int/2addr v10, v13

    .line 62
    goto :goto_3

    .line 63
    :cond_3
    move-object/from16 v11, p1

    .line 64
    .line 65
    :goto_3
    and-int/lit16 v13, v1, 0x180

    .line 66
    .line 67
    if-nez v13, :cond_5

    .line 68
    .line 69
    move-object/from16 v13, p2

    .line 70
    .line 71
    invoke-virtual {v12, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v14

    .line 75
    if-eqz v14, :cond_4

    .line 76
    .line 77
    const/16 v14, 0x100

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_4
    const/16 v14, 0x80

    .line 81
    .line 82
    :goto_4
    or-int/2addr v10, v14

    .line 83
    goto :goto_5

    .line 84
    :cond_5
    move-object/from16 v13, p2

    .line 85
    .line 86
    :goto_5
    and-int/lit16 v14, v1, 0xc00

    .line 87
    .line 88
    if-nez v14, :cond_7

    .line 89
    .line 90
    move-object/from16 v14, p3

    .line 91
    .line 92
    invoke-virtual {v12, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v15

    .line 96
    if-eqz v15, :cond_6

    .line 97
    .line 98
    const/16 v15, 0x800

    .line 99
    .line 100
    goto :goto_6

    .line 101
    :cond_6
    const/16 v15, 0x400

    .line 102
    .line 103
    :goto_6
    or-int/2addr v10, v15

    .line 104
    goto :goto_7

    .line 105
    :cond_7
    move-object/from16 v14, p3

    .line 106
    .line 107
    :goto_7
    and-int/lit16 v15, v1, 0x6000

    .line 108
    .line 109
    if-nez v15, :cond_9

    .line 110
    .line 111
    invoke-virtual {v12, v5}, Ll2/t;->h(Z)Z

    .line 112
    .line 113
    .line 114
    move-result v15

    .line 115
    if-eqz v15, :cond_8

    .line 116
    .line 117
    const/16 v15, 0x4000

    .line 118
    .line 119
    goto :goto_8

    .line 120
    :cond_8
    const/16 v15, 0x2000

    .line 121
    .line 122
    :goto_8
    or-int/2addr v10, v15

    .line 123
    :cond_9
    const/high16 v15, 0x30000

    .line 124
    .line 125
    and-int/2addr v15, v1

    .line 126
    if-nez v15, :cond_b

    .line 127
    .line 128
    invoke-virtual {v12, v6, v7}, Ll2/t;->f(J)Z

    .line 129
    .line 130
    .line 131
    move-result v15

    .line 132
    if-eqz v15, :cond_a

    .line 133
    .line 134
    const/high16 v15, 0x20000

    .line 135
    .line 136
    goto :goto_9

    .line 137
    :cond_a
    const/high16 v15, 0x10000

    .line 138
    .line 139
    :goto_9
    or-int/2addr v10, v15

    .line 140
    :cond_b
    const/high16 v15, 0x180000

    .line 141
    .line 142
    and-int/2addr v15, v1

    .line 143
    if-nez v15, :cond_d

    .line 144
    .line 145
    invoke-virtual {v12, v8}, Ll2/t;->h(Z)Z

    .line 146
    .line 147
    .line 148
    move-result v15

    .line 149
    if-eqz v15, :cond_c

    .line 150
    .line 151
    const/high16 v15, 0x100000

    .line 152
    .line 153
    goto :goto_a

    .line 154
    :cond_c
    const/high16 v15, 0x80000

    .line 155
    .line 156
    :goto_a
    or-int/2addr v10, v15

    .line 157
    :cond_d
    const/high16 v15, 0xc00000

    .line 158
    .line 159
    and-int/2addr v15, v1

    .line 160
    if-nez v15, :cond_f

    .line 161
    .line 162
    invoke-virtual {v12, v9}, Ll2/t;->h(Z)Z

    .line 163
    .line 164
    .line 165
    move-result v15

    .line 166
    if-eqz v15, :cond_e

    .line 167
    .line 168
    const/high16 v15, 0x800000

    .line 169
    .line 170
    goto :goto_b

    .line 171
    :cond_e
    const/high16 v15, 0x400000

    .line 172
    .line 173
    :goto_b
    or-int/2addr v10, v15

    .line 174
    :cond_f
    const/high16 v15, 0x6000000

    .line 175
    .line 176
    and-int/2addr v15, v1

    .line 177
    if-nez v15, :cond_11

    .line 178
    .line 179
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v15

    .line 183
    if-eqz v15, :cond_10

    .line 184
    .line 185
    const/high16 v15, 0x4000000

    .line 186
    .line 187
    goto :goto_c

    .line 188
    :cond_10
    const/high16 v15, 0x2000000

    .line 189
    .line 190
    :goto_c
    or-int/2addr v10, v15

    .line 191
    :cond_11
    const/high16 v15, 0x30000000

    .line 192
    .line 193
    and-int/2addr v15, v1

    .line 194
    if-nez v15, :cond_13

    .line 195
    .line 196
    move-object/from16 v15, p10

    .line 197
    .line 198
    invoke-virtual {v12, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result v16

    .line 202
    if-eqz v16, :cond_12

    .line 203
    .line 204
    const/high16 v16, 0x20000000

    .line 205
    .line 206
    goto :goto_d

    .line 207
    :cond_12
    const/high16 v16, 0x10000000

    .line 208
    .line 209
    :goto_d
    or-int v10, v10, v16

    .line 210
    .line 211
    :goto_e
    move/from16 v32, v10

    .line 212
    .line 213
    goto :goto_f

    .line 214
    :cond_13
    move-object/from16 v15, p10

    .line 215
    .line 216
    goto :goto_e

    .line 217
    :goto_f
    and-int/lit8 v10, p14, 0x6

    .line 218
    .line 219
    if-nez v10, :cond_15

    .line 220
    .line 221
    move-object/from16 v10, p11

    .line 222
    .line 223
    invoke-virtual {v12, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v16

    .line 227
    if-eqz v16, :cond_14

    .line 228
    .line 229
    goto :goto_10

    .line 230
    :cond_14
    const/4 v3, 0x2

    .line 231
    :goto_10
    or-int v3, p14, v3

    .line 232
    .line 233
    goto :goto_11

    .line 234
    :cond_15
    move-object/from16 v10, p11

    .line 235
    .line 236
    move/from16 v3, p14

    .line 237
    .line 238
    :goto_11
    const v16, 0x12492493

    .line 239
    .line 240
    .line 241
    and-int v4, v32, v16

    .line 242
    .line 243
    const v0, 0x12492492

    .line 244
    .line 245
    .line 246
    if-ne v4, v0, :cond_17

    .line 247
    .line 248
    and-int/lit8 v0, v3, 0x3

    .line 249
    .line 250
    const/4 v4, 0x2

    .line 251
    if-eq v0, v4, :cond_16

    .line 252
    .line 253
    goto :goto_12

    .line 254
    :cond_16
    const/4 v0, 0x0

    .line 255
    goto :goto_13

    .line 256
    :cond_17
    :goto_12
    const/4 v0, 0x1

    .line 257
    :goto_13
    and-int/lit8 v4, v32, 0x1

    .line 258
    .line 259
    invoke-virtual {v12, v4, v0}, Ll2/t;->O(IZ)Z

    .line 260
    .line 261
    .line 262
    move-result v0

    .line 263
    if-eqz v0, :cond_2b

    .line 264
    .line 265
    sget-object v0, Lx2/c;->n:Lx2/i;

    .line 266
    .line 267
    sget-object v4, Lk1/j;->a:Lk1/c;

    .line 268
    .line 269
    const/16 v11, 0x30

    .line 270
    .line 271
    invoke-static {v4, v0, v12, v11}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 272
    .line 273
    .line 274
    move-result-object v4

    .line 275
    iget-wide v1, v12, Ll2/t;->T:J

    .line 276
    .line 277
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 282
    .line 283
    .line 284
    move-result-object v2

    .line 285
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 286
    .line 287
    move/from16 v33, v3

    .line 288
    .line 289
    invoke-static {v12, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 290
    .line 291
    .line 292
    move-result-object v3

    .line 293
    sget-object v17, Lv3/k;->m1:Lv3/j;

    .line 294
    .line 295
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 296
    .line 297
    .line 298
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 299
    .line 300
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 301
    .line 302
    .line 303
    iget-boolean v5, v12, Ll2/t;->S:Z

    .line 304
    .line 305
    if-eqz v5, :cond_18

    .line 306
    .line 307
    invoke-virtual {v12, v13}, Ll2/t;->l(Lay0/a;)V

    .line 308
    .line 309
    .line 310
    goto :goto_14

    .line 311
    :cond_18
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 312
    .line 313
    .line 314
    :goto_14
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 315
    .line 316
    invoke-static {v5, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 317
    .line 318
    .line 319
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 320
    .line 321
    invoke-static {v4, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 322
    .line 323
    .line 324
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 325
    .line 326
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 327
    .line 328
    if-nez v8, :cond_19

    .line 329
    .line 330
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v8

    .line 334
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 335
    .line 336
    .line 337
    move-result-object v9

    .line 338
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 339
    .line 340
    .line 341
    move-result v8

    .line 342
    if-nez v8, :cond_1a

    .line 343
    .line 344
    :cond_19
    invoke-static {v1, v12, v1, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 345
    .line 346
    .line 347
    :cond_1a
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 348
    .line 349
    invoke-static {v1, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 350
    .line 351
    .line 352
    if-nez p9, :cond_1b

    .line 353
    .line 354
    const v3, 0x43e42304

    .line 355
    .line 356
    .line 357
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 358
    .line 359
    .line 360
    const/4 v3, 0x0

    .line 361
    invoke-virtual {v12, v3}, Ll2/t;->q(Z)V

    .line 362
    .line 363
    .line 364
    move v9, v3

    .line 365
    move-object v8, v11

    .line 366
    move-object v3, v13

    .line 367
    goto :goto_15

    .line 368
    :cond_1b
    const/4 v3, 0x0

    .line 369
    const v8, 0x43e42305

    .line 370
    .line 371
    .line 372
    invoke-virtual {v12, v8}, Ll2/t;->Y(I)V

    .line 373
    .line 374
    .line 375
    const/16 v8, 0x18

    .line 376
    .line 377
    int-to-float v8, v8

    .line 378
    invoke-static {v11, v8}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 379
    .line 380
    .line 381
    move-result-object v8

    .line 382
    const-string v9, "battery_gauge_bolt"

    .line 383
    .line 384
    invoke-static {v8, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 385
    .line 386
    .line 387
    move-result-object v8

    .line 388
    invoke-virtual/range {p9 .. p9}, Ljava/lang/Integer;->intValue()I

    .line 389
    .line 390
    .line 391
    move-result v9

    .line 392
    shr-int/lit8 v17, v32, 0x18

    .line 393
    .line 394
    and-int/lit8 v3, v17, 0xe

    .line 395
    .line 396
    invoke-static {v9, v3, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 397
    .line 398
    .line 399
    move-result-object v3

    .line 400
    new-instance v9, Le3/m;

    .line 401
    .line 402
    move-object/from16 v17, v3

    .line 403
    .line 404
    const/4 v3, 0x5

    .line 405
    invoke-direct {v9, v6, v7, v3}, Le3/m;-><init>(JI)V

    .line 406
    .line 407
    .line 408
    const/16 v18, 0x1b0

    .line 409
    .line 410
    const/16 v19, 0x38

    .line 411
    .line 412
    move-object v3, v11

    .line 413
    const/4 v11, 0x0

    .line 414
    move-object/from16 v20, v13

    .line 415
    .line 416
    const/4 v13, 0x0

    .line 417
    const/4 v14, 0x0

    .line 418
    const/4 v15, 0x0

    .line 419
    move-object/from16 v16, v9

    .line 420
    .line 421
    move-object/from16 v10, v17

    .line 422
    .line 423
    const/4 v9, 0x0

    .line 424
    move-object/from16 v17, v12

    .line 425
    .line 426
    move-object v12, v8

    .line 427
    move-object v8, v3

    .line 428
    move-object/from16 v3, v20

    .line 429
    .line 430
    invoke-static/range {v10 .. v19}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 431
    .line 432
    .line 433
    move-object/from16 v12, v17

    .line 434
    .line 435
    sget-object v10, Lj91/a;->a:Ll2/u2;

    .line 436
    .line 437
    invoke-virtual {v12, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    move-result-object v10

    .line 441
    check-cast v10, Lj91/c;

    .line 442
    .line 443
    iget v10, v10, Lj91/c;->b:F

    .line 444
    .line 445
    invoke-static {v8, v10}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 446
    .line 447
    .line 448
    move-result-object v10

    .line 449
    invoke-static {v12, v10}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 450
    .line 451
    .line 452
    invoke-virtual {v12, v9}, Ll2/t;->q(Z)V

    .line 453
    .line 454
    .line 455
    :goto_15
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 456
    .line 457
    .line 458
    move-result-object v10

    .line 459
    invoke-virtual {v10}, Lj91/f;->a()Lg4/p0;

    .line 460
    .line 461
    .line 462
    move-result-object v11

    .line 463
    if-eqz p4, :cond_1c

    .line 464
    .line 465
    const v10, -0x58a5cb95

    .line 466
    .line 467
    .line 468
    invoke-virtual {v12, v10}, Ll2/t;->Y(I)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {v12, v9}, Ll2/t;->q(Z)V

    .line 472
    .line 473
    .line 474
    move-wide v13, v6

    .line 475
    goto :goto_16

    .line 476
    :cond_1c
    const v10, -0x58a5c6d6

    .line 477
    .line 478
    .line 479
    invoke-virtual {v12, v10}, Ll2/t;->Y(I)V

    .line 480
    .line 481
    .line 482
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 483
    .line 484
    .line 485
    move-result-object v10

    .line 486
    invoke-virtual {v10}, Lj91/e;->r()J

    .line 487
    .line 488
    .line 489
    move-result-wide v13

    .line 490
    invoke-virtual {v12, v9}, Ll2/t;->q(Z)V

    .line 491
    .line 492
    .line 493
    :goto_16
    const-string v10, "battery_gauge_title"

    .line 494
    .line 495
    invoke-static {v8, v10}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 496
    .line 497
    .line 498
    move-result-object v10

    .line 499
    and-int/lit8 v15, v32, 0xe

    .line 500
    .line 501
    or-int/lit16 v15, v15, 0x180

    .line 502
    .line 503
    const/16 v30, 0x0

    .line 504
    .line 505
    const v31, 0xfff0

    .line 506
    .line 507
    .line 508
    move/from16 v29, v15

    .line 509
    .line 510
    const-wide/16 v15, 0x0

    .line 511
    .line 512
    const/16 v17, 0x0

    .line 513
    .line 514
    const-wide/16 v18, 0x0

    .line 515
    .line 516
    const/16 v20, 0x0

    .line 517
    .line 518
    const/16 v21, 0x0

    .line 519
    .line 520
    const-wide/16 v22, 0x0

    .line 521
    .line 522
    const/16 v24, 0x0

    .line 523
    .line 524
    const/16 v25, 0x0

    .line 525
    .line 526
    const/16 v26, 0x0

    .line 527
    .line 528
    const/16 v27, 0x0

    .line 529
    .line 530
    move-object/from16 v28, v12

    .line 531
    .line 532
    move-object v12, v10

    .line 533
    move-object/from16 v10, p0

    .line 534
    .line 535
    invoke-static/range {v10 .. v31}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 536
    .line 537
    .line 538
    move-object/from16 v15, v28

    .line 539
    .line 540
    const/4 v10, 0x1

    .line 541
    invoke-virtual {v15, v10}, Ll2/t;->q(Z)V

    .line 542
    .line 543
    .line 544
    const/high16 v10, 0x3f800000    # 1.0f

    .line 545
    .line 546
    invoke-static {v8, v10}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 547
    .line 548
    .line 549
    move-result-object v11

    .line 550
    sget-object v12, Lk1/j;->g:Lk1/f;

    .line 551
    .line 552
    const/16 v13, 0x36

    .line 553
    .line 554
    invoke-static {v12, v0, v15, v13}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 555
    .line 556
    .line 557
    move-result-object v0

    .line 558
    iget-wide v12, v15, Ll2/t;->T:J

    .line 559
    .line 560
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 561
    .line 562
    .line 563
    move-result v12

    .line 564
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 565
    .line 566
    .line 567
    move-result-object v13

    .line 568
    invoke-static {v15, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 569
    .line 570
    .line 571
    move-result-object v11

    .line 572
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 573
    .line 574
    .line 575
    iget-boolean v14, v15, Ll2/t;->S:Z

    .line 576
    .line 577
    if-eqz v14, :cond_1d

    .line 578
    .line 579
    invoke-virtual {v15, v3}, Ll2/t;->l(Lay0/a;)V

    .line 580
    .line 581
    .line 582
    goto :goto_17

    .line 583
    :cond_1d
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 584
    .line 585
    .line 586
    :goto_17
    invoke-static {v5, v0, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 587
    .line 588
    .line 589
    invoke-static {v4, v13, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 590
    .line 591
    .line 592
    iget-boolean v0, v15, Ll2/t;->S:Z

    .line 593
    .line 594
    if-nez v0, :cond_1e

    .line 595
    .line 596
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 597
    .line 598
    .line 599
    move-result-object v0

    .line 600
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 601
    .line 602
    .line 603
    move-result-object v13

    .line 604
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 605
    .line 606
    .line 607
    move-result v0

    .line 608
    if-nez v0, :cond_1f

    .line 609
    .line 610
    :cond_1e
    invoke-static {v12, v15, v12, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 611
    .line 612
    .line 613
    :cond_1f
    invoke-static {v1, v11, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 614
    .line 615
    .line 616
    invoke-static {v15}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 617
    .line 618
    .line 619
    move-result-object v0

    .line 620
    iget v0, v0, Lj91/c;->e:F

    .line 621
    .line 622
    const/16 v21, 0x0

    .line 623
    .line 624
    const/16 v22, 0xe

    .line 625
    .line 626
    const/16 v19, 0x0

    .line 627
    .line 628
    const/16 v20, 0x0

    .line 629
    .line 630
    move/from16 v18, v0

    .line 631
    .line 632
    move-object/from16 v17, v8

    .line 633
    .line 634
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    const/16 v11, 0x40

    .line 639
    .line 640
    int-to-float v11, v11

    .line 641
    invoke-static {v0, v11}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 642
    .line 643
    .line 644
    move-result-object v0

    .line 645
    const/16 v31, 0x0

    .line 646
    .line 647
    if-eqz p8, :cond_20

    .line 648
    .line 649
    move v12, v10

    .line 650
    goto :goto_18

    .line 651
    :cond_20
    move/from16 v12, v31

    .line 652
    .line 653
    :goto_18
    invoke-static {v0, v12}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 654
    .line 655
    .line 656
    move-result-object v0

    .line 657
    new-instance v12, Ld4/i;

    .line 658
    .line 659
    invoke-direct {v12, v9}, Ld4/i;-><init>(I)V

    .line 660
    .line 661
    .line 662
    const/16 v14, 0xa

    .line 663
    .line 664
    move v13, v11

    .line 665
    const/4 v11, 0x0

    .line 666
    move/from16 v10, p8

    .line 667
    .line 668
    move v6, v9

    .line 669
    move-object v9, v0

    .line 670
    move v0, v13

    .line 671
    move-object/from16 v13, p11

    .line 672
    .line 673
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 674
    .line 675
    .line 676
    move-result-object v7

    .line 677
    sget-object v9, Lx2/c;->h:Lx2/j;

    .line 678
    .line 679
    invoke-static {v9, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 680
    .line 681
    .line 682
    move-result-object v10

    .line 683
    iget-wide v11, v15, Ll2/t;->T:J

    .line 684
    .line 685
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 686
    .line 687
    .line 688
    move-result v11

    .line 689
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 690
    .line 691
    .line 692
    move-result-object v12

    .line 693
    invoke-static {v15, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 694
    .line 695
    .line 696
    move-result-object v7

    .line 697
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 698
    .line 699
    .line 700
    iget-boolean v13, v15, Ll2/t;->S:Z

    .line 701
    .line 702
    if-eqz v13, :cond_21

    .line 703
    .line 704
    invoke-virtual {v15, v3}, Ll2/t;->l(Lay0/a;)V

    .line 705
    .line 706
    .line 707
    goto :goto_19

    .line 708
    :cond_21
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 709
    .line 710
    .line 711
    :goto_19
    invoke-static {v5, v10, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 712
    .line 713
    .line 714
    invoke-static {v4, v12, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 715
    .line 716
    .line 717
    iget-boolean v10, v15, Ll2/t;->S:Z

    .line 718
    .line 719
    if-nez v10, :cond_22

    .line 720
    .line 721
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 722
    .line 723
    .line 724
    move-result-object v10

    .line 725
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 726
    .line 727
    .line 728
    move-result-object v12

    .line 729
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 730
    .line 731
    .line 732
    move-result v10

    .line 733
    if-nez v10, :cond_23

    .line 734
    .line 735
    :cond_22
    invoke-static {v11, v15, v11, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 736
    .line 737
    .line 738
    :cond_23
    invoke-static {v1, v7, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 739
    .line 740
    .line 741
    const/16 v7, 0x1a

    .line 742
    .line 743
    int-to-float v7, v7

    .line 744
    invoke-static {v8, v7}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 745
    .line 746
    .line 747
    move-result-object v10

    .line 748
    const-string v11, "minus_button"

    .line 749
    .line 750
    invoke-static {v10, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 751
    .line 752
    .line 753
    move-result-object v14

    .line 754
    shl-int/lit8 v10, v33, 0x3

    .line 755
    .line 756
    and-int/lit8 v10, v10, 0x70

    .line 757
    .line 758
    or-int/lit16 v10, v10, 0x180

    .line 759
    .line 760
    shr-int/lit8 v11, v32, 0xc

    .line 761
    .line 762
    and-int/lit16 v11, v11, 0x1c00

    .line 763
    .line 764
    or-int/2addr v10, v11

    .line 765
    const/4 v11, 0x0

    .line 766
    move-object v12, v9

    .line 767
    const v9, 0x7f080426

    .line 768
    .line 769
    .line 770
    move-object/from16 v34, v12

    .line 771
    .line 772
    move-object v13, v15

    .line 773
    move/from16 v15, p8

    .line 774
    .line 775
    move-object/from16 v12, p11

    .line 776
    .line 777
    invoke-static/range {v9 .. v15}, Li91/j0;->j0(IIILay0/a;Ll2/o;Lx2/s;Z)V

    .line 778
    .line 779
    .line 780
    move-object v12, v13

    .line 781
    const/4 v9, 0x1

    .line 782
    invoke-virtual {v12, v9}, Ll2/t;->q(Z)V

    .line 783
    .line 784
    .line 785
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 786
    .line 787
    .line 788
    move-result-object v10

    .line 789
    invoke-virtual {v10}, Lj91/f;->h()Lg4/p0;

    .line 790
    .line 791
    .line 792
    move-result-object v10

    .line 793
    if-eqz p4, :cond_24

    .line 794
    .line 795
    const v11, -0x2e9f7b9e

    .line 796
    .line 797
    .line 798
    invoke-virtual {v12, v11}, Ll2/t;->Y(I)V

    .line 799
    .line 800
    .line 801
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 802
    .line 803
    .line 804
    move-wide/from16 v13, p5

    .line 805
    .line 806
    goto :goto_1a

    .line 807
    :cond_24
    const v11, -0x2e9f76df

    .line 808
    .line 809
    .line 810
    invoke-virtual {v12, v11}, Ll2/t;->Y(I)V

    .line 811
    .line 812
    .line 813
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 814
    .line 815
    .line 816
    move-result-object v11

    .line 817
    invoke-virtual {v11}, Lj91/e;->r()J

    .line 818
    .line 819
    .line 820
    move-result-wide v13

    .line 821
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 822
    .line 823
    .line 824
    :goto_1a
    const-string v11, "battery_gauge_charge"

    .line 825
    .line 826
    invoke-static {v8, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 827
    .line 828
    .line 829
    move-result-object v11

    .line 830
    shr-int/lit8 v15, v32, 0x3

    .line 831
    .line 832
    and-int/lit8 v15, v15, 0xe

    .line 833
    .line 834
    or-int/lit16 v15, v15, 0x180

    .line 835
    .line 836
    const/16 v29, 0x0

    .line 837
    .line 838
    const v30, 0xfff0

    .line 839
    .line 840
    .line 841
    move-object/from16 v26, v12

    .line 842
    .line 843
    move-wide v12, v13

    .line 844
    move/from16 v28, v15

    .line 845
    .line 846
    const-wide/16 v14, 0x0

    .line 847
    .line 848
    const/16 v16, 0x0

    .line 849
    .line 850
    const-wide/16 v17, 0x0

    .line 851
    .line 852
    const/16 v19, 0x0

    .line 853
    .line 854
    const/16 v20, 0x0

    .line 855
    .line 856
    const-wide/16 v21, 0x0

    .line 857
    .line 858
    const/16 v23, 0x0

    .line 859
    .line 860
    const/16 v24, 0x0

    .line 861
    .line 862
    const/16 v25, 0x0

    .line 863
    .line 864
    move-object/from16 v27, v26

    .line 865
    .line 866
    const/16 v26, 0x0

    .line 867
    .line 868
    move/from16 v33, v9

    .line 869
    .line 870
    move-object/from16 v9, p1

    .line 871
    .line 872
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 873
    .line 874
    .line 875
    move-object/from16 v15, v27

    .line 876
    .line 877
    invoke-static {v15}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 878
    .line 879
    .line 880
    move-result-object v9

    .line 881
    iget v9, v9, Lj91/c;->e:F

    .line 882
    .line 883
    const/16 v21, 0x0

    .line 884
    .line 885
    const/16 v22, 0xb

    .line 886
    .line 887
    const/16 v18, 0x0

    .line 888
    .line 889
    const/16 v19, 0x0

    .line 890
    .line 891
    move-object/from16 v17, v8

    .line 892
    .line 893
    move/from16 v20, v9

    .line 894
    .line 895
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 896
    .line 897
    .line 898
    move-result-object v8

    .line 899
    move-object/from16 v14, v17

    .line 900
    .line 901
    invoke-static {v8, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 902
    .line 903
    .line 904
    move-result-object v8

    .line 905
    new-instance v11, Ld4/i;

    .line 906
    .line 907
    invoke-direct {v11, v6}, Ld4/i;-><init>(I)V

    .line 908
    .line 909
    .line 910
    const/16 v13, 0xa

    .line 911
    .line 912
    const/4 v10, 0x0

    .line 913
    move/from16 v9, p7

    .line 914
    .line 915
    move-object/from16 v12, p10

    .line 916
    .line 917
    move/from16 v0, v33

    .line 918
    .line 919
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 920
    .line 921
    .line 922
    move-result-object v8

    .line 923
    if-eqz p7, :cond_25

    .line 924
    .line 925
    const/high16 v10, 0x3f800000    # 1.0f

    .line 926
    .line 927
    goto :goto_1b

    .line 928
    :cond_25
    move/from16 v10, v31

    .line 929
    .line 930
    :goto_1b
    invoke-static {v8, v10}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 931
    .line 932
    .line 933
    move-result-object v8

    .line 934
    move-object/from16 v12, v34

    .line 935
    .line 936
    invoke-static {v12, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 937
    .line 938
    .line 939
    move-result-object v9

    .line 940
    iget-wide v10, v15, Ll2/t;->T:J

    .line 941
    .line 942
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 943
    .line 944
    .line 945
    move-result v10

    .line 946
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 947
    .line 948
    .line 949
    move-result-object v11

    .line 950
    invoke-static {v15, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 951
    .line 952
    .line 953
    move-result-object v8

    .line 954
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 955
    .line 956
    .line 957
    iget-boolean v12, v15, Ll2/t;->S:Z

    .line 958
    .line 959
    if-eqz v12, :cond_26

    .line 960
    .line 961
    invoke-virtual {v15, v3}, Ll2/t;->l(Lay0/a;)V

    .line 962
    .line 963
    .line 964
    goto :goto_1c

    .line 965
    :cond_26
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 966
    .line 967
    .line 968
    :goto_1c
    invoke-static {v5, v9, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 969
    .line 970
    .line 971
    invoke-static {v4, v11, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 972
    .line 973
    .line 974
    iget-boolean v3, v15, Ll2/t;->S:Z

    .line 975
    .line 976
    if-nez v3, :cond_27

    .line 977
    .line 978
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 979
    .line 980
    .line 981
    move-result-object v3

    .line 982
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 983
    .line 984
    .line 985
    move-result-object v4

    .line 986
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 987
    .line 988
    .line 989
    move-result v3

    .line 990
    if-nez v3, :cond_28

    .line 991
    .line 992
    :cond_27
    invoke-static {v10, v15, v10, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 993
    .line 994
    .line 995
    :cond_28
    invoke-static {v1, v8, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 996
    .line 997
    .line 998
    invoke-static {v14, v7}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 999
    .line 1000
    .line 1001
    move-result-object v1

    .line 1002
    const-string v2, "plus_button"

    .line 1003
    .line 1004
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v13

    .line 1008
    shr-int/lit8 v1, v32, 0x18

    .line 1009
    .line 1010
    and-int/lit8 v1, v1, 0x70

    .line 1011
    .line 1012
    or-int/lit16 v1, v1, 0x180

    .line 1013
    .line 1014
    shr-int/lit8 v2, v32, 0x9

    .line 1015
    .line 1016
    and-int/lit16 v3, v2, 0x1c00

    .line 1017
    .line 1018
    or-int v9, v1, v3

    .line 1019
    .line 1020
    const/4 v10, 0x0

    .line 1021
    const v8, 0x7f080466

    .line 1022
    .line 1023
    .line 1024
    move-object/from16 v11, p10

    .line 1025
    .line 1026
    move-object v3, v14

    .line 1027
    move-object v12, v15

    .line 1028
    move/from16 v14, p7

    .line 1029
    .line 1030
    invoke-static/range {v8 .. v14}, Li91/j0;->j0(IIILay0/a;Ll2/o;Lx2/s;Z)V

    .line 1031
    .line 1032
    .line 1033
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 1034
    .line 1035
    .line 1036
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 1037
    .line 1038
    .line 1039
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v0

    .line 1043
    iget v0, v0, Lj91/c;->b:F

    .line 1044
    .line 1045
    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v0

    .line 1049
    invoke-static {v12, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1050
    .line 1051
    .line 1052
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v0

    .line 1056
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v9

    .line 1060
    if-eqz p4, :cond_29

    .line 1061
    .line 1062
    const v0, -0x7d2eed9d

    .line 1063
    .line 1064
    .line 1065
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 1066
    .line 1067
    .line 1068
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v0

    .line 1072
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 1073
    .line 1074
    .line 1075
    move-result-wide v0

    .line 1076
    :goto_1d
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 1077
    .line 1078
    .line 1079
    goto :goto_1e

    .line 1080
    :cond_29
    const v0, -0x7d2ee95a

    .line 1081
    .line 1082
    .line 1083
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 1084
    .line 1085
    .line 1086
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v0

    .line 1090
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 1091
    .line 1092
    .line 1093
    move-result-wide v0

    .line 1094
    goto :goto_1d

    .line 1095
    :goto_1e
    const-string v4, "battery_gauge_range_title"

    .line 1096
    .line 1097
    invoke-static {v3, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v10

    .line 1101
    shr-int/lit8 v4, v32, 0x6

    .line 1102
    .line 1103
    and-int/lit8 v4, v4, 0xe

    .line 1104
    .line 1105
    or-int/lit16 v4, v4, 0x180

    .line 1106
    .line 1107
    const/16 v28, 0x0

    .line 1108
    .line 1109
    const v29, 0xfff0

    .line 1110
    .line 1111
    .line 1112
    const-wide/16 v13, 0x0

    .line 1113
    .line 1114
    const/4 v15, 0x0

    .line 1115
    const-wide/16 v16, 0x0

    .line 1116
    .line 1117
    const/16 v18, 0x0

    .line 1118
    .line 1119
    const/16 v19, 0x0

    .line 1120
    .line 1121
    const-wide/16 v20, 0x0

    .line 1122
    .line 1123
    const/16 v22, 0x0

    .line 1124
    .line 1125
    const/16 v23, 0x0

    .line 1126
    .line 1127
    const/16 v24, 0x0

    .line 1128
    .line 1129
    const/16 v25, 0x0

    .line 1130
    .line 1131
    move-object/from16 v8, p2

    .line 1132
    .line 1133
    move/from16 v27, v4

    .line 1134
    .line 1135
    move-object/from16 v26, v12

    .line 1136
    .line 1137
    move-wide v11, v0

    .line 1138
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1139
    .line 1140
    .line 1141
    move-object/from16 v12, v26

    .line 1142
    .line 1143
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v0

    .line 1147
    iget v0, v0, Lj91/c;->c:F

    .line 1148
    .line 1149
    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 1150
    .line 1151
    .line 1152
    move-result-object v0

    .line 1153
    invoke-static {v12, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1154
    .line 1155
    .line 1156
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v0

    .line 1160
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 1161
    .line 1162
    .line 1163
    move-result-object v9

    .line 1164
    if-eqz p4, :cond_2a

    .line 1165
    .line 1166
    const v0, -0x7d2ec55d

    .line 1167
    .line 1168
    .line 1169
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 1170
    .line 1171
    .line 1172
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1173
    .line 1174
    .line 1175
    move-result-object v0

    .line 1176
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 1177
    .line 1178
    .line 1179
    move-result-wide v0

    .line 1180
    :goto_1f
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 1181
    .line 1182
    .line 1183
    goto :goto_20

    .line 1184
    :cond_2a
    const v0, -0x7d2ec11a

    .line 1185
    .line 1186
    .line 1187
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 1188
    .line 1189
    .line 1190
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1191
    .line 1192
    .line 1193
    move-result-object v0

    .line 1194
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 1195
    .line 1196
    .line 1197
    move-result-wide v0

    .line 1198
    goto :goto_1f

    .line 1199
    :goto_20
    const-string v4, "battery_gauge_range"

    .line 1200
    .line 1201
    invoke-static {v3, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1202
    .line 1203
    .line 1204
    move-result-object v10

    .line 1205
    and-int/lit8 v2, v2, 0xe

    .line 1206
    .line 1207
    or-int/lit16 v2, v2, 0x180

    .line 1208
    .line 1209
    const/16 v28, 0x0

    .line 1210
    .line 1211
    const v29, 0xfff0

    .line 1212
    .line 1213
    .line 1214
    const-wide/16 v13, 0x0

    .line 1215
    .line 1216
    const/4 v15, 0x0

    .line 1217
    const-wide/16 v16, 0x0

    .line 1218
    .line 1219
    const/16 v18, 0x0

    .line 1220
    .line 1221
    const/16 v19, 0x0

    .line 1222
    .line 1223
    const-wide/16 v20, 0x0

    .line 1224
    .line 1225
    const/16 v22, 0x0

    .line 1226
    .line 1227
    const/16 v23, 0x0

    .line 1228
    .line 1229
    const/16 v24, 0x0

    .line 1230
    .line 1231
    const/16 v25, 0x0

    .line 1232
    .line 1233
    move-object/from16 v8, p3

    .line 1234
    .line 1235
    move/from16 v27, v2

    .line 1236
    .line 1237
    move-object/from16 v26, v12

    .line 1238
    .line 1239
    move-wide v11, v0

    .line 1240
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1241
    .line 1242
    .line 1243
    move-object/from16 v12, v26

    .line 1244
    .line 1245
    goto :goto_21

    .line 1246
    :cond_2b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 1247
    .line 1248
    .line 1249
    :goto_21
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 1250
    .line 1251
    .line 1252
    move-result-object v15

    .line 1253
    if-eqz v15, :cond_2c

    .line 1254
    .line 1255
    new-instance v0, Lxf0/p;

    .line 1256
    .line 1257
    move-object/from16 v1, p0

    .line 1258
    .line 1259
    move-object/from16 v2, p1

    .line 1260
    .line 1261
    move-object/from16 v3, p2

    .line 1262
    .line 1263
    move-object/from16 v4, p3

    .line 1264
    .line 1265
    move/from16 v5, p4

    .line 1266
    .line 1267
    move-wide/from16 v6, p5

    .line 1268
    .line 1269
    move/from16 v8, p7

    .line 1270
    .line 1271
    move/from16 v9, p8

    .line 1272
    .line 1273
    move-object/from16 v10, p9

    .line 1274
    .line 1275
    move-object/from16 v11, p10

    .line 1276
    .line 1277
    move-object/from16 v12, p11

    .line 1278
    .line 1279
    move/from16 v13, p13

    .line 1280
    .line 1281
    move/from16 v14, p14

    .line 1282
    .line 1283
    invoke-direct/range {v0 .. v14}, Lxf0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZLjava/lang/Integer;Lay0/a;Lay0/a;II)V

    .line 1284
    .line 1285
    .line 1286
    iput-object v0, v15, Ll2/u1;->d:Lay0/n;

    .line 1287
    .line 1288
    :cond_2c
    return-void
.end method

.method public static final b(Lx2/s;IIIILgy0/j;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLay0/a;Lay0/a;ZLl2/o;III)V
    .locals 64

    move-object/from16 v1, p0

    move/from16 v0, p19

    move/from16 v2, p20

    move/from16 v3, p21

    .line 1
    move-object/from16 v4, p18

    check-cast v4, Ll2/t;

    const v5, -0x771909d5

    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v5, v0, 0x6

    if-nez v5, :cond_1

    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v0

    goto :goto_1

    :cond_1
    move v5, v0

    :goto_1
    and-int/lit8 v8, v0, 0x30

    if-nez v8, :cond_4

    and-int/lit8 v8, v3, 0x2

    if-nez v8, :cond_2

    move/from16 v8, p1

    invoke-virtual {v4, v8}, Ll2/t;->e(I)Z

    move-result v11

    if-eqz v11, :cond_3

    const/16 v11, 0x20

    goto :goto_2

    :cond_2
    move/from16 v8, p1

    :cond_3
    const/16 v11, 0x10

    :goto_2
    or-int/2addr v5, v11

    goto :goto_3

    :cond_4
    move/from16 v8, p1

    :goto_3
    and-int/lit8 v11, v3, 0x4

    if-eqz v11, :cond_6

    or-int/lit16 v5, v5, 0x180

    :cond_5
    move/from16 v14, p2

    goto :goto_5

    :cond_6
    and-int/lit16 v14, v0, 0x180

    if-nez v14, :cond_5

    move/from16 v14, p2

    invoke-virtual {v4, v14}, Ll2/t;->e(I)Z

    move-result v15

    if-eqz v15, :cond_7

    const/16 v15, 0x100

    goto :goto_4

    :cond_7
    const/16 v15, 0x80

    :goto_4
    or-int/2addr v5, v15

    :goto_5
    and-int/lit8 v15, v3, 0x8

    const/16 v16, 0x400

    if-eqz v15, :cond_8

    or-int/lit16 v5, v5, 0xc00

    move/from16 v10, p3

    const/16 v17, 0x20

    goto :goto_7

    :cond_8
    const/16 v17, 0x20

    and-int/lit16 v10, v0, 0xc00

    if-nez v10, :cond_a

    move/from16 v10, p3

    invoke-virtual {v4, v10}, Ll2/t;->e(I)Z

    move-result v18

    if-eqz v18, :cond_9

    const/16 v18, 0x800

    goto :goto_6

    :cond_9
    move/from16 v18, v16

    :goto_6
    or-int v5, v5, v18

    goto :goto_7

    :cond_a
    move/from16 v10, p3

    :goto_7
    and-int/lit16 v12, v0, 0x6000

    const/16 v19, 0x2000

    const/16 v20, 0x4000

    if-nez v12, :cond_d

    and-int/lit8 v12, v3, 0x10

    if-nez v12, :cond_b

    move/from16 v12, p4

    invoke-virtual {v4, v12}, Ll2/t;->e(I)Z

    move-result v21

    if-eqz v21, :cond_c

    move/from16 v21, v20

    goto :goto_8

    :cond_b
    move/from16 v12, p4

    :cond_c
    move/from16 v21, v19

    :goto_8
    or-int v5, v5, v21

    goto :goto_9

    :cond_d
    move/from16 v12, p4

    :goto_9
    const/high16 v21, 0x30000

    and-int v21, v0, v21

    if-nez v21, :cond_e

    const/high16 v21, 0x10000

    or-int v5, v5, v21

    :cond_e
    and-int/lit8 v21, v3, 0x40

    const/high16 v22, 0x180000

    if-eqz v21, :cond_f

    or-int v5, v5, v22

    move-object/from16 v9, p6

    goto :goto_b

    :cond_f
    and-int v22, v0, v22

    move-object/from16 v9, p6

    if-nez v22, :cond_11

    invoke-virtual {v4, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_10

    const/high16 v23, 0x100000

    goto :goto_a

    :cond_10
    const/high16 v23, 0x80000

    :goto_a
    or-int v5, v5, v23

    :cond_11
    :goto_b
    and-int/lit16 v13, v3, 0x80

    const/high16 v24, 0xc00000

    if-eqz v13, :cond_12

    or-int v5, v5, v24

    move-object/from16 v7, p7

    goto :goto_d

    :cond_12
    and-int v24, v0, v24

    move-object/from16 v7, p7

    if-nez v24, :cond_14

    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_13

    const/high16 v25, 0x800000

    goto :goto_c

    :cond_13
    const/high16 v25, 0x400000

    :goto_c
    or-int v5, v5, v25

    :cond_14
    :goto_d
    and-int/lit16 v6, v3, 0x100

    const/high16 v26, 0x2000000

    const/high16 v27, 0x4000000

    const/high16 v28, 0x6000000

    if-eqz v6, :cond_15

    or-int v5, v5, v28

    move-object/from16 v0, p8

    goto :goto_f

    :cond_15
    and-int v28, v0, v28

    move-object/from16 v0, p8

    if-nez v28, :cond_17

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v28

    if-eqz v28, :cond_16

    move/from16 v28, v27

    goto :goto_e

    :cond_16
    move/from16 v28, v26

    :goto_e
    or-int v5, v5, v28

    :cond_17
    :goto_f
    and-int/lit16 v0, v3, 0x200

    const/high16 v28, 0x30000000

    if-eqz v0, :cond_19

    or-int v5, v5, v28

    :cond_18
    move/from16 v29, v0

    move-object/from16 v0, p9

    goto :goto_11

    :cond_19
    and-int v29, p19, v28

    if-nez v29, :cond_18

    move/from16 v29, v0

    move-object/from16 v0, p9

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_1a

    const/high16 v30, 0x20000000

    goto :goto_10

    :cond_1a
    const/high16 v30, 0x10000000

    :goto_10
    or-int v5, v5, v30

    :goto_11
    and-int/lit16 v0, v3, 0x400

    if-eqz v0, :cond_1b

    or-int/lit8 v30, v2, 0x6

    move/from16 v31, v0

    move-object/from16 v0, p10

    goto :goto_13

    :cond_1b
    move/from16 v31, v0

    move-object/from16 v0, p10

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_1c

    const/16 v30, 0x4

    goto :goto_12

    :cond_1c
    const/16 v30, 0x2

    :goto_12
    or-int v30, v2, v30

    :goto_13
    and-int/lit16 v0, v3, 0x800

    if-eqz v0, :cond_1d

    or-int/lit8 v30, v30, 0x30

    move/from16 v32, v0

    :goto_14
    move/from16 v0, v30

    goto :goto_16

    :cond_1d
    move/from16 v32, v0

    move-object/from16 v0, p11

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v33

    if-eqz v33, :cond_1e

    move/from16 v33, v17

    goto :goto_15

    :cond_1e
    const/16 v33, 0x10

    :goto_15
    or-int v30, v30, v33

    goto :goto_14

    :goto_16
    move/from16 p18, v5

    and-int/lit16 v5, v3, 0x1000

    if-eqz v5, :cond_1f

    or-int/lit16 v0, v0, 0x180

    goto :goto_18

    :cond_1f
    move/from16 v30, v0

    move/from16 v0, p12

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v33

    if-eqz v33, :cond_20

    const/16 v18, 0x100

    goto :goto_17

    :cond_20
    const/16 v18, 0x80

    :goto_17
    or-int v18, v30, v18

    move/from16 v0, v18

    :goto_18
    move/from16 v18, v5

    and-int/lit16 v5, v3, 0x2000

    if-eqz v5, :cond_21

    or-int/lit16 v0, v0, 0xc00

    goto :goto_19

    :cond_21
    move/from16 v30, v0

    and-int/lit16 v0, v2, 0xc00

    if-nez v0, :cond_23

    move/from16 v0, p13

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v33

    if-eqz v33, :cond_22

    const/16 v16, 0x800

    :cond_22
    or-int v16, v30, v16

    move/from16 v0, v16

    goto :goto_19

    :cond_23
    move/from16 v0, p13

    move/from16 v0, v30

    :goto_19
    move/from16 v16, v5

    and-int/lit16 v5, v3, 0x4000

    if-eqz v5, :cond_25

    or-int/lit16 v0, v0, 0x6000

    move/from16 v30, v0

    :cond_24
    move/from16 v0, p14

    goto :goto_1a

    :cond_25
    move/from16 v30, v0

    and-int/lit16 v0, v2, 0x6000

    if-nez v0, :cond_24

    move/from16 v0, p14

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v33

    if-eqz v33, :cond_26

    move/from16 v19, v20

    :cond_26
    or-int v19, v30, v19

    move/from16 v30, v19

    :goto_1a
    const/high16 v19, 0xdb0000

    or-int v19, v30, v19

    const/high16 v20, 0x40000

    and-int v20, v3, v20

    if-eqz v20, :cond_27

    const/high16 v19, 0x6db0000

    or-int v19, v30, v19

    :goto_1b
    move/from16 v0, v19

    goto :goto_1c

    :cond_27
    move/from16 v0, p17

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v30

    if-eqz v30, :cond_28

    move/from16 v26, v27

    :cond_28
    or-int v19, v19, v26

    goto :goto_1b

    :goto_1c
    const v19, 0x12492493

    and-int v2, p18, v19

    const v3, 0x12492492

    move/from16 v19, v5

    if-ne v2, v3, :cond_2a

    const v2, 0x2492493

    and-int/2addr v2, v0

    const v3, 0x2492492

    if-eq v2, v3, :cond_29

    goto :goto_1d

    :cond_29
    const/4 v2, 0x0

    goto :goto_1e

    :cond_2a
    :goto_1d
    const/4 v2, 0x1

    :goto_1e
    and-int/lit8 v3, p18, 0x1

    invoke-virtual {v4, v3, v2}, Ll2/t;->O(IZ)Z

    move-result v2

    if-eqz v2, :cond_52

    invoke-virtual {v4}, Ll2/t;->T()V

    and-int/lit8 v2, p19, 0x1

    sget-object v3, Ll2/n;->a:Ll2/x0;

    sget-object v5, Lxf0/q;->a:Lgy0/j;

    const v30, -0x70001

    const v33, -0xe001

    move/from16 v34, v2

    if-eqz v34, :cond_2e

    invoke-virtual {v4}, Ll2/t;->y()Z

    move-result v34

    if-eqz v34, :cond_2b

    goto :goto_20

    .line 2
    :cond_2b
    invoke-virtual {v4}, Ll2/t;->R()V

    and-int/lit8 v6, p21, 0x2

    if-eqz v6, :cond_2c

    and-int/lit8 v6, p18, -0x71

    goto :goto_1f

    :cond_2c
    move/from16 v6, p18

    :goto_1f
    and-int/lit8 v11, p21, 0x10

    if-eqz v11, :cond_2d

    and-int v6, v6, v33

    :cond_2d
    and-int v6, v6, v30

    move-object/from16 v15, p5

    move-object/from16 v2, p8

    move-object/from16 v21, p9

    move-object/from16 v29, p10

    move-object/from16 v13, p11

    move/from16 v31, p12

    move/from16 v32, p13

    move/from16 v19, p14

    move/from16 v16, p17

    move/from16 v18, v6

    move v11, v14

    move-object/from16 v6, p15

    move-object/from16 v14, p16

    goto/16 :goto_2d

    :cond_2e
    :goto_20
    and-int/lit8 v34, p21, 0x2

    if-eqz v34, :cond_2f

    .line 3
    iget v8, v5, Lgy0/h;->d:I

    and-int/lit8 v34, p18, -0x71

    goto :goto_21

    :cond_2f
    move/from16 v34, p18

    :goto_21
    if-eqz v11, :cond_30

    const/16 v11, 0x14

    goto :goto_22

    :cond_30
    move v11, v14

    :goto_22
    if-eqz v15, :cond_31

    const/16 v10, 0xa

    :cond_31
    and-int/lit8 v14, p21, 0x10

    .line 4
    sget-object v15, Lxf0/q;->b:Lgy0/j;

    if-eqz v14, :cond_32

    .line 5
    iget v12, v15, Lgy0/h;->e:I

    and-int v34, v34, v33

    :cond_32
    and-int v14, v34, v30

    if-eqz v21, :cond_33

    const/4 v9, 0x0

    :cond_33
    if-eqz v13, :cond_34

    const/4 v7, 0x0

    .line 6
    :cond_34
    const-string v13, ""

    if-eqz v6, :cond_35

    move-object v6, v13

    goto :goto_23

    :cond_35
    move-object/from16 v6, p8

    :goto_23
    if-eqz v29, :cond_36

    move-object/from16 v21, v13

    goto :goto_24

    :cond_36
    move-object/from16 v21, p9

    :goto_24
    if-eqz v31, :cond_37

    move-object/from16 v29, v13

    goto :goto_25

    :cond_37
    move-object/from16 v29, p10

    :goto_25
    if-eqz v32, :cond_38

    goto :goto_26

    :cond_38
    move-object/from16 v13, p11

    :goto_26
    if-eqz v18, :cond_39

    const/16 v18, 0x0

    goto :goto_27

    :cond_39
    move/from16 v18, p12

    :goto_27
    if-eqz v16, :cond_3a

    const/16 v16, 0x0

    goto :goto_28

    :cond_3a
    move/from16 v16, p13

    :goto_28
    if-eqz v19, :cond_3b

    const/16 v19, 0x0

    goto :goto_29

    :cond_3b
    move/from16 v19, p14

    .line 7
    :goto_29
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v3, :cond_3c

    .line 8
    new-instance v2, Lxf/b;

    move-object/from16 p1, v6

    const/4 v6, 0x5

    invoke-direct {v2, v6}, Lxf/b;-><init>(I)V

    .line 9
    invoke-virtual {v4, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_2a

    :cond_3c
    move-object/from16 p1, v6

    .line 10
    :goto_2a
    check-cast v2, Lay0/a;

    .line 11
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v3, :cond_3d

    .line 12
    new-instance v6, Lxf/b;

    move-object/from16 p2, v2

    const/4 v2, 0x5

    invoke-direct {v6, v2}, Lxf/b;-><init>(I)V

    .line 13
    invoke-virtual {v4, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_2b

    :cond_3d
    move-object/from16 p2, v2

    .line 14
    :goto_2b
    move-object v2, v6

    check-cast v2, Lay0/a;

    move-object/from16 v6, p2

    move/from16 v32, v16

    move/from16 v31, v18

    if-eqz v20, :cond_3e

    const/16 v16, 0x0

    :goto_2c
    move/from16 v18, v14

    move-object v14, v2

    move-object/from16 v2, p1

    goto :goto_2d

    :cond_3e
    move/from16 v16, p17

    goto :goto_2c

    .line 15
    :goto_2d
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 16
    invoke-static {v8, v5}, Lkp/r9;->f(ILgy0/g;)I

    move-result v5

    move-object/from16 p12, v2

    .line 17
    invoke-static {v12, v15}, Lkp/r9;->f(ILgy0/g;)I

    move-result v2

    move-object/from16 p13, v6

    const/16 v6, 0x168

    int-to-float v6, v6

    move/from16 v20, v6

    int-to-float v6, v5

    const/high16 v30, 0x42c80000    # 100.0f

    div-float v6, v6, v30

    mul-float v6, v6, v20

    int-to-float v2, v2

    div-float v2, v2, v30

    mul-float v2, v2, v20

    if-nez v31, :cond_41

    if-le v5, v11, :cond_3f

    goto :goto_2f

    :cond_3f
    if-le v5, v10, :cond_40

    const v5, -0x14fd4cae

    .line 18
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 19
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 20
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v5

    .line 21
    check-cast v5, Lj91/e;

    .line 22
    invoke-virtual {v5}, Lj91/e;->u()J

    move-result-wide v33

    const/4 v5, 0x0

    .line 23
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    :goto_2e
    move-wide/from16 v51, v33

    goto :goto_30

    :cond_40
    const v5, -0x14fd4790

    .line 24
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 25
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 26
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v5

    .line 27
    check-cast v5, Lj91/e;

    .line 28
    invoke-virtual {v5}, Lj91/e;->a()J

    move-result-wide v33

    const/4 v5, 0x0

    .line 29
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    goto :goto_2e

    :cond_41
    :goto_2f
    const v5, -0x14fd552d

    .line 30
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 31
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 32
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v5

    .line 33
    check-cast v5, Lj91/e;

    .line 34
    invoke-virtual {v5}, Lj91/e;->n()J

    move-result-wide v33

    const/4 v5, 0x0

    .line 35
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    goto :goto_2e

    :goto_30
    if-eqz v16, :cond_42

    const v5, 0x75559751

    .line 36
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 37
    const-string v5, "gaugePulseColorTransition"

    move/from16 p16, v2

    const/4 v2, 0x0

    invoke-static {v5, v4, v2}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    move-result-object v5

    .line 38
    new-instance v2, Lc1/s;

    move-object/from16 v20, v4

    move-object/from16 p1, v5

    move/from16 p17, v6

    move-object/from16 v53, v7

    const/high16 v4, 0x3f800000    # 1.0f

    const v5, 0x3ecccccd    # 0.4f

    const v6, 0x3f19999a    # 0.6f

    const/4 v7, 0x0

    invoke-direct {v2, v5, v7, v6, v4}, Lc1/s;-><init>(FFFF)V

    .line 39
    new-instance v4, Lc1/a2;

    const/16 v5, 0x4b0

    const/4 v6, 0x0

    invoke-direct {v4, v5, v6, v2}, Lc1/a2;-><init>(IILc1/w;)V

    .line 40
    sget-object v2, Lc1/t0;->d:Lc1/t0;

    const/4 v5, 0x4

    .line 41
    invoke-static {v4, v2, v5}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    move-result-object v2

    const/16 v4, 0x71b8

    const/4 v5, 0x0

    const v6, 0x3f333333    # 0.7f

    const/4 v7, 0x0

    .line 42
    const-string v30, "gaugePulseAnimationColor"

    move-object/from16 p4, v2

    move/from16 p7, v4

    move/from16 p8, v5

    move/from16 p2, v6

    move/from16 p3, v7

    move-object/from16 p6, v20

    move-object/from16 p5, v30

    invoke-static/range {p1 .. p8}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    move-result-object v2

    move-object/from16 v4, p6

    .line 43
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 44
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v5

    .line 45
    check-cast v5, Lj91/e;

    .line 46
    invoke-virtual {v5}, Lj91/e;->n()J

    move-result-wide v5

    .line 47
    iget-object v2, v2, Lc1/g0;->g:Ll2/j1;

    .line 48
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v2

    .line 49
    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    .line 50
    invoke-static {v5, v6, v2}, Le3/s;->b(JF)J

    move-result-wide v5

    const/4 v2, 0x0

    .line 51
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    goto :goto_31

    :cond_42
    move/from16 p16, v2

    move/from16 p17, v6

    move-object/from16 v53, v7

    const/4 v2, 0x0

    const v5, 0x755e3e9b

    .line 52
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 53
    sget-object v5, Lj91/h;->a:Ll2/u2;

    .line 54
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v5

    .line 55
    check-cast v5, Lj91/e;

    .line 56
    invoke-virtual {v5}, Lj91/e;->n()J

    move-result-wide v5

    const v7, 0x3f19999a    # 0.6f

    invoke-static {v5, v6, v7}, Le3/s;->b(JF)J

    move-result-wide v5

    .line 57
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 58
    :goto_31
    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v7

    move-object/from16 v20, v3

    invoke-virtual {v7}, Lj91/e;->b()J

    move-result-wide v2

    if-eqz v31, :cond_43

    const v7, -0x14fcdda3

    .line 59
    invoke-virtual {v4, v7}, Ll2/t;->Y(I)V

    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v7

    move/from16 v30, v8

    invoke-virtual {v7}, Lj91/e;->n()J

    move-result-wide v7

    move-object/from16 v33, v9

    const v9, 0x3e99999a    # 0.3f

    invoke-static {v7, v8, v9}, Le3/s;->b(JF)J

    move-result-wide v7

    const/4 v9, 0x0

    .line 60
    invoke-virtual {v4, v9}, Ll2/t;->q(Z)V

    move/from16 v34, v10

    goto :goto_32

    :cond_43
    move/from16 v30, v8

    move-object/from16 v33, v9

    const/4 v9, 0x0

    const v7, -0x14fcd662

    .line 61
    invoke-virtual {v4, v7}, Ll2/t;->Y(I)V

    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v7

    invoke-virtual {v7}, Lj91/e;->p()J

    move-result-wide v7

    move/from16 v34, v10

    const v10, 0x3df5c28f    # 0.12f

    invoke-static {v7, v8, v10}, Le3/s;->b(JF)J

    move-result-wide v7

    .line 62
    invoke-virtual {v4, v9}, Ll2/t;->q(Z)V

    .line 63
    :goto_32
    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v10

    invoke-virtual {v10}, Lj91/e;->k()J

    move-result-wide v9

    .line 64
    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v35

    move/from16 v36, v11

    move/from16 v54, v12

    invoke-virtual/range {v35 .. v35}, Lj91/e;->l()J

    move-result-wide v11

    if-eqz v31, :cond_44

    move-object/from16 v55, v13

    const v13, -0x14fcb38d

    .line 65
    invoke-virtual {v4, v13}, Ll2/t;->Y(I)V

    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v13

    invoke-virtual {v13}, Lj91/e;->n()J

    move-result-wide v37

    const/4 v13, 0x0

    .line 66
    invoke-virtual {v4, v13}, Ll2/t;->q(Z)V

    move-object/from16 v56, v14

    move-wide/from16 v57, v37

    goto :goto_33

    :cond_44
    move-object/from16 v55, v13

    move-object/from16 v56, v14

    const/4 v13, 0x0

    const v14, -0x14fcb06a

    .line 67
    invoke-virtual {v4, v14}, Ll2/t;->Y(I)V

    .line 68
    invoke-virtual {v4, v13}, Ll2/t;->q(Z)V

    move-wide/from16 v57, v51

    :goto_33
    const/16 v13, 0x18

    int-to-float v13, v13

    .line 69
    invoke-static {v13}, Lxf0/i0;->O(F)I

    move-result v13

    int-to-float v13, v13

    const v14, 0x3eaaaaab

    mul-float/2addr v14, v13

    const/high16 v35, 0x3fa00000    # 1.25f

    .line 70
    invoke-static/range {v35 .. v35}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v35

    if-eqz v16, :cond_45

    goto :goto_34

    :cond_45
    const/16 v35, 0x0

    :goto_34
    if-eqz v35, :cond_46

    invoke-virtual/range {v35 .. v35}, Ljava/lang/Float;->floatValue()F

    move-result v35

    goto :goto_35

    :cond_46
    const/high16 v35, 0x3f400000    # 0.75f

    :goto_35
    mul-float v35, v35, v13

    move/from16 v37, v13

    move/from16 v38, v14

    const/4 v13, 0x4

    int-to-float v14, v13

    .line 71
    invoke-static {v14}, Lxf0/i0;->O(F)I

    move-result v13

    int-to-float v13, v13

    .line 72
    sget-object v14, Lc1/t0;->d:Lc1/t0;

    if-eqz v16, :cond_47

    goto :goto_36

    :cond_47
    const/4 v14, 0x0

    :goto_36
    if-nez v14, :cond_48

    sget-object v14, Lc1/t0;->e:Lc1/t0;

    :cond_48
    if-eqz v31, :cond_49

    if-eqz v32, :cond_49

    move/from16 v39, v13

    const v13, 0x756f1417

    .line 73
    invoke-virtual {v4, v13}, Ll2/t;->Y(I)V

    .line 74
    const-string v13, "gaugePulseTransition"

    move-object/from16 v40, v15

    const/4 v15, 0x0

    invoke-static {v13, v4, v15}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    move-result-object v13

    .line 75
    new-instance v15, Lc1/s;

    move-object/from16 p6, v4

    move-wide/from16 v47, v11

    move-object/from16 p1, v13

    const/high16 v4, 0x3f800000    # 1.0f

    const v11, 0x3f19999a    # 0.6f

    const/4 v12, 0x0

    const v13, 0x3ecccccd    # 0.4f

    invoke-direct {v15, v13, v12, v11, v4}, Lc1/s;-><init>(FFFF)V

    .line 76
    new-instance v4, Lc1/a2;

    const/16 v11, 0x4b0

    const/4 v13, 0x0

    invoke-direct {v4, v11, v13, v15}, Lc1/a2;-><init>(IILc1/w;)V

    const/4 v11, 0x4

    .line 77
    invoke-static {v4, v14, v11}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    move-result-object v4

    const/16 v11, 0x7038

    const/4 v12, 0x0

    const/4 v14, 0x0

    .line 78
    const-string v15, "gaugePulseAnimation"

    move-object/from16 p4, v4

    move/from16 p7, v11

    move/from16 p8, v12

    move/from16 p2, v14

    move-object/from16 p5, v15

    move/from16 p3, v35

    invoke-static/range {p1 .. p8}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    move-result-object v4

    move/from16 v14, p3

    move-object/from16 v11, p6

    .line 79
    iget-object v4, v4, Lc1/g0;->g:Ll2/j1;

    .line 80
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v4

    .line 81
    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    move-result v4

    .line 82
    invoke-virtual {v11, v13}, Ll2/t;->q(Z)V

    move v12, v4

    goto :goto_37

    :cond_49
    move-wide/from16 v47, v11

    move/from16 v39, v13

    move-object/from16 v40, v15

    move/from16 v14, v35

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-object v11, v4

    const v4, 0x75779fc5

    .line 83
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 84
    invoke-virtual {v11, v13}, Ll2/t;->q(Z)V

    :goto_37
    if-eqz v19, :cond_4a

    const v4, 0x7578f848

    .line 85
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 86
    const-string v4, "gaugeBackgroundTransition"

    invoke-static {v4, v11, v13}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    move-result-object v4

    .line 87
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v13

    move-object/from16 p6, v11

    move/from16 p14, v12

    invoke-virtual {v13}, Lj91/e;->o()J

    move-result-wide v11

    invoke-static/range {p6 .. p6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v13

    move/from16 p15, v14

    invoke-virtual {v13}, Lj91/e;->i()J

    move-result-wide v13

    invoke-static {v11, v12, v13, v14}, Le3/j0;->l(JJ)J

    move-result-wide v11

    .line 88
    invoke-static/range {p6 .. p6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v13

    invoke-virtual {v13}, Lj91/e;->d()J

    move-result-wide v13

    const/16 v15, 0x320

    move-object/from16 p1, v4

    const/16 v4, 0xc8

    move-wide/from16 p4, v11

    const/4 v11, 0x4

    const/4 v12, 0x0

    .line 89
    invoke-static {v15, v4, v12, v11}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    move-result-object v4

    .line 90
    sget-object v12, Lc1/t0;->e:Lc1/t0;

    .line 91
    invoke-static {v4, v12, v11}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    move-result-object v4

    move-object/from16 p7, p6

    move-object/from16 p6, v4

    move-wide/from16 p2, v13

    .line 92
    invoke-static/range {p1 .. p7}, Ljp/y1;->b(Lc1/i0;JJLc1/f0;Ll2/o;)Lc1/g0;

    move-result-object v4

    move-object/from16 v11, p7

    .line 93
    iget-object v4, v4, Lc1/g0;->g:Ll2/j1;

    .line 94
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v4

    .line 95
    check-cast v4, Le3/s;

    .line 96
    iget-wide v12, v4, Le3/s;->a:J

    const/4 v15, 0x0

    .line 97
    invoke-virtual {v11, v15}, Ll2/t;->q(Z)V

    goto :goto_38

    :cond_4a
    move/from16 p14, v12

    move v15, v13

    move/from16 p15, v14

    const v4, 0x7583a086

    .line 98
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 99
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v4

    invoke-virtual {v4}, Lj91/e;->p()J

    move-result-wide v12

    .line 100
    invoke-virtual {v11, v15}, Ll2/t;->q(Z)V

    .line 101
    :goto_38
    invoke-static {v11}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v4

    invoke-virtual {v4}, Lj91/e;->b()J

    move-result-wide v14

    .line 102
    new-instance v49, Lxf0/v0;

    const/high16 v4, -0x3d700000    # -72.0f

    move/from16 p7, p16

    move/from16 p6, p17

    move/from16 p8, v4

    move/from16 p4, v30

    move-object/from16 p5, v33

    move/from16 p10, v34

    move/from16 p11, v36

    move-object/from16 p9, v40

    move-object/from16 p3, v49

    invoke-direct/range {p3 .. p11}, Lxf0/v0;-><init>(ILjava/lang/Integer;FFFLgy0/j;II)V

    move-object/from16 v4, p3

    move/from16 p16, p4

    move-object/from16 v61, p5

    move-object/from16 v25, p9

    move/from16 v60, p10

    move/from16 v59, p11

    .line 103
    new-instance v50, Lxf0/a1;

    move/from16 p4, p14

    move/from16 p5, p15

    move/from16 p2, v37

    move/from16 p3, v38

    move/from16 p6, v39

    move-object/from16 p1, v50

    invoke-direct/range {p1 .. p6}, Lxf0/a1;-><init>(FFFFF)V

    move-object/from16 v62, p1

    move/from16 v30, p5

    move-object/from16 p3, v4

    .line 104
    sget-object v4, Lw3/h1;->t:Ll2/u2;

    .line 105
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lw3/j2;

    .line 106
    check-cast v4, Lw3/r1;

    invoke-virtual {v4}, Lw3/r1;->a()J

    move-result-wide v33

    move-wide/from16 v45, v9

    shr-long v9, v33, v17

    long-to-int v4, v9

    .line 107
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    .line 108
    invoke-static {v4}, Lxf0/i0;->N(Ljava/lang/Number;)F

    move-result v4

    const v9, 0x3f4ccccd    # 0.8f

    mul-float/2addr v4, v9

    float-to-int v4, v4

    const/16 v9, 0x122

    const/16 v10, 0x186

    .line 109
    invoke-static {v4, v9, v10}, Lkp/r9;->e(III)I

    move-result v4

    .line 110
    sget-object v9, Lk1/j;->e:Lk1/f;

    .line 111
    sget-object v10, Lx2/c;->q:Lx2/h;

    move-object/from16 p1, v9

    const/4 v9, 0x2

    int-to-float v9, v9

    div-float v35, v30, v9

    .line 112
    invoke-static/range {v35 .. v35}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v9

    invoke-static {v9}, Lxf0/i0;->N(Ljava/lang/Number;)F

    move-result v9

    invoke-static {v1, v9}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    move-result-object v9

    int-to-float v4, v4

    .line 113
    invoke-static {v9, v4}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    move-result-object v4

    and-int/lit16 v9, v0, 0x380

    const/16 v1, 0x100

    if-ne v9, v1, :cond_4b

    const/4 v1, 0x1

    goto :goto_39

    :cond_4b
    const/4 v1, 0x0

    :goto_39
    and-int/lit16 v9, v0, 0x1c00

    move/from16 p18, v0

    const/16 v0, 0x800

    if-ne v9, v0, :cond_4c

    const/16 v26, 0x1

    goto :goto_3a

    :cond_4c
    const/16 v26, 0x0

    :goto_3a
    or-int v0, v1, v26

    .line 114
    invoke-virtual {v11, v5, v6}, Ll2/t;->f(J)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v11, v12, v13}, Ll2/t;->f(J)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v11, v14, v15}, Ll2/t;->f(J)Z

    move-result v1

    or-int/2addr v0, v1

    move/from16 p2, v0

    move-wide/from16 v0, v51

    invoke-virtual {v11, v0, v1}, Ll2/t;->f(J)Z

    move-result v9

    or-int v9, p2, v9

    invoke-virtual {v11, v7, v8}, Ll2/t;->f(J)Z

    move-result v17

    or-int v9, v9, v17

    invoke-virtual {v11, v2, v3}, Ll2/t;->f(J)Z

    move-result v17

    or-int v9, v9, v17

    move-wide/from16 v39, v0

    move-wide/from16 v0, v45

    invoke-virtual {v11, v0, v1}, Ll2/t;->f(J)Z

    move-result v17

    or-int v9, v9, v17

    move-wide/from16 v0, v47

    invoke-virtual {v11, v0, v1}, Ll2/t;->f(J)Z

    move-result v17

    or-int v9, v9, v17

    move-object/from16 v0, p3

    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v1, v9

    move-object/from16 v9, v62

    invoke-virtual {v11, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v17

    or-int v1, v1, v17

    .line 115
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    if-nez v1, :cond_4d

    move-object/from16 v1, v20

    if-ne v0, v1, :cond_4e

    .line 116
    :cond_4d
    new-instance v30, Lxf0/n;

    move-object/from16 v49, p3

    move-wide/from16 v43, v2

    move-wide/from16 v33, v5

    move-wide/from16 v41, v7

    move-object/from16 v50, v9

    move-wide/from16 v35, v12

    move-wide/from16 v37, v14

    invoke-direct/range {v30 .. v50}, Lxf0/n;-><init>(ZZJJJJJJJJLxf0/v0;Lxf0/a1;)V

    move-object/from16 v0, v30

    .line 117
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    :cond_4e
    check-cast v0, Lay0/k;

    invoke-static {v4, v0}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    move-result-object v0

    const/16 v1, 0x36

    move-object/from16 v2, p1

    .line 119
    invoke-static {v2, v10, v11, v1}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    move-result-object v1

    .line 120
    iget-wide v2, v11, Ll2/t;->T:J

    .line 121
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    move-result v2

    .line 122
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    move-result-object v3

    .line 123
    invoke-static {v11, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 124
    sget-object v4, Lv3/k;->m1:Lv3/j;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 126
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 127
    iget-boolean v5, v11, Ll2/t;->S:Z

    if-eqz v5, :cond_4f

    .line 128
    invoke-virtual {v11, v4}, Ll2/t;->l(Lay0/a;)V

    goto :goto_3b

    .line 129
    :cond_4f
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 130
    :goto_3b
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 131
    invoke-static {v4, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 132
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 133
    invoke-static {v1, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 135
    iget-boolean v3, v11, Ll2/t;->S:Z

    if-nez v3, :cond_50

    .line 136
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_51

    .line 137
    :cond_50
    invoke-static {v2, v11, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 138
    :cond_51
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 139
    invoke-static {v1, v0, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    shr-int/lit8 v0, v18, 0x18

    and-int/lit8 v0, v0, 0x7e

    shl-int/lit8 v1, p18, 0x3

    and-int/lit16 v2, v1, 0x380

    or-int/2addr v0, v2

    shl-int/lit8 v2, p18, 0x9

    and-int/lit16 v2, v2, 0x1c00

    or-int/2addr v0, v2

    const v2, 0xe000

    and-int/2addr v1, v2

    or-int/2addr v0, v1

    const/high16 v1, 0xe000000

    shl-int/lit8 v2, v18, 0x3

    and-int/2addr v1, v2

    or-int/2addr v0, v1

    or-int v0, v0, v28

    const/4 v1, 0x6

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object/from16 p1, p12

    move-object/from16 p11, p13

    move/from16 p14, v0

    move/from16 p15, v1

    move/from16 p8, v2

    move/from16 p9, v3

    move-object/from16 p13, v11

    move-object/from16 p2, v21

    move-object/from16 p4, v29

    move/from16 p5, v32

    move-object/from16 p10, v53

    move-object/from16 p3, v55

    move-object/from16 p12, v56

    move-wide/from16 p6, v57

    .line 140
    invoke-static/range {p1 .. p15}, Lxf0/q;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZLjava/lang/Integer;Lay0/a;Lay0/a;Ll2/o;II)V

    move-object/from16 v0, p1

    move-object/from16 v1, p11

    const/4 v2, 0x1

    .line 141
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    move/from16 v2, p16

    move-object v9, v0

    move-object/from16 v20, v11

    move/from16 v18, v16

    move/from16 v15, v19

    move-object/from16 v10, v21

    move-object/from16 v6, v25

    move-object/from16 v11, v29

    move/from16 v13, v31

    move/from16 v14, v32

    move-object/from16 v8, v53

    move/from16 v5, v54

    move-object/from16 v12, v55

    move-object/from16 v17, v56

    move/from16 v3, v59

    move/from16 v4, v60

    move-object/from16 v7, v61

    move-object/from16 v16, v1

    goto :goto_3c

    :cond_52
    move-object v11, v4

    .line 142
    invoke-virtual {v11}, Ll2/t;->R()V

    move-object/from16 v6, p5

    move/from16 v13, p12

    move/from16 v15, p14

    move-object/from16 v16, p15

    move-object/from16 v17, p16

    move/from16 v18, p17

    move v2, v8

    move v4, v10

    move-object/from16 v20, v11

    move v5, v12

    move v3, v14

    move-object/from16 v10, p9

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move/from16 v14, p13

    move-object v8, v7

    move-object v7, v9

    move-object/from16 v9, p8

    .line 143
    :goto_3c
    invoke-virtual/range {v20 .. v20}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_53

    move-object v1, v0

    new-instance v0, Lxf0/o;

    move/from16 v19, p19

    move/from16 v20, p20

    move/from16 v21, p21

    move-object/from16 v63, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v21}, Lxf0/o;-><init>(Lx2/s;IIIILgy0/j;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLay0/a;Lay0/a;ZIII)V

    move-object/from16 v1, v63

    .line 144
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_53
    return-void
.end method
