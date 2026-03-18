.class public abstract Lxf0/m;
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
    sput-object v0, Lxf0/m;->a:Lgy0/j;

    .line 11
    .line 12
    new-instance v0, Lgy0/j;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lxf0/m;->b:Lgy0/j;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZZLay0/a;Lay0/a;Ll2/o;I)V
    .locals 37

    .line 1
    move/from16 v4, p3

    .line 2
    .line 3
    move-wide/from16 v5, p4

    .line 4
    .line 5
    move/from16 v0, p6

    .line 6
    .line 7
    move/from16 v1, p7

    .line 8
    .line 9
    move/from16 v8, p8

    .line 10
    .line 11
    move/from16 v2, p12

    .line 12
    .line 13
    move-object/from16 v9, p11

    .line 14
    .line 15
    check-cast v9, Ll2/t;

    .line 16
    .line 17
    const v3, 0x146c1ae4

    .line 18
    .line 19
    .line 20
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v3, v2, 0x6

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    move-object/from16 v3, p0

    .line 28
    .line 29
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v7

    .line 33
    if-eqz v7, :cond_0

    .line 34
    .line 35
    const/4 v7, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v7, 0x2

    .line 38
    :goto_0
    or-int/2addr v7, v2

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move-object/from16 v3, p0

    .line 41
    .line 42
    move v7, v2

    .line 43
    :goto_1
    and-int/lit8 v10, v2, 0x30

    .line 44
    .line 45
    if-nez v10, :cond_3

    .line 46
    .line 47
    move-object/from16 v10, p1

    .line 48
    .line 49
    invoke-virtual {v9, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v7, v11

    .line 61
    goto :goto_3

    .line 62
    :cond_3
    move-object/from16 v10, p1

    .line 63
    .line 64
    :goto_3
    and-int/lit16 v11, v2, 0x180

    .line 65
    .line 66
    if-nez v11, :cond_5

    .line 67
    .line 68
    move-object/from16 v11, p2

    .line 69
    .line 70
    invoke-virtual {v9, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v12

    .line 74
    if-eqz v12, :cond_4

    .line 75
    .line 76
    const/16 v12, 0x100

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/16 v12, 0x80

    .line 80
    .line 81
    :goto_4
    or-int/2addr v7, v12

    .line 82
    goto :goto_5

    .line 83
    :cond_5
    move-object/from16 v11, p2

    .line 84
    .line 85
    :goto_5
    and-int/lit16 v12, v2, 0xc00

    .line 86
    .line 87
    if-nez v12, :cond_7

    .line 88
    .line 89
    invoke-virtual {v9, v4}, Ll2/t;->h(Z)Z

    .line 90
    .line 91
    .line 92
    move-result v12

    .line 93
    if-eqz v12, :cond_6

    .line 94
    .line 95
    const/16 v12, 0x800

    .line 96
    .line 97
    goto :goto_6

    .line 98
    :cond_6
    const/16 v12, 0x400

    .line 99
    .line 100
    :goto_6
    or-int/2addr v7, v12

    .line 101
    :cond_7
    and-int/lit16 v12, v2, 0x6000

    .line 102
    .line 103
    if-nez v12, :cond_9

    .line 104
    .line 105
    invoke-virtual {v9, v5, v6}, Ll2/t;->f(J)Z

    .line 106
    .line 107
    .line 108
    move-result v12

    .line 109
    if-eqz v12, :cond_8

    .line 110
    .line 111
    const/16 v12, 0x4000

    .line 112
    .line 113
    goto :goto_7

    .line 114
    :cond_8
    const/16 v12, 0x2000

    .line 115
    .line 116
    :goto_7
    or-int/2addr v7, v12

    .line 117
    :cond_9
    const/high16 v12, 0x30000

    .line 118
    .line 119
    and-int/2addr v12, v2

    .line 120
    if-nez v12, :cond_b

    .line 121
    .line 122
    invoke-virtual {v9, v0}, Ll2/t;->h(Z)Z

    .line 123
    .line 124
    .line 125
    move-result v12

    .line 126
    if-eqz v12, :cond_a

    .line 127
    .line 128
    const/high16 v12, 0x20000

    .line 129
    .line 130
    goto :goto_8

    .line 131
    :cond_a
    const/high16 v12, 0x10000

    .line 132
    .line 133
    :goto_8
    or-int/2addr v7, v12

    .line 134
    :cond_b
    const/high16 v12, 0x180000

    .line 135
    .line 136
    and-int/2addr v12, v2

    .line 137
    if-nez v12, :cond_d

    .line 138
    .line 139
    invoke-virtual {v9, v1}, Ll2/t;->h(Z)Z

    .line 140
    .line 141
    .line 142
    move-result v12

    .line 143
    if-eqz v12, :cond_c

    .line 144
    .line 145
    const/high16 v12, 0x100000

    .line 146
    .line 147
    goto :goto_9

    .line 148
    :cond_c
    const/high16 v12, 0x80000

    .line 149
    .line 150
    :goto_9
    or-int/2addr v7, v12

    .line 151
    :cond_d
    const/high16 v12, 0xc00000

    .line 152
    .line 153
    and-int/2addr v12, v2

    .line 154
    if-nez v12, :cond_f

    .line 155
    .line 156
    invoke-virtual {v9, v8}, Ll2/t;->h(Z)Z

    .line 157
    .line 158
    .line 159
    move-result v12

    .line 160
    if-eqz v12, :cond_e

    .line 161
    .line 162
    const/high16 v12, 0x800000

    .line 163
    .line 164
    goto :goto_a

    .line 165
    :cond_e
    const/high16 v12, 0x400000

    .line 166
    .line 167
    :goto_a
    or-int/2addr v7, v12

    .line 168
    :cond_f
    const/high16 v12, 0x6000000

    .line 169
    .line 170
    and-int/2addr v12, v2

    .line 171
    if-nez v12, :cond_11

    .line 172
    .line 173
    move-object/from16 v12, p9

    .line 174
    .line 175
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v13

    .line 179
    if-eqz v13, :cond_10

    .line 180
    .line 181
    const/high16 v13, 0x4000000

    .line 182
    .line 183
    goto :goto_b

    .line 184
    :cond_10
    const/high16 v13, 0x2000000

    .line 185
    .line 186
    :goto_b
    or-int/2addr v7, v13

    .line 187
    goto :goto_c

    .line 188
    :cond_11
    move-object/from16 v12, p9

    .line 189
    .line 190
    :goto_c
    const/high16 v13, 0x30000000

    .line 191
    .line 192
    and-int/2addr v13, v2

    .line 193
    if-nez v13, :cond_13

    .line 194
    .line 195
    move-object/from16 v13, p10

    .line 196
    .line 197
    invoke-virtual {v9, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v14

    .line 201
    if-eqz v14, :cond_12

    .line 202
    .line 203
    const/high16 v14, 0x20000000

    .line 204
    .line 205
    goto :goto_d

    .line 206
    :cond_12
    const/high16 v14, 0x10000000

    .line 207
    .line 208
    :goto_d
    or-int/2addr v7, v14

    .line 209
    :goto_e
    move/from16 v31, v7

    .line 210
    .line 211
    goto :goto_f

    .line 212
    :cond_13
    move-object/from16 v13, p10

    .line 213
    .line 214
    goto :goto_e

    .line 215
    :goto_f
    const v7, 0x12492493

    .line 216
    .line 217
    .line 218
    and-int v7, v31, v7

    .line 219
    .line 220
    const v14, 0x12492492

    .line 221
    .line 222
    .line 223
    if-eq v7, v14, :cond_14

    .line 224
    .line 225
    const/4 v7, 0x1

    .line 226
    goto :goto_10

    .line 227
    :cond_14
    const/4 v7, 0x0

    .line 228
    :goto_10
    and-int/lit8 v14, v31, 0x1

    .line 229
    .line 230
    invoke-virtual {v9, v14, v7}, Ll2/t;->O(IZ)Z

    .line 231
    .line 232
    .line 233
    move-result v7

    .line 234
    if-eqz v7, :cond_25

    .line 235
    .line 236
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 237
    .line 238
    const-string v14, "battery_gauge_range"

    .line 239
    .line 240
    const-string v12, "battery_gauge_charge"

    .line 241
    .line 242
    const-string v15, "battery_gauge_title"

    .line 243
    .line 244
    if-eqz v4, :cond_24

    .line 245
    .line 246
    const v0, -0x6faca28a

    .line 247
    .line 248
    .line 249
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 250
    .line 251
    .line 252
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-virtual {v0}, Lj91/f;->l()Lg4/p0;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    invoke-static {v7, v15}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v11

    .line 264
    and-int/lit8 v15, v31, 0xe

    .line 265
    .line 266
    or-int/lit16 v15, v15, 0x180

    .line 267
    .line 268
    const/16 v29, 0x0

    .line 269
    .line 270
    const v30, 0xfff8

    .line 271
    .line 272
    .line 273
    move-object/from16 v17, v12

    .line 274
    .line 275
    const-wide/16 v12, 0x0

    .line 276
    .line 277
    move-object/from16 v18, v14

    .line 278
    .line 279
    move/from16 v28, v15

    .line 280
    .line 281
    const-wide/16 v14, 0x0

    .line 282
    .line 283
    const/16 v19, 0x1

    .line 284
    .line 285
    const/16 v16, 0x0

    .line 286
    .line 287
    move-object/from16 v21, v17

    .line 288
    .line 289
    move-object/from16 v20, v18

    .line 290
    .line 291
    const-wide/16 v17, 0x0

    .line 292
    .line 293
    move/from16 v22, v19

    .line 294
    .line 295
    const/16 v19, 0x0

    .line 296
    .line 297
    move-object/from16 v23, v20

    .line 298
    .line 299
    const/16 v20, 0x0

    .line 300
    .line 301
    move-object/from16 v24, v21

    .line 302
    .line 303
    move/from16 v25, v22

    .line 304
    .line 305
    const-wide/16 v21, 0x0

    .line 306
    .line 307
    move-object/from16 v26, v23

    .line 308
    .line 309
    const/16 v23, 0x0

    .line 310
    .line 311
    move-object/from16 v27, v24

    .line 312
    .line 313
    const/16 v24, 0x0

    .line 314
    .line 315
    move/from16 v32, v25

    .line 316
    .line 317
    const/16 v25, 0x0

    .line 318
    .line 319
    move-object/from16 v33, v26

    .line 320
    .line 321
    const/16 v26, 0x0

    .line 322
    .line 323
    move-object v1, v9

    .line 324
    move-object v9, v3

    .line 325
    move-object/from16 v3, v27

    .line 326
    .line 327
    move-object/from16 v27, v1

    .line 328
    .line 329
    move-object v10, v0

    .line 330
    move-object/from16 v0, v33

    .line 331
    .line 332
    const/4 v1, 0x0

    .line 333
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 334
    .line 335
    .line 336
    move-object/from16 v13, v27

    .line 337
    .line 338
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 339
    .line 340
    .line 341
    move-result-object v9

    .line 342
    iget v9, v9, Lj91/c;->c:F

    .line 343
    .line 344
    invoke-static {v7, v9}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 345
    .line 346
    .line 347
    move-result-object v9

    .line 348
    invoke-static {v13, v9}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 349
    .line 350
    .line 351
    const/high16 v14, 0x3f800000    # 1.0f

    .line 352
    .line 353
    invoke-static {v7, v14}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 354
    .line 355
    .line 356
    move-result-object v9

    .line 357
    sget-object v15, Lx2/c;->n:Lx2/i;

    .line 358
    .line 359
    sget-object v10, Lk1/j;->g:Lk1/f;

    .line 360
    .line 361
    const/16 v11, 0x36

    .line 362
    .line 363
    invoke-static {v10, v15, v13, v11}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 364
    .line 365
    .line 366
    move-result-object v10

    .line 367
    iget-wide v11, v13, Ll2/t;->T:J

    .line 368
    .line 369
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 370
    .line 371
    .line 372
    move-result v11

    .line 373
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 374
    .line 375
    .line 376
    move-result-object v12

    .line 377
    invoke-static {v13, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 378
    .line 379
    .line 380
    move-result-object v9

    .line 381
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 382
    .line 383
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 384
    .line 385
    .line 386
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 387
    .line 388
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 389
    .line 390
    .line 391
    iget-boolean v1, v13, Ll2/t;->S:Z

    .line 392
    .line 393
    if-eqz v1, :cond_15

    .line 394
    .line 395
    invoke-virtual {v13, v14}, Ll2/t;->l(Lay0/a;)V

    .line 396
    .line 397
    .line 398
    goto :goto_11

    .line 399
    :cond_15
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 400
    .line 401
    .line 402
    :goto_11
    sget-object v1, Lv3/j;->g:Lv3/h;

    .line 403
    .line 404
    invoke-static {v1, v10, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 405
    .line 406
    .line 407
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 408
    .line 409
    invoke-static {v10, v12, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 410
    .line 411
    .line 412
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 413
    .line 414
    iget-boolean v2, v13, Ll2/t;->S:Z

    .line 415
    .line 416
    if-nez v2, :cond_16

    .line 417
    .line 418
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 423
    .line 424
    .line 425
    move-result-object v4

    .line 426
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 427
    .line 428
    .line 429
    move-result v2

    .line 430
    if-nez v2, :cond_17

    .line 431
    .line 432
    :cond_16
    invoke-static {v11, v13, v11, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 433
    .line 434
    .line 435
    :cond_17
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 436
    .line 437
    invoke-static {v2, v9, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 438
    .line 439
    .line 440
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 441
    .line 442
    .line 443
    move-result-object v4

    .line 444
    iget v4, v4, Lj91/c;->e:F

    .line 445
    .line 446
    const/16 v20, 0x0

    .line 447
    .line 448
    const/16 v21, 0xe

    .line 449
    .line 450
    const/16 v18, 0x0

    .line 451
    .line 452
    const/16 v19, 0x0

    .line 453
    .line 454
    move/from16 v17, v4

    .line 455
    .line 456
    move-object/from16 v16, v7

    .line 457
    .line 458
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    const/16 v7, 0x40

    .line 463
    .line 464
    int-to-float v7, v7

    .line 465
    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 466
    .line 467
    .line 468
    move-result-object v4

    .line 469
    const/16 v28, 0x0

    .line 470
    .line 471
    if-eqz v8, :cond_18

    .line 472
    .line 473
    const/high16 v9, 0x3f800000    # 1.0f

    .line 474
    .line 475
    goto :goto_12

    .line 476
    :cond_18
    move/from16 v9, v28

    .line 477
    .line 478
    :goto_12
    invoke-static {v4, v9}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 479
    .line 480
    .line 481
    move-result-object v4

    .line 482
    move-object v9, v10

    .line 483
    new-instance v10, Ld4/i;

    .line 484
    .line 485
    const/4 v11, 0x0

    .line 486
    invoke-direct {v10, v11}, Ld4/i;-><init>(I)V

    .line 487
    .line 488
    .line 489
    move-object/from16 v17, v12

    .line 490
    .line 491
    const/16 v12, 0xa

    .line 492
    .line 493
    move-object/from16 v18, v9

    .line 494
    .line 495
    const/4 v9, 0x0

    .line 496
    move-object/from16 v33, v0

    .line 497
    .line 498
    move/from16 v34, v7

    .line 499
    .line 500
    move v6, v11

    .line 501
    move-object/from16 v5, v16

    .line 502
    .line 503
    move-object/from16 v0, v17

    .line 504
    .line 505
    move-object/from16 v11, p10

    .line 506
    .line 507
    move-object v7, v4

    .line 508
    move-object/from16 v4, v18

    .line 509
    .line 510
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 511
    .line 512
    .line 513
    move-result-object v7

    .line 514
    sget-object v8, Lx2/c;->h:Lx2/j;

    .line 515
    .line 516
    invoke-static {v8, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 517
    .line 518
    .line 519
    move-result-object v9

    .line 520
    iget-wide v10, v13, Ll2/t;->T:J

    .line 521
    .line 522
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 523
    .line 524
    .line 525
    move-result v6

    .line 526
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 527
    .line 528
    .line 529
    move-result-object v10

    .line 530
    invoke-static {v13, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 531
    .line 532
    .line 533
    move-result-object v7

    .line 534
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 535
    .line 536
    .line 537
    iget-boolean v11, v13, Ll2/t;->S:Z

    .line 538
    .line 539
    if-eqz v11, :cond_19

    .line 540
    .line 541
    invoke-virtual {v13, v14}, Ll2/t;->l(Lay0/a;)V

    .line 542
    .line 543
    .line 544
    goto :goto_13

    .line 545
    :cond_19
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 546
    .line 547
    .line 548
    :goto_13
    invoke-static {v1, v9, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 549
    .line 550
    .line 551
    invoke-static {v4, v10, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 552
    .line 553
    .line 554
    iget-boolean v9, v13, Ll2/t;->S:Z

    .line 555
    .line 556
    if-nez v9, :cond_1a

    .line 557
    .line 558
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 559
    .line 560
    .line 561
    move-result-object v9

    .line 562
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 563
    .line 564
    .line 565
    move-result-object v10

    .line 566
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 567
    .line 568
    .line 569
    move-result v9

    .line 570
    if-nez v9, :cond_1b

    .line 571
    .line 572
    :cond_1a
    invoke-static {v6, v13, v6, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 573
    .line 574
    .line 575
    :cond_1b
    invoke-static {v2, v7, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 576
    .line 577
    .line 578
    const/16 v6, 0x1a

    .line 579
    .line 580
    int-to-float v6, v6

    .line 581
    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 582
    .line 583
    .line 584
    move-result-object v7

    .line 585
    const-string v9, "minus_button"

    .line 586
    .line 587
    invoke-static {v7, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 588
    .line 589
    .line 590
    move-result-object v12

    .line 591
    shr-int/lit8 v7, v31, 0x18

    .line 592
    .line 593
    and-int/lit8 v7, v7, 0x70

    .line 594
    .line 595
    or-int/lit16 v7, v7, 0x180

    .line 596
    .line 597
    shr-int/lit8 v9, v31, 0xc

    .line 598
    .line 599
    and-int/lit16 v9, v9, 0x1c00

    .line 600
    .line 601
    or-int/2addr v7, v9

    .line 602
    const/4 v9, 0x0

    .line 603
    move-object v10, v8

    .line 604
    move v8, v7

    .line 605
    const v7, 0x7f080426

    .line 606
    .line 607
    .line 608
    move-object/from16 v35, v10

    .line 609
    .line 610
    move-object v11, v13

    .line 611
    move/from16 v13, p8

    .line 612
    .line 613
    move-object/from16 v10, p10

    .line 614
    .line 615
    invoke-static/range {v7 .. v13}, Li91/j0;->j0(IIILay0/a;Ll2/o;Lx2/s;Z)V

    .line 616
    .line 617
    .line 618
    move-object v9, v11

    .line 619
    const/4 v7, 0x1

    .line 620
    invoke-virtual {v9, v7}, Ll2/t;->q(Z)V

    .line 621
    .line 622
    .line 623
    sget-object v7, Lk1/j;->a:Lk1/c;

    .line 624
    .line 625
    const/16 v8, 0x30

    .line 626
    .line 627
    invoke-static {v7, v15, v9, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 628
    .line 629
    .line 630
    move-result-object v7

    .line 631
    iget-wide v10, v9, Ll2/t;->T:J

    .line 632
    .line 633
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 634
    .line 635
    .line 636
    move-result v8

    .line 637
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 638
    .line 639
    .line 640
    move-result-object v10

    .line 641
    invoke-static {v9, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 642
    .line 643
    .line 644
    move-result-object v11

    .line 645
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 646
    .line 647
    .line 648
    iget-boolean v12, v9, Ll2/t;->S:Z

    .line 649
    .line 650
    if-eqz v12, :cond_1c

    .line 651
    .line 652
    invoke-virtual {v9, v14}, Ll2/t;->l(Lay0/a;)V

    .line 653
    .line 654
    .line 655
    goto :goto_14

    .line 656
    :cond_1c
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 657
    .line 658
    .line 659
    :goto_14
    invoke-static {v1, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 660
    .line 661
    .line 662
    invoke-static {v4, v10, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 663
    .line 664
    .line 665
    iget-boolean v7, v9, Ll2/t;->S:Z

    .line 666
    .line 667
    if-nez v7, :cond_1d

    .line 668
    .line 669
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v7

    .line 673
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 674
    .line 675
    .line 676
    move-result-object v10

    .line 677
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 678
    .line 679
    .line 680
    move-result v7

    .line 681
    if-nez v7, :cond_1e

    .line 682
    .line 683
    :cond_1d
    invoke-static {v8, v9, v8, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 684
    .line 685
    .line 686
    :cond_1e
    invoke-static {v2, v11, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 687
    .line 688
    .line 689
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 690
    .line 691
    .line 692
    move-result-object v7

    .line 693
    invoke-virtual {v7}, Lj91/f;->h()Lg4/p0;

    .line 694
    .line 695
    .line 696
    move-result-object v7

    .line 697
    move v8, v6

    .line 698
    move-object v6, v7

    .line 699
    invoke-static {v5, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 700
    .line 701
    .line 702
    move-result-object v7

    .line 703
    shr-int/lit8 v3, v31, 0x3

    .line 704
    .line 705
    and-int/lit8 v10, v3, 0xe

    .line 706
    .line 707
    or-int/lit16 v10, v10, 0x180

    .line 708
    .line 709
    and-int/lit16 v3, v3, 0x1c00

    .line 710
    .line 711
    or-int v24, v10, v3

    .line 712
    .line 713
    const/16 v25, 0x0

    .line 714
    .line 715
    const v26, 0xfff0

    .line 716
    .line 717
    .line 718
    const-wide/16 v10, 0x0

    .line 719
    .line 720
    const/4 v12, 0x0

    .line 721
    move-object v3, v14

    .line 722
    const-wide/16 v13, 0x0

    .line 723
    .line 724
    const/4 v15, 0x0

    .line 725
    const/16 v16, 0x0

    .line 726
    .line 727
    const-wide/16 v17, 0x0

    .line 728
    .line 729
    const/16 v19, 0x0

    .line 730
    .line 731
    const/16 v20, 0x0

    .line 732
    .line 733
    const/16 v21, 0x0

    .line 734
    .line 735
    const/16 v22, 0x0

    .line 736
    .line 737
    move-object/from16 v29, v5

    .line 738
    .line 739
    move/from16 v36, v8

    .line 740
    .line 741
    move-object/from16 v23, v9

    .line 742
    .line 743
    move-object/from16 v5, p1

    .line 744
    .line 745
    move-wide/from16 v8, p4

    .line 746
    .line 747
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 748
    .line 749
    .line 750
    move-wide v5, v8

    .line 751
    move-object/from16 v9, v23

    .line 752
    .line 753
    if-eqz p6, :cond_1f

    .line 754
    .line 755
    const v7, 0x7460fa4e

    .line 756
    .line 757
    .line 758
    invoke-virtual {v9, v7}, Ll2/t;->Y(I)V

    .line 759
    .line 760
    .line 761
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 762
    .line 763
    .line 764
    move-result-object v7

    .line 765
    iget v7, v7, Lj91/c;->b:F

    .line 766
    .line 767
    const/16 v20, 0x0

    .line 768
    .line 769
    const/16 v21, 0xe

    .line 770
    .line 771
    const/16 v18, 0x0

    .line 772
    .line 773
    const/16 v19, 0x0

    .line 774
    .line 775
    move/from16 v17, v7

    .line 776
    .line 777
    move-object/from16 v16, v29

    .line 778
    .line 779
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 780
    .line 781
    .line 782
    move-result-object v7

    .line 783
    const/16 v8, 0x1c

    .line 784
    .line 785
    int-to-float v8, v8

    .line 786
    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 787
    .line 788
    .line 789
    move-result-object v7

    .line 790
    const-string v8, "battery_gauge_bolt"

    .line 791
    .line 792
    invoke-static {v7, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 793
    .line 794
    .line 795
    move-result-object v7

    .line 796
    const v8, 0x7f0802dc

    .line 797
    .line 798
    .line 799
    const/4 v15, 0x0

    .line 800
    invoke-static {v8, v15, v9}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 801
    .line 802
    .line 803
    move-result-object v8

    .line 804
    new-instance v11, Le3/m;

    .line 805
    .line 806
    const/4 v10, 0x5

    .line 807
    invoke-direct {v11, v5, v6, v10}, Le3/m;-><init>(JI)V

    .line 808
    .line 809
    .line 810
    const/16 v13, 0x30

    .line 811
    .line 812
    const/16 v14, 0x38

    .line 813
    .line 814
    const/4 v6, 0x0

    .line 815
    move-object v5, v8

    .line 816
    const/4 v8, 0x0

    .line 817
    move-object/from16 v23, v9

    .line 818
    .line 819
    const/4 v9, 0x0

    .line 820
    const/4 v10, 0x0

    .line 821
    move-object/from16 v12, v23

    .line 822
    .line 823
    invoke-static/range {v5 .. v14}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 824
    .line 825
    .line 826
    move-object v11, v12

    .line 827
    :goto_15
    invoke-virtual {v11, v15}, Ll2/t;->q(Z)V

    .line 828
    .line 829
    .line 830
    const/4 v7, 0x1

    .line 831
    goto :goto_16

    .line 832
    :cond_1f
    move-object v11, v9

    .line 833
    move-object/from16 v16, v29

    .line 834
    .line 835
    const/4 v15, 0x0

    .line 836
    const v5, 0x73a009fb

    .line 837
    .line 838
    .line 839
    invoke-virtual {v11, v5}, Ll2/t;->Y(I)V

    .line 840
    .line 841
    .line 842
    goto :goto_15

    .line 843
    :goto_16
    invoke-virtual {v11, v7}, Ll2/t;->q(Z)V

    .line 844
    .line 845
    .line 846
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 847
    .line 848
    .line 849
    move-result-object v5

    .line 850
    iget v5, v5, Lj91/c;->e:F

    .line 851
    .line 852
    const/16 v20, 0x0

    .line 853
    .line 854
    const/16 v21, 0xb

    .line 855
    .line 856
    const/16 v17, 0x0

    .line 857
    .line 858
    const/16 v18, 0x0

    .line 859
    .line 860
    move/from16 v19, v5

    .line 861
    .line 862
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 863
    .line 864
    .line 865
    move-result-object v5

    .line 866
    move-object/from16 v12, v16

    .line 867
    .line 868
    move/from16 v6, v34

    .line 869
    .line 870
    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 871
    .line 872
    .line 873
    move-result-object v5

    .line 874
    new-instance v8, Ld4/i;

    .line 875
    .line 876
    const/4 v15, 0x0

    .line 877
    invoke-direct {v8, v15}, Ld4/i;-><init>(I)V

    .line 878
    .line 879
    .line 880
    const/16 v10, 0xa

    .line 881
    .line 882
    const/4 v7, 0x0

    .line 883
    move/from16 v6, p7

    .line 884
    .line 885
    move-object/from16 v9, p9

    .line 886
    .line 887
    invoke-static/range {v5 .. v10}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 888
    .line 889
    .line 890
    move-result-object v5

    .line 891
    if-eqz p7, :cond_20

    .line 892
    .line 893
    const/high16 v14, 0x3f800000    # 1.0f

    .line 894
    .line 895
    goto :goto_17

    .line 896
    :cond_20
    move/from16 v14, v28

    .line 897
    .line 898
    :goto_17
    invoke-static {v5, v14}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 899
    .line 900
    .line 901
    move-result-object v5

    .line 902
    move-object/from16 v10, v35

    .line 903
    .line 904
    invoke-static {v10, v15}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 905
    .line 906
    .line 907
    move-result-object v6

    .line 908
    iget-wide v7, v11, Ll2/t;->T:J

    .line 909
    .line 910
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 911
    .line 912
    .line 913
    move-result v7

    .line 914
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 915
    .line 916
    .line 917
    move-result-object v8

    .line 918
    invoke-static {v11, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 919
    .line 920
    .line 921
    move-result-object v5

    .line 922
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 923
    .line 924
    .line 925
    iget-boolean v9, v11, Ll2/t;->S:Z

    .line 926
    .line 927
    if-eqz v9, :cond_21

    .line 928
    .line 929
    invoke-virtual {v11, v3}, Ll2/t;->l(Lay0/a;)V

    .line 930
    .line 931
    .line 932
    goto :goto_18

    .line 933
    :cond_21
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 934
    .line 935
    .line 936
    :goto_18
    invoke-static {v1, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 937
    .line 938
    .line 939
    invoke-static {v4, v8, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 940
    .line 941
    .line 942
    iget-boolean v1, v11, Ll2/t;->S:Z

    .line 943
    .line 944
    if-nez v1, :cond_22

    .line 945
    .line 946
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 947
    .line 948
    .line 949
    move-result-object v1

    .line 950
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 951
    .line 952
    .line 953
    move-result-object v3

    .line 954
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 955
    .line 956
    .line 957
    move-result v1

    .line 958
    if-nez v1, :cond_23

    .line 959
    .line 960
    :cond_22
    invoke-static {v7, v11, v7, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 961
    .line 962
    .line 963
    :cond_23
    invoke-static {v2, v5, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 964
    .line 965
    .line 966
    move/from16 v8, v36

    .line 967
    .line 968
    invoke-static {v12, v8}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 969
    .line 970
    .line 971
    move-result-object v0

    .line 972
    const-string v1, "plus_button"

    .line 973
    .line 974
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 975
    .line 976
    .line 977
    move-result-object v10

    .line 978
    shr-int/lit8 v0, v31, 0x15

    .line 979
    .line 980
    and-int/lit8 v0, v0, 0x70

    .line 981
    .line 982
    or-int/lit16 v0, v0, 0x180

    .line 983
    .line 984
    shr-int/lit8 v1, v31, 0x9

    .line 985
    .line 986
    and-int/lit16 v1, v1, 0x1c00

    .line 987
    .line 988
    or-int v6, v0, v1

    .line 989
    .line 990
    const/4 v7, 0x0

    .line 991
    const v5, 0x7f080466

    .line 992
    .line 993
    .line 994
    move-object/from16 v8, p9

    .line 995
    .line 996
    move-object v9, v11

    .line 997
    move/from16 v11, p7

    .line 998
    .line 999
    invoke-static/range {v5 .. v11}, Li91/j0;->j0(IIILay0/a;Ll2/o;Lx2/s;Z)V

    .line 1000
    .line 1001
    .line 1002
    const/4 v7, 0x1

    .line 1003
    invoke-virtual {v9, v7}, Ll2/t;->q(Z)V

    .line 1004
    .line 1005
    .line 1006
    invoke-virtual {v9, v7}, Ll2/t;->q(Z)V

    .line 1007
    .line 1008
    .line 1009
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1010
    .line 1011
    .line 1012
    move-result-object v0

    .line 1013
    iget v0, v0, Lj91/c;->d:F

    .line 1014
    .line 1015
    invoke-static {v12, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v0

    .line 1019
    invoke-static {v9, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1020
    .line 1021
    .line 1022
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v0

    .line 1026
    invoke-virtual {v0}, Lj91/f;->l()Lg4/p0;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v6

    .line 1030
    move-object/from16 v0, v33

    .line 1031
    .line 1032
    invoke-static {v12, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v7

    .line 1036
    shr-int/lit8 v0, v31, 0x6

    .line 1037
    .line 1038
    and-int/lit8 v0, v0, 0xe

    .line 1039
    .line 1040
    or-int/lit16 v0, v0, 0x180

    .line 1041
    .line 1042
    const/16 v25, 0x0

    .line 1043
    .line 1044
    const v26, 0xfff8

    .line 1045
    .line 1046
    .line 1047
    move-object/from16 v23, v9

    .line 1048
    .line 1049
    const-wide/16 v8, 0x0

    .line 1050
    .line 1051
    const-wide/16 v10, 0x0

    .line 1052
    .line 1053
    const/4 v12, 0x0

    .line 1054
    const-wide/16 v13, 0x0

    .line 1055
    .line 1056
    const/4 v15, 0x0

    .line 1057
    const/16 v16, 0x0

    .line 1058
    .line 1059
    const-wide/16 v17, 0x0

    .line 1060
    .line 1061
    const/16 v19, 0x0

    .line 1062
    .line 1063
    const/16 v20, 0x0

    .line 1064
    .line 1065
    const/16 v21, 0x0

    .line 1066
    .line 1067
    const/16 v22, 0x0

    .line 1068
    .line 1069
    move-object/from16 v5, p2

    .line 1070
    .line 1071
    move/from16 v24, v0

    .line 1072
    .line 1073
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1074
    .line 1075
    .line 1076
    move-object/from16 v9, v23

    .line 1077
    .line 1078
    const/4 v15, 0x0

    .line 1079
    invoke-virtual {v9, v15}, Ll2/t;->q(Z)V

    .line 1080
    .line 1081
    .line 1082
    goto/16 :goto_19

    .line 1083
    .line 1084
    :cond_24
    move-object v3, v12

    .line 1085
    move-object v0, v14

    .line 1086
    move-object v12, v7

    .line 1087
    const v1, -0x6f8252b4

    .line 1088
    .line 1089
    .line 1090
    invoke-virtual {v9, v1}, Ll2/t;->Y(I)V

    .line 1091
    .line 1092
    .line 1093
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 1094
    .line 1095
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v2

    .line 1099
    check-cast v2, Lj91/f;

    .line 1100
    .line 1101
    invoke-virtual {v2}, Lj91/f;->l()Lg4/p0;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v6

    .line 1105
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 1106
    .line 1107
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1108
    .line 1109
    .line 1110
    move-result-object v4

    .line 1111
    check-cast v4, Lj91/e;

    .line 1112
    .line 1113
    invoke-virtual {v4}, Lj91/e;->r()J

    .line 1114
    .line 1115
    .line 1116
    move-result-wide v4

    .line 1117
    invoke-static {v12, v15}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v7

    .line 1121
    and-int/lit8 v8, v31, 0xe

    .line 1122
    .line 1123
    or-int/lit16 v8, v8, 0x180

    .line 1124
    .line 1125
    const/16 v25, 0x0

    .line 1126
    .line 1127
    const v26, 0xfff0

    .line 1128
    .line 1129
    .line 1130
    const-wide/16 v10, 0x0

    .line 1131
    .line 1132
    move-object/from16 v16, v12

    .line 1133
    .line 1134
    const/4 v12, 0x0

    .line 1135
    const-wide/16 v13, 0x0

    .line 1136
    .line 1137
    const/4 v15, 0x0

    .line 1138
    move-object/from16 v29, v16

    .line 1139
    .line 1140
    const/16 v16, 0x0

    .line 1141
    .line 1142
    const-wide/16 v17, 0x0

    .line 1143
    .line 1144
    const/16 v19, 0x0

    .line 1145
    .line 1146
    const/16 v20, 0x0

    .line 1147
    .line 1148
    const/16 v21, 0x0

    .line 1149
    .line 1150
    const/16 v22, 0x0

    .line 1151
    .line 1152
    move/from16 v24, v8

    .line 1153
    .line 1154
    move-object/from16 v23, v9

    .line 1155
    .line 1156
    move-wide v8, v4

    .line 1157
    move-object/from16 v4, v29

    .line 1158
    .line 1159
    move-object/from16 v5, p0

    .line 1160
    .line 1161
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1162
    .line 1163
    .line 1164
    move-object/from16 v9, v23

    .line 1165
    .line 1166
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 1167
    .line 1168
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v6

    .line 1172
    check-cast v6, Lj91/c;

    .line 1173
    .line 1174
    iget v6, v6, Lj91/c;->d:F

    .line 1175
    .line 1176
    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 1177
    .line 1178
    .line 1179
    move-result-object v6

    .line 1180
    invoke-static {v9, v6}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1181
    .line 1182
    .line 1183
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v6

    .line 1187
    check-cast v6, Lj91/f;

    .line 1188
    .line 1189
    invoke-virtual {v6}, Lj91/f;->h()Lg4/p0;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v6

    .line 1193
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1194
    .line 1195
    .line 1196
    move-result-object v2

    .line 1197
    check-cast v2, Lj91/e;

    .line 1198
    .line 1199
    invoke-virtual {v2}, Lj91/e;->r()J

    .line 1200
    .line 1201
    .line 1202
    move-result-wide v7

    .line 1203
    invoke-static {v4, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v2

    .line 1207
    shr-int/lit8 v3, v31, 0x3

    .line 1208
    .line 1209
    and-int/lit8 v3, v3, 0xe

    .line 1210
    .line 1211
    or-int/lit16 v3, v3, 0x180

    .line 1212
    .line 1213
    move/from16 v24, v3

    .line 1214
    .line 1215
    move-wide v8, v7

    .line 1216
    move-object v7, v2

    .line 1217
    move-object v2, v5

    .line 1218
    move-object/from16 v5, p1

    .line 1219
    .line 1220
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1221
    .line 1222
    .line 1223
    move-object/from16 v9, v23

    .line 1224
    .line 1225
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v2

    .line 1229
    check-cast v2, Lj91/c;

    .line 1230
    .line 1231
    iget v2, v2, Lj91/c;->d:F

    .line 1232
    .line 1233
    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v2

    .line 1237
    invoke-static {v9, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1238
    .line 1239
    .line 1240
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v1

    .line 1244
    check-cast v1, Lj91/f;

    .line 1245
    .line 1246
    invoke-virtual {v1}, Lj91/f;->l()Lg4/p0;

    .line 1247
    .line 1248
    .line 1249
    move-result-object v6

    .line 1250
    invoke-static {v4, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v7

    .line 1254
    shr-int/lit8 v0, v31, 0x6

    .line 1255
    .line 1256
    and-int/lit8 v0, v0, 0xe

    .line 1257
    .line 1258
    or-int/lit16 v0, v0, 0x180

    .line 1259
    .line 1260
    const v26, 0xfff8

    .line 1261
    .line 1262
    .line 1263
    const-wide/16 v8, 0x0

    .line 1264
    .line 1265
    move-object/from16 v5, p2

    .line 1266
    .line 1267
    move/from16 v24, v0

    .line 1268
    .line 1269
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1270
    .line 1271
    .line 1272
    move-object/from16 v9, v23

    .line 1273
    .line 1274
    const/4 v15, 0x0

    .line 1275
    invoke-virtual {v9, v15}, Ll2/t;->q(Z)V

    .line 1276
    .line 1277
    .line 1278
    goto :goto_19

    .line 1279
    :cond_25
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 1280
    .line 1281
    .line 1282
    :goto_19
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v13

    .line 1286
    if-eqz v13, :cond_26

    .line 1287
    .line 1288
    new-instance v0, Lxf0/l;

    .line 1289
    .line 1290
    move-object/from16 v1, p0

    .line 1291
    .line 1292
    move-object/from16 v2, p1

    .line 1293
    .line 1294
    move-object/from16 v3, p2

    .line 1295
    .line 1296
    move/from16 v4, p3

    .line 1297
    .line 1298
    move-wide/from16 v5, p4

    .line 1299
    .line 1300
    move/from16 v7, p6

    .line 1301
    .line 1302
    move/from16 v8, p7

    .line 1303
    .line 1304
    move/from16 v9, p8

    .line 1305
    .line 1306
    move-object/from16 v10, p9

    .line 1307
    .line 1308
    move-object/from16 v11, p10

    .line 1309
    .line 1310
    move/from16 v12, p12

    .line 1311
    .line 1312
    invoke-direct/range {v0 .. v12}, Lxf0/l;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZZLay0/a;Lay0/a;I)V

    .line 1313
    .line 1314
    .line 1315
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 1316
    .line 1317
    :cond_26
    return-void
.end method

.method public static final b(Lx2/s;IIIILgy0/j;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLay0/a;Lay0/a;ZLl2/o;III)V
    .locals 62

    move-object/from16 v1, p0

    move/from16 v0, p18

    move/from16 v2, p19

    move/from16 v3, p20

    .line 1
    move-object/from16 v4, p17

    check-cast v4, Ll2/t;

    const v5, -0x63c9c6f3

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

    if-eqz v15, :cond_9

    or-int/lit16 v5, v5, 0xc00

    :cond_8
    move/from16 v12, p3

    goto :goto_7

    :cond_9
    and-int/lit16 v12, v0, 0xc00

    if-nez v12, :cond_8

    move/from16 v12, p3

    invoke-virtual {v4, v12}, Ll2/t;->e(I)Z

    move-result v18

    if-eqz v18, :cond_a

    const/16 v18, 0x800

    goto :goto_6

    :cond_a
    move/from16 v18, v16

    :goto_6
    or-int v5, v5, v18

    :goto_7
    and-int/lit16 v9, v0, 0x6000

    const/16 v19, 0x2000

    const/16 v20, 0x4000

    if-nez v9, :cond_d

    and-int/lit8 v9, v3, 0x10

    if-nez v9, :cond_b

    move/from16 v9, p4

    invoke-virtual {v4, v9}, Ll2/t;->e(I)Z

    move-result v21

    if-eqz v21, :cond_c

    move/from16 v21, v20

    goto :goto_8

    :cond_b
    move/from16 v9, p4

    :cond_c
    move/from16 v21, v19

    :goto_8
    or-int v5, v5, v21

    goto :goto_9

    :cond_d
    move/from16 v9, p4

    :goto_9
    const/high16 v21, 0x30000

    and-int v22, v0, v21

    const/high16 v23, 0x20000

    const/high16 v24, 0x10000

    if-nez v22, :cond_10

    and-int/lit8 v22, v3, 0x20

    move-object/from16 v10, p5

    if-nez v22, :cond_e

    const/16 v22, 0x20

    invoke-virtual {v4, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_f

    move/from16 v25, v23

    goto :goto_a

    :cond_e
    const/16 v22, 0x20

    :cond_f
    move/from16 v25, v24

    :goto_a
    or-int v5, v5, v25

    goto :goto_b

    :cond_10
    move-object/from16 v10, p5

    const/16 v22, 0x20

    :goto_b
    and-int/lit8 v25, v3, 0x40

    const/high16 v26, 0x80000

    const/high16 v27, 0x100000

    const/high16 v28, 0x180000

    if-eqz v25, :cond_11

    or-int v5, v5, v28

    move-object/from16 v13, p6

    goto :goto_d

    :cond_11
    and-int v29, v0, v28

    move-object/from16 v13, p6

    if-nez v29, :cond_13

    invoke-virtual {v4, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_12

    move/from16 v30, v27

    goto :goto_c

    :cond_12
    move/from16 v30, v26

    :goto_c
    or-int v5, v5, v30

    :cond_13
    :goto_d
    and-int/lit16 v6, v3, 0x80

    const/high16 v31, 0xc00000

    if-eqz v6, :cond_14

    or-int v5, v5, v31

    move-object/from16 v7, p7

    goto :goto_f

    :cond_14
    and-int v31, v0, v31

    move-object/from16 v7, p7

    if-nez v31, :cond_16

    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v32

    if-eqz v32, :cond_15

    const/high16 v32, 0x800000

    goto :goto_e

    :cond_15
    const/high16 v32, 0x400000

    :goto_e
    or-int v5, v5, v32

    :cond_16
    :goto_f
    and-int/lit16 v0, v3, 0x100

    const/high16 v32, 0x6000000

    if-eqz v0, :cond_18

    or-int v5, v5, v32

    :cond_17
    move/from16 v32, v0

    move-object/from16 v0, p8

    goto :goto_11

    :cond_18
    and-int v32, p18, v32

    if-nez v32, :cond_17

    move/from16 v32, v0

    move-object/from16 v0, p8

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v33

    if-eqz v33, :cond_19

    const/high16 v33, 0x4000000

    goto :goto_10

    :cond_19
    const/high16 v33, 0x2000000

    :goto_10
    or-int v5, v5, v33

    :goto_11
    and-int/lit16 v0, v3, 0x200

    const/high16 v33, 0x30000000

    if-eqz v0, :cond_1b

    or-int v5, v5, v33

    :cond_1a
    move/from16 v33, v0

    move-object/from16 v0, p9

    goto :goto_13

    :cond_1b
    and-int v33, p18, v33

    if-nez v33, :cond_1a

    move/from16 v33, v0

    move-object/from16 v0, p9

    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v34

    if-eqz v34, :cond_1c

    const/high16 v34, 0x20000000

    goto :goto_12

    :cond_1c
    const/high16 v34, 0x10000000

    :goto_12
    or-int v5, v5, v34

    :goto_13
    and-int/lit16 v0, v3, 0x400

    if-eqz v0, :cond_1d

    or-int/lit8 v34, v2, 0x6

    move/from16 v35, v0

    move/from16 v0, p10

    goto :goto_15

    :cond_1d
    move/from16 v35, v0

    move/from16 v0, p10

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v34

    if-eqz v34, :cond_1e

    const/16 v34, 0x4

    goto :goto_14

    :cond_1e
    const/16 v34, 0x2

    :goto_14
    or-int v34, v2, v34

    :goto_15
    and-int/lit16 v0, v3, 0x800

    if-eqz v0, :cond_1f

    or-int/lit8 v34, v34, 0x30

    move/from16 v36, v0

    :goto_16
    move/from16 v0, v34

    goto :goto_18

    :cond_1f
    and-int/lit8 v36, v2, 0x30

    if-nez v36, :cond_21

    move/from16 v36, v0

    move/from16 v0, p11

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v37

    if-eqz v37, :cond_20

    move/from16 v37, v22

    goto :goto_17

    :cond_20
    const/16 v37, 0x10

    :goto_17
    or-int v34, v34, v37

    goto :goto_16

    :cond_21
    move/from16 v36, v0

    move/from16 v0, p11

    goto :goto_16

    :goto_18
    move/from16 p17, v5

    and-int/lit16 v5, v3, 0x1000

    if-eqz v5, :cond_22

    or-int/lit16 v0, v0, 0x180

    goto :goto_1a

    :cond_22
    move/from16 v34, v0

    and-int/lit16 v0, v2, 0x180

    if-nez v0, :cond_24

    move/from16 v0, p12

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v37

    if-eqz v37, :cond_23

    const/16 v17, 0x100

    goto :goto_19

    :cond_23
    const/16 v17, 0x80

    :goto_19
    or-int v17, v34, v17

    move/from16 v0, v17

    goto :goto_1a

    :cond_24
    move/from16 v0, p12

    move/from16 v0, v34

    :goto_1a
    move/from16 v17, v5

    and-int/lit16 v5, v3, 0x2000

    if-eqz v5, :cond_25

    or-int/lit16 v0, v0, 0xc00

    goto :goto_1b

    :cond_25
    move/from16 v34, v0

    and-int/lit16 v0, v2, 0xc00

    if-nez v0, :cond_27

    move/from16 v0, p13

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v37

    if-eqz v37, :cond_26

    const/16 v16, 0x800

    :cond_26
    or-int v16, v34, v16

    move/from16 v0, v16

    goto :goto_1b

    :cond_27
    move/from16 v0, p13

    move/from16 v0, v34

    :goto_1b
    and-int/lit16 v2, v3, 0x4000

    if-eqz v2, :cond_28

    or-int/lit16 v0, v0, 0x6000

    move/from16 v16, v0

    move-object/from16 v0, p14

    goto :goto_1c

    :cond_28
    move/from16 v16, v0

    move-object/from16 v0, p14

    invoke-virtual {v4, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v34

    if-eqz v34, :cond_29

    move/from16 v19, v20

    :cond_29
    or-int v16, v16, v19

    :goto_1c
    const v19, 0x8000

    and-int v19, v3, v19

    if-eqz v19, :cond_2a

    or-int v16, v16, v21

    move-object/from16 v0, p15

    goto :goto_1e

    :cond_2a
    move-object/from16 v0, p15

    invoke-virtual {v4, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_2b

    goto :goto_1d

    :cond_2b
    move/from16 v23, v24

    :goto_1d
    or-int v16, v16, v23

    :goto_1e
    and-int v20, v3, v24

    if-eqz v20, :cond_2c

    or-int v16, v16, v28

    :goto_1f
    move/from16 v0, v16

    goto :goto_20

    :cond_2c
    move/from16 v0, p16

    invoke-virtual {v4, v0}, Ll2/t;->h(Z)Z

    move-result v21

    if-eqz v21, :cond_2d

    move/from16 v26, v27

    :cond_2d
    or-int v16, v16, v26

    goto :goto_1f

    :goto_20
    const v16, 0x12492493

    move/from16 v21, v2

    and-int v2, p17, v16

    const v3, 0x12492492

    move/from16 v16, v5

    if-ne v2, v3, :cond_2f

    const v2, 0x92493

    and-int/2addr v2, v0

    const v3, 0x92492

    if-eq v2, v3, :cond_2e

    goto :goto_21

    :cond_2e
    const/4 v2, 0x0

    goto :goto_22

    :cond_2f
    :goto_21
    const/4 v2, 0x1

    :goto_22
    and-int/lit8 v3, p17, 0x1

    invoke-virtual {v4, v3, v2}, Ll2/t;->O(IZ)Z

    move-result v2

    if-eqz v2, :cond_60

    invoke-virtual {v4}, Ll2/t;->T()V

    and-int/lit8 v2, p18, 0x1

    sget-object v3, Lxf0/m;->a:Lgy0/j;

    const v24, -0x70001

    const v26, -0xe001

    sget-object v5, Ll2/n;->a:Ll2/x0;

    move/from16 v28, v2

    if-eqz v28, :cond_34

    invoke-virtual {v4}, Ll2/t;->y()Z

    move-result v28

    if-eqz v28, :cond_30

    goto :goto_24

    .line 2
    :cond_30
    invoke-virtual {v4}, Ll2/t;->R()V

    and-int/lit8 v6, p20, 0x2

    if-eqz v6, :cond_31

    and-int/lit8 v6, p17, -0x71

    goto :goto_23

    :cond_31
    move/from16 v6, p17

    :goto_23
    and-int/lit8 v11, p20, 0x10

    if-eqz v11, :cond_32

    and-int v6, v6, v26

    :cond_32
    and-int/lit8 v11, p20, 0x20

    if-eqz v11, :cond_33

    and-int v6, v6, v24

    :cond_33
    move-object/from16 v2, p8

    move/from16 v34, p10

    move/from16 v35, p11

    move/from16 v33, p12

    move/from16 v52, p13

    move/from16 v16, p16

    move/from16 v28, v6

    move-object v15, v10

    move v11, v14

    move-object/from16 v10, p9

    move-object/from16 v6, p14

    move-object/from16 v14, p15

    goto/16 :goto_33

    :cond_34
    :goto_24
    and-int/lit8 v28, p20, 0x2

    if-eqz v28, :cond_35

    .line 3
    iget v8, v3, Lgy0/h;->d:I

    and-int/lit8 v28, p17, -0x71

    goto :goto_25

    :cond_35
    move/from16 v28, p17

    :goto_25
    if-eqz v11, :cond_36

    const/16 v11, 0x14

    goto :goto_26

    :cond_36
    move v11, v14

    :goto_26
    if-eqz v15, :cond_37

    const/16 v12, 0xa

    :cond_37
    and-int/lit8 v14, p20, 0x10

    .line 4
    sget-object v15, Lxf0/m;->b:Lgy0/j;

    if-eqz v14, :cond_38

    .line 5
    iget v9, v15, Lgy0/h;->e:I

    and-int v28, v28, v26

    :cond_38
    and-int/lit8 v14, p20, 0x20

    if-eqz v14, :cond_39

    and-int v10, v28, v24

    move/from16 v28, v10

    goto :goto_27

    :cond_39
    move-object v15, v10

    :goto_27
    if-eqz v25, :cond_3a

    const/4 v13, 0x0

    .line 6
    :cond_3a
    const-string v10, ""

    if-eqz v6, :cond_3b

    move-object v7, v10

    :cond_3b
    if-eqz v32, :cond_3c

    move-object v6, v10

    goto :goto_28

    :cond_3c
    move-object/from16 v6, p8

    :goto_28
    if-eqz v33, :cond_3d

    goto :goto_29

    :cond_3d
    move-object/from16 v10, p9

    :goto_29
    if-eqz v35, :cond_3e

    const/4 v14, 0x0

    goto :goto_2a

    :cond_3e
    move/from16 v14, p10

    :goto_2a
    if-eqz v36, :cond_3f

    const/16 v24, 0x0

    goto :goto_2b

    :cond_3f
    move/from16 v24, p11

    :goto_2b
    if-eqz v17, :cond_40

    const/16 v17, 0x0

    goto :goto_2c

    :cond_40
    move/from16 v17, p12

    :goto_2c
    if-eqz v16, :cond_41

    const/16 v16, 0x0

    goto :goto_2d

    :cond_41
    move/from16 v16, p13

    :goto_2d
    if-eqz v21, :cond_43

    .line 7
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v5, :cond_42

    .line 8
    new-instance v2, Lxf/b;

    move-object/from16 p1, v6

    const/4 v6, 0x4

    invoke-direct {v2, v6}, Lxf/b;-><init>(I)V

    .line 9
    invoke-virtual {v4, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_2e

    :cond_42
    move-object/from16 p1, v6

    .line 10
    :goto_2e
    check-cast v2, Lay0/a;

    goto :goto_2f

    :cond_43
    move-object/from16 p1, v6

    move-object/from16 v2, p14

    :goto_2f
    if-eqz v19, :cond_45

    .line 11
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v5, :cond_44

    .line 12
    new-instance v6, Lxf/b;

    move-object/from16 p2, v2

    const/4 v2, 0x4

    invoke-direct {v6, v2}, Lxf/b;-><init>(I)V

    .line 13
    invoke-virtual {v4, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    goto :goto_30

    :cond_44
    move-object/from16 p2, v2

    .line 14
    :goto_30
    move-object v2, v6

    check-cast v2, Lay0/a;

    goto :goto_31

    :cond_45
    move-object/from16 p2, v2

    move-object/from16 v2, p15

    :goto_31
    move-object/from16 v6, p2

    move/from16 v34, v14

    move/from16 v52, v16

    move/from16 v33, v17

    move/from16 v35, v24

    if-eqz v20, :cond_46

    const/16 v16, 0x0

    :goto_32
    move-object v14, v2

    move-object/from16 v2, p1

    goto :goto_33

    :cond_46
    move/from16 v16, p16

    goto :goto_32

    .line 15
    :goto_33
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 16
    invoke-static {v8, v3}, Lkp/r9;->f(ILgy0/g;)I

    move-result v3

    move-object/from16 p12, v2

    .line 17
    invoke-static {v9, v15}, Lkp/r9;->f(ILgy0/g;)I

    move-result v2

    move-object/from16 p13, v6

    const/16 v6, 0x168

    int-to-float v6, v6

    move/from16 v17, v6

    int-to-float v6, v3

    const/high16 v19, 0x42c80000    # 100.0f

    div-float v6, v6, v19

    mul-float v6, v6, v17

    move/from16 p9, v6

    const/16 v6, -0x168

    int-to-float v6, v6

    move/from16 v17, v6

    rsub-int/lit8 v6, v2, 0x64

    int-to-float v6, v6

    div-float v6, v6, v19

    mul-float v6, v6, v17

    if-nez v34, :cond_49

    if-le v3, v11, :cond_47

    goto :goto_35

    :cond_47
    if-le v3, v12, :cond_48

    const v3, 0x678cc317

    .line 18
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    sget-object v3, Lxf0/h0;->h:Lxf0/h0;

    invoke-virtual {v3, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v19

    const/4 v3, 0x0

    .line 19
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    :goto_34
    move-wide/from16 v55, v19

    goto :goto_36

    :cond_48
    const v3, 0x678cc9d7

    .line 20
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    sget-object v3, Lxf0/h0;->i:Lxf0/h0;

    invoke-virtual {v3, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v19

    const/4 v3, 0x0

    .line 21
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    goto :goto_34

    :cond_49
    :goto_35
    const v3, 0x678cb937

    .line 22
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    sget-object v3, Lxf0/h0;->f:Lxf0/h0;

    invoke-virtual {v3, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v19

    const/4 v3, 0x0

    .line 23
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    goto :goto_34

    :goto_36
    if-eqz v16, :cond_4a

    const v3, -0x75f23599

    .line 24
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    .line 25
    const-string v3, "gaugePulseColorTransition"

    move/from16 v17, v6

    const/4 v6, 0x0

    invoke-static {v3, v4, v6}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    move-result-object v3

    .line 26
    new-instance v6, Lc1/s;

    move-object/from16 p1, v3

    move-object/from16 v19, v4

    move-object/from16 v20, v7

    move/from16 v21, v8

    const/high16 v3, 0x3f800000    # 1.0f

    const v4, 0x3ecccccd    # 0.4f

    const v7, 0x3f19999a    # 0.6f

    const/4 v8, 0x0

    invoke-direct {v6, v4, v8, v7, v3}, Lc1/s;-><init>(FFFF)V

    .line 27
    new-instance v3, Lc1/a2;

    const/16 v4, 0x4b0

    const/4 v7, 0x0

    invoke-direct {v3, v4, v7, v6}, Lc1/a2;-><init>(IILc1/w;)V

    .line 28
    sget-object v4, Lc1/t0;->d:Lc1/t0;

    const/4 v6, 0x4

    .line 29
    invoke-static {v3, v4, v6}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    move-result-object v3

    const/16 v4, 0x71b8

    const/4 v6, 0x0

    const v7, 0x3f333333    # 0.7f

    const/4 v8, 0x0

    .line 30
    const-string v24, "gaugePulseAnimationColor"

    move-object/from16 p4, v3

    move/from16 p7, v4

    move/from16 p8, v6

    move/from16 p2, v7

    move/from16 p3, v8

    move-object/from16 p6, v19

    move-object/from16 p5, v24

    invoke-static/range {p1 .. p8}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    move-result-object v3

    move-object/from16 v4, p6

    .line 31
    sget-object v6, Lxf0/h0;->f:Lxf0/h0;

    invoke-virtual {v6, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v6

    .line 32
    iget-object v3, v3, Lc1/g0;->g:Ll2/j1;

    .line 33
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v3

    .line 34
    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    .line 35
    invoke-static {v6, v7, v3}, Le3/s;->b(JF)J

    move-result-wide v6

    const/4 v3, 0x0

    .line 36
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    goto :goto_37

    :cond_4a
    move/from16 v17, v6

    move-object/from16 v20, v7

    move/from16 v21, v8

    const/4 v3, 0x0

    const v6, -0x75e96f4f

    .line 37
    invoke-virtual {v4, v6}, Ll2/t;->Y(I)V

    .line 38
    sget-object v6, Lxf0/h0;->f:Lxf0/h0;

    invoke-virtual {v6, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v6

    const v8, 0x3f19999a    # 0.6f

    invoke-static {v6, v7, v8}, Le3/s;->b(JF)J

    move-result-wide v6

    .line 39
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 40
    :goto_37
    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v3

    move/from16 v19, v9

    invoke-virtual {v3}, Lj91/e;->m()J

    move-result-wide v8

    .line 41
    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v3

    move-object/from16 v25, v10

    move/from16 v24, v11

    invoke-virtual {v3}, Lj91/e;->k()J

    move-result-wide v10

    .line 42
    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v3

    move/from16 v26, v12

    move-object/from16 v32, v13

    invoke-virtual {v3}, Lj91/e;->l()J

    move-result-wide v12

    .line 43
    sget-object v3, Lxf0/h0;->o:Lxf0/h0;

    move-object/from16 v57, v14

    move-object/from16 v36, v15

    invoke-virtual {v3, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v14

    if-eqz v52, :cond_4b

    const v3, 0x678d4e7a

    .line 44
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    invoke-static {v4}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v3

    invoke-virtual {v3}, Lj91/e;->s()J

    move-result-wide v37

    const/4 v3, 0x0

    .line 45
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    :goto_38
    move/from16 v58, v2

    move-wide/from16 v59, v37

    goto :goto_39

    :cond_4b
    const/4 v3, 0x0

    if-eqz v34, :cond_4c

    const v3, 0x678d55b7

    .line 46
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    sget-object v3, Lxf0/h0;->f:Lxf0/h0;

    invoke-virtual {v3, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v37

    const/4 v3, 0x0

    .line 47
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    goto :goto_38

    :cond_4c
    move/from16 v58, v2

    const v2, 0x678d5918

    .line 48
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    .line 49
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    move-wide/from16 v59, v55

    :goto_39
    if-eqz v35, :cond_4d

    const v2, 0x678d6257

    .line 50
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    sget-object v2, Lxf0/h0;->m:Lxf0/h0;

    :goto_3a
    invoke-virtual {v2, v4}, Lxf0/h0;->a(Ll2/o;)J

    move-result-wide v37

    .line 51
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    move-wide/from16 v2, v37

    move-object/from16 v37, v5

    goto :goto_3b

    :cond_4d
    const v2, 0x678d6717

    .line 52
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    sget-object v2, Lxf0/h0;->n:Lxf0/h0;

    goto :goto_3a

    :goto_3b
    const/16 v5, 0x18

    int-to-float v5, v5

    .line 53
    invoke-static {v5}, Lxf0/i0;->O(F)I

    move-result v5

    int-to-float v5, v5

    const v38, 0x3eaaaaab

    mul-float v38, v38, v5

    const/high16 v39, 0x3fa00000    # 1.25f

    .line 54
    invoke-static/range {v39 .. v39}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v39

    if-eqz v16, :cond_4e

    goto :goto_3c

    :cond_4e
    const/16 v39, 0x0

    :goto_3c
    if-eqz v39, :cond_4f

    invoke-virtual/range {v39 .. v39}, Ljava/lang/Float;->floatValue()F

    move-result v39

    goto :goto_3d

    :cond_4f
    const/high16 v39, 0x3f400000    # 0.75f

    :goto_3d
    mul-float v39, v39, v5

    move/from16 v40, v5

    move-wide/from16 v50, v12

    const/4 v5, 0x4

    int-to-float v12, v5

    .line 55
    invoke-static {v12}, Lxf0/i0;->O(F)I

    move-result v5

    int-to-float v5, v5

    .line 56
    sget-object v12, Lc1/t0;->d:Lc1/t0;

    if-eqz v16, :cond_50

    goto :goto_3e

    :cond_50
    const/4 v12, 0x0

    :goto_3e
    if-nez v12, :cond_51

    sget-object v12, Lc1/t0;->e:Lc1/t0;

    :cond_51
    if-eqz v34, :cond_52

    if-eqz v35, :cond_52

    const v13, -0x75d82e4b

    .line 57
    invoke-virtual {v4, v13}, Ll2/t;->Y(I)V

    .line 58
    const-string v13, "gaugePulseTransition"

    move/from16 v41, v5

    const/4 v5, 0x0

    invoke-static {v13, v4, v5}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    move-result-object v13

    .line 59
    new-instance v5, Lc1/s;

    move-object/from16 p6, v4

    move-wide/from16 v48, v10

    move-object/from16 p1, v13

    const/high16 v4, 0x3f800000    # 1.0f

    const v10, 0x3f19999a    # 0.6f

    const/4 v11, 0x0

    const v13, 0x3ecccccd    # 0.4f

    invoke-direct {v5, v13, v11, v10, v4}, Lc1/s;-><init>(FFFF)V

    .line 60
    new-instance v4, Lc1/a2;

    const/16 v10, 0x4b0

    const/4 v13, 0x0

    invoke-direct {v4, v10, v13, v5}, Lc1/a2;-><init>(IILc1/w;)V

    const/4 v5, 0x4

    .line 61
    invoke-static {v4, v12, v5}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    move-result-object v4

    const/16 v5, 0x7038

    const/4 v10, 0x0

    const/4 v11, 0x0

    .line 62
    const-string v12, "gaugePulseAnimation"

    move-object/from16 p4, v4

    move/from16 p7, v5

    move/from16 p8, v10

    move/from16 p2, v11

    move-object/from16 p5, v12

    move/from16 p3, v39

    invoke-static/range {p1 .. p8}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    move-result-object v4

    move/from16 v10, p3

    move-object/from16 v5, p6

    .line 63
    iget-object v4, v4, Lc1/g0;->g:Ll2/j1;

    .line 64
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v4

    .line 65
    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    move-result v4

    .line 66
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    move v11, v4

    goto :goto_3f

    :cond_52
    move/from16 v41, v5

    move-wide/from16 v48, v10

    move/from16 v10, v39

    const/4 v11, 0x0

    const/4 v13, 0x0

    move-object v5, v4

    const v4, -0x75cfa29d

    .line 67
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 68
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    :goto_3f
    if-eqz v33, :cond_53

    const v4, -0x75ce4a1a

    .line 69
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 70
    const-string v4, "gaugeBackgroundTransition"

    invoke-static {v4, v5, v13}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    move-result-object v4

    .line 71
    invoke-static {v5}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v12

    invoke-virtual {v12}, Lj91/e;->o()J

    move-result-wide v12

    invoke-static {v5}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v39

    move-object/from16 p1, v4

    move-object/from16 p6, v5

    invoke-virtual/range {v39 .. v39}, Lj91/e;->i()J

    move-result-wide v4

    invoke-static {v12, v13, v4, v5}, Le3/j0;->l(JJ)J

    move-result-wide v4

    .line 72
    invoke-static/range {p6 .. p6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v12

    invoke-virtual {v12}, Lj91/e;->d()J

    move-result-wide v12

    move-wide/from16 p4, v4

    const/16 v4, 0x320

    const/16 v5, 0xc8

    move/from16 p14, v10

    move/from16 p15, v11

    const/4 v10, 0x0

    const/4 v11, 0x4

    .line 73
    invoke-static {v4, v5, v10, v11}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    move-result-object v4

    .line 74
    sget-object v5, Lc1/t0;->e:Lc1/t0;

    .line 75
    invoke-static {v4, v5, v11}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    move-result-object v4

    move-object/from16 p7, p6

    move-object/from16 p6, v4

    move-wide/from16 p2, v12

    .line 76
    invoke-static/range {p1 .. p7}, Ljp/y1;->b(Lc1/i0;JJLc1/f0;Ll2/o;)Lc1/g0;

    move-result-object v4

    move-object/from16 v5, p7

    .line 77
    iget-object v4, v4, Lc1/g0;->g:Ll2/j1;

    .line 78
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    move-result-object v4

    .line 79
    check-cast v4, Le3/s;

    .line 80
    iget-wide v10, v4, Le3/s;->a:J

    const/4 v13, 0x0

    .line 81
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    goto :goto_40

    :cond_53
    move/from16 p14, v10

    move/from16 p15, v11

    const v4, -0x75c3a19e

    .line 82
    invoke-virtual {v5, v4}, Ll2/t;->Y(I)V

    .line 83
    invoke-static {v5}, Llp/nb;->a(Ll2/o;)Lj91/e;

    move-result-object v4

    invoke-virtual {v4}, Lj91/e;->d()J

    move-result-wide v10

    .line 84
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    .line 85
    :goto_40
    new-instance v53, Lxf0/v0;

    const/4 v4, 0x0

    move/from16 p6, p9

    move/from16 p7, v4

    move/from16 p8, v17

    move/from16 p4, v21

    move/from16 p11, v24

    move/from16 p10, v26

    move-object/from16 p5, v32

    move-object/from16 p9, v36

    move-object/from16 p3, v53

    invoke-direct/range {p3 .. p11}, Lxf0/v0;-><init>(ILjava/lang/Integer;FFFLgy0/j;II)V

    move-object/from16 v13, p3

    move-object/from16 v12, p5

    move-object/from16 v4, p9

    .line 86
    new-instance v54, Lxf0/a1;

    move/from16 p5, p14

    move/from16 p4, p15

    move/from16 p3, v38

    move/from16 p2, v40

    move/from16 p6, v41

    move-object/from16 p1, v54

    invoke-direct/range {p1 .. p6}, Lxf0/a1;-><init>(FFFFF)V

    move/from16 v17, p5

    move-object/from16 p15, v4

    move-object/from16 p14, v12

    move-object/from16 v12, p1

    .line 87
    sget-object v4, Lw3/h1;->t:Ll2/u2;

    .line 88
    invoke-virtual {v5, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lw3/j2;

    .line 89
    check-cast v4, Lw3/r1;

    invoke-virtual {v4}, Lw3/r1;->a()J

    move-result-wide v38

    move-object/from16 p3, v13

    shr-long v12, v38, v22

    long-to-int v4, v12

    .line 90
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    .line 91
    invoke-static {v4}, Lxf0/i0;->N(Ljava/lang/Number;)F

    move-result v4

    float-to-double v12, v4

    const-wide v38, 0x3fe999999999999aL    # 0.8

    mul-double v12, v12, v38

    double-to-int v4, v12

    const/16 v12, 0x122

    const/16 v13, 0x186

    .line 92
    invoke-static {v4, v12, v13}, Lkp/r9;->e(III)I

    move-result v4

    .line 93
    sget-object v12, Lk1/j;->e:Lk1/f;

    .line 94
    sget-object v13, Lx2/c;->q:Lx2/h;

    move-object/from16 p2, v12

    const/4 v12, 0x2

    int-to-float v12, v12

    div-float v39, v17, v12

    .line 95
    invoke-static/range {v39 .. v39}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v12

    invoke-static {v12}, Lxf0/i0;->N(Ljava/lang/Number;)F

    move-result v12

    invoke-static {v1, v12}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    move-result-object v12

    int-to-float v4, v4

    .line 96
    invoke-static {v12, v4}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    move-result-object v4

    and-int/lit16 v12, v0, 0x380

    const/16 v1, 0x100

    if-ne v12, v1, :cond_54

    const/4 v1, 0x1

    goto :goto_41

    :cond_54
    const/4 v1, 0x0

    :goto_41
    and-int/lit8 v12, v0, 0xe

    move/from16 p4, v1

    const/4 v1, 0x4

    if-ne v12, v1, :cond_55

    const/4 v1, 0x1

    goto :goto_42

    :cond_55
    const/4 v1, 0x0

    :goto_42
    or-int v1, p4, v1

    and-int/lit8 v12, v0, 0x70

    move/from16 p4, v1

    move/from16 v1, v22

    if-ne v12, v1, :cond_56

    const/4 v1, 0x1

    goto :goto_43

    :cond_56
    const/4 v1, 0x0

    :goto_43
    or-int v1, p4, v1

    .line 97
    invoke-virtual {v5, v6, v7}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v1, v12

    invoke-virtual {v5, v10, v11}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v1, v12

    move-wide/from16 v29, v6

    move-wide/from16 v6, v55

    invoke-virtual {v5, v6, v7}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v1, v12

    invoke-virtual {v5, v8, v9}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v1, v12

    invoke-virtual {v5, v14, v15}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v1, v12

    invoke-virtual {v5, v2, v3}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v1, v12

    move/from16 p4, v1

    move-wide/from16 v46, v2

    move-wide/from16 v1, v48

    invoke-virtual {v5, v1, v2}, Ll2/t;->f(J)Z

    move-result v3

    or-int v3, p4, v3

    move-wide/from16 v1, v50

    invoke-virtual {v5, v1, v2}, Ll2/t;->f(J)Z

    move-result v12

    or-int/2addr v3, v12

    and-int/lit16 v12, v0, 0x1c00

    move/from16 p17, v0

    const/16 v0, 0x800

    if-ne v12, v0, :cond_57

    const/4 v0, 0x1

    goto :goto_44

    :cond_57
    const/4 v0, 0x0

    :goto_44
    or-int/2addr v0, v3

    move-object/from16 v3, p3

    invoke-virtual {v5, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v0, v12

    move-object/from16 v12, p1

    invoke-virtual {v5, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v17

    or-int v0, v0, v17

    move/from16 p1, v0

    .line 98
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v0

    move-wide/from16 v50, v1

    if-nez p1, :cond_58

    move-object/from16 v1, v37

    if-ne v0, v1, :cond_59

    .line 99
    :cond_58
    new-instance v32, Lxf0/i;

    move-object/from16 v53, v3

    move-wide/from16 v40, v6

    move-wide/from16 v42, v8

    move-wide/from16 v38, v10

    move-object/from16 v54, v12

    move-wide/from16 v44, v14

    move-wide/from16 v36, v29

    invoke-direct/range {v32 .. v54}, Lxf0/i;-><init>(ZZZJJJJJJJJZLxf0/v0;Lxf0/a1;)V

    move-object/from16 v0, v32

    .line 100
    invoke-virtual {v5, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 101
    :cond_59
    check-cast v0, Lay0/k;

    invoke-static {v4, v0}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    move-result-object v0

    const/16 v1, 0x36

    move-object/from16 v2, p2

    .line 102
    invoke-static {v2, v13, v5, v1}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    move-result-object v1

    .line 103
    iget-wide v2, v5, Ll2/t;->T:J

    .line 104
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    move-result v2

    .line 105
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    move-result-object v3

    .line 106
    invoke-static {v5, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 107
    sget-object v4, Lv3/k;->m1:Lv3/j;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 109
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 110
    iget-boolean v6, v5, Ll2/t;->S:Z

    if-eqz v6, :cond_5a

    .line 111
    invoke-virtual {v5, v4}, Ll2/t;->l(Lay0/a;)V

    goto :goto_45

    .line 112
    :cond_5a
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 113
    :goto_45
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 114
    invoke-static {v4, v1, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 116
    invoke-static {v1, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 118
    iget-boolean v3, v5, Ll2/t;->S:Z

    if-nez v3, :cond_5b

    .line 119
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_5c

    .line 120
    :cond_5b
    invoke-static {v2, v5, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 121
    :cond_5c
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 122
    invoke-static {v1, v0, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    move-object/from16 v4, p15

    if-eqz v52, :cond_5d

    .line 123
    iget v0, v4, Lgy0/h;->e:I

    move/from16 v1, v58

    if-ge v1, v0, :cond_5e

    const/4 v3, 0x1

    goto :goto_46

    :cond_5d
    move/from16 v1, v58

    :cond_5e
    const/4 v3, 0x0

    :goto_46
    if-eqz v52, :cond_5f

    .line 124
    iget v0, v4, Lgy0/h;->d:I

    if-le v1, v0, :cond_5f

    const/16 v23, 0x1

    goto :goto_47

    :cond_5f
    const/16 v23, 0x0

    :goto_47
    shr-int/lit8 v0, v28, 0x15

    and-int/lit16 v0, v0, 0x3fe

    shl-int/lit8 v1, p17, 0x6

    and-int/lit16 v1, v1, 0x1c00

    or-int/2addr v0, v1

    shl-int/lit8 v1, p17, 0xf

    const/high16 v2, 0x70000

    and-int/2addr v1, v2

    or-int/2addr v0, v1

    shl-int/lit8 v1, p17, 0xc

    const/high16 v2, 0xe000000

    and-int/2addr v2, v1

    or-int/2addr v0, v2

    const/high16 v2, 0x70000000

    and-int/2addr v1, v2

    or-int/2addr v0, v1

    move-object/from16 p2, p12

    move-object/from16 p10, p13

    move/from16 p13, v0

    move/from16 p8, v3

    move-object/from16 p12, v5

    move-object/from16 p1, v20

    move/from16 p9, v23

    move-object/from16 p3, v25

    move/from16 p7, v34

    move/from16 p4, v35

    move-object/from16 p11, v57

    move-wide/from16 p5, v59

    .line 125
    invoke-static/range {p1 .. p13}, Lxf0/m;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJZZZLay0/a;Lay0/a;Ll2/o;I)V

    move-object/from16 v0, p2

    move-object/from16 v1, p10

    const/4 v2, 0x1

    .line 126
    invoke-virtual {v5, v2}, Ll2/t;->q(Z)V

    move/from16 v2, v19

    move-object/from16 v19, v5

    move v5, v2

    move-object/from16 v7, p14

    move-object v9, v0

    move-object v15, v1

    move-object v6, v4

    move/from16 v17, v16

    move-object/from16 v8, v20

    move/from16 v2, v21

    move/from16 v3, v24

    move-object/from16 v10, v25

    move/from16 v4, v26

    move/from16 v13, v33

    move/from16 v11, v34

    move/from16 v12, v35

    move/from16 v14, v52

    move-object/from16 v16, v57

    goto :goto_48

    :cond_60
    move-object v5, v4

    .line 127
    invoke-virtual {v5}, Ll2/t;->R()V

    move/from16 v11, p10

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move/from16 v17, p16

    move-object/from16 v19, v5

    move v2, v8

    move v5, v9

    move-object v6, v10

    move v4, v12

    move v3, v14

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move/from16 v12, p11

    move/from16 v14, p13

    move-object v8, v7

    move-object v7, v13

    move/from16 v13, p12

    .line 128
    :goto_48
    invoke-virtual/range {v19 .. v19}, Ll2/t;->s()Ll2/u1;

    move-result-object v0

    if-eqz v0, :cond_61

    move-object v1, v0

    new-instance v0, Lxf0/j;

    move/from16 v18, p18

    move/from16 v19, p19

    move/from16 v20, p20

    move-object/from16 v61, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v20}, Lxf0/j;-><init>(Lx2/s;IIIILgy0/j;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLay0/a;Lay0/a;ZIII)V

    move-object/from16 v1, v61

    .line 129
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    :cond_61
    return-void
.end method

.method public static final c(Lg3/d;FJJJLg3/h;)V
    .locals 20

    .line 1
    const/4 v0, 0x3

    .line 2
    int-to-float v0, v0

    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-interface {v1, v0}, Lt4/c;->w0(F)F

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v2, 0x2

    .line 10
    int-to-float v3, v2

    .line 11
    mul-float/2addr v3, v0

    .line 12
    div-float/2addr v0, v3

    .line 13
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    sget-wide v5, Le3/s;->h:J

    .line 18
    .line 19
    new-instance v7, Le3/s;

    .line 20
    .line 21
    invoke-direct {v7, v5, v6}, Le3/s;-><init>(J)V

    .line 22
    .line 23
    .line 24
    new-instance v5, Llx0/l;

    .line 25
    .line 26
    invoke-direct {v5, v4, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    new-instance v4, Le3/s;

    .line 34
    .line 35
    move-wide/from16 v6, p2

    .line 36
    .line 37
    invoke-direct {v4, v6, v7}, Le3/s;-><init>(J)V

    .line 38
    .line 39
    .line 40
    new-instance v6, Llx0/l;

    .line 41
    .line 42
    invoke-direct {v6, v0, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    filled-new-array {v5, v6}, [Llx0/l;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    const/4 v4, 0x0

    .line 50
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    int-to-long v5, v5

    .line 55
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    int-to-long v7, v7

    .line 60
    const/16 v9, 0x20

    .line 61
    .line 62
    shl-long/2addr v5, v9

    .line 63
    const-wide v10, 0xffffffffL

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    and-long/2addr v7, v10

    .line 69
    or-long v15, v5, v7

    .line 70
    .line 71
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    int-to-long v5, v3

    .line 76
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    int-to-long v3, v3

    .line 81
    shl-long/2addr v5, v9

    .line 82
    and-long/2addr v3, v10

    .line 83
    or-long v17, v5, v3

    .line 84
    .line 85
    new-instance v13, Ljava/util/ArrayList;

    .line 86
    .line 87
    invoke-direct {v13, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 88
    .line 89
    .line 90
    const/4 v3, 0x0

    .line 91
    move v4, v3

    .line 92
    :goto_0
    if-ge v4, v2, :cond_0

    .line 93
    .line 94
    aget-object v5, v0, v4

    .line 95
    .line 96
    iget-object v5, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v5, Le3/s;

    .line 99
    .line 100
    iget-wide v5, v5, Le3/s;->a:J

    .line 101
    .line 102
    new-instance v7, Le3/s;

    .line 103
    .line 104
    invoke-direct {v7, v5, v6}, Le3/s;-><init>(J)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v13, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    add-int/lit8 v4, v4, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_0
    new-instance v14, Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-direct {v14, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 116
    .line 117
    .line 118
    :goto_1
    if-ge v3, v2, :cond_1

    .line 119
    .line 120
    aget-object v4, v0, v3

    .line 121
    .line 122
    iget-object v4, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v4, Ljava/lang/Number;

    .line 125
    .line 126
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    invoke-virtual {v14, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    add-int/lit8 v3, v3, 0x1

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_1
    new-instance v12, Le3/b0;

    .line 141
    .line 142
    const/16 v19, 0x1

    .line 143
    .line 144
    invoke-direct/range {v12 .. v19}, Le3/b0;-><init>(Ljava/util/List;Ljava/util/ArrayList;JJI)V

    .line 145
    .line 146
    .line 147
    move/from16 v3, p1

    .line 148
    .line 149
    move-wide/from16 v4, p4

    .line 150
    .line 151
    move-wide/from16 v6, p6

    .line 152
    .line 153
    move-object/from16 v8, p8

    .line 154
    .line 155
    move-object v2, v12

    .line 156
    invoke-interface/range {v1 .. v8}, Lg3/d;->Y(Le3/b0;FJJLg3/h;)V

    .line 157
    .line 158
    .line 159
    return-void
.end method
