.class public abstract Lxf0/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:J

.field public static final d:Lc1/s;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const/16 v0, 0xb4

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lxf0/b0;->a:F

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    int-to-float v0, v0

    .line 8
    sput v0, Lxf0/b0;->b:F

    .line 9
    .line 10
    sget v0, Le3/s;->j:I

    .line 11
    .line 12
    sget-wide v0, Le3/s;->c:J

    .line 13
    .line 14
    sput-wide v0, Lxf0/b0;->c:J

    .line 15
    .line 16
    new-instance v0, Lc1/s;

    .line 17
    .line 18
    const v1, 0x3f28f5c3    # 0.66f

    .line 19
    .line 20
    .line 21
    const/high16 v2, 0x3f800000    # 1.0f

    .line 22
    .line 23
    const v3, 0x3f47ae14    # 0.78f

    .line 24
    .line 25
    .line 26
    const v4, -0x43dc28f6    # -0.01f

    .line 27
    .line 28
    .line 29
    invoke-direct {v0, v3, v4, v1, v2}, Lc1/s;-><init>(FFFF)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lxf0/b0;->d:Lc1/s;

    .line 33
    .line 34
    return-void
.end method

.method public static final a(ILjava/util/List;IFLjava/lang/Integer;Ljava/util/List;Lay0/k;ZZLl2/o;I)V
    .locals 33

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v3, p2

    .line 6
    .line 7
    move/from16 v4, p3

    .line 8
    .line 9
    move-object/from16 v5, p4

    .line 10
    .line 11
    move-object/from16 v6, p5

    .line 12
    .line 13
    move-object/from16 v7, p6

    .line 14
    .line 15
    move/from16 v8, p7

    .line 16
    .line 17
    move/from16 v9, p8

    .line 18
    .line 19
    move-object/from16 v15, p9

    .line 20
    .line 21
    check-cast v15, Ll2/t;

    .line 22
    .line 23
    const v0, 0x7114b9a1

    .line 24
    .line 25
    .line 26
    invoke-virtual {v15, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v15, v1}, Ll2/t;->e(I)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    const/16 v0, 0x20

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/16 v0, 0x10

    .line 39
    .line 40
    :goto_0
    or-int v0, p10, v0

    .line 41
    .line 42
    invoke-virtual {v15, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v11

    .line 46
    if-eqz v11, :cond_1

    .line 47
    .line 48
    const/16 v11, 0x100

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    const/16 v11, 0x80

    .line 52
    .line 53
    :goto_1
    or-int/2addr v0, v11

    .line 54
    invoke-virtual {v15, v3}, Ll2/t;->e(I)Z

    .line 55
    .line 56
    .line 57
    move-result v11

    .line 58
    if-eqz v11, :cond_2

    .line 59
    .line 60
    const/16 v11, 0x800

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    const/16 v11, 0x400

    .line 64
    .line 65
    :goto_2
    or-int/2addr v0, v11

    .line 66
    invoke-virtual {v15, v4}, Ll2/t;->d(F)Z

    .line 67
    .line 68
    .line 69
    move-result v11

    .line 70
    if-eqz v11, :cond_3

    .line 71
    .line 72
    const/16 v11, 0x4000

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_3
    const/16 v11, 0x2000

    .line 76
    .line 77
    :goto_3
    or-int/2addr v0, v11

    .line 78
    invoke-virtual {v15, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    if-eqz v11, :cond_4

    .line 83
    .line 84
    const/high16 v11, 0x20000

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_4
    const/high16 v11, 0x10000

    .line 88
    .line 89
    :goto_4
    or-int/2addr v0, v11

    .line 90
    invoke-virtual {v15, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v11

    .line 94
    if-eqz v11, :cond_5

    .line 95
    .line 96
    const/high16 v11, 0x100000

    .line 97
    .line 98
    goto :goto_5

    .line 99
    :cond_5
    const/high16 v11, 0x80000

    .line 100
    .line 101
    :goto_5
    or-int/2addr v0, v11

    .line 102
    invoke-virtual {v15, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v11

    .line 106
    if-eqz v11, :cond_6

    .line 107
    .line 108
    const/high16 v11, 0x800000

    .line 109
    .line 110
    goto :goto_6

    .line 111
    :cond_6
    const/high16 v11, 0x400000

    .line 112
    .line 113
    :goto_6
    or-int/2addr v0, v11

    .line 114
    invoke-virtual {v15, v8}, Ll2/t;->h(Z)Z

    .line 115
    .line 116
    .line 117
    move-result v11

    .line 118
    if-eqz v11, :cond_7

    .line 119
    .line 120
    const/high16 v11, 0x4000000

    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_7
    const/high16 v11, 0x2000000

    .line 124
    .line 125
    :goto_7
    or-int/2addr v0, v11

    .line 126
    invoke-virtual {v15, v9}, Ll2/t;->h(Z)Z

    .line 127
    .line 128
    .line 129
    move-result v11

    .line 130
    if-eqz v11, :cond_8

    .line 131
    .line 132
    const/high16 v11, 0x20000000

    .line 133
    .line 134
    goto :goto_8

    .line 135
    :cond_8
    const/high16 v11, 0x10000000

    .line 136
    .line 137
    :goto_8
    or-int/2addr v0, v11

    .line 138
    const v11, 0x12492493

    .line 139
    .line 140
    .line 141
    and-int/2addr v11, v0

    .line 142
    const v13, 0x12492492

    .line 143
    .line 144
    .line 145
    move/from16 p9, v0

    .line 146
    .line 147
    if-eq v11, v13, :cond_9

    .line 148
    .line 149
    const/4 v11, 0x1

    .line 150
    goto :goto_9

    .line 151
    :cond_9
    const/4 v11, 0x0

    .line 152
    :goto_9
    and-int/lit8 v13, p9, 0x1

    .line 153
    .line 154
    invoke-virtual {v15, v13, v11}, Ll2/t;->O(IZ)Z

    .line 155
    .line 156
    .line 157
    move-result v11

    .line 158
    if-eqz v11, :cond_42

    .line 159
    .line 160
    move-object v11, v2

    .line 161
    check-cast v11, Ljava/lang/Iterable;

    .line 162
    .line 163
    new-instance v13, Ljava/util/ArrayList;

    .line 164
    .line 165
    const/16 v0, 0xa

    .line 166
    .line 167
    invoke-static {v11, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 168
    .line 169
    .line 170
    move-result v10

    .line 171
    invoke-direct {v13, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 172
    .line 173
    .line 174
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 175
    .line 176
    .line 177
    move-result-object v10

    .line 178
    :goto_a
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 179
    .line 180
    .line 181
    move-result v17

    .line 182
    if-eqz v17, :cond_a

    .line 183
    .line 184
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v17

    .line 188
    check-cast v17, Ljava/lang/Number;

    .line 189
    .line 190
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Number;->floatValue()F

    .line 191
    .line 192
    .line 193
    move-result v17

    .line 194
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 195
    .line 196
    .line 197
    move-result-object v12

    .line 198
    invoke-virtual {v13, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    goto :goto_a

    .line 202
    :cond_a
    new-instance v10, Ljava/util/ArrayList;

    .line 203
    .line 204
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 208
    .line 209
    .line 210
    move-result-object v12

    .line 211
    :goto_b
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 212
    .line 213
    .line 214
    move-result v13

    .line 215
    const/4 v0, 0x0

    .line 216
    if-eqz v13, :cond_c

    .line 217
    .line 218
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v13

    .line 222
    move-object/from16 v19, v13

    .line 223
    .line 224
    check-cast v19, Ljava/lang/Number;

    .line 225
    .line 226
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Number;->floatValue()F

    .line 227
    .line 228
    .line 229
    move-result v19

    .line 230
    cmpl-float v0, v19, v0

    .line 231
    .line 232
    if-lez v0, :cond_b

    .line 233
    .line 234
    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    :cond_b
    const/16 v0, 0xa

    .line 238
    .line 239
    goto :goto_b

    .line 240
    :cond_c
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 241
    .line 242
    .line 243
    move-result-object v10

    .line 244
    move v12, v0

    .line 245
    :goto_c
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 246
    .line 247
    .line 248
    move-result v13

    .line 249
    if-eqz v13, :cond_d

    .line 250
    .line 251
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v13

    .line 255
    check-cast v13, Ljava/lang/Number;

    .line 256
    .line 257
    invoke-virtual {v13}, Ljava/lang/Number;->floatValue()F

    .line 258
    .line 259
    .line 260
    move-result v13

    .line 261
    add-float/2addr v12, v13

    .line 262
    goto :goto_c

    .line 263
    :cond_d
    if-lez v3, :cond_e

    .line 264
    .line 265
    int-to-float v10, v3

    .line 266
    div-float/2addr v12, v10

    .line 267
    goto :goto_d

    .line 268
    :cond_e
    move v12, v0

    .line 269
    :goto_d
    invoke-static {v15}, Lxf0/y1;->F(Ll2/o;)Z

    .line 270
    .line 271
    .line 272
    move-result v10

    .line 273
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v13

    .line 277
    move/from16 v19, v0

    .line 278
    .line 279
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 280
    .line 281
    if-ne v13, v0, :cond_11

    .line 282
    .line 283
    if-nez v10, :cond_10

    .line 284
    .line 285
    if-nez v8, :cond_10

    .line 286
    .line 287
    if-eqz v10, :cond_f

    .line 288
    .line 289
    goto :goto_f

    .line 290
    :cond_f
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 291
    .line 292
    .line 293
    move-result-object v10

    .line 294
    invoke-static {v10}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 295
    .line 296
    .line 297
    move-result-object v10

    .line 298
    :goto_e
    move-object v13, v10

    .line 299
    goto :goto_10

    .line 300
    :cond_10
    :goto_f
    invoke-static {v12}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 301
    .line 302
    .line 303
    move-result-object v10

    .line 304
    invoke-static {v10}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 305
    .line 306
    .line 307
    move-result-object v10

    .line 308
    goto :goto_e

    .line 309
    :goto_10
    invoke-virtual {v15, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    :cond_11
    move-object v10, v13

    .line 313
    check-cast v10, Ll2/b1;

    .line 314
    .line 315
    const-string v13, "chartColumnValueTransition"

    .line 316
    .line 317
    const/16 v2, 0x36

    .line 318
    .line 319
    const/4 v14, 0x0

    .line 320
    invoke-static {v10, v13, v15, v2, v14}, Lc1/z1;->f(Ljava/lang/Object;Ljava/lang/String;Ll2/o;II)Lc1/w1;

    .line 321
    .line 322
    .line 323
    move-result-object v13

    .line 324
    iget-object v14, v13, Lc1/w1;->a:Lap0/o;

    .line 325
    .line 326
    move-object/from16 v20, v14

    .line 327
    .line 328
    sget-object v14, Lc1/d;->j:Lc1/b2;

    .line 329
    .line 330
    invoke-virtual {v13}, Lc1/w1;->g()Z

    .line 331
    .line 332
    .line 333
    move-result v21

    .line 334
    const v2, 0x63564970

    .line 335
    .line 336
    .line 337
    if-nez v21, :cond_15

    .line 338
    .line 339
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 340
    .line 341
    .line 342
    invoke-virtual {v15, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 343
    .line 344
    .line 345
    move-result v21

    .line 346
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v2

    .line 350
    if-nez v21, :cond_13

    .line 351
    .line 352
    if-ne v2, v0, :cond_12

    .line 353
    .line 354
    goto :goto_12

    .line 355
    :cond_12
    :goto_11
    const/4 v6, 0x0

    .line 356
    goto :goto_14

    .line 357
    :cond_13
    :goto_12
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 358
    .line 359
    .line 360
    move-result-object v2

    .line 361
    if-eqz v2, :cond_14

    .line 362
    .line 363
    invoke-virtual {v2}, Lv2/f;->e()Lay0/k;

    .line 364
    .line 365
    .line 366
    move-result-object v21

    .line 367
    move-object/from16 v3, v21

    .line 368
    .line 369
    goto :goto_13

    .line 370
    :cond_14
    const/4 v3, 0x0

    .line 371
    :goto_13
    invoke-static {v2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 372
    .line 373
    .line 374
    move-result-object v5

    .line 375
    :try_start_0
    invoke-virtual/range {v20 .. v20}, Lap0/o;->D()Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 379
    invoke-static {v2, v5, v3}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v15, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 383
    .line 384
    .line 385
    move-object v2, v6

    .line 386
    goto :goto_11

    .line 387
    :goto_14
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 388
    .line 389
    .line 390
    goto :goto_15

    .line 391
    :catchall_0
    move-exception v0

    .line 392
    invoke-static {v2, v5, v3}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 393
    .line 394
    .line 395
    throw v0

    .line 396
    :cond_15
    const v2, 0x635a29cd

    .line 397
    .line 398
    .line 399
    const/4 v6, 0x0

    .line 400
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 404
    .line 405
    .line 406
    invoke-virtual/range {v20 .. v20}, Lap0/o;->D()Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v2

    .line 410
    :goto_15
    check-cast v2, Ll2/b1;

    .line 411
    .line 412
    const v3, 0x259fdda0

    .line 413
    .line 414
    .line 415
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 416
    .line 417
    .line 418
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    check-cast v2, Ljava/lang/Number;

    .line 423
    .line 424
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 425
    .line 426
    .line 427
    move-result v2

    .line 428
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 429
    .line 430
    .line 431
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 432
    .line 433
    .line 434
    move-result-object v2

    .line 435
    invoke-virtual {v15, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 436
    .line 437
    .line 438
    move-result v5

    .line 439
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v6

    .line 443
    if-nez v5, :cond_16

    .line 444
    .line 445
    if-ne v6, v0, :cond_17

    .line 446
    .line 447
    :cond_16
    new-instance v5, Lb1/f0;

    .line 448
    .line 449
    const/16 v6, 0xa

    .line 450
    .line 451
    invoke-direct {v5, v13, v6}, Lb1/f0;-><init>(Lc1/w1;I)V

    .line 452
    .line 453
    .line 454
    invoke-static {v5}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 455
    .line 456
    .line 457
    move-result-object v6

    .line 458
    invoke-virtual {v15, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 459
    .line 460
    .line 461
    :cond_17
    check-cast v6, Ll2/t2;

    .line 462
    .line 463
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v5

    .line 467
    check-cast v5, Ll2/b1;

    .line 468
    .line 469
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 470
    .line 471
    .line 472
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v3

    .line 476
    check-cast v3, Ljava/lang/Number;

    .line 477
    .line 478
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 479
    .line 480
    .line 481
    move-result v3

    .line 482
    const/4 v6, 0x0

    .line 483
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 484
    .line 485
    .line 486
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 487
    .line 488
    .line 489
    move-result-object v3

    .line 490
    invoke-virtual {v15, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 491
    .line 492
    .line 493
    move-result v5

    .line 494
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v6

    .line 498
    if-nez v5, :cond_18

    .line 499
    .line 500
    if-ne v6, v0, :cond_19

    .line 501
    .line 502
    :cond_18
    new-instance v5, Lb1/f0;

    .line 503
    .line 504
    const/16 v6, 0xb

    .line 505
    .line 506
    invoke-direct {v5, v13, v6}, Lb1/f0;-><init>(Lc1/w1;I)V

    .line 507
    .line 508
    .line 509
    invoke-static {v5}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 510
    .line 511
    .line 512
    move-result-object v6

    .line 513
    invoke-virtual {v15, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 514
    .line 515
    .line 516
    :cond_19
    check-cast v6, Ll2/t2;

    .line 517
    .line 518
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v5

    .line 522
    check-cast v5, Lc1/r1;

    .line 523
    .line 524
    const-string v6, "$this$animateFloat"

    .line 525
    .line 526
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    const v5, -0x52accdbe

    .line 530
    .line 531
    .line 532
    invoke-virtual {v15, v5}, Ll2/t;->Y(I)V

    .line 533
    .line 534
    .line 535
    const/16 v5, 0x190

    .line 536
    .line 537
    sget-object v6, Lxf0/b0;->d:Lc1/s;

    .line 538
    .line 539
    move-object/from16 v20, v2

    .line 540
    .line 541
    const/4 v2, 0x2

    .line 542
    move-object/from16 v24, v3

    .line 543
    .line 544
    const/4 v3, 0x0

    .line 545
    invoke-static {v5, v3, v6, v2}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 546
    .line 547
    .line 548
    move-result-object v5

    .line 549
    invoke-virtual {v15, v3}, Ll2/t;->q(Z)V

    .line 550
    .line 551
    .line 552
    const/16 v3, 0x20

    .line 553
    .line 554
    const/high16 v16, 0x30000

    .line 555
    .line 556
    move-object v3, v10

    .line 557
    move v6, v12

    .line 558
    move-object v10, v13

    .line 559
    move-object/from16 v12, v24

    .line 560
    .line 561
    move-object v13, v5

    .line 562
    move-object v5, v11

    .line 563
    move-object/from16 v11, v20

    .line 564
    .line 565
    invoke-static/range {v10 .. v16}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 566
    .line 567
    .line 568
    move-result-object v10

    .line 569
    if-nez v8, :cond_1c

    .line 570
    .line 571
    const v11, 0x5adedf38

    .line 572
    .line 573
    .line 574
    invoke-virtual {v15, v11}, Ll2/t;->Y(I)V

    .line 575
    .line 576
    .line 577
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 578
    .line 579
    .line 580
    move-result-object v11

    .line 581
    invoke-virtual {v15, v6}, Ll2/t;->d(F)Z

    .line 582
    .line 583
    .line 584
    move-result v12

    .line 585
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 586
    .line 587
    .line 588
    move-result-object v13

    .line 589
    if-nez v12, :cond_1a

    .line 590
    .line 591
    if-ne v13, v0, :cond_1b

    .line 592
    .line 593
    :cond_1a
    new-instance v13, Lxf0/w;

    .line 594
    .line 595
    const/4 v12, 0x0

    .line 596
    invoke-direct {v13, v3, v6, v12}, Lxf0/w;-><init>(Ll2/b1;FLkotlin/coroutines/Continuation;)V

    .line 597
    .line 598
    .line 599
    invoke-virtual {v15, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 600
    .line 601
    .line 602
    :cond_1b
    check-cast v13, Lay0/n;

    .line 603
    .line 604
    invoke-static {v13, v11, v15}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 605
    .line 606
    .line 607
    const/4 v6, 0x0

    .line 608
    :goto_16
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 609
    .line 610
    .line 611
    goto :goto_17

    .line 612
    :cond_1c
    const/4 v6, 0x0

    .line 613
    const v3, 0x5a5d6f01

    .line 614
    .line 615
    .line 616
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 617
    .line 618
    .line 619
    goto :goto_16

    .line 620
    :goto_17
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 621
    .line 622
    invoke-direct {v3}, Ljava/util/LinkedHashMap;-><init>()V

    .line 623
    .line 624
    .line 625
    const v6, 0x7ecd7a71

    .line 626
    .line 627
    .line 628
    invoke-virtual {v15, v6}, Ll2/t;->Y(I)V

    .line 629
    .line 630
    .line 631
    move-object/from16 v6, p5

    .line 632
    .line 633
    check-cast v6, Ljava/lang/Iterable;

    .line 634
    .line 635
    invoke-static {v6}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 636
    .line 637
    .line 638
    move-result-object v6

    .line 639
    check-cast v6, Ljava/lang/Iterable;

    .line 640
    .line 641
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 642
    .line 643
    .line 644
    move-result-object v6

    .line 645
    const/16 v18, 0x0

    .line 646
    .line 647
    :goto_18
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 648
    .line 649
    .line 650
    move-result v11

    .line 651
    if-eqz v11, :cond_2b

    .line 652
    .line 653
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object v11

    .line 657
    add-int/lit8 v20, v18, 0x1

    .line 658
    .line 659
    if-ltz v18, :cond_2a

    .line 660
    .line 661
    check-cast v11, Le3/s;

    .line 662
    .line 663
    iget-wide v11, v11, Le3/s;->a:J

    .line 664
    .line 665
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 666
    .line 667
    .line 668
    move-result-object v13

    .line 669
    if-ne v13, v0, :cond_1d

    .line 670
    .line 671
    new-instance v13, Le3/s;

    .line 672
    .line 673
    invoke-direct {v13, v11, v12}, Le3/s;-><init>(J)V

    .line 674
    .line 675
    .line 676
    invoke-static {v13}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 677
    .line 678
    .line 679
    move-result-object v13

    .line 680
    invoke-virtual {v15, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 681
    .line 682
    .line 683
    :cond_1d
    check-cast v13, Ll2/b1;

    .line 684
    .line 685
    const-string v14, "chartColumnColorTransition"

    .line 686
    .line 687
    move-object/from16 v25, v5

    .line 688
    .line 689
    const/16 v2, 0x36

    .line 690
    .line 691
    const/4 v5, 0x0

    .line 692
    invoke-static {v13, v14, v15, v2, v5}, Lc1/z1;->f(Ljava/lang/Object;Ljava/lang/String;Ll2/o;II)Lc1/w1;

    .line 693
    .line 694
    .line 695
    move-result-object v14

    .line 696
    iget-object v2, v14, Lc1/w1;->a:Lap0/o;

    .line 697
    .line 698
    iget-object v5, v14, Lc1/w1;->d:Ll2/j1;

    .line 699
    .line 700
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 701
    .line 702
    .line 703
    move-result-object v5

    .line 704
    check-cast v5, Ll2/b1;

    .line 705
    .line 706
    move-object/from16 v26, v2

    .line 707
    .line 708
    const v2, 0x41d8e83e

    .line 709
    .line 710
    .line 711
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 712
    .line 713
    .line 714
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 715
    .line 716
    .line 717
    move-result-object v5

    .line 718
    check-cast v5, Le3/s;

    .line 719
    .line 720
    move-object/from16 v27, v3

    .line 721
    .line 722
    iget-wide v2, v5, Le3/s;->a:J

    .line 723
    .line 724
    const/4 v5, 0x0

    .line 725
    invoke-virtual {v15, v5}, Ll2/t;->q(Z)V

    .line 726
    .line 727
    .line 728
    invoke-static {v2, v3}, Le3/s;->f(J)Lf3/c;

    .line 729
    .line 730
    .line 731
    move-result-object v2

    .line 732
    invoke-virtual {v15, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 733
    .line 734
    .line 735
    move-result v3

    .line 736
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 737
    .line 738
    .line 739
    move-result-object v5

    .line 740
    if-nez v3, :cond_1f

    .line 741
    .line 742
    if-ne v5, v0, :cond_1e

    .line 743
    .line 744
    goto :goto_19

    .line 745
    :cond_1e
    move-object/from16 v29, v6

    .line 746
    .line 747
    goto :goto_1a

    .line 748
    :cond_1f
    :goto_19
    sget-object v3, Lb1/c;->l:Lb1/c;

    .line 749
    .line 750
    new-instance v5, La3/f;

    .line 751
    .line 752
    move-object/from16 v29, v6

    .line 753
    .line 754
    const/4 v6, 0x7

    .line 755
    invoke-direct {v5, v2, v6}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 756
    .line 757
    .line 758
    new-instance v2, Lc1/b2;

    .line 759
    .line 760
    invoke-direct {v2, v3, v5}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 761
    .line 762
    .line 763
    invoke-virtual {v15, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 764
    .line 765
    .line 766
    move-object v5, v2

    .line 767
    :goto_1a
    check-cast v5, Lc1/b2;

    .line 768
    .line 769
    invoke-virtual {v14}, Lc1/w1;->g()Z

    .line 770
    .line 771
    .line 772
    move-result v2

    .line 773
    if-nez v2, :cond_23

    .line 774
    .line 775
    const v2, 0x63564970

    .line 776
    .line 777
    .line 778
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 779
    .line 780
    .line 781
    invoke-virtual {v15, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 782
    .line 783
    .line 784
    move-result v3

    .line 785
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v6

    .line 789
    if-nez v3, :cond_21

    .line 790
    .line 791
    if-ne v6, v0, :cond_20

    .line 792
    .line 793
    goto :goto_1c

    .line 794
    :cond_20
    move-object/from16 v30, v5

    .line 795
    .line 796
    :goto_1b
    const/4 v5, 0x0

    .line 797
    goto :goto_1e

    .line 798
    :cond_21
    :goto_1c
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 799
    .line 800
    .line 801
    move-result-object v3

    .line 802
    if-eqz v3, :cond_22

    .line 803
    .line 804
    invoke-virtual {v3}, Lv2/f;->e()Lay0/k;

    .line 805
    .line 806
    .line 807
    move-result-object v6

    .line 808
    goto :goto_1d

    .line 809
    :cond_22
    const/4 v6, 0x0

    .line 810
    :goto_1d
    invoke-static {v3}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 811
    .line 812
    .line 813
    move-result-object v2

    .line 814
    move-object/from16 v30, v5

    .line 815
    .line 816
    :try_start_1
    invoke-virtual/range {v26 .. v26}, Lap0/o;->D()Ljava/lang/Object;

    .line 817
    .line 818
    .line 819
    move-result-object v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 820
    invoke-static {v3, v2, v6}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 821
    .line 822
    .line 823
    invoke-virtual {v15, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 824
    .line 825
    .line 826
    move-object v6, v5

    .line 827
    goto :goto_1b

    .line 828
    :goto_1e
    invoke-virtual {v15, v5}, Ll2/t;->q(Z)V

    .line 829
    .line 830
    .line 831
    const v2, 0x635a29cd

    .line 832
    .line 833
    .line 834
    goto :goto_1f

    .line 835
    :catchall_1
    move-exception v0

    .line 836
    invoke-static {v3, v2, v6}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 837
    .line 838
    .line 839
    throw v0

    .line 840
    :cond_23
    move-object/from16 v30, v5

    .line 841
    .line 842
    const v2, 0x635a29cd

    .line 843
    .line 844
    .line 845
    const/4 v5, 0x0

    .line 846
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 847
    .line 848
    .line 849
    invoke-virtual {v15, v5}, Ll2/t;->q(Z)V

    .line 850
    .line 851
    .line 852
    invoke-virtual/range {v26 .. v26}, Lap0/o;->D()Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v6

    .line 856
    :goto_1f
    check-cast v6, Ll2/b1;

    .line 857
    .line 858
    const v3, 0x41d8e83e

    .line 859
    .line 860
    .line 861
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 862
    .line 863
    .line 864
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 865
    .line 866
    .line 867
    move-result-object v3

    .line 868
    check-cast v3, Le3/s;

    .line 869
    .line 870
    iget-wide v2, v3, Le3/s;->a:J

    .line 871
    .line 872
    invoke-virtual {v15, v5}, Ll2/t;->q(Z)V

    .line 873
    .line 874
    .line 875
    move-wide v5, v11

    .line 876
    new-instance v11, Le3/s;

    .line 877
    .line 878
    invoke-direct {v11, v2, v3}, Le3/s;-><init>(J)V

    .line 879
    .line 880
    .line 881
    invoke-virtual {v15, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 882
    .line 883
    .line 884
    move-result v2

    .line 885
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 886
    .line 887
    .line 888
    move-result-object v3

    .line 889
    if-nez v2, :cond_24

    .line 890
    .line 891
    if-ne v3, v0, :cond_25

    .line 892
    .line 893
    :cond_24
    new-instance v2, Lb1/f0;

    .line 894
    .line 895
    const/16 v3, 0xc

    .line 896
    .line 897
    invoke-direct {v2, v14, v3}, Lb1/f0;-><init>(Lc1/w1;I)V

    .line 898
    .line 899
    .line 900
    invoke-static {v2}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 901
    .line 902
    .line 903
    move-result-object v3

    .line 904
    invoke-virtual {v15, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 905
    .line 906
    .line 907
    :cond_25
    check-cast v3, Ll2/t2;

    .line 908
    .line 909
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 910
    .line 911
    .line 912
    move-result-object v2

    .line 913
    check-cast v2, Ll2/b1;

    .line 914
    .line 915
    const v3, 0x41d8e83e

    .line 916
    .line 917
    .line 918
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 919
    .line 920
    .line 921
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 922
    .line 923
    .line 924
    move-result-object v2

    .line 925
    check-cast v2, Le3/s;

    .line 926
    .line 927
    iget-wide v2, v2, Le3/s;->a:J

    .line 928
    .line 929
    const/4 v12, 0x0

    .line 930
    invoke-virtual {v15, v12}, Ll2/t;->q(Z)V

    .line 931
    .line 932
    .line 933
    new-instance v12, Le3/s;

    .line 934
    .line 935
    invoke-direct {v12, v2, v3}, Le3/s;-><init>(J)V

    .line 936
    .line 937
    .line 938
    invoke-virtual {v15, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 939
    .line 940
    .line 941
    move-result v2

    .line 942
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 943
    .line 944
    .line 945
    move-result-object v3

    .line 946
    if-nez v2, :cond_26

    .line 947
    .line 948
    if-ne v3, v0, :cond_27

    .line 949
    .line 950
    :cond_26
    new-instance v2, Lb1/f0;

    .line 951
    .line 952
    const/16 v3, 0xd

    .line 953
    .line 954
    invoke-direct {v2, v14, v3}, Lb1/f0;-><init>(Lc1/w1;I)V

    .line 955
    .line 956
    .line 957
    invoke-static {v2}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 958
    .line 959
    .line 960
    move-result-object v3

    .line 961
    invoke-virtual {v15, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 962
    .line 963
    .line 964
    :cond_27
    check-cast v3, Ll2/t2;

    .line 965
    .line 966
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 967
    .line 968
    .line 969
    move-result-object v2

    .line 970
    check-cast v2, Lc1/r1;

    .line 971
    .line 972
    const-string v3, "$this$animateColor"

    .line 973
    .line 974
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 975
    .line 976
    .line 977
    const v2, -0x5638bdfd

    .line 978
    .line 979
    .line 980
    invoke-virtual {v15, v2}, Ll2/t;->Y(I)V

    .line 981
    .line 982
    .line 983
    const/16 v2, 0xc8

    .line 984
    .line 985
    sget-object v3, Lc1/z;->d:Lc1/y;

    .line 986
    .line 987
    move-wide/from16 v31, v5

    .line 988
    .line 989
    const/4 v5, 0x2

    .line 990
    const/4 v6, 0x0

    .line 991
    invoke-static {v2, v6, v3, v5}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 992
    .line 993
    .line 994
    move-result-object v2

    .line 995
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 996
    .line 997
    .line 998
    move-object v3, v13

    .line 999
    move-wide/from16 v5, v31

    .line 1000
    .line 1001
    move-object v13, v2

    .line 1002
    move-object v2, v10

    .line 1003
    move-object v10, v14

    .line 1004
    move-object/from16 v14, v30

    .line 1005
    .line 1006
    invoke-static/range {v10 .. v16}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v10

    .line 1010
    new-instance v11, Le3/s;

    .line 1011
    .line 1012
    invoke-direct {v11, v5, v6}, Le3/s;-><init>(J)V

    .line 1013
    .line 1014
    .line 1015
    invoke-virtual {v15, v5, v6}, Ll2/t;->f(J)Z

    .line 1016
    .line 1017
    .line 1018
    move-result v12

    .line 1019
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 1020
    .line 1021
    .line 1022
    move-result-object v13

    .line 1023
    if-nez v12, :cond_28

    .line 1024
    .line 1025
    if-ne v13, v0, :cond_29

    .line 1026
    .line 1027
    :cond_28
    new-instance v13, Lg1/n2;

    .line 1028
    .line 1029
    const/4 v12, 0x0

    .line 1030
    invoke-direct {v13, v3, v5, v6, v12}, Lg1/n2;-><init>(Ll2/b1;JLkotlin/coroutines/Continuation;)V

    .line 1031
    .line 1032
    .line 1033
    invoke-virtual {v15, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1034
    .line 1035
    .line 1036
    :cond_29
    check-cast v13, Lay0/n;

    .line 1037
    .line 1038
    invoke-static {v13, v11, v15}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1039
    .line 1040
    .line 1041
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1042
    .line 1043
    .line 1044
    move-result-object v3

    .line 1045
    iget-object v5, v10, Lc1/t1;->m:Ll2/j1;

    .line 1046
    .line 1047
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v5

    .line 1051
    check-cast v5, Le3/s;

    .line 1052
    .line 1053
    iget-wide v5, v5, Le3/s;->a:J

    .line 1054
    .line 1055
    new-instance v10, Le3/s;

    .line 1056
    .line 1057
    invoke-direct {v10, v5, v6}, Le3/s;-><init>(J)V

    .line 1058
    .line 1059
    .line 1060
    move-object/from16 v5, v27

    .line 1061
    .line 1062
    invoke-interface {v5, v3, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-object v10, v2

    .line 1066
    move-object v3, v5

    .line 1067
    move/from16 v18, v20

    .line 1068
    .line 1069
    move-object/from16 v5, v25

    .line 1070
    .line 1071
    move-object/from16 v6, v29

    .line 1072
    .line 1073
    const/4 v2, 0x2

    .line 1074
    goto/16 :goto_18

    .line 1075
    .line 1076
    :cond_2a
    invoke-static {}, Ljp/k1;->r()V

    .line 1077
    .line 1078
    .line 1079
    const/16 v21, 0x0

    .line 1080
    .line 1081
    throw v21

    .line 1082
    :cond_2b
    move-object/from16 v25, v5

    .line 1083
    .line 1084
    move-object v2, v10

    .line 1085
    const/4 v6, 0x0

    .line 1086
    move-object v5, v3

    .line 1087
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 1088
    .line 1089
    .line 1090
    const/high16 v3, 0x3f800000    # 1.0f

    .line 1091
    .line 1092
    if-eqz p4, :cond_2d

    .line 1093
    .line 1094
    invoke-virtual/range {p4 .. p4}, Ljava/lang/Integer;->intValue()I

    .line 1095
    .line 1096
    .line 1097
    move-result v6

    .line 1098
    if-ne v1, v6, :cond_2c

    .line 1099
    .line 1100
    goto :goto_20

    .line 1101
    :cond_2c
    const v6, 0x3ecccccd    # 0.4f

    .line 1102
    .line 1103
    .line 1104
    goto :goto_21

    .line 1105
    :cond_2d
    :goto_20
    move v6, v3

    .line 1106
    :goto_21
    const v10, 0x7ecddd8c

    .line 1107
    .line 1108
    .line 1109
    invoke-virtual {v15, v10}, Ll2/t;->Y(I)V

    .line 1110
    .line 1111
    .line 1112
    float-to-double v10, v3

    .line 1113
    const-wide/16 v12, 0x0

    .line 1114
    .line 1115
    cmpl-double v10, v10, v12

    .line 1116
    .line 1117
    const-string v11, "invalid weight; must be greater than zero"

    .line 1118
    .line 1119
    if-lez v10, :cond_2e

    .line 1120
    .line 1121
    goto :goto_22

    .line 1122
    :cond_2e
    invoke-static {v11}, Ll1/a;->a(Ljava/lang/String;)V

    .line 1123
    .line 1124
    .line 1125
    :goto_22
    new-instance v10, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 1126
    .line 1127
    const v14, 0x7f7fffff    # Float.MAX_VALUE

    .line 1128
    .line 1129
    .line 1130
    cmpl-float v16, v3, v14

    .line 1131
    .line 1132
    move-wide/from16 v22, v12

    .line 1133
    .line 1134
    if-lez v16, :cond_2f

    .line 1135
    .line 1136
    move v12, v14

    .line 1137
    :goto_23
    const/4 v13, 0x1

    .line 1138
    goto :goto_24

    .line 1139
    :cond_2f
    move v12, v3

    .line 1140
    goto :goto_23

    .line 1141
    :goto_24
    invoke-direct {v10, v12, v13}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 1142
    .line 1143
    .line 1144
    invoke-static {v10, v3}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v26

    .line 1148
    if-eqz v9, :cond_34

    .line 1149
    .line 1150
    if-eqz v7, :cond_34

    .line 1151
    .line 1152
    const v10, -0x75a1d54

    .line 1153
    .line 1154
    .line 1155
    invoke-virtual {v15, v10}, Ll2/t;->Y(I)V

    .line 1156
    .line 1157
    .line 1158
    const/high16 v10, 0x1c00000

    .line 1159
    .line 1160
    and-int v10, p9, v10

    .line 1161
    .line 1162
    const/high16 v12, 0x800000

    .line 1163
    .line 1164
    if-ne v10, v12, :cond_30

    .line 1165
    .line 1166
    const/4 v10, 0x1

    .line 1167
    goto :goto_25

    .line 1168
    :cond_30
    const/4 v10, 0x0

    .line 1169
    :goto_25
    and-int/lit8 v12, p9, 0x70

    .line 1170
    .line 1171
    const/16 v13, 0x20

    .line 1172
    .line 1173
    if-ne v12, v13, :cond_31

    .line 1174
    .line 1175
    const/4 v12, 0x1

    .line 1176
    goto :goto_26

    .line 1177
    :cond_31
    const/4 v12, 0x0

    .line 1178
    :goto_26
    or-int/2addr v10, v12

    .line 1179
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v12

    .line 1183
    if-nez v10, :cond_32

    .line 1184
    .line 1185
    if-ne v12, v0, :cond_33

    .line 1186
    .line 1187
    :cond_32
    new-instance v12, Lcz/k;

    .line 1188
    .line 1189
    const/16 v0, 0xa

    .line 1190
    .line 1191
    invoke-direct {v12, v1, v0, v7}, Lcz/k;-><init>(IILay0/k;)V

    .line 1192
    .line 1193
    .line 1194
    invoke-virtual {v15, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1195
    .line 1196
    .line 1197
    :cond_33
    move-object/from16 v30, v12

    .line 1198
    .line 1199
    check-cast v30, Lay0/a;

    .line 1200
    .line 1201
    const/16 v31, 0xf

    .line 1202
    .line 1203
    const/16 v27, 0x0

    .line 1204
    .line 1205
    const/16 v28, 0x0

    .line 1206
    .line 1207
    const/16 v29, 0x0

    .line 1208
    .line 1209
    invoke-static/range {v26 .. v31}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v26

    .line 1213
    const/4 v12, 0x0

    .line 1214
    invoke-virtual {v15, v12}, Ll2/t;->q(Z)V

    .line 1215
    .line 1216
    .line 1217
    :goto_27
    move-object/from16 v0, v26

    .line 1218
    .line 1219
    goto :goto_28

    .line 1220
    :cond_34
    const/4 v12, 0x0

    .line 1221
    const v0, -0x758514b

    .line 1222
    .line 1223
    .line 1224
    invoke-virtual {v15, v0}, Ll2/t;->Y(I)V

    .line 1225
    .line 1226
    .line 1227
    invoke-virtual {v15, v12}, Ll2/t;->q(Z)V

    .line 1228
    .line 1229
    .line 1230
    goto :goto_27

    .line 1231
    :goto_28
    invoke-virtual {v15, v12}, Ll2/t;->q(Z)V

    .line 1232
    .line 1233
    .line 1234
    sget-object v10, Lk1/j;->e:Lk1/f;

    .line 1235
    .line 1236
    sget-object v12, Lx2/c;->o:Lx2/i;

    .line 1237
    .line 1238
    const/16 v13, 0x36

    .line 1239
    .line 1240
    invoke-static {v10, v12, v15, v13}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v10

    .line 1244
    iget-wide v12, v15, Ll2/t;->T:J

    .line 1245
    .line 1246
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 1247
    .line 1248
    .line 1249
    move-result v12

    .line 1250
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v13

    .line 1254
    invoke-static {v15, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1255
    .line 1256
    .line 1257
    move-result-object v0

    .line 1258
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 1259
    .line 1260
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1261
    .line 1262
    .line 1263
    move/from16 p9, v14

    .line 1264
    .line 1265
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 1266
    .line 1267
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 1268
    .line 1269
    .line 1270
    iget-boolean v3, v15, Ll2/t;->S:Z

    .line 1271
    .line 1272
    if-eqz v3, :cond_35

    .line 1273
    .line 1274
    invoke-virtual {v15, v14}, Ll2/t;->l(Lay0/a;)V

    .line 1275
    .line 1276
    .line 1277
    goto :goto_29

    .line 1278
    :cond_35
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 1279
    .line 1280
    .line 1281
    :goto_29
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 1282
    .line 1283
    invoke-static {v3, v10, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1284
    .line 1285
    .line 1286
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 1287
    .line 1288
    invoke-static {v10, v13, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1289
    .line 1290
    .line 1291
    sget-object v13, Lv3/j;->j:Lv3/h;

    .line 1292
    .line 1293
    iget-boolean v1, v15, Ll2/t;->S:Z

    .line 1294
    .line 1295
    if-nez v1, :cond_36

    .line 1296
    .line 1297
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 1298
    .line 1299
    .line 1300
    move-result-object v1

    .line 1301
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1302
    .line 1303
    .line 1304
    move-result-object v7

    .line 1305
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1306
    .line 1307
    .line 1308
    move-result v1

    .line 1309
    if-nez v1, :cond_37

    .line 1310
    .line 1311
    :cond_36
    invoke-static {v12, v15, v12, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1312
    .line 1313
    .line 1314
    :cond_37
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 1315
    .line 1316
    invoke-static {v1, v0, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1317
    .line 1318
    .line 1319
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 1320
    .line 1321
    invoke-static {v0, v6}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 1322
    .line 1323
    .line 1324
    move-result-object v0

    .line 1325
    iget-object v2, v2, Lc1/t1;->m:Ll2/j1;

    .line 1326
    .line 1327
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1328
    .line 1329
    .line 1330
    move-result-object v2

    .line 1331
    check-cast v2, Ljava/lang/Number;

    .line 1332
    .line 1333
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1334
    .line 1335
    .line 1336
    move-result v2

    .line 1337
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 1338
    .line 1339
    .line 1340
    move-result-object v0

    .line 1341
    move/from16 v6, v19

    .line 1342
    .line 1343
    const/high16 v2, 0x3f800000    # 1.0f

    .line 1344
    .line 1345
    invoke-static {v4, v6, v2}, Lkp/r9;->d(FFF)F

    .line 1346
    .line 1347
    .line 1348
    move-result v7

    .line 1349
    invoke-static {v0, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v0

    .line 1353
    invoke-static {v0, v8}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v0

    .line 1357
    sget v2, Lxf0/b0;->b:F

    .line 1358
    .line 1359
    invoke-static {v2, v2}, Ls1/f;->d(FF)Ls1/e;

    .line 1360
    .line 1361
    .line 1362
    move-result-object v2

    .line 1363
    invoke-static {v0, v2}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v0

    .line 1367
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 1368
    .line 1369
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 1370
    .line 1371
    const/4 v12, 0x0

    .line 1372
    invoke-static {v2, v6, v15, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v2

    .line 1376
    iget-wide v6, v15, Ll2/t;->T:J

    .line 1377
    .line 1378
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 1379
    .line 1380
    .line 1381
    move-result v6

    .line 1382
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 1383
    .line 1384
    .line 1385
    move-result-object v7

    .line 1386
    invoke-static {v15, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1387
    .line 1388
    .line 1389
    move-result-object v0

    .line 1390
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 1391
    .line 1392
    .line 1393
    iget-boolean v12, v15, Ll2/t;->S:Z

    .line 1394
    .line 1395
    if-eqz v12, :cond_38

    .line 1396
    .line 1397
    invoke-virtual {v15, v14}, Ll2/t;->l(Lay0/a;)V

    .line 1398
    .line 1399
    .line 1400
    goto :goto_2a

    .line 1401
    :cond_38
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 1402
    .line 1403
    .line 1404
    :goto_2a
    invoke-static {v3, v2, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1405
    .line 1406
    .line 1407
    invoke-static {v10, v7, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1408
    .line 1409
    .line 1410
    iget-boolean v2, v15, Ll2/t;->S:Z

    .line 1411
    .line 1412
    if-nez v2, :cond_39

    .line 1413
    .line 1414
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 1415
    .line 1416
    .line 1417
    move-result-object v2

    .line 1418
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v3

    .line 1422
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1423
    .line 1424
    .line 1425
    move-result v2

    .line 1426
    if-nez v2, :cond_3a

    .line 1427
    .line 1428
    :cond_39
    invoke-static {v6, v15, v6, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1429
    .line 1430
    .line 1431
    :cond_3a
    invoke-static {v1, v0, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1432
    .line 1433
    .line 1434
    const v0, -0x78487781

    .line 1435
    .line 1436
    .line 1437
    invoke-virtual {v15, v0}, Ll2/t;->Y(I)V

    .line 1438
    .line 1439
    .line 1440
    invoke-static/range {v25 .. v25}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v0

    .line 1444
    check-cast v0, Ljava/lang/Iterable;

    .line 1445
    .line 1446
    new-instance v1, Ljava/util/ArrayList;

    .line 1447
    .line 1448
    const/16 v2, 0xa

    .line 1449
    .line 1450
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1451
    .line 1452
    .line 1453
    move-result v2

    .line 1454
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1455
    .line 1456
    .line 1457
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1458
    .line 1459
    .line 1460
    move-result-object v0

    .line 1461
    :goto_2b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1462
    .line 1463
    .line 1464
    move-result v2

    .line 1465
    if-eqz v2, :cond_3b

    .line 1466
    .line 1467
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1468
    .line 1469
    .line 1470
    move-result-object v2

    .line 1471
    check-cast v2, Ljava/lang/Number;

    .line 1472
    .line 1473
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1474
    .line 1475
    .line 1476
    move-result v2

    .line 1477
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1478
    .line 1479
    .line 1480
    move-result-object v2

    .line 1481
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1482
    .line 1483
    .line 1484
    goto :goto_2b

    .line 1485
    :cond_3b
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1486
    .line 1487
    .line 1488
    move-result-object v0

    .line 1489
    const/4 v14, 0x0

    .line 1490
    :goto_2c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1491
    .line 1492
    .line 1493
    move-result v1

    .line 1494
    if-eqz v1, :cond_41

    .line 1495
    .line 1496
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1497
    .line 1498
    .line 1499
    move-result-object v1

    .line 1500
    add-int/lit8 v2, v14, 0x1

    .line 1501
    .line 1502
    if-ltz v14, :cond_40

    .line 1503
    .line 1504
    check-cast v1, Ljava/lang/Number;

    .line 1505
    .line 1506
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 1507
    .line 1508
    .line 1509
    move-result v1

    .line 1510
    const/16 v19, 0x0

    .line 1511
    .line 1512
    cmpl-float v3, v1, v19

    .line 1513
    .line 1514
    if-lez v3, :cond_3f

    .line 1515
    .line 1516
    const v3, -0x4d124824

    .line 1517
    .line 1518
    .line 1519
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 1520
    .line 1521
    .line 1522
    float-to-double v6, v1

    .line 1523
    cmpl-double v3, v6, v22

    .line 1524
    .line 1525
    if-lez v3, :cond_3c

    .line 1526
    .line 1527
    goto :goto_2d

    .line 1528
    :cond_3c
    invoke-static {v11}, Ll1/a;->a(Ljava/lang/String;)V

    .line 1529
    .line 1530
    .line 1531
    :goto_2d
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 1532
    .line 1533
    cmpl-float v6, v1, p9

    .line 1534
    .line 1535
    if-lez v6, :cond_3d

    .line 1536
    .line 1537
    move/from16 v1, p9

    .line 1538
    .line 1539
    :cond_3d
    const/4 v13, 0x1

    .line 1540
    invoke-direct {v3, v1, v13}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 1541
    .line 1542
    .line 1543
    const/high16 v1, 0x3f800000    # 1.0f

    .line 1544
    .line 1545
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 1546
    .line 1547
    .line 1548
    move-result-object v3

    .line 1549
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1550
    .line 1551
    .line 1552
    move-result-object v6

    .line 1553
    invoke-virtual {v5, v6}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1554
    .line 1555
    .line 1556
    move-result-object v6

    .line 1557
    check-cast v6, Le3/s;

    .line 1558
    .line 1559
    if-eqz v6, :cond_3e

    .line 1560
    .line 1561
    iget-wide v6, v6, Le3/s;->a:J

    .line 1562
    .line 1563
    goto :goto_2e

    .line 1564
    :cond_3e
    sget-wide v6, Lxf0/b0;->c:J

    .line 1565
    .line 1566
    :goto_2e
    sget-object v10, Le3/j0;->a:Le3/i0;

    .line 1567
    .line 1568
    invoke-static {v3, v6, v7, v10}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 1569
    .line 1570
    .line 1571
    move-result-object v3

    .line 1572
    invoke-static {v3, v8}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 1573
    .line 1574
    .line 1575
    move-result-object v3

    .line 1576
    const/4 v6, 0x0

    .line 1577
    invoke-static {v3, v15, v6}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 1578
    .line 1579
    .line 1580
    :goto_2f
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 1581
    .line 1582
    .line 1583
    goto :goto_30

    .line 1584
    :cond_3f
    const/high16 v1, 0x3f800000    # 1.0f

    .line 1585
    .line 1586
    const/4 v6, 0x0

    .line 1587
    const v3, -0x4dae54ba

    .line 1588
    .line 1589
    .line 1590
    invoke-virtual {v15, v3}, Ll2/t;->Y(I)V

    .line 1591
    .line 1592
    .line 1593
    goto :goto_2f

    .line 1594
    :goto_30
    move v14, v2

    .line 1595
    goto :goto_2c

    .line 1596
    :cond_40
    invoke-static {}, Ljp/k1;->r()V

    .line 1597
    .line 1598
    .line 1599
    const/16 v21, 0x0

    .line 1600
    .line 1601
    throw v21

    .line 1602
    :cond_41
    const/4 v6, 0x0

    .line 1603
    const/4 v13, 0x1

    .line 1604
    invoke-static {v15, v6, v13, v13}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 1605
    .line 1606
    .line 1607
    goto :goto_31

    .line 1608
    :cond_42
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 1609
    .line 1610
    .line 1611
    :goto_31
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 1612
    .line 1613
    .line 1614
    move-result-object v11

    .line 1615
    if-eqz v11, :cond_43

    .line 1616
    .line 1617
    new-instance v0, Lxf0/v;

    .line 1618
    .line 1619
    move/from16 v1, p0

    .line 1620
    .line 1621
    move-object/from16 v2, p1

    .line 1622
    .line 1623
    move/from16 v3, p2

    .line 1624
    .line 1625
    move-object/from16 v5, p4

    .line 1626
    .line 1627
    move-object/from16 v6, p5

    .line 1628
    .line 1629
    move-object/from16 v7, p6

    .line 1630
    .line 1631
    move/from16 v10, p10

    .line 1632
    .line 1633
    invoke-direct/range {v0 .. v10}, Lxf0/v;-><init>(ILjava/util/List;IFLjava/lang/Integer;Ljava/util/List;Lay0/k;ZZI)V

    .line 1634
    .line 1635
    .line 1636
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 1637
    .line 1638
    :cond_43
    return-void
.end method

.method public static final b(Lvf0/a;Ljava/lang/Integer;Ljava/util/List;Lx2/s;Lay0/k;ZJZLl2/o;I)V
    .locals 28

    .line 1
    move/from16 v10, p10

    .line 2
    .line 3
    move-object/from16 v0, p9

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, 0x6b89d8a6

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, v10, 0x6

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    move-object/from16 v1, p0

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    const/4 v2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v2, 0x2

    .line 28
    :goto_0
    or-int/2addr v2, v10

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move-object/from16 v1, p0

    .line 31
    .line 32
    move v2, v10

    .line 33
    :goto_1
    and-int/lit8 v3, v10, 0x30

    .line 34
    .line 35
    if-nez v3, :cond_3

    .line 36
    .line 37
    move-object/from16 v3, p1

    .line 38
    .line 39
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    if-eqz v4, :cond_2

    .line 44
    .line 45
    const/16 v4, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v4, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v2, v4

    .line 51
    goto :goto_3

    .line 52
    :cond_3
    move-object/from16 v3, p1

    .line 53
    .line 54
    :goto_3
    and-int/lit16 v4, v10, 0x180

    .line 55
    .line 56
    if-nez v4, :cond_5

    .line 57
    .line 58
    move-object/from16 v4, p2

    .line 59
    .line 60
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_4

    .line 65
    .line 66
    const/16 v5, 0x100

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_4
    const/16 v5, 0x80

    .line 70
    .line 71
    :goto_4
    or-int/2addr v2, v5

    .line 72
    goto :goto_5

    .line 73
    :cond_5
    move-object/from16 v4, p2

    .line 74
    .line 75
    :goto_5
    or-int/lit16 v2, v2, 0xc00

    .line 76
    .line 77
    and-int/lit16 v5, v10, 0x6000

    .line 78
    .line 79
    if-nez v5, :cond_7

    .line 80
    .line 81
    move-object/from16 v5, p4

    .line 82
    .line 83
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    if-eqz v6, :cond_6

    .line 88
    .line 89
    const/16 v6, 0x4000

    .line 90
    .line 91
    goto :goto_6

    .line 92
    :cond_6
    const/16 v6, 0x2000

    .line 93
    .line 94
    :goto_6
    or-int/2addr v2, v6

    .line 95
    goto :goto_7

    .line 96
    :cond_7
    move-object/from16 v5, p4

    .line 97
    .line 98
    :goto_7
    const/high16 v6, 0x30000

    .line 99
    .line 100
    and-int/2addr v6, v10

    .line 101
    const/4 v7, 0x0

    .line 102
    if-nez v6, :cond_9

    .line 103
    .line 104
    invoke-virtual {v0, v7}, Ll2/t;->h(Z)Z

    .line 105
    .line 106
    .line 107
    move-result v6

    .line 108
    if-eqz v6, :cond_8

    .line 109
    .line 110
    const/high16 v6, 0x20000

    .line 111
    .line 112
    goto :goto_8

    .line 113
    :cond_8
    const/high16 v6, 0x10000

    .line 114
    .line 115
    :goto_8
    or-int/2addr v2, v6

    .line 116
    :cond_9
    const/high16 v6, 0x180000

    .line 117
    .line 118
    and-int/2addr v6, v10

    .line 119
    if-nez v6, :cond_b

    .line 120
    .line 121
    move/from16 v6, p5

    .line 122
    .line 123
    invoke-virtual {v0, v6}, Ll2/t;->h(Z)Z

    .line 124
    .line 125
    .line 126
    move-result v8

    .line 127
    if-eqz v8, :cond_a

    .line 128
    .line 129
    const/high16 v8, 0x100000

    .line 130
    .line 131
    goto :goto_9

    .line 132
    :cond_a
    const/high16 v8, 0x80000

    .line 133
    .line 134
    :goto_9
    or-int/2addr v2, v8

    .line 135
    goto :goto_a

    .line 136
    :cond_b
    move/from16 v6, p5

    .line 137
    .line 138
    :goto_a
    const/high16 v8, 0xc00000

    .line 139
    .line 140
    and-int/2addr v8, v10

    .line 141
    if-nez v8, :cond_d

    .line 142
    .line 143
    move-wide/from16 v8, p6

    .line 144
    .line 145
    invoke-virtual {v0, v8, v9}, Ll2/t;->f(J)Z

    .line 146
    .line 147
    .line 148
    move-result v11

    .line 149
    if-eqz v11, :cond_c

    .line 150
    .line 151
    const/high16 v11, 0x800000

    .line 152
    .line 153
    goto :goto_b

    .line 154
    :cond_c
    const/high16 v11, 0x400000

    .line 155
    .line 156
    :goto_b
    or-int/2addr v2, v11

    .line 157
    goto :goto_c

    .line 158
    :cond_d
    move-wide/from16 v8, p6

    .line 159
    .line 160
    :goto_c
    const/high16 v11, 0x6000000

    .line 161
    .line 162
    and-int/2addr v11, v10

    .line 163
    move/from16 v15, p8

    .line 164
    .line 165
    if-nez v11, :cond_f

    .line 166
    .line 167
    invoke-virtual {v0, v15}, Ll2/t;->h(Z)Z

    .line 168
    .line 169
    .line 170
    move-result v11

    .line 171
    if-eqz v11, :cond_e

    .line 172
    .line 173
    const/high16 v11, 0x4000000

    .line 174
    .line 175
    goto :goto_d

    .line 176
    :cond_e
    const/high16 v11, 0x2000000

    .line 177
    .line 178
    :goto_d
    or-int/2addr v2, v11

    .line 179
    :cond_f
    const v11, 0x2492493

    .line 180
    .line 181
    .line 182
    and-int/2addr v11, v2

    .line 183
    const v12, 0x2492492

    .line 184
    .line 185
    .line 186
    const/4 v13, 0x1

    .line 187
    if-eq v11, v12, :cond_10

    .line 188
    .line 189
    move v11, v13

    .line 190
    goto :goto_e

    .line 191
    :cond_10
    move v11, v7

    .line 192
    :goto_e
    and-int/2addr v2, v13

    .line 193
    invoke-virtual {v0, v2, v11}, Ll2/t;->O(IZ)Z

    .line 194
    .line 195
    .line 196
    move-result v2

    .line 197
    if-eqz v2, :cond_1d

    .line 198
    .line 199
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 200
    .line 201
    .line 202
    and-int/lit8 v2, v10, 0x1

    .line 203
    .line 204
    if-eqz v2, :cond_12

    .line 205
    .line 206
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    if-eqz v2, :cond_11

    .line 211
    .line 212
    goto :goto_f

    .line 213
    :cond_11
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 214
    .line 215
    .line 216
    move-object/from16 v2, p3

    .line 217
    .line 218
    goto :goto_10

    .line 219
    :cond_12
    :goto_f
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 220
    .line 221
    :goto_10
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 222
    .line 223
    .line 224
    sget-object v11, Lj91/h;->a:Ll2/u2;

    .line 225
    .line 226
    invoke-virtual {v0, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v11

    .line 230
    check-cast v11, Lj91/e;

    .line 231
    .line 232
    iget-object v11, v11, Lj91/e;->w:Ll2/j1;

    .line 233
    .line 234
    invoke-virtual {v11}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v11

    .line 238
    check-cast v11, Le3/s;

    .line 239
    .line 240
    iget-wide v11, v11, Le3/s;->a:J

    .line 241
    .line 242
    sget-object v13, Lj91/a;->a:Ll2/u2;

    .line 243
    .line 244
    invoke-virtual {v0, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v13

    .line 248
    check-cast v13, Lj91/c;

    .line 249
    .line 250
    iget v13, v13, Lj91/c;->c:F

    .line 251
    .line 252
    sget v14, Lxf0/b0;->a:F

    .line 253
    .line 254
    invoke-static {v2, v14}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 255
    .line 256
    .line 257
    move-result-object v14

    .line 258
    sget-object v7, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 259
    .line 260
    invoke-interface {v14, v7}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v7

    .line 264
    const v14, -0x3bced2e6

    .line 265
    .line 266
    .line 267
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 268
    .line 269
    .line 270
    const v14, 0xca3d8b5

    .line 271
    .line 272
    .line 273
    invoke-virtual {v0, v14}, Ll2/t;->Y(I)V

    .line 274
    .line 275
    .line 276
    const/4 v14, 0x0

    .line 277
    invoke-virtual {v0, v14}, Ll2/t;->q(Z)V

    .line 278
    .line 279
    .line 280
    sget-object v14, Lw3/h1;->h:Ll2/u2;

    .line 281
    .line 282
    invoke-virtual {v0, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v14

    .line 286
    check-cast v14, Lt4/c;

    .line 287
    .line 288
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    move-object/from16 p3, v2

    .line 293
    .line 294
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 295
    .line 296
    if-ne v1, v2, :cond_13

    .line 297
    .line 298
    invoke-static {v14, v0}, Lvj/b;->t(Lt4/c;Ll2/t;)Lz4/p;

    .line 299
    .line 300
    .line 301
    move-result-object v1

    .line 302
    :cond_13
    check-cast v1, Lz4/p;

    .line 303
    .line 304
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v14

    .line 308
    if-ne v14, v2, :cond_14

    .line 309
    .line 310
    invoke-static {v0}, Lvj/b;->r(Ll2/t;)Lz4/k;

    .line 311
    .line 312
    .line 313
    move-result-object v14

    .line 314
    :cond_14
    check-cast v14, Lz4/k;

    .line 315
    .line 316
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v3

    .line 320
    if-ne v3, v2, :cond_15

    .line 321
    .line 322
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 323
    .line 324
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 325
    .line 326
    .line 327
    move-result-object v3

    .line 328
    invoke-virtual {v0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    :cond_15
    move-object/from16 v20, v3

    .line 332
    .line 333
    check-cast v20, Ll2/b1;

    .line 334
    .line 335
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v3

    .line 339
    if-ne v3, v2, :cond_16

    .line 340
    .line 341
    invoke-static {v14, v0}, Lvj/b;->s(Lz4/k;Ll2/t;)Lz4/m;

    .line 342
    .line 343
    .line 344
    move-result-object v3

    .line 345
    :cond_16
    move-object/from16 v19, v3

    .line 346
    .line 347
    check-cast v19, Lz4/m;

    .line 348
    .line 349
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v3

    .line 353
    if-ne v3, v2, :cond_17

    .line 354
    .line 355
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 356
    .line 357
    sget-object v4, Ll2/x0;->f:Ll2/x0;

    .line 358
    .line 359
    invoke-static {v3, v4, v0}, Lf2/m0;->r(Llx0/b0;Ll2/x0;Ll2/t;)Ll2/j1;

    .line 360
    .line 361
    .line 362
    move-result-object v3

    .line 363
    :cond_17
    move-object/from16 v17, v3

    .line 364
    .line 365
    check-cast v17, Ll2/b1;

    .line 366
    .line 367
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 368
    .line 369
    .line 370
    move-result v3

    .line 371
    const/16 v4, 0x101

    .line 372
    .line 373
    invoke-virtual {v0, v4}, Ll2/t;->e(I)Z

    .line 374
    .line 375
    .line 376
    move-result v4

    .line 377
    or-int/2addr v3, v4

    .line 378
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v4

    .line 382
    if-nez v3, :cond_19

    .line 383
    .line 384
    if-ne v4, v2, :cond_18

    .line 385
    .line 386
    goto :goto_11

    .line 387
    :cond_18
    move-object/from16 v5, v19

    .line 388
    .line 389
    move-object/from16 v3, v20

    .line 390
    .line 391
    goto :goto_12

    .line 392
    :cond_19
    :goto_11
    new-instance v16, Lc40/b;

    .line 393
    .line 394
    const/16 v21, 0xc

    .line 395
    .line 396
    move-object/from16 v18, v1

    .line 397
    .line 398
    invoke-direct/range {v16 .. v21}, Lc40/b;-><init>(Ll2/b1;Lz4/p;Lz4/m;Ll2/b1;I)V

    .line 399
    .line 400
    .line 401
    move-object/from16 v4, v16

    .line 402
    .line 403
    move-object/from16 v5, v19

    .line 404
    .line 405
    move-object/from16 v3, v20

    .line 406
    .line 407
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 408
    .line 409
    .line 410
    :goto_12
    check-cast v4, Lt3/q0;

    .line 411
    .line 412
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v6

    .line 416
    if-ne v6, v2, :cond_1a

    .line 417
    .line 418
    new-instance v6, Lc40/c;

    .line 419
    .line 420
    const/16 v8, 0xc

    .line 421
    .line 422
    invoke-direct {v6, v3, v5, v8}, Lc40/c;-><init>(Ll2/b1;Lz4/m;I)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v0, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 426
    .line 427
    .line 428
    :cond_1a
    check-cast v6, Lay0/a;

    .line 429
    .line 430
    invoke-virtual {v0, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 431
    .line 432
    .line 433
    move-result v3

    .line 434
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v5

    .line 438
    if-nez v3, :cond_1b

    .line 439
    .line 440
    if-ne v5, v2, :cond_1c

    .line 441
    .line 442
    :cond_1b
    new-instance v5, Lc40/d;

    .line 443
    .line 444
    const/16 v2, 0xc

    .line 445
    .line 446
    invoke-direct {v5, v1, v2}, Lc40/d;-><init>(Lz4/p;I)V

    .line 447
    .line 448
    .line 449
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 450
    .line 451
    .line 452
    :cond_1c
    check-cast v5, Lay0/k;

    .line 453
    .line 454
    const/4 v1, 0x0

    .line 455
    invoke-static {v7, v1, v5}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    move-wide/from16 v26, v11

    .line 460
    .line 461
    move-object/from16 v12, v17

    .line 462
    .line 463
    move-wide/from16 v17, v26

    .line 464
    .line 465
    new-instance v11, Lxf0/a0;

    .line 466
    .line 467
    move-object/from16 v16, p0

    .line 468
    .line 469
    move-object/from16 v23, p1

    .line 470
    .line 471
    move-object/from16 v24, p2

    .line 472
    .line 473
    move-object/from16 v25, p4

    .line 474
    .line 475
    move/from16 v19, p5

    .line 476
    .line 477
    move-wide/from16 v20, p6

    .line 478
    .line 479
    move/from16 v22, v13

    .line 480
    .line 481
    move-object v13, v14

    .line 482
    move-object v14, v6

    .line 483
    invoke-direct/range {v11 .. v25}, Lxf0/a0;-><init>(Ll2/b1;Lz4/k;Lay0/a;ZLvf0/a;JZJFLjava/lang/Integer;Ljava/util/List;Lay0/k;)V

    .line 484
    .line 485
    .line 486
    const v3, 0x478ef317

    .line 487
    .line 488
    .line 489
    invoke-static {v3, v0, v11}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 490
    .line 491
    .line 492
    move-result-object v3

    .line 493
    const/16 v5, 0x30

    .line 494
    .line 495
    invoke-static {v2, v3, v4, v0, v5}, Lt3/k1;->a(Lx2/s;Lt2/b;Lt3/q0;Ll2/o;I)V

    .line 496
    .line 497
    .line 498
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 499
    .line 500
    .line 501
    :goto_13
    move-object/from16 v4, p3

    .line 502
    .line 503
    goto :goto_14

    .line 504
    :cond_1d
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 505
    .line 506
    .line 507
    goto :goto_13

    .line 508
    :goto_14
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 509
    .line 510
    .line 511
    move-result-object v11

    .line 512
    if-eqz v11, :cond_1e

    .line 513
    .line 514
    new-instance v0, Lxf0/u;

    .line 515
    .line 516
    move-object/from16 v1, p0

    .line 517
    .line 518
    move-object/from16 v2, p1

    .line 519
    .line 520
    move-object/from16 v3, p2

    .line 521
    .line 522
    move-object/from16 v5, p4

    .line 523
    .line 524
    move/from16 v6, p5

    .line 525
    .line 526
    move-wide/from16 v7, p6

    .line 527
    .line 528
    move/from16 v9, p8

    .line 529
    .line 530
    invoke-direct/range {v0 .. v10}, Lxf0/u;-><init>(Lvf0/a;Ljava/lang/Integer;Ljava/util/List;Lx2/s;Lay0/k;ZJZI)V

    .line 531
    .line 532
    .line 533
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 534
    .line 535
    :cond_1e
    return-void
.end method

.method public static final c(FIJLg3/d;)V
    .locals 33

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-le v0, v1, :cond_1

    .line 5
    .line 6
    invoke-interface/range {p4 .. p4}, Lg3/d;->e()J

    .line 7
    .line 8
    .line 9
    move-result-wide v2

    .line 10
    const/16 v4, 0x20

    .line 11
    .line 12
    shr-long/2addr v2, v4

    .line 13
    long-to-int v2, v2

    .line 14
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    int-to-float v3, v0

    .line 19
    div-float/2addr v2, v3

    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    int-to-long v5, v5

    .line 26
    invoke-static/range {p0 .. p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    int-to-long v7, v7

    .line 31
    shl-long/2addr v5, v4

    .line 32
    const-wide v9, 0xffffffffL

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    and-long/2addr v7, v9

    .line 38
    or-long v14, v5, v7

    .line 39
    .line 40
    invoke-interface/range {p4 .. p4}, Lg3/d;->e()J

    .line 41
    .line 42
    .line 43
    move-result-wide v5

    .line 44
    and-long/2addr v5, v9

    .line 45
    long-to-int v5, v5

    .line 46
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v6

    .line 54
    int-to-long v6, v6

    .line 55
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    int-to-long v11, v5

    .line 60
    shl-long v5, v6, v4

    .line 61
    .line 62
    and-long v7, v11, v9

    .line 63
    .line 64
    or-long v16, v5, v7

    .line 65
    .line 66
    const/16 v20, 0x0

    .line 67
    .line 68
    const/16 v21, 0x1f0

    .line 69
    .line 70
    const/high16 v29, 0x40800000    # 4.0f

    .line 71
    .line 72
    const/16 v19, 0x0

    .line 73
    .line 74
    move-wide/from16 v12, p2

    .line 75
    .line 76
    move-object/from16 v11, p4

    .line 77
    .line 78
    move/from16 v18, v29

    .line 79
    .line 80
    invoke-static/range {v11 .. v21}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 81
    .line 82
    .line 83
    :goto_0
    if-ge v1, v0, :cond_0

    .line 84
    .line 85
    int-to-float v5, v1

    .line 86
    mul-float/2addr v5, v2

    .line 87
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 88
    .line 89
    .line 90
    move-result v6

    .line 91
    int-to-long v6, v6

    .line 92
    invoke-static/range {p0 .. p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 93
    .line 94
    .line 95
    move-result v8

    .line 96
    int-to-long v11, v8

    .line 97
    shl-long/2addr v6, v4

    .line 98
    and-long/2addr v11, v9

    .line 99
    or-long v25, v6, v11

    .line 100
    .line 101
    invoke-interface/range {p4 .. p4}, Lg3/d;->e()J

    .line 102
    .line 103
    .line 104
    move-result-wide v6

    .line 105
    and-long/2addr v6, v9

    .line 106
    long-to-int v6, v6

    .line 107
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    int-to-long v7, v5

    .line 116
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 117
    .line 118
    .line 119
    move-result v5

    .line 120
    int-to-long v5, v5

    .line 121
    shl-long/2addr v7, v4

    .line 122
    and-long/2addr v5, v9

    .line 123
    or-long v27, v7, v5

    .line 124
    .line 125
    const/4 v5, 0x2

    .line 126
    new-array v5, v5, [F

    .line 127
    .line 128
    fill-array-data v5, :array_0

    .line 129
    .line 130
    .line 131
    new-instance v6, Le3/j;

    .line 132
    .line 133
    new-instance v7, Landroid/graphics/DashPathEffect;

    .line 134
    .line 135
    invoke-direct {v7, v5, v3}, Landroid/graphics/DashPathEffect;-><init>([FF)V

    .line 136
    .line 137
    .line 138
    invoke-direct {v6, v7}, Le3/j;-><init>(Landroid/graphics/DashPathEffect;)V

    .line 139
    .line 140
    .line 141
    const/16 v30, 0x0

    .line 142
    .line 143
    const/16 v32, 0x1d0

    .line 144
    .line 145
    move-wide/from16 v23, p2

    .line 146
    .line 147
    move-object/from16 v22, p4

    .line 148
    .line 149
    move-object/from16 v31, v6

    .line 150
    .line 151
    invoke-static/range {v22 .. v32}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 152
    .line 153
    .line 154
    add-int/lit8 v1, v1, 0x1

    .line 155
    .line 156
    goto :goto_0

    .line 157
    :cond_0
    invoke-interface/range {p4 .. p4}, Lg3/d;->e()J

    .line 158
    .line 159
    .line 160
    move-result-wide v0

    .line 161
    shr-long/2addr v0, v4

    .line 162
    long-to-int v0, v0

    .line 163
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    int-to-long v0, v0

    .line 172
    invoke-static/range {p0 .. p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 173
    .line 174
    .line 175
    move-result v2

    .line 176
    int-to-long v2, v2

    .line 177
    shl-long/2addr v0, v4

    .line 178
    and-long/2addr v2, v9

    .line 179
    or-long v25, v0, v2

    .line 180
    .line 181
    invoke-interface/range {p4 .. p4}, Lg3/d;->e()J

    .line 182
    .line 183
    .line 184
    move-result-wide v0

    .line 185
    shr-long/2addr v0, v4

    .line 186
    long-to-int v0, v0

    .line 187
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    invoke-interface/range {p4 .. p4}, Lg3/d;->e()J

    .line 192
    .line 193
    .line 194
    move-result-wide v1

    .line 195
    and-long/2addr v1, v9

    .line 196
    long-to-int v1, v1

    .line 197
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 202
    .line 203
    .line 204
    move-result v0

    .line 205
    int-to-long v2, v0

    .line 206
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 207
    .line 208
    .line 209
    move-result v0

    .line 210
    int-to-long v0, v0

    .line 211
    shl-long/2addr v2, v4

    .line 212
    and-long/2addr v0, v9

    .line 213
    or-long v27, v2, v0

    .line 214
    .line 215
    const/16 v31, 0x0

    .line 216
    .line 217
    const/16 v32, 0x1f0

    .line 218
    .line 219
    const/16 v30, 0x0

    .line 220
    .line 221
    move-wide/from16 v23, p2

    .line 222
    .line 223
    move-object/from16 v22, p4

    .line 224
    .line 225
    invoke-static/range {v22 .. v32}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 226
    .line 227
    .line 228
    :cond_1
    return-void

    .line 229
    :array_0
    .array-data 4
        0x41000000    # 8.0f
        0x41000000    # 8.0f
    .end array-data
.end method
