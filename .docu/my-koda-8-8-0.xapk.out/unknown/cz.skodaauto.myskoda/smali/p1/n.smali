.class public final Lp1/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/c0;


# instance fields
.field public final synthetic a:Lp1/v;

.field public final synthetic b:Lk1/z0;

.field public final synthetic c:Z

.field public final synthetic d:F

.field public final synthetic e:Lp1/f;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lx2/i;

.field public final synthetic i:Lh1/n;

.field public final synthetic j:Lvy0/b0;


# direct methods
.method public constructor <init>(Lp1/v;Lk1/z0;ZFLp1/f;Lhy0/u;Lay0/a;Lx2/i;Lh1/n;Lvy0/b0;)V
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lp1/n;->a:Lp1/v;

    .line 7
    .line 8
    iput-object p2, p0, Lp1/n;->b:Lk1/z0;

    .line 9
    .line 10
    iput-boolean p3, p0, Lp1/n;->c:Z

    .line 11
    .line 12
    iput p4, p0, Lp1/n;->d:F

    .line 13
    .line 14
    iput-object p5, p0, Lp1/n;->e:Lp1/f;

    .line 15
    .line 16
    iput-object p6, p0, Lp1/n;->f:Lay0/a;

    .line 17
    .line 18
    iput-object p7, p0, Lp1/n;->g:Lay0/a;

    .line 19
    .line 20
    iput-object p8, p0, Lp1/n;->h:Lx2/i;

    .line 21
    .line 22
    iput-object p9, p0, Lp1/n;->i:Lh1/n;

    .line 23
    .line 24
    iput-object p10, p0, Lp1/n;->j:Lvy0/b0;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a(Lo1/d0;J)Lt3/r0;
    .locals 55

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v13, p2

    .line 6
    .line 7
    iget-object v15, v0, Lp1/n;->a:Lp1/v;

    .line 8
    .line 9
    iget-object v2, v15, Lp1/v;->D:Ll2/b1;

    .line 10
    .line 11
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    sget-object v2, Lg1/w1;->e:Lg1/w1;

    .line 15
    .line 16
    sget-object v3, Lg1/w1;->d:Lg1/w1;

    .line 17
    .line 18
    invoke-static {v13, v14, v2}, Lkp/j;->a(JLg1/w1;)V

    .line 19
    .line 20
    .line 21
    iget-object v3, v1, Lo1/d0;->e:Lt3/p1;

    .line 22
    .line 23
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    iget-object v5, v0, Lp1/n;->b:Lk1/z0;

    .line 28
    .line 29
    invoke-static {v5, v4}, Landroidx/compose/foundation/layout/a;->f(Lk1/z0;Lt4/m;)F

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    invoke-interface {v3, v4}, Lt4/c;->Q(F)I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/a;->e(Lk1/z0;Lt4/m;)F

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    invoke-interface {v3, v6}, Lt4/c;->Q(F)I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    invoke-interface {v5}, Lk1/z0;->d()F

    .line 50
    .line 51
    .line 52
    move-result v7

    .line 53
    invoke-interface {v3, v7}, Lt4/c;->Q(F)I

    .line 54
    .line 55
    .line 56
    move-result v7

    .line 57
    invoke-interface {v5}, Lk1/z0;->c()F

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    invoke-interface {v3, v5}, Lt4/c;->Q(F)I

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    add-int/2addr v5, v7

    .line 66
    add-int v8, v4, v6

    .line 67
    .line 68
    iget-boolean v9, v0, Lp1/n;->c:Z

    .line 69
    .line 70
    if-nez v9, :cond_0

    .line 71
    .line 72
    move v6, v4

    .line 73
    :cond_0
    sub-int v10, v8, v6

    .line 74
    .line 75
    neg-int v11, v8

    .line 76
    neg-int v12, v5

    .line 77
    invoke-static {v13, v14, v11, v12}, Lt4/b;->i(JII)J

    .line 78
    .line 79
    .line 80
    move-result-wide v11

    .line 81
    iput-object v1, v15, Lp1/v;->q:Lt4/c;

    .line 82
    .line 83
    move-object/from16 v21, v2

    .line 84
    .line 85
    iget v2, v0, Lp1/n;->d:F

    .line 86
    .line 87
    invoke-interface {v3, v2}, Lt4/c;->Q(F)I

    .line 88
    .line 89
    .line 90
    move-result v18

    .line 91
    invoke-static {v13, v14}, Lt4/a;->h(J)I

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    sub-int/2addr v2, v8

    .line 96
    const-wide v16, 0xffffffffL

    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    const/16 v19, 0x20

    .line 102
    .line 103
    if-eqz v9, :cond_2

    .line 104
    .line 105
    if-lez v2, :cond_1

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_1
    add-int/2addr v4, v2

    .line 109
    :cond_2
    :goto_0
    move v9, v5

    .line 110
    int-to-long v4, v4

    .line 111
    shl-long v4, v4, v19

    .line 112
    .line 113
    move-wide/from16 v19, v4

    .line 114
    .line 115
    int-to-long v4, v7

    .line 116
    and-long v4, v4, v16

    .line 117
    .line 118
    or-long v4, v19, v4

    .line 119
    .line 120
    iget-object v7, v0, Lp1/n;->e:Lp1/f;

    .line 121
    .line 122
    invoke-interface {v7, v1, v2}, Lp1/f;->a(Lo1/d0;I)I

    .line 123
    .line 124
    .line 125
    move-result v7

    .line 126
    if-gez v7, :cond_3

    .line 127
    .line 128
    const/4 v7, 0x0

    .line 129
    :cond_3
    invoke-static {v11, v12}, Lt4/a;->g(J)I

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    move/from16 v16, v2

    .line 134
    .line 135
    const/4 v2, 0x5

    .line 136
    move-wide/from16 v19, v4

    .line 137
    .line 138
    invoke-static {v7, v1, v2}, Lt4/b;->b(III)J

    .line 139
    .line 140
    .line 141
    move-result-wide v4

    .line 142
    iput-wide v4, v15, Lp1/v;->A:J

    .line 143
    .line 144
    iget-object v1, v0, Lp1/n;->f:Lay0/a;

    .line 145
    .line 146
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    move-object v4, v1

    .line 151
    check-cast v4, Lp1/m;

    .line 152
    .line 153
    add-int v1, v16, v6

    .line 154
    .line 155
    add-int/2addr v1, v10

    .line 156
    iget-object v5, v0, Lp1/n;->i:Lh1/n;

    .line 157
    .line 158
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    move/from16 v22, v8

    .line 163
    .line 164
    if-eqz v2, :cond_4

    .line 165
    .line 166
    invoke-virtual {v2}, Lv2/f;->e()Lay0/k;

    .line 167
    .line 168
    .line 169
    move-result-object v23

    .line 170
    move-object/from16 v8, v23

    .line 171
    .line 172
    :goto_1
    move/from16 v24, v9

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_4
    const/4 v8, 0x0

    .line 176
    goto :goto_1

    .line 177
    :goto_2
    invoke-static {v2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 178
    .line 179
    .line 180
    move-result-object v9

    .line 181
    move-wide/from16 v27, v11

    .line 182
    .line 183
    :try_start_0
    invoke-virtual {v15}, Lp1/v;->k()I

    .line 184
    .line 185
    .line 186
    move-result v11

    .line 187
    iget-object v12, v15, Lp1/v;->d:Lh8/o;

    .line 188
    .line 189
    move-object/from16 v29, v3

    .line 190
    .line 191
    iget-object v3, v12, Lh8/o;->e:Ljava/lang/Object;

    .line 192
    .line 193
    invoke-static {v11, v3, v4}, Lo1/y;->i(ILjava/lang/Object;Lo1/b0;)I

    .line 194
    .line 195
    .line 196
    move-result v3

    .line 197
    if-eq v11, v3, :cond_5

    .line 198
    .line 199
    iget-object v13, v12, Lh8/o;->c:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v13, Ll2/g1;

    .line 202
    .line 203
    invoke-virtual {v13, v3}, Ll2/g1;->p(I)V

    .line 204
    .line 205
    .line 206
    iget-object v13, v12, Lh8/o;->f:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v13, Lo1/g0;

    .line 209
    .line 210
    invoke-virtual {v13, v11}, Lo1/g0;->a(I)V

    .line 211
    .line 212
    .line 213
    :cond_5
    invoke-virtual {v15}, Lp1/v;->k()I

    .line 214
    .line 215
    .line 216
    iget-object v11, v12, Lh8/o;->d:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v11, Ll2/f1;

    .line 219
    .line 220
    invoke-virtual {v11}, Ll2/f1;->o()F

    .line 221
    .line 222
    .line 223
    move-result v11

    .line 224
    invoke-virtual {v15}, Lp1/v;->m()I

    .line 225
    .line 226
    .line 227
    invoke-interface {v5, v1, v7, v6, v10}, Lh1/n;->a(IIII)I

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    int-to-float v5, v5

    .line 232
    add-int v13, v7, v18

    .line 233
    .line 234
    int-to-float v12, v13

    .line 235
    mul-float/2addr v11, v12

    .line 236
    sub-float/2addr v5, v11

    .line 237
    invoke-static {v5}, Lcy0/a;->i(F)I

    .line 238
    .line 239
    .line 240
    move-result v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 241
    invoke-static {v2, v9, v8}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 242
    .line 243
    .line 244
    iget-object v2, v15, Lp1/v;->B:Lo1/i0;

    .line 245
    .line 246
    iget-object v8, v15, Lp1/v;->w:Lg1/r;

    .line 247
    .line 248
    invoke-static {v4, v2, v8}, Lo1/y;->g(Lo1/b0;Lo1/i0;Lg1/r;)Ljava/util/List;

    .line 249
    .line 250
    .line 251
    move-result-object v14

    .line 252
    sget-object v2, Landroidx/collection/q;->a:Landroidx/collection/b0;

    .line 253
    .line 254
    new-instance v11, Landroidx/collection/b0;

    .line 255
    .line 256
    invoke-direct {v11}, Landroidx/collection/b0;-><init>()V

    .line 257
    .line 258
    .line 259
    iget-object v2, v0, Lp1/n;->g:Lay0/a;

    .line 260
    .line 261
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    check-cast v2, Ljava/lang/Number;

    .line 266
    .line 267
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 268
    .line 269
    .line 270
    move-result v2

    .line 271
    iget-object v8, v15, Lp1/v;->C:Ll2/b1;

    .line 272
    .line 273
    if-ltz v6, :cond_6

    .line 274
    .line 275
    goto :goto_3

    .line 276
    :cond_6
    const-string v9, "negative beforeContentPadding"

    .line 277
    .line 278
    invoke-static {v9}, Lj1/b;->a(Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    :goto_3
    if-ltz v10, :cond_7

    .line 282
    .line 283
    goto :goto_4

    .line 284
    :cond_7
    const-string v9, "negative afterContentPadding"

    .line 285
    .line 286
    invoke-static {v9}, Lj1/b;->a(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    :goto_4
    if-gez v13, :cond_8

    .line 290
    .line 291
    const/4 v9, 0x0

    .line 292
    goto :goto_5

    .line 293
    :cond_8
    move v9, v13

    .line 294
    :goto_5
    if-gez v2, :cond_9

    .line 295
    .line 296
    move/from16 v25, v2

    .line 297
    .line 298
    goto :goto_6

    .line 299
    :cond_9
    const/16 v25, 0x0

    .line 300
    .line 301
    :goto_6
    sget-object v12, Lmx0/t;->d:Lmx0/t;

    .line 302
    .line 303
    move/from16 v30, v1

    .line 304
    .line 305
    iget-object v1, v0, Lp1/n;->i:Lh1/n;

    .line 306
    .line 307
    move-object/from16 v31, v1

    .line 308
    .line 309
    iget-object v1, v0, Lp1/n;->j:Lvy0/b0;

    .line 310
    .line 311
    if-gtz v2, :cond_a

    .line 312
    .line 313
    neg-int v0, v6

    .line 314
    add-int v21, v16, v10

    .line 315
    .line 316
    invoke-static/range {v27 .. v28}, Lt4/a;->j(J)I

    .line 317
    .line 318
    .line 319
    move-result v2

    .line 320
    invoke-static/range {v27 .. v28}, Lt4/a;->i(J)I

    .line 321
    .line 322
    .line 323
    move-result v3

    .line 324
    new-instance v4, Ldj/a;

    .line 325
    .line 326
    const/16 v5, 0xe

    .line 327
    .line 328
    invoke-direct {v4, v5}, Ldj/a;-><init>(I)V

    .line 329
    .line 330
    .line 331
    add-int v2, v2, v22

    .line 332
    .line 333
    move-wide/from16 v5, p2

    .line 334
    .line 335
    invoke-static {v2, v5, v6}, Lt4/b;->g(IJ)I

    .line 336
    .line 337
    .line 338
    move-result v2

    .line 339
    add-int v3, v3, v24

    .line 340
    .line 341
    invoke-static {v3, v5, v6}, Lt4/b;->f(IJ)I

    .line 342
    .line 343
    .line 344
    move-result v3

    .line 345
    move-object/from16 v5, v29

    .line 346
    .line 347
    invoke-interface {v5, v2, v3, v12, v4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 348
    .line 349
    .line 350
    move-result-object v24

    .line 351
    new-instance v16, Lp1/o;

    .line 352
    .line 353
    move/from16 v20, v0

    .line 354
    .line 355
    move/from16 v17, v7

    .line 356
    .line 357
    move/from16 v19, v10

    .line 358
    .line 359
    move/from16 v22, v25

    .line 360
    .line 361
    move-object/from16 v23, v31

    .line 362
    .line 363
    move-object/from16 v25, v1

    .line 364
    .line 365
    invoke-direct/range {v16 .. v25}, Lp1/o;-><init>(IIIIIILh1/n;Lt3/r0;Lvy0/b0;)V

    .line 366
    .line 367
    .line 368
    move-object v6, v5

    .line 369
    move-object/from16 v37, v15

    .line 370
    .line 371
    :goto_7
    move-object/from16 v0, v16

    .line 372
    .line 373
    goto/16 :goto_43

    .line 374
    .line 375
    :cond_a
    move-object/from16 v36, v1

    .line 376
    .line 377
    move v1, v10

    .line 378
    move v10, v7

    .line 379
    invoke-static/range {v27 .. v28}, Lt4/a;->g(J)I

    .line 380
    .line 381
    .line 382
    move-result v7

    .line 383
    move/from16 v32, v1

    .line 384
    .line 385
    const/4 v1, 0x5

    .line 386
    invoke-static {v10, v7, v1}, Lt4/b;->b(III)J

    .line 387
    .line 388
    .line 389
    move-result-wide v33

    .line 390
    :goto_8
    if-lez v3, :cond_b

    .line 391
    .line 392
    if-lez v5, :cond_b

    .line 393
    .line 394
    add-int/lit8 v3, v3, -0x1

    .line 395
    .line 396
    sub-int/2addr v5, v9

    .line 397
    goto :goto_8

    .line 398
    :cond_b
    mul-int/lit8 v5, v5, -0x1

    .line 399
    .line 400
    if-lt v3, v2, :cond_c

    .line 401
    .line 402
    add-int/lit8 v3, v2, -0x1

    .line 403
    .line 404
    const/4 v5, 0x0

    .line 405
    :cond_c
    new-instance v1, Lmx0/l;

    .line 406
    .line 407
    invoke-direct {v1}, Lmx0/l;-><init>()V

    .line 408
    .line 409
    .line 410
    neg-int v7, v6

    .line 411
    if-gez v18, :cond_d

    .line 412
    .line 413
    move/from16 v17, v18

    .line 414
    .line 415
    :goto_9
    move/from16 v35, v13

    .line 416
    .line 417
    goto :goto_a

    .line 418
    :cond_d
    const/16 v17, 0x0

    .line 419
    .line 420
    goto :goto_9

    .line 421
    :goto_a
    add-int v13, v7, v17

    .line 422
    .line 423
    add-int/2addr v5, v13

    .line 424
    move-object/from16 v17, v8

    .line 425
    .line 426
    move-object/from16 v37, v15

    .line 427
    .line 428
    const/4 v15, 0x0

    .line 429
    :goto_b
    iget-object v8, v0, Lp1/n;->h:Lx2/i;

    .line 430
    .line 431
    move-object/from16 v38, v12

    .line 432
    .line 433
    move-object v12, v11

    .line 434
    move v11, v10

    .line 435
    iget-boolean v10, v0, Lp1/n;->c:Z

    .line 436
    .line 437
    if-gez v5, :cond_e

    .line 438
    .line 439
    if-lez v3, :cond_e

    .line 440
    .line 441
    add-int/lit8 v3, v3, -0x1

    .line 442
    .line 443
    move/from16 v39, v9

    .line 444
    .line 445
    invoke-interface/range {v29 .. v29}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 446
    .line 447
    .line 448
    move-result-object v9

    .line 449
    move-object v0, v1

    .line 450
    move/from16 v48, v2

    .line 451
    .line 452
    move v2, v3

    .line 453
    move/from16 v41, v6

    .line 454
    .line 455
    move-object/from16 v40, v14

    .line 456
    .line 457
    move/from16 v46, v16

    .line 458
    .line 459
    move-object/from16 v49, v17

    .line 460
    .line 461
    move/from16 v45, v18

    .line 462
    .line 463
    move/from16 v50, v25

    .line 464
    .line 465
    move-wide/from16 v43, v27

    .line 466
    .line 467
    move/from16 v47, v30

    .line 468
    .line 469
    move-object/from16 v52, v31

    .line 470
    .line 471
    move/from16 v42, v32

    .line 472
    .line 473
    move-object/from16 v51, v38

    .line 474
    .line 475
    const/4 v14, 0x0

    .line 476
    move-object/from16 v1, p1

    .line 477
    .line 478
    move/from16 v16, v5

    .line 479
    .line 480
    move/from16 v17, v7

    .line 481
    .line 482
    move-wide/from16 v6, v19

    .line 483
    .line 484
    move-object/from16 v38, v29

    .line 485
    .line 486
    move-object v5, v4

    .line 487
    move-wide/from16 v3, v33

    .line 488
    .line 489
    invoke-static/range {v1 .. v12}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 490
    .line 491
    .line 492
    move-result-object v8

    .line 493
    move-wide/from16 v18, v3

    .line 494
    .line 495
    move-object v4, v5

    .line 496
    move-wide v5, v6

    .line 497
    move v10, v11

    .line 498
    move-object v11, v12

    .line 499
    invoke-virtual {v0, v14, v8}, Lmx0/l;->add(ILjava/lang/Object;)V

    .line 500
    .line 501
    .line 502
    iget v1, v8, Lp1/d;->j:I

    .line 503
    .line 504
    invoke-static {v15, v1}, Ljava/lang/Math;->max(II)I

    .line 505
    .line 506
    .line 507
    move-result v15

    .line 508
    add-int v1, v16, v39

    .line 509
    .line 510
    move v3, v2

    .line 511
    move/from16 v7, v17

    .line 512
    .line 513
    move-wide/from16 v33, v18

    .line 514
    .line 515
    move/from16 v9, v39

    .line 516
    .line 517
    move-object/from16 v14, v40

    .line 518
    .line 519
    move/from16 v18, v45

    .line 520
    .line 521
    move/from16 v16, v46

    .line 522
    .line 523
    move/from16 v2, v48

    .line 524
    .line 525
    move-object/from16 v17, v49

    .line 526
    .line 527
    move-object/from16 v12, v51

    .line 528
    .line 529
    move-wide/from16 v19, v5

    .line 530
    .line 531
    move/from16 v6, v41

    .line 532
    .line 533
    move v5, v1

    .line 534
    move-object v1, v0

    .line 535
    move-object/from16 v0, p0

    .line 536
    .line 537
    goto :goto_b

    .line 538
    :cond_e
    move-object v0, v1

    .line 539
    move/from16 v48, v2

    .line 540
    .line 541
    move/from16 v41, v6

    .line 542
    .line 543
    move/from16 v39, v9

    .line 544
    .line 545
    move v9, v10

    .line 546
    move v10, v11

    .line 547
    move-object v11, v12

    .line 548
    move-object/from16 v40, v14

    .line 549
    .line 550
    move/from16 v46, v16

    .line 551
    .line 552
    move-object/from16 v49, v17

    .line 553
    .line 554
    move/from16 v45, v18

    .line 555
    .line 556
    move/from16 v50, v25

    .line 557
    .line 558
    move-wide/from16 v43, v27

    .line 559
    .line 560
    move/from16 v47, v30

    .line 561
    .line 562
    move-object/from16 v52, v31

    .line 563
    .line 564
    move/from16 v42, v32

    .line 565
    .line 566
    move-object/from16 v51, v38

    .line 567
    .line 568
    const/4 v14, 0x0

    .line 569
    move/from16 v16, v5

    .line 570
    .line 571
    move/from16 v17, v7

    .line 572
    .line 573
    move-object v7, v8

    .line 574
    move-wide/from16 v5, v19

    .line 575
    .line 576
    move-object/from16 v38, v29

    .line 577
    .line 578
    move-wide/from16 v18, v33

    .line 579
    .line 580
    move/from16 v1, v16

    .line 581
    .line 582
    if-ge v1, v13, :cond_f

    .line 583
    .line 584
    move v1, v13

    .line 585
    :cond_f
    sub-int/2addr v1, v13

    .line 586
    move/from16 v12, v42

    .line 587
    .line 588
    add-int v23, v46, v12

    .line 589
    .line 590
    if-gez v23, :cond_10

    .line 591
    .line 592
    move v2, v14

    .line 593
    goto :goto_c

    .line 594
    :cond_10
    move/from16 v2, v23

    .line 595
    .line 596
    :goto_c
    neg-int v8, v1

    .line 597
    move/from16 p0, v1

    .line 598
    .line 599
    move/from16 v20, v3

    .line 600
    .line 601
    move/from16 v16, v14

    .line 602
    .line 603
    move v14, v8

    .line 604
    move/from16 v8, v16

    .line 605
    .line 606
    :goto_d
    iget v1, v0, Lmx0/l;->f:I

    .line 607
    .line 608
    move/from16 v25, v15

    .line 609
    .line 610
    if-ge v8, v1, :cond_12

    .line 611
    .line 612
    if-lt v14, v2, :cond_11

    .line 613
    .line 614
    invoke-virtual {v0, v8}, Lmx0/l;->e(I)Ljava/lang/Object;

    .line 615
    .line 616
    .line 617
    const/16 v16, 0x1

    .line 618
    .line 619
    goto :goto_e

    .line 620
    :cond_11
    add-int/lit8 v20, v20, 0x1

    .line 621
    .line 622
    add-int v14, v14, v39

    .line 623
    .line 624
    add-int/lit8 v8, v8, 0x1

    .line 625
    .line 626
    :goto_e
    move/from16 v15, v25

    .line 627
    .line 628
    goto :goto_d

    .line 629
    :cond_12
    move v1, v14

    .line 630
    move/from16 v33, v16

    .line 631
    .line 632
    move/from16 v14, p0

    .line 633
    .line 634
    move/from16 v16, v3

    .line 635
    .line 636
    move/from16 v3, v20

    .line 637
    .line 638
    :goto_f
    move/from16 v8, v48

    .line 639
    .line 640
    if-ge v3, v8, :cond_17

    .line 641
    .line 642
    if-lt v1, v2, :cond_13

    .line 643
    .line 644
    if-lez v1, :cond_13

    .line 645
    .line 646
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 647
    .line 648
    .line 649
    move-result v20

    .line 650
    if-eqz v20, :cond_14

    .line 651
    .line 652
    :cond_13
    move/from16 v48, v8

    .line 653
    .line 654
    goto :goto_10

    .line 655
    :cond_14
    move/from16 p0, v12

    .line 656
    .line 657
    move-object v12, v0

    .line 658
    move v0, v3

    .line 659
    move-wide/from16 v2, v18

    .line 660
    .line 661
    move/from16 v19, p0

    .line 662
    .line 663
    move v15, v1

    .line 664
    move/from16 v48, v8

    .line 665
    .line 666
    move/from16 v18, v14

    .line 667
    .line 668
    move/from16 v14, v25

    .line 669
    .line 670
    move/from16 v13, v46

    .line 671
    .line 672
    const/16 p0, 0x1

    .line 673
    .line 674
    goto/16 :goto_13

    .line 675
    .line 676
    :goto_10
    invoke-interface/range {v38 .. v38}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 677
    .line 678
    .line 679
    move-result-object v8

    .line 680
    move v15, v1

    .line 681
    move/from16 v20, v2

    .line 682
    .line 683
    move v1, v3

    .line 684
    move-wide/from16 v2, v18

    .line 685
    .line 686
    const/16 p0, 0x1

    .line 687
    .line 688
    move/from16 v19, v12

    .line 689
    .line 690
    move/from16 v18, v14

    .line 691
    .line 692
    move/from16 v14, v25

    .line 693
    .line 694
    move-object v12, v0

    .line 695
    move-object/from16 v0, p1

    .line 696
    .line 697
    invoke-static/range {v0 .. v11}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 698
    .line 699
    .line 700
    move-result-object v8

    .line 701
    move v0, v1

    .line 702
    add-int/lit8 v1, v48, -0x1

    .line 703
    .line 704
    if-ne v0, v1, :cond_15

    .line 705
    .line 706
    move/from16 v25, v10

    .line 707
    .line 708
    goto :goto_11

    .line 709
    :cond_15
    move/from16 v25, v39

    .line 710
    .line 711
    :goto_11
    add-int v15, v15, v25

    .line 712
    .line 713
    if-gt v15, v13, :cond_16

    .line 714
    .line 715
    if-eq v0, v1, :cond_16

    .line 716
    .line 717
    add-int/lit8 v1, v0, 0x1

    .line 718
    .line 719
    sub-int v8, v18, v39

    .line 720
    .line 721
    move/from16 v33, p0

    .line 722
    .line 723
    move/from16 v16, v1

    .line 724
    .line 725
    move/from16 v25, v14

    .line 726
    .line 727
    move v14, v8

    .line 728
    goto :goto_12

    .line 729
    :cond_16
    iget v1, v8, Lp1/d;->j:I

    .line 730
    .line 731
    invoke-static {v14, v1}, Ljava/lang/Math;->max(II)I

    .line 732
    .line 733
    .line 734
    move-result v1

    .line 735
    invoke-virtual {v12, v8}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 736
    .line 737
    .line 738
    move/from16 v25, v1

    .line 739
    .line 740
    move/from16 v14, v18

    .line 741
    .line 742
    :goto_12
    add-int/lit8 v0, v0, 0x1

    .line 743
    .line 744
    move-wide/from16 v53, v2

    .line 745
    .line 746
    move v3, v0

    .line 747
    move-object v0, v12

    .line 748
    move/from16 v12, v19

    .line 749
    .line 750
    move-wide/from16 v18, v53

    .line 751
    .line 752
    move v1, v15

    .line 753
    move/from16 v2, v20

    .line 754
    .line 755
    goto :goto_f

    .line 756
    :cond_17
    move/from16 p0, v12

    .line 757
    .line 758
    move-object v12, v0

    .line 759
    move v0, v3

    .line 760
    move-wide/from16 v2, v18

    .line 761
    .line 762
    move/from16 v19, p0

    .line 763
    .line 764
    move v15, v1

    .line 765
    move/from16 v48, v8

    .line 766
    .line 767
    move/from16 v18, v14

    .line 768
    .line 769
    move/from16 v14, v25

    .line 770
    .line 771
    const/16 p0, 0x1

    .line 772
    .line 773
    move/from16 v13, v46

    .line 774
    .line 775
    :goto_13
    if-ge v15, v13, :cond_1a

    .line 776
    .line 777
    sub-int v1, v13, v15

    .line 778
    .line 779
    sub-int v8, v18, v1

    .line 780
    .line 781
    add-int/2addr v15, v1

    .line 782
    move/from16 v25, v14

    .line 783
    .line 784
    move/from16 v1, v41

    .line 785
    .line 786
    :goto_14
    move v14, v8

    .line 787
    if-ge v14, v1, :cond_18

    .line 788
    .line 789
    if-lez v16, :cond_18

    .line 790
    .line 791
    add-int/lit8 v16, v16, -0x1

    .line 792
    .line 793
    invoke-interface/range {v38 .. v38}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 794
    .line 795
    .line 796
    move-result-object v8

    .line 797
    move/from16 v18, v14

    .line 798
    .line 799
    move/from16 v20, v15

    .line 800
    .line 801
    move/from16 v15, v25

    .line 802
    .line 803
    move/from16 v25, v0

    .line 804
    .line 805
    move v14, v1

    .line 806
    move/from16 v1, v16

    .line 807
    .line 808
    move-object/from16 v0, p1

    .line 809
    .line 810
    invoke-static/range {v0 .. v11}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 811
    .line 812
    .line 813
    move-result-object v8

    .line 814
    const/4 v0, 0x0

    .line 815
    invoke-virtual {v12, v0, v8}, Lmx0/l;->add(ILjava/lang/Object;)V

    .line 816
    .line 817
    .line 818
    iget v0, v8, Lp1/d;->j:I

    .line 819
    .line 820
    invoke-static {v15, v0}, Ljava/lang/Math;->max(II)I

    .line 821
    .line 822
    .line 823
    move-result v0

    .line 824
    add-int v8, v18, v39

    .line 825
    .line 826
    move/from16 v15, v25

    .line 827
    .line 828
    move/from16 v25, v0

    .line 829
    .line 830
    move v0, v15

    .line 831
    move v1, v14

    .line 832
    move/from16 v15, v20

    .line 833
    .line 834
    goto :goto_14

    .line 835
    :cond_18
    move/from16 v18, v14

    .line 836
    .line 837
    move/from16 v20, v15

    .line 838
    .line 839
    move/from16 v15, v25

    .line 840
    .line 841
    move/from16 v25, v0

    .line 842
    .line 843
    move v14, v1

    .line 844
    if-gez v18, :cond_19

    .line 845
    .line 846
    add-int v1, v20, v18

    .line 847
    .line 848
    move/from16 v18, v15

    .line 849
    .line 850
    move v15, v1

    .line 851
    const/4 v1, 0x0

    .line 852
    goto :goto_15

    .line 853
    :cond_19
    move/from16 v1, v18

    .line 854
    .line 855
    move/from16 v18, v15

    .line 856
    .line 857
    move/from16 v15, v20

    .line 858
    .line 859
    goto :goto_15

    .line 860
    :cond_1a
    move/from16 v25, v0

    .line 861
    .line 862
    move v0, v14

    .line 863
    move/from16 v14, v41

    .line 864
    .line 865
    move/from16 v1, v18

    .line 866
    .line 867
    move/from16 v18, v0

    .line 868
    .line 869
    :goto_15
    if-ltz v1, :cond_1b

    .line 870
    .line 871
    goto :goto_16

    .line 872
    :cond_1b
    const-string v0, "invalid currentFirstPageScrollOffset"

    .line 873
    .line 874
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    :goto_16
    neg-int v0, v1

    .line 878
    invoke-virtual {v12}, Lmx0/l;->first()Ljava/lang/Object;

    .line 879
    .line 880
    .line 881
    move-result-object v8

    .line 882
    check-cast v8, Lp1/d;

    .line 883
    .line 884
    move/from16 v41, v14

    .line 885
    .line 886
    if-gtz v14, :cond_1d

    .line 887
    .line 888
    move/from16 v14, v45

    .line 889
    .line 890
    move/from16 v20, v0

    .line 891
    .line 892
    if-gez v14, :cond_1c

    .line 893
    .line 894
    goto :goto_17

    .line 895
    :cond_1c
    move/from16 v29, v1

    .line 896
    .line 897
    move-object/from16 v26, v8

    .line 898
    .line 899
    move/from16 v45, v14

    .line 900
    .line 901
    move/from16 v14, v39

    .line 902
    .line 903
    goto :goto_19

    .line 904
    :cond_1d
    move/from16 v14, v45

    .line 905
    .line 906
    move/from16 v20, v0

    .line 907
    .line 908
    :goto_17
    invoke-virtual {v12}, Lmx0/l;->c()I

    .line 909
    .line 910
    .line 911
    move-result v0

    .line 912
    move-object/from16 v26, v8

    .line 913
    .line 914
    move v8, v1

    .line 915
    const/4 v1, 0x0

    .line 916
    :goto_18
    if-ge v1, v0, :cond_1e

    .line 917
    .line 918
    if-eqz v8, :cond_1e

    .line 919
    .line 920
    move/from16 v45, v14

    .line 921
    .line 922
    move/from16 v14, v39

    .line 923
    .line 924
    if-gt v14, v8, :cond_1f

    .line 925
    .line 926
    move/from16 v27, v0

    .line 927
    .line 928
    invoke-static {v12}, Ljp/k1;->h(Ljava/util/List;)I

    .line 929
    .line 930
    .line 931
    move-result v0

    .line 932
    if-eq v1, v0, :cond_1f

    .line 933
    .line 934
    sub-int/2addr v8, v14

    .line 935
    add-int/lit8 v1, v1, 0x1

    .line 936
    .line 937
    invoke-virtual {v12, v1}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 938
    .line 939
    .line 940
    move-result-object v0

    .line 941
    move-object/from16 v26, v0

    .line 942
    .line 943
    check-cast v26, Lp1/d;

    .line 944
    .line 945
    move/from16 v39, v14

    .line 946
    .line 947
    move/from16 v0, v27

    .line 948
    .line 949
    move/from16 v14, v45

    .line 950
    .line 951
    goto :goto_18

    .line 952
    :cond_1e
    move/from16 v45, v14

    .line 953
    .line 954
    move/from16 v14, v39

    .line 955
    .line 956
    :cond_1f
    move/from16 v29, v8

    .line 957
    .line 958
    :goto_19
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 959
    .line 960
    sub-int v0, v16, v50

    .line 961
    .line 962
    const/4 v1, 0x0

    .line 963
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 964
    .line 965
    .line 966
    move-result v0

    .line 967
    add-int/lit8 v1, v16, -0x1

    .line 968
    .line 969
    if-gt v0, v1, :cond_22

    .line 970
    .line 971
    const/4 v8, 0x0

    .line 972
    :goto_1a
    if-nez v8, :cond_20

    .line 973
    .line 974
    new-instance v8, Ljava/util/ArrayList;

    .line 975
    .line 976
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 977
    .line 978
    .line 979
    :cond_20
    sget-object v16, Lg1/w1;->d:Lg1/w1;

    .line 980
    .line 981
    move-object/from16 v16, v8

    .line 982
    .line 983
    invoke-interface/range {v38 .. v38}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 984
    .line 985
    .line 986
    move-result-object v8

    .line 987
    move/from16 v46, v13

    .line 988
    .line 989
    move/from16 v39, v14

    .line 990
    .line 991
    move-object/from16 v14, v26

    .line 992
    .line 993
    move v13, v0

    .line 994
    move/from16 v26, v15

    .line 995
    .line 996
    move-object/from16 v15, v16

    .line 997
    .line 998
    move-object/from16 v0, p1

    .line 999
    .line 1000
    move-object/from16 v16, v12

    .line 1001
    .line 1002
    move/from16 v12, v50

    .line 1003
    .line 1004
    invoke-static/range {v0 .. v11}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v8

    .line 1008
    invoke-interface {v15, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1009
    .line 1010
    .line 1011
    if-eq v1, v13, :cond_21

    .line 1012
    .line 1013
    add-int/lit8 v1, v1, -0x1

    .line 1014
    .line 1015
    move/from16 v50, v12

    .line 1016
    .line 1017
    move v0, v13

    .line 1018
    move-object v8, v15

    .line 1019
    move-object/from16 v12, v16

    .line 1020
    .line 1021
    move/from16 v15, v26

    .line 1022
    .line 1023
    move/from16 v13, v46

    .line 1024
    .line 1025
    move-object/from16 v26, v14

    .line 1026
    .line 1027
    move/from16 v14, v39

    .line 1028
    .line 1029
    goto :goto_1a

    .line 1030
    :cond_21
    move-object v8, v15

    .line 1031
    goto :goto_1b

    .line 1032
    :cond_22
    move-object/from16 v16, v12

    .line 1033
    .line 1034
    move/from16 v46, v13

    .line 1035
    .line 1036
    move/from16 v39, v14

    .line 1037
    .line 1038
    move-object/from16 v14, v26

    .line 1039
    .line 1040
    move/from16 v12, v50

    .line 1041
    .line 1042
    move v13, v0

    .line 1043
    move/from16 v26, v15

    .line 1044
    .line 1045
    const/4 v8, 0x0

    .line 1046
    :goto_1b
    move-object/from16 v15, v40

    .line 1047
    .line 1048
    check-cast v15, Ljava/util/Collection;

    .line 1049
    .line 1050
    invoke-interface {v15}, Ljava/util/Collection;->size()I

    .line 1051
    .line 1052
    .line 1053
    move-result v0

    .line 1054
    const/4 v1, 0x0

    .line 1055
    :goto_1c
    if-ge v1, v0, :cond_25

    .line 1056
    .line 1057
    move-object/from16 v27, v15

    .line 1058
    .line 1059
    move-object/from16 v15, v40

    .line 1060
    .line 1061
    invoke-interface {v15, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1062
    .line 1063
    .line 1064
    move-result-object v28

    .line 1065
    check-cast v28, Ljava/lang/Number;

    .line 1066
    .line 1067
    move/from16 v30, v0

    .line 1068
    .line 1069
    invoke-virtual/range {v28 .. v28}, Ljava/lang/Number;->intValue()I

    .line 1070
    .line 1071
    .line 1072
    move-result v0

    .line 1073
    if-ge v0, v13, :cond_24

    .line 1074
    .line 1075
    if-nez v8, :cond_23

    .line 1076
    .line 1077
    new-instance v8, Ljava/util/ArrayList;

    .line 1078
    .line 1079
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 1080
    .line 1081
    .line 1082
    :cond_23
    sget-object v28, Lg1/w1;->d:Lg1/w1;

    .line 1083
    .line 1084
    move-object/from16 v28, v8

    .line 1085
    .line 1086
    invoke-interface/range {v38 .. v38}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v8

    .line 1090
    move/from16 v31, v13

    .line 1091
    .line 1092
    move-object/from16 v13, v28

    .line 1093
    .line 1094
    move/from16 v28, v1

    .line 1095
    .line 1096
    move v1, v0

    .line 1097
    move-object/from16 v0, p1

    .line 1098
    .line 1099
    invoke-static/range {v0 .. v11}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v1

    .line 1103
    invoke-interface {v13, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1104
    .line 1105
    .line 1106
    move-object v8, v13

    .line 1107
    goto :goto_1d

    .line 1108
    :cond_24
    move/from16 v28, v1

    .line 1109
    .line 1110
    move/from16 v31, v13

    .line 1111
    .line 1112
    :goto_1d
    add-int/lit8 v1, v28, 0x1

    .line 1113
    .line 1114
    move-object/from16 v40, v15

    .line 1115
    .line 1116
    move-object/from16 v15, v27

    .line 1117
    .line 1118
    move/from16 v0, v30

    .line 1119
    .line 1120
    move/from16 v13, v31

    .line 1121
    .line 1122
    goto :goto_1c

    .line 1123
    :cond_25
    move-object/from16 v27, v15

    .line 1124
    .line 1125
    move-object/from16 v15, v40

    .line 1126
    .line 1127
    sget-object v13, Lmx0/s;->d:Lmx0/s;

    .line 1128
    .line 1129
    if-nez v8, :cond_26

    .line 1130
    .line 1131
    move-object v0, v13

    .line 1132
    goto :goto_1e

    .line 1133
    :cond_26
    move-object v0, v8

    .line 1134
    :goto_1e
    move-object/from16 v28, v0

    .line 1135
    .line 1136
    check-cast v28, Ljava/util/Collection;

    .line 1137
    .line 1138
    invoke-interface/range {v28 .. v28}, Ljava/util/Collection;->size()I

    .line 1139
    .line 1140
    .line 1141
    move-result v1

    .line 1142
    move/from16 v8, v18

    .line 1143
    .line 1144
    move-object/from16 v18, v13

    .line 1145
    .line 1146
    move v13, v8

    .line 1147
    const/4 v8, 0x0

    .line 1148
    :goto_1f
    if-ge v8, v1, :cond_27

    .line 1149
    .line 1150
    invoke-interface {v0, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v30

    .line 1154
    move-object/from16 v31, v0

    .line 1155
    .line 1156
    move-object/from16 v0, v30

    .line 1157
    .line 1158
    check-cast v0, Lp1/d;

    .line 1159
    .line 1160
    iget v0, v0, Lp1/d;->j:I

    .line 1161
    .line 1162
    invoke-static {v13, v0}, Ljava/lang/Math;->max(II)I

    .line 1163
    .line 1164
    .line 1165
    move-result v13

    .line 1166
    add-int/lit8 v8, v8, 0x1

    .line 1167
    .line 1168
    move-object/from16 v0, v31

    .line 1169
    .line 1170
    goto :goto_1f

    .line 1171
    :cond_27
    move-object/from16 v31, v0

    .line 1172
    .line 1173
    invoke-virtual/range {v16 .. v16}, Lmx0/l;->last()Ljava/lang/Object;

    .line 1174
    .line 1175
    .line 1176
    move-result-object v0

    .line 1177
    check-cast v0, Lp1/d;

    .line 1178
    .line 1179
    iget v0, v0, Lp1/d;->a:I

    .line 1180
    .line 1181
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 1182
    .line 1183
    sub-int v1, v48, v0

    .line 1184
    .line 1185
    add-int/lit8 v1, v1, -0x1

    .line 1186
    .line 1187
    invoke-static {v12, v1}, Ljava/lang/Math;->min(II)I

    .line 1188
    .line 1189
    .line 1190
    move-result v1

    .line 1191
    add-int/2addr v1, v0

    .line 1192
    add-int/lit8 v0, v0, 0x1

    .line 1193
    .line 1194
    if-gt v0, v1, :cond_2a

    .line 1195
    .line 1196
    const/4 v8, 0x0

    .line 1197
    :goto_20
    if-nez v8, :cond_28

    .line 1198
    .line 1199
    new-instance v8, Ljava/util/ArrayList;

    .line 1200
    .line 1201
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 1202
    .line 1203
    .line 1204
    :cond_28
    sget-object v30, Lg1/w1;->d:Lg1/w1;

    .line 1205
    .line 1206
    move-object/from16 v30, v8

    .line 1207
    .line 1208
    invoke-interface/range {v38 .. v38}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v8

    .line 1212
    move-object/from16 v32, v30

    .line 1213
    .line 1214
    move/from16 v30, v13

    .line 1215
    .line 1216
    move-object/from16 v13, v32

    .line 1217
    .line 1218
    move/from16 v50, v12

    .line 1219
    .line 1220
    move-object/from16 v32, v31

    .line 1221
    .line 1222
    move v12, v1

    .line 1223
    move v1, v0

    .line 1224
    move-object/from16 v0, p1

    .line 1225
    .line 1226
    invoke-static/range {v0 .. v11}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v8

    .line 1230
    invoke-interface {v13, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1231
    .line 1232
    .line 1233
    if-eq v1, v12, :cond_29

    .line 1234
    .line 1235
    add-int/lit8 v0, v1, 0x1

    .line 1236
    .line 1237
    move v1, v12

    .line 1238
    move-object v8, v13

    .line 1239
    move/from16 v13, v30

    .line 1240
    .line 1241
    move-object/from16 v31, v32

    .line 1242
    .line 1243
    move/from16 v12, v50

    .line 1244
    .line 1245
    goto :goto_20

    .line 1246
    :cond_29
    move-object v8, v13

    .line 1247
    goto :goto_21

    .line 1248
    :cond_2a
    move/from16 v50, v12

    .line 1249
    .line 1250
    move/from16 v30, v13

    .line 1251
    .line 1252
    move-object/from16 v32, v31

    .line 1253
    .line 1254
    move v12, v1

    .line 1255
    const/4 v8, 0x0

    .line 1256
    :goto_21
    invoke-interface/range {v27 .. v27}, Ljava/util/Collection;->size()I

    .line 1257
    .line 1258
    .line 1259
    move-result v13

    .line 1260
    const/4 v0, 0x0

    .line 1261
    :goto_22
    if-ge v0, v13, :cond_2e

    .line 1262
    .line 1263
    invoke-interface {v15, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v1

    .line 1267
    check-cast v1, Ljava/lang/Number;

    .line 1268
    .line 1269
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1270
    .line 1271
    .line 1272
    move-result v1

    .line 1273
    move/from16 v27, v0

    .line 1274
    .line 1275
    add-int/lit8 v0, v12, 0x1

    .line 1276
    .line 1277
    if-gt v0, v1, :cond_2d

    .line 1278
    .line 1279
    move/from16 v0, v48

    .line 1280
    .line 1281
    if-ge v1, v0, :cond_2c

    .line 1282
    .line 1283
    if-nez v8, :cond_2b

    .line 1284
    .line 1285
    new-instance v8, Ljava/util/ArrayList;

    .line 1286
    .line 1287
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 1288
    .line 1289
    .line 1290
    :cond_2b
    sget-object v31, Lg1/w1;->d:Lg1/w1;

    .line 1291
    .line 1292
    move-object/from16 v31, v8

    .line 1293
    .line 1294
    invoke-interface/range {v38 .. v38}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 1295
    .line 1296
    .line 1297
    move-result-object v8

    .line 1298
    move-object/from16 v34, v31

    .line 1299
    .line 1300
    move/from16 v31, v13

    .line 1301
    .line 1302
    move-object/from16 v13, v34

    .line 1303
    .line 1304
    move/from16 v34, v12

    .line 1305
    .line 1306
    move v12, v0

    .line 1307
    move-object/from16 v0, p1

    .line 1308
    .line 1309
    invoke-static/range {v0 .. v11}, Ljp/cd;->a(Lo1/d0;IJLp1/m;JLx2/i;Lt4/m;ZILandroidx/collection/b0;)Lp1/d;

    .line 1310
    .line 1311
    .line 1312
    move-result-object v1

    .line 1313
    invoke-interface {v13, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1314
    .line 1315
    .line 1316
    move-object v8, v13

    .line 1317
    goto :goto_24

    .line 1318
    :cond_2c
    move/from16 v34, v12

    .line 1319
    .line 1320
    move v12, v0

    .line 1321
    :goto_23
    move/from16 v31, v13

    .line 1322
    .line 1323
    goto :goto_24

    .line 1324
    :cond_2d
    move/from16 v34, v12

    .line 1325
    .line 1326
    move/from16 v12, v48

    .line 1327
    .line 1328
    goto :goto_23

    .line 1329
    :goto_24
    add-int/lit8 v0, v27, 0x1

    .line 1330
    .line 1331
    move/from16 v48, v12

    .line 1332
    .line 1333
    move/from16 v13, v31

    .line 1334
    .line 1335
    move/from16 v12, v34

    .line 1336
    .line 1337
    goto :goto_22

    .line 1338
    :cond_2e
    move/from16 v12, v48

    .line 1339
    .line 1340
    if-nez v8, :cond_2f

    .line 1341
    .line 1342
    move-object/from16 v8, v18

    .line 1343
    .line 1344
    :cond_2f
    move-object v0, v8

    .line 1345
    check-cast v0, Ljava/util/Collection;

    .line 1346
    .line 1347
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 1348
    .line 1349
    .line 1350
    move-result v1

    .line 1351
    move/from16 v13, v30

    .line 1352
    .line 1353
    const/4 v2, 0x0

    .line 1354
    :goto_25
    if-ge v2, v1, :cond_30

    .line 1355
    .line 1356
    invoke-interface {v8, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1357
    .line 1358
    .line 1359
    move-result-object v3

    .line 1360
    check-cast v3, Lp1/d;

    .line 1361
    .line 1362
    iget v3, v3, Lp1/d;->j:I

    .line 1363
    .line 1364
    invoke-static {v13, v3}, Ljava/lang/Math;->max(II)I

    .line 1365
    .line 1366
    .line 1367
    move-result v13

    .line 1368
    add-int/lit8 v2, v2, 0x1

    .line 1369
    .line 1370
    goto :goto_25

    .line 1371
    :cond_30
    invoke-virtual/range {v16 .. v16}, Lmx0/l;->first()Ljava/lang/Object;

    .line 1372
    .line 1373
    .line 1374
    move-result-object v1

    .line 1375
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1376
    .line 1377
    .line 1378
    move-result v1

    .line 1379
    if-eqz v1, :cond_31

    .line 1380
    .line 1381
    invoke-interface/range {v32 .. v32}, Ljava/util/List;->isEmpty()Z

    .line 1382
    .line 1383
    .line 1384
    move-result v1

    .line 1385
    if-eqz v1, :cond_31

    .line 1386
    .line 1387
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 1388
    .line 1389
    .line 1390
    move-result v1

    .line 1391
    if-eqz v1, :cond_31

    .line 1392
    .line 1393
    move/from16 v6, p0

    .line 1394
    .line 1395
    goto :goto_26

    .line 1396
    :cond_31
    const/4 v6, 0x0

    .line 1397
    :goto_26
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 1398
    .line 1399
    move/from16 v15, v26

    .line 1400
    .line 1401
    move-wide/from16 v1, v43

    .line 1402
    .line 1403
    invoke-static {v15, v1, v2}, Lt4/b;->g(IJ)I

    .line 1404
    .line 1405
    .line 1406
    move-result v3

    .line 1407
    invoke-static {v13, v1, v2}, Lt4/b;->f(IJ)I

    .line 1408
    .line 1409
    .line 1410
    move-result v7

    .line 1411
    move/from16 v13, v46

    .line 1412
    .line 1413
    invoke-static {v3, v13}, Ljava/lang/Math;->min(II)I

    .line 1414
    .line 1415
    .line 1416
    move-result v1

    .line 1417
    if-ge v15, v1, :cond_32

    .line 1418
    .line 1419
    move/from16 v1, p0

    .line 1420
    .line 1421
    goto :goto_27

    .line 1422
    :cond_32
    const/4 v1, 0x0

    .line 1423
    :goto_27
    if-eqz v1, :cond_34

    .line 1424
    .line 1425
    if-nez v20, :cond_33

    .line 1426
    .line 1427
    goto :goto_28

    .line 1428
    :cond_33
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1429
    .line 1430
    const-string v4, "non-zero pagesScrollOffset="

    .line 1431
    .line 1432
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1433
    .line 1434
    .line 1435
    move/from16 v4, v20

    .line 1436
    .line 1437
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1438
    .line 1439
    .line 1440
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v2

    .line 1444
    invoke-static {v2}, Lj1/b;->c(Ljava/lang/String;)V

    .line 1445
    .line 1446
    .line 1447
    goto :goto_29

    .line 1448
    :cond_34
    :goto_28
    move/from16 v4, v20

    .line 1449
    .line 1450
    :goto_29
    new-instance v11, Ljava/util/ArrayList;

    .line 1451
    .line 1452
    invoke-virtual/range {v16 .. v16}, Lmx0/l;->c()I

    .line 1453
    .line 1454
    .line 1455
    move-result v2

    .line 1456
    invoke-interface/range {v32 .. v32}, Ljava/util/List;->size()I

    .line 1457
    .line 1458
    .line 1459
    move-result v5

    .line 1460
    add-int/2addr v5, v2

    .line 1461
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 1462
    .line 1463
    .line 1464
    move-result v2

    .line 1465
    add-int/2addr v2, v5

    .line 1466
    invoke-direct {v11, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1467
    .line 1468
    .line 1469
    if-eqz v1, :cond_3e

    .line 1470
    .line 1471
    invoke-interface/range {v32 .. v32}, Ljava/util/List;->isEmpty()Z

    .line 1472
    .line 1473
    .line 1474
    move-result v0

    .line 1475
    if-eqz v0, :cond_35

    .line 1476
    .line 1477
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 1478
    .line 1479
    .line 1480
    move-result v0

    .line 1481
    if-eqz v0, :cond_35

    .line 1482
    .line 1483
    goto :goto_2a

    .line 1484
    :cond_35
    const-string v0, "No extra pages"

    .line 1485
    .line 1486
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 1487
    .line 1488
    .line 1489
    :goto_2a
    invoke-virtual/range {v16 .. v16}, Lmx0/l;->c()I

    .line 1490
    .line 1491
    .line 1492
    move-result v0

    .line 1493
    move v2, v3

    .line 1494
    new-array v3, v0, [I

    .line 1495
    .line 1496
    const/4 v1, 0x0

    .line 1497
    :goto_2b
    if-ge v1, v0, :cond_36

    .line 1498
    .line 1499
    aput v10, v3, v1

    .line 1500
    .line 1501
    add-int/lit8 v1, v1, 0x1

    .line 1502
    .line 1503
    goto :goto_2b

    .line 1504
    :cond_36
    new-array v5, v0, [I

    .line 1505
    .line 1506
    move/from16 v20, v0

    .line 1507
    .line 1508
    move-object/from16 v1, v38

    .line 1509
    .line 1510
    move/from16 v4, v45

    .line 1511
    .line 1512
    invoke-interface {v1, v4}, Lt4/c;->n0(I)F

    .line 1513
    .line 1514
    .line 1515
    move-result v0

    .line 1516
    new-instance v1, Lk1/h;

    .line 1517
    .line 1518
    move/from16 v27, v2

    .line 1519
    .line 1520
    move/from16 v26, v6

    .line 1521
    .line 1522
    const/4 v2, 0x0

    .line 1523
    const/4 v6, 0x0

    .line 1524
    invoke-direct {v1, v0, v2, v6}, Lk1/h;-><init>(FZLay0/n;)V

    .line 1525
    .line 1526
    .line 1527
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 1528
    .line 1529
    sget-object v4, Lt4/m;->d:Lt4/m;

    .line 1530
    .line 1531
    move-object v0, v1

    .line 1532
    move/from16 v2, v27

    .line 1533
    .line 1534
    move-object/from16 v6, v38

    .line 1535
    .line 1536
    move-object/from16 v1, p1

    .line 1537
    .line 1538
    invoke-virtual/range {v0 .. v5}, Lk1/h;->c(Lt4/c;I[ILt4/m;[I)V

    .line 1539
    .line 1540
    .line 1541
    invoke-static {v5}, Lmx0/n;->z([I)Lgy0/j;

    .line 1542
    .line 1543
    .line 1544
    move-result-object v0

    .line 1545
    if-nez v9, :cond_37

    .line 1546
    .line 1547
    goto :goto_2c

    .line 1548
    :cond_37
    iget v1, v0, Lgy0/h;->e:I

    .line 1549
    .line 1550
    iget v3, v0, Lgy0/h;->d:I

    .line 1551
    .line 1552
    iget v0, v0, Lgy0/h;->f:I

    .line 1553
    .line 1554
    neg-int v0, v0

    .line 1555
    new-instance v4, Lgy0/h;

    .line 1556
    .line 1557
    invoke-direct {v4, v1, v3, v0}, Lgy0/h;-><init>(III)V

    .line 1558
    .line 1559
    .line 1560
    move-object v0, v4

    .line 1561
    :goto_2c
    iget v1, v0, Lgy0/h;->d:I

    .line 1562
    .line 1563
    iget v3, v0, Lgy0/h;->e:I

    .line 1564
    .line 1565
    iget v0, v0, Lgy0/h;->f:I

    .line 1566
    .line 1567
    if-lez v0, :cond_38

    .line 1568
    .line 1569
    if-le v1, v3, :cond_39

    .line 1570
    .line 1571
    :cond_38
    if-gez v0, :cond_3d

    .line 1572
    .line 1573
    if-gt v3, v1, :cond_3d

    .line 1574
    .line 1575
    :cond_39
    :goto_2d
    aget v4, v5, v1

    .line 1576
    .line 1577
    if-nez v9, :cond_3a

    .line 1578
    .line 1579
    move/from16 v28, v0

    .line 1580
    .line 1581
    move v0, v1

    .line 1582
    :goto_2e
    move/from16 p1, v4

    .line 1583
    .line 1584
    move-object/from16 v4, v16

    .line 1585
    .line 1586
    goto :goto_2f

    .line 1587
    :cond_3a
    sub-int v27, v20, v1

    .line 1588
    .line 1589
    add-int/lit8 v27, v27, -0x1

    .line 1590
    .line 1591
    move/from16 v28, v0

    .line 1592
    .line 1593
    move/from16 v0, v27

    .line 1594
    .line 1595
    goto :goto_2e

    .line 1596
    :goto_2f
    invoke-virtual {v4, v0}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1597
    .line 1598
    .line 1599
    move-result-object v0

    .line 1600
    check-cast v0, Lp1/d;

    .line 1601
    .line 1602
    if-eqz v9, :cond_3b

    .line 1603
    .line 1604
    sub-int v16, v2, p1

    .line 1605
    .line 1606
    move-object/from16 v27, v5

    .line 1607
    .line 1608
    iget v5, v0, Lp1/d;->b:I

    .line 1609
    .line 1610
    sub-int v5, v16, v5

    .line 1611
    .line 1612
    goto :goto_30

    .line 1613
    :cond_3b
    move-object/from16 v27, v5

    .line 1614
    .line 1615
    move/from16 v5, p1

    .line 1616
    .line 1617
    :goto_30
    invoke-virtual {v0, v5, v2, v7}, Lp1/d;->b(III)V

    .line 1618
    .line 1619
    .line 1620
    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1621
    .line 1622
    .line 1623
    if-eq v1, v3, :cond_3c

    .line 1624
    .line 1625
    add-int v1, v1, v28

    .line 1626
    .line 1627
    move-object/from16 v16, v4

    .line 1628
    .line 1629
    move-object/from16 v5, v27

    .line 1630
    .line 1631
    move/from16 v0, v28

    .line 1632
    .line 1633
    goto :goto_2d

    .line 1634
    :cond_3c
    :goto_31
    move-object/from16 v31, v32

    .line 1635
    .line 1636
    goto/16 :goto_35

    .line 1637
    .line 1638
    :cond_3d
    move-object/from16 v4, v16

    .line 1639
    .line 1640
    goto :goto_31

    .line 1641
    :cond_3e
    move v2, v3

    .line 1642
    move/from16 v20, v4

    .line 1643
    .line 1644
    move/from16 v26, v6

    .line 1645
    .line 1646
    move-object/from16 v4, v16

    .line 1647
    .line 1648
    move-object/from16 v6, v38

    .line 1649
    .line 1650
    invoke-interface/range {v28 .. v28}, Ljava/util/Collection;->size()I

    .line 1651
    .line 1652
    .line 1653
    move-result v1

    .line 1654
    move/from16 v3, v20

    .line 1655
    .line 1656
    const/4 v5, 0x0

    .line 1657
    :goto_32
    if-ge v5, v1, :cond_3f

    .line 1658
    .line 1659
    move-object/from16 v16, v0

    .line 1660
    .line 1661
    move-object/from16 v0, v32

    .line 1662
    .line 1663
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1664
    .line 1665
    .line 1666
    move-result-object v27

    .line 1667
    move-object/from16 v31, v0

    .line 1668
    .line 1669
    move-object/from16 v0, v27

    .line 1670
    .line 1671
    check-cast v0, Lp1/d;

    .line 1672
    .line 1673
    sub-int v3, v3, v35

    .line 1674
    .line 1675
    invoke-virtual {v0, v3, v2, v7}, Lp1/d;->b(III)V

    .line 1676
    .line 1677
    .line 1678
    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1679
    .line 1680
    .line 1681
    add-int/lit8 v5, v5, 0x1

    .line 1682
    .line 1683
    move-object/from16 v0, v16

    .line 1684
    .line 1685
    move-object/from16 v32, v31

    .line 1686
    .line 1687
    goto :goto_32

    .line 1688
    :cond_3f
    move-object/from16 v16, v0

    .line 1689
    .line 1690
    move-object/from16 v31, v32

    .line 1691
    .line 1692
    invoke-virtual {v4}, Lmx0/l;->c()I

    .line 1693
    .line 1694
    .line 1695
    move-result v0

    .line 1696
    move/from16 v1, v20

    .line 1697
    .line 1698
    const/4 v3, 0x0

    .line 1699
    :goto_33
    if-ge v3, v0, :cond_40

    .line 1700
    .line 1701
    invoke-virtual {v4, v3}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1702
    .line 1703
    .line 1704
    move-result-object v5

    .line 1705
    check-cast v5, Lp1/d;

    .line 1706
    .line 1707
    invoke-virtual {v5, v1, v2, v7}, Lp1/d;->b(III)V

    .line 1708
    .line 1709
    .line 1710
    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1711
    .line 1712
    .line 1713
    add-int v1, v1, v35

    .line 1714
    .line 1715
    add-int/lit8 v3, v3, 0x1

    .line 1716
    .line 1717
    goto :goto_33

    .line 1718
    :cond_40
    invoke-interface/range {v16 .. v16}, Ljava/util/Collection;->size()I

    .line 1719
    .line 1720
    .line 1721
    move-result v0

    .line 1722
    move v3, v1

    .line 1723
    const/4 v1, 0x0

    .line 1724
    :goto_34
    if-ge v1, v0, :cond_41

    .line 1725
    .line 1726
    invoke-interface {v8, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1727
    .line 1728
    .line 1729
    move-result-object v5

    .line 1730
    check-cast v5, Lp1/d;

    .line 1731
    .line 1732
    invoke-virtual {v5, v3, v2, v7}, Lp1/d;->b(III)V

    .line 1733
    .line 1734
    .line 1735
    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1736
    .line 1737
    .line 1738
    add-int v3, v3, v35

    .line 1739
    .line 1740
    add-int/lit8 v1, v1, 0x1

    .line 1741
    .line 1742
    goto :goto_34

    .line 1743
    :cond_41
    :goto_35
    if-eqz v26, :cond_43

    .line 1744
    .line 1745
    move-object v0, v11

    .line 1746
    :cond_42
    move/from16 v27, v2

    .line 1747
    .line 1748
    goto :goto_37

    .line 1749
    :cond_43
    new-instance v0, Ljava/util/ArrayList;

    .line 1750
    .line 1751
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1752
    .line 1753
    .line 1754
    move-result v1

    .line 1755
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 1756
    .line 1757
    .line 1758
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1759
    .line 1760
    .line 1761
    move-result v1

    .line 1762
    const/4 v3, 0x0

    .line 1763
    :goto_36
    if-ge v3, v1, :cond_42

    .line 1764
    .line 1765
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1766
    .line 1767
    .line 1768
    move-result-object v5

    .line 1769
    move/from16 p1, v1

    .line 1770
    .line 1771
    move-object v1, v5

    .line 1772
    check-cast v1, Lp1/d;

    .line 1773
    .line 1774
    move/from16 v27, v2

    .line 1775
    .line 1776
    iget v2, v1, Lp1/d;->a:I

    .line 1777
    .line 1778
    invoke-virtual {v4}, Lmx0/l;->first()Ljava/lang/Object;

    .line 1779
    .line 1780
    .line 1781
    move-result-object v16

    .line 1782
    move/from16 v20, v3

    .line 1783
    .line 1784
    move-object/from16 v3, v16

    .line 1785
    .line 1786
    check-cast v3, Lp1/d;

    .line 1787
    .line 1788
    iget v3, v3, Lp1/d;->a:I

    .line 1789
    .line 1790
    if-lt v2, v3, :cond_44

    .line 1791
    .line 1792
    iget v1, v1, Lp1/d;->a:I

    .line 1793
    .line 1794
    invoke-virtual {v4}, Lmx0/l;->last()Ljava/lang/Object;

    .line 1795
    .line 1796
    .line 1797
    move-result-object v2

    .line 1798
    check-cast v2, Lp1/d;

    .line 1799
    .line 1800
    iget v2, v2, Lp1/d;->a:I

    .line 1801
    .line 1802
    if-gt v1, v2, :cond_44

    .line 1803
    .line 1804
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1805
    .line 1806
    .line 1807
    :cond_44
    add-int/lit8 v3, v20, 0x1

    .line 1808
    .line 1809
    move/from16 v1, p1

    .line 1810
    .line 1811
    move/from16 v2, v27

    .line 1812
    .line 1813
    goto :goto_36

    .line 1814
    :goto_37
    invoke-interface/range {v31 .. v31}, Ljava/util/List;->isEmpty()Z

    .line 1815
    .line 1816
    .line 1817
    move-result v1

    .line 1818
    if-eqz v1, :cond_45

    .line 1819
    .line 1820
    move-object/from16 v34, v18

    .line 1821
    .line 1822
    goto :goto_39

    .line 1823
    :cond_45
    new-instance v1, Ljava/util/ArrayList;

    .line 1824
    .line 1825
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1826
    .line 1827
    .line 1828
    move-result v2

    .line 1829
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1830
    .line 1831
    .line 1832
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1833
    .line 1834
    .line 1835
    move-result v2

    .line 1836
    const/4 v3, 0x0

    .line 1837
    :goto_38
    if-ge v3, v2, :cond_47

    .line 1838
    .line 1839
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1840
    .line 1841
    .line 1842
    move-result-object v5

    .line 1843
    move/from16 p1, v2

    .line 1844
    .line 1845
    move-object v2, v5

    .line 1846
    check-cast v2, Lp1/d;

    .line 1847
    .line 1848
    iget v2, v2, Lp1/d;->a:I

    .line 1849
    .line 1850
    invoke-virtual {v4}, Lmx0/l;->first()Ljava/lang/Object;

    .line 1851
    .line 1852
    .line 1853
    move-result-object v16

    .line 1854
    move/from16 v20, v3

    .line 1855
    .line 1856
    move-object/from16 v3, v16

    .line 1857
    .line 1858
    check-cast v3, Lp1/d;

    .line 1859
    .line 1860
    iget v3, v3, Lp1/d;->a:I

    .line 1861
    .line 1862
    if-ge v2, v3, :cond_46

    .line 1863
    .line 1864
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1865
    .line 1866
    .line 1867
    :cond_46
    add-int/lit8 v3, v20, 0x1

    .line 1868
    .line 1869
    move/from16 v2, p1

    .line 1870
    .line 1871
    goto :goto_38

    .line 1872
    :cond_47
    move-object/from16 v34, v1

    .line 1873
    .line 1874
    :goto_39
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 1875
    .line 1876
    .line 1877
    move-result v1

    .line 1878
    if-eqz v1, :cond_48

    .line 1879
    .line 1880
    move-object/from16 v35, v18

    .line 1881
    .line 1882
    goto :goto_3b

    .line 1883
    :cond_48
    new-instance v1, Ljava/util/ArrayList;

    .line 1884
    .line 1885
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1886
    .line 1887
    .line 1888
    move-result v2

    .line 1889
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1890
    .line 1891
    .line 1892
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1893
    .line 1894
    .line 1895
    move-result v2

    .line 1896
    const/4 v3, 0x0

    .line 1897
    :goto_3a
    if-ge v3, v2, :cond_4a

    .line 1898
    .line 1899
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1900
    .line 1901
    .line 1902
    move-result-object v5

    .line 1903
    move-object v8, v5

    .line 1904
    check-cast v8, Lp1/d;

    .line 1905
    .line 1906
    iget v8, v8, Lp1/d;->a:I

    .line 1907
    .line 1908
    invoke-virtual {v4}, Lmx0/l;->last()Ljava/lang/Object;

    .line 1909
    .line 1910
    .line 1911
    move-result-object v16

    .line 1912
    move/from16 p1, v2

    .line 1913
    .line 1914
    move-object/from16 v2, v16

    .line 1915
    .line 1916
    check-cast v2, Lp1/d;

    .line 1917
    .line 1918
    iget v2, v2, Lp1/d;->a:I

    .line 1919
    .line 1920
    if-le v8, v2, :cond_49

    .line 1921
    .line 1922
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1923
    .line 1924
    .line 1925
    :cond_49
    add-int/lit8 v3, v3, 0x1

    .line 1926
    .line 1927
    move/from16 v2, p1

    .line 1928
    .line 1929
    goto :goto_3a

    .line 1930
    :cond_4a
    move-object/from16 v35, v1

    .line 1931
    .line 1932
    :goto_3b
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 1933
    .line 1934
    .line 1935
    move-result v1

    .line 1936
    if-eqz v1, :cond_4b

    .line 1937
    .line 1938
    move-object/from16 v20, v0

    .line 1939
    .line 1940
    move/from16 v18, v7

    .line 1941
    .line 1942
    move/from16 v26, v9

    .line 1943
    .line 1944
    move/from16 v8, v19

    .line 1945
    .line 1946
    move/from16 v4, v41

    .line 1947
    .line 1948
    move/from16 v3, v47

    .line 1949
    .line 1950
    move-object/from16 v5, v52

    .line 1951
    .line 1952
    const/16 v16, 0x0

    .line 1953
    .line 1954
    goto/16 :goto_3d

    .line 1955
    .line 1956
    :cond_4b
    const/4 v1, 0x0

    .line 1957
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1958
    .line 1959
    .line 1960
    move-result-object v2

    .line 1961
    move-object v1, v2

    .line 1962
    check-cast v1, Lp1/d;

    .line 1963
    .line 1964
    iget v1, v1, Lp1/d;->l:I

    .line 1965
    .line 1966
    move-object/from16 p1, v2

    .line 1967
    .line 1968
    move/from16 v8, v19

    .line 1969
    .line 1970
    move/from16 v4, v41

    .line 1971
    .line 1972
    move/from16 v3, v47

    .line 1973
    .line 1974
    move-object/from16 v5, v52

    .line 1975
    .line 1976
    invoke-interface {v5, v3, v10, v4, v8}, Lh1/n;->a(IIII)I

    .line 1977
    .line 1978
    .line 1979
    move-result v2

    .line 1980
    int-to-float v2, v2

    .line 1981
    int-to-float v1, v1

    .line 1982
    sub-float/2addr v1, v2

    .line 1983
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 1984
    .line 1985
    .line 1986
    move-result v1

    .line 1987
    neg-float v1, v1

    .line 1988
    invoke-static {v0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 1989
    .line 1990
    .line 1991
    move-result v2

    .line 1992
    move/from16 v16, v1

    .line 1993
    .line 1994
    move/from16 v1, p0

    .line 1995
    .line 1996
    if-gt v1, v2, :cond_4d

    .line 1997
    .line 1998
    move/from16 v18, v7

    .line 1999
    .line 2000
    move v7, v1

    .line 2001
    move/from16 v1, v16

    .line 2002
    .line 2003
    move-object/from16 v16, p1

    .line 2004
    .line 2005
    :goto_3c
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 2006
    .line 2007
    .line 2008
    move-result-object v19

    .line 2009
    move-object/from16 v20, v0

    .line 2010
    .line 2011
    move-object/from16 v0, v19

    .line 2012
    .line 2013
    check-cast v0, Lp1/d;

    .line 2014
    .line 2015
    iget v0, v0, Lp1/d;->l:I

    .line 2016
    .line 2017
    move/from16 v26, v9

    .line 2018
    .line 2019
    invoke-interface {v5, v3, v10, v4, v8}, Lh1/n;->a(IIII)I

    .line 2020
    .line 2021
    .line 2022
    move-result v9

    .line 2023
    int-to-float v9, v9

    .line 2024
    int-to-float v0, v0

    .line 2025
    sub-float/2addr v0, v9

    .line 2026
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 2027
    .line 2028
    .line 2029
    move-result v0

    .line 2030
    neg-float v0, v0

    .line 2031
    invoke-static {v1, v0}, Ljava/lang/Float;->compare(FF)I

    .line 2032
    .line 2033
    .line 2034
    move-result v9

    .line 2035
    if-gez v9, :cond_4c

    .line 2036
    .line 2037
    move v1, v0

    .line 2038
    move-object/from16 v16, v19

    .line 2039
    .line 2040
    :cond_4c
    if-eq v7, v2, :cond_4e

    .line 2041
    .line 2042
    add-int/lit8 v7, v7, 0x1

    .line 2043
    .line 2044
    move-object/from16 v0, v20

    .line 2045
    .line 2046
    move/from16 v9, v26

    .line 2047
    .line 2048
    goto :goto_3c

    .line 2049
    :cond_4d
    move-object/from16 v20, v0

    .line 2050
    .line 2051
    move/from16 v18, v7

    .line 2052
    .line 2053
    move/from16 v26, v9

    .line 2054
    .line 2055
    move-object/from16 v16, p1

    .line 2056
    .line 2057
    :cond_4e
    :goto_3d
    move-object/from16 v0, v16

    .line 2058
    .line 2059
    check-cast v0, Lp1/d;

    .line 2060
    .line 2061
    invoke-interface {v5, v3, v10, v4, v8}, Lh1/n;->a(IIII)I

    .line 2062
    .line 2063
    .line 2064
    move-result v1

    .line 2065
    if-eqz v0, :cond_4f

    .line 2066
    .line 2067
    iget v2, v0, Lp1/d;->l:I

    .line 2068
    .line 2069
    goto :goto_3e

    .line 2070
    :cond_4f
    const/4 v2, 0x0

    .line 2071
    :goto_3e
    if-nez v39, :cond_50

    .line 2072
    .line 2073
    const/4 v1, 0x0

    .line 2074
    :goto_3f
    move/from16 v28, v1

    .line 2075
    .line 2076
    goto :goto_40

    .line 2077
    :cond_50
    sub-int/2addr v1, v2

    .line 2078
    int-to-float v1, v1

    .line 2079
    move/from16 v2, v39

    .line 2080
    .line 2081
    int-to-float v2, v2

    .line 2082
    div-float/2addr v1, v2

    .line 2083
    const/high16 v2, -0x41000000    # -0.5f

    .line 2084
    .line 2085
    const/high16 v3, 0x3f000000    # 0.5f

    .line 2086
    .line 2087
    invoke-static {v1, v2, v3}, Lkp/r9;->d(FFF)F

    .line 2088
    .line 2089
    .line 2090
    move-result v1

    .line 2091
    goto :goto_3f

    .line 2092
    :goto_40
    new-instance v1, Lod0/n;

    .line 2093
    .line 2094
    const/4 v2, 0x2

    .line 2095
    move-object/from16 v3, v49

    .line 2096
    .line 2097
    invoke-direct {v1, v2, v3, v11}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 2098
    .line 2099
    .line 2100
    add-int v3, v27, v22

    .line 2101
    .line 2102
    move-object/from16 v31, v5

    .line 2103
    .line 2104
    move-wide/from16 v4, p2

    .line 2105
    .line 2106
    invoke-static {v3, v4, v5}, Lt4/b;->g(IJ)I

    .line 2107
    .line 2108
    .line 2109
    move-result v2

    .line 2110
    add-int v7, v18, v24

    .line 2111
    .line 2112
    invoke-static {v7, v4, v5}, Lt4/b;->f(IJ)I

    .line 2113
    .line 2114
    .line 2115
    move-result v3

    .line 2116
    move-object/from16 v4, v51

    .line 2117
    .line 2118
    invoke-interface {v6, v2, v3, v4, v1}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 2119
    .line 2120
    .line 2121
    move-result-object v32

    .line 2122
    move/from16 v1, v25

    .line 2123
    .line 2124
    if-lt v1, v12, :cond_52

    .line 2125
    .line 2126
    if-le v15, v13, :cond_51

    .line 2127
    .line 2128
    goto :goto_41

    .line 2129
    :cond_51
    const/16 v30, 0x0

    .line 2130
    .line 2131
    goto :goto_42

    .line 2132
    :cond_52
    :goto_41
    const/16 v30, 0x1

    .line 2133
    .line 2134
    :goto_42
    new-instance v16, Lp1/o;

    .line 2135
    .line 2136
    move-object/from16 v27, v0

    .line 2137
    .line 2138
    move/from16 v18, v10

    .line 2139
    .line 2140
    move/from16 v22, v17

    .line 2141
    .line 2142
    move-object/from16 v17, v20

    .line 2143
    .line 2144
    move/from16 v24, v26

    .line 2145
    .line 2146
    move/from16 v19, v45

    .line 2147
    .line 2148
    move/from16 v25, v50

    .line 2149
    .line 2150
    move/from16 v20, v8

    .line 2151
    .line 2152
    move-object/from16 v26, v14

    .line 2153
    .line 2154
    invoke-direct/range {v16 .. v36}, Lp1/o;-><init>(Ljava/util/List;IIILg1/w1;IIZILp1/d;Lp1/d;FIZLh1/n;Lt3/r0;ZLjava/util/List;Ljava/util/List;Lvy0/b0;)V

    .line 2155
    .line 2156
    .line 2157
    goto/16 :goto_7

    .line 2158
    .line 2159
    :goto_43
    invoke-interface {v6}, Lt3/t;->I()Z

    .line 2160
    .line 2161
    .line 2162
    move-result v1

    .line 2163
    move-object/from16 v2, v37

    .line 2164
    .line 2165
    const/4 v14, 0x0

    .line 2166
    invoke-virtual {v2, v0, v1, v14}, Lp1/v;->h(Lp1/o;ZZ)V

    .line 2167
    .line 2168
    .line 2169
    return-object v0

    .line 2170
    :catchall_0
    move-exception v0

    .line 2171
    invoke-static {v2, v9, v8}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 2172
    .line 2173
    .line 2174
    throw v0
.end method
