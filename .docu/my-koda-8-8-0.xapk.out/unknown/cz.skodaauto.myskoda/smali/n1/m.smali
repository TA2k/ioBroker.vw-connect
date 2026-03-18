.class public final Ln1/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/c0;


# instance fields
.field public final synthetic a:Ln1/v;

.field public final synthetic b:Lk1/z0;

.field public final synthetic c:Lay0/a;

.field public final synthetic d:Ln1/c;

.field public final synthetic e:Lk1/i;

.field public final synthetic f:Lvy0/b0;

.field public final synthetic g:Le3/w;

.field public final synthetic h:Lo1/f0;


# direct methods
.method public constructor <init>(Ln1/v;Lk1/z0;Lhy0/u;Ln1/c;Lk1/i;Lk1/g;Lvy0/b0;Le3/w;Lo1/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln1/m;->a:Ln1/v;

    .line 5
    .line 6
    iput-object p2, p0, Ln1/m;->b:Lk1/z0;

    .line 7
    .line 8
    iput-object p3, p0, Ln1/m;->c:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, Ln1/m;->d:Ln1/c;

    .line 11
    .line 12
    iput-object p5, p0, Ln1/m;->e:Lk1/i;

    .line 13
    .line 14
    iput-object p7, p0, Ln1/m;->f:Lvy0/b0;

    .line 15
    .line 16
    iput-object p8, p0, Ln1/m;->g:Le3/w;

    .line 17
    .line 18
    iput-object p9, p0, Ln1/m;->h:Lo1/f0;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Lo1/d0;J)Lt3/r0;
    .locals 66

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    move-wide/from16 v10, p2

    .line 6
    .line 7
    iget-object v12, v9, Lo1/d0;->e:Lt3/p1;

    .line 8
    .line 9
    iget-object v13, v0, Ln1/m;->a:Ln1/v;

    .line 10
    .line 11
    iget-object v1, v13, Ln1/v;->s:Ll2/b1;

    .line 12
    .line 13
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    iget-boolean v1, v13, Ln1/v;->b:Z

    .line 17
    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    invoke-interface {v12}, Lt3/t;->I()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/16 v26, 0x0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    :goto_0
    const/16 v26, 0x1

    .line 31
    .line 32
    :goto_1
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 33
    .line 34
    invoke-static {v10, v11, v1}, Lkp/j;->a(JLg1/w1;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v12}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    iget-object v3, v0, Ln1/m;->b:Lk1/z0;

    .line 42
    .line 43
    invoke-interface {v3, v2}, Lk1/z0;->b(Lt4/m;)F

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-interface {v12, v2}, Lt4/c;->Q(F)I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    invoke-interface {v12}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-interface {v3, v4}, Lk1/z0;->a(Lt4/m;)F

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    invoke-interface {v12, v4}, Lt4/c;->Q(F)I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    invoke-interface {v3}, Lk1/z0;->d()F

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    invoke-interface {v12, v5}, Lt4/c;->Q(F)I

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    invoke-interface {v3}, Lk1/z0;->c()F

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    invoke-interface {v12, v3}, Lt4/c;->Q(F)I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    add-int/2addr v3, v6

    .line 80
    add-int/2addr v4, v2

    .line 81
    sub-int v18, v3, v6

    .line 82
    .line 83
    neg-int v5, v4

    .line 84
    neg-int v7, v3

    .line 85
    invoke-static {v10, v11, v5, v7}, Lt4/b;->i(JII)J

    .line 86
    .line 87
    .line 88
    move-result-wide v7

    .line 89
    iget-object v5, v0, Ln1/m;->c:Lay0/a;

    .line 90
    .line 91
    invoke-interface {v5}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    check-cast v5, Ln1/h;

    .line 96
    .line 97
    const/16 v31, 0x1

    .line 98
    .line 99
    iget-object v14, v5, Ln1/h;->b:Ln1/g;

    .line 100
    .line 101
    iget-object v14, v14, Ln1/g;->c:Lca/m;

    .line 102
    .line 103
    iget-object v15, v0, Ln1/m;->d:Ln1/c;

    .line 104
    .line 105
    move-object/from16 v17, v1

    .line 106
    .line 107
    iget-object v1, v15, Ln1/c;->d:Lb81/a;

    .line 108
    .line 109
    if-eqz v1, :cond_2

    .line 110
    .line 111
    move v1, v3

    .line 112
    move/from16 v16, v4

    .line 113
    .line 114
    iget-wide v3, v15, Ln1/c;->b:J

    .line 115
    .line 116
    invoke-static {v3, v4, v7, v8}, Lt4/a;->b(JJ)Z

    .line 117
    .line 118
    .line 119
    move-result v3

    .line 120
    if-eqz v3, :cond_3

    .line 121
    .line 122
    iget v3, v15, Ln1/c;->c:F

    .line 123
    .line 124
    invoke-interface {v12}, Lt4/c;->a()F

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    cmpg-float v3, v3, v4

    .line 129
    .line 130
    if-nez v3, :cond_3

    .line 131
    .line 132
    iget-object v3, v15, Ln1/c;->d:Lb81/a;

    .line 133
    .line 134
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    :goto_2
    move-object v15, v3

    .line 138
    goto :goto_3

    .line 139
    :cond_2
    move v1, v3

    .line 140
    move/from16 v16, v4

    .line 141
    .line 142
    :cond_3
    iput-wide v7, v15, Ln1/c;->b:J

    .line 143
    .line 144
    invoke-interface {v12}, Lt4/c;->a()F

    .line 145
    .line 146
    .line 147
    move-result v3

    .line 148
    iput v3, v15, Ln1/c;->c:F

    .line 149
    .line 150
    iget-object v3, v15, Ln1/c;->a:Llk/c;

    .line 151
    .line 152
    new-instance v4, Lt4/a;

    .line 153
    .line 154
    invoke-direct {v4, v7, v8}, Lt4/a;-><init>(J)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v3, v9, v4}, Llk/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    check-cast v3, Lb81/a;

    .line 162
    .line 163
    iput-object v3, v15, Ln1/c;->d:Lb81/a;

    .line 164
    .line 165
    goto :goto_2

    .line 166
    :goto_3
    iget-object v3, v15, Lb81/a;->e:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v3, [I

    .line 169
    .line 170
    array-length v3, v3

    .line 171
    iget v4, v14, Lca/m;->d:I

    .line 172
    .line 173
    if-eq v3, v4, :cond_4

    .line 174
    .line 175
    iput v3, v14, Lca/m;->d:I

    .line 176
    .line 177
    iget-object v4, v14, Lca/m;->f:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v4, Ljava/util/ArrayList;

    .line 180
    .line 181
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 182
    .line 183
    .line 184
    move/from16 v19, v1

    .line 185
    .line 186
    new-instance v1, Ln1/r;

    .line 187
    .line 188
    move-object/from16 v20, v15

    .line 189
    .line 190
    const/4 v15, 0x0

    .line 191
    invoke-direct {v1, v15, v15}, Ln1/r;-><init>(II)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    iget-object v1, v14, Lca/m;->g:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v1, Ljava/util/ArrayList;

    .line 200
    .line 201
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 202
    .line 203
    .line 204
    goto :goto_4

    .line 205
    :cond_4
    move/from16 v19, v1

    .line 206
    .line 207
    move-object/from16 v20, v15

    .line 208
    .line 209
    const/4 v15, 0x0

    .line 210
    :goto_4
    iget-object v1, v0, Ln1/m;->e:Lk1/i;

    .line 211
    .line 212
    invoke-interface {v1}, Lk1/i;->a()F

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    invoke-interface {v12, v4}, Lt4/c;->Q(F)I

    .line 217
    .line 218
    .line 219
    move-result v4

    .line 220
    iget-object v15, v5, Ln1/h;->b:Ln1/g;

    .line 221
    .line 222
    invoke-virtual {v15}, Ln1/g;->k()Lbb/g0;

    .line 223
    .line 224
    .line 225
    move-result-object v15

    .line 226
    iget v15, v15, Lbb/g0;->e:I

    .line 227
    .line 228
    invoke-static {v10, v11}, Lt4/a;->g(J)I

    .line 229
    .line 230
    .line 231
    move-result v21

    .line 232
    move-object/from16 v24, v14

    .line 233
    .line 234
    sub-int v14, v21, v19

    .line 235
    .line 236
    move-object/from16 v21, v1

    .line 237
    .line 238
    int-to-long v1, v2

    .line 239
    const/16 v33, 0x20

    .line 240
    .line 241
    shl-long v1, v1, v33

    .line 242
    .line 243
    move-wide/from16 v22, v1

    .line 244
    .line 245
    int-to-long v1, v6

    .line 246
    const-wide v34, 0xffffffffL

    .line 247
    .line 248
    .line 249
    .line 250
    .line 251
    and-long v1, v1, v34

    .line 252
    .line 253
    or-long v1, v22, v1

    .line 254
    .line 255
    new-instance v36, Ln1/k;

    .line 256
    .line 257
    move-wide/from16 v22, v7

    .line 258
    .line 259
    move-wide v8, v1

    .line 260
    move-object v2, v5

    .line 261
    iget-object v5, v0, Ln1/m;->a:Ln1/v;

    .line 262
    .line 263
    move-object/from16 v1, v21

    .line 264
    .line 265
    move/from16 v21, v15

    .line 266
    .line 267
    move-object v15, v1

    .line 268
    move/from16 v25, v3

    .line 269
    .line 270
    move/from16 v44, v16

    .line 271
    .line 272
    move/from16 v7, v18

    .line 273
    .line 274
    move/from16 v43, v19

    .line 275
    .line 276
    move-wide/from16 v45, v22

    .line 277
    .line 278
    move-object/from16 v1, v36

    .line 279
    .line 280
    move-object/from16 v3, p1

    .line 281
    .line 282
    move-object/from16 v36, v17

    .line 283
    .line 284
    invoke-direct/range {v1 .. v9}, Ln1/k;-><init>(Ln1/h;Lo1/d0;ILn1/v;IIJ)V

    .line 285
    .line 286
    .line 287
    move-object/from16 v22, v1

    .line 288
    .line 289
    move/from16 v19, v4

    .line 290
    .line 291
    new-instance v1, Ln1/l;

    .line 292
    .line 293
    move-object/from16 v23, v22

    .line 294
    .line 295
    move/from16 v22, v19

    .line 296
    .line 297
    move-object/from16 v19, v1

    .line 298
    .line 299
    invoke-direct/range {v19 .. v24}, Ln1/l;-><init>(Lb81/a;IILn1/k;Lca/m;)V

    .line 300
    .line 301
    .line 302
    move-object/from16 v8, v19

    .line 303
    .line 304
    move/from16 v3, v21

    .line 305
    .line 306
    move/from16 v4, v22

    .line 307
    .line 308
    move-object/from16 v5, v23

    .line 309
    .line 310
    move-object/from16 v1, v24

    .line 311
    .line 312
    iget-object v9, v8, Ln1/l;->f:Ljava/lang/Object;

    .line 313
    .line 314
    check-cast v9, Lca/m;

    .line 315
    .line 316
    move/from16 v37, v4

    .line 317
    .line 318
    new-instance v4, Ll2/v1;

    .line 319
    .line 320
    move/from16 v38, v7

    .line 321
    .line 322
    const/16 v7, 0x12

    .line 323
    .line 324
    invoke-direct {v4, v7, v1, v8}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 325
    .line 326
    .line 327
    new-instance v7, Lla/p;

    .line 328
    .line 329
    move-object/from16 v39, v4

    .line 330
    .line 331
    const/16 v4, 0x12

    .line 332
    .line 333
    invoke-direct {v7, v1, v4}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 334
    .line 335
    .line 336
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    const/16 v16, 0x0

    .line 341
    .line 342
    if-eqz v4, :cond_5

    .line 343
    .line 344
    invoke-virtual {v4}, Lv2/f;->e()Lay0/k;

    .line 345
    .line 346
    .line 347
    move-result-object v17

    .line 348
    move-object/from16 v40, v7

    .line 349
    .line 350
    move-object/from16 v7, v17

    .line 351
    .line 352
    :goto_5
    move-object/from16 v21, v15

    .line 353
    .line 354
    goto :goto_6

    .line 355
    :cond_5
    move-object/from16 v40, v7

    .line 356
    .line 357
    move-object/from16 v7, v16

    .line 358
    .line 359
    goto :goto_5

    .line 360
    :goto_6
    invoke-static {v4}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 361
    .line 362
    .line 363
    move-result-object v15

    .line 364
    move-object/from16 v17, v9

    .line 365
    .line 366
    :try_start_0
    iget-object v9, v13, Ln1/v;->d:Lm1/o;

    .line 367
    .line 368
    move/from16 v47, v14

    .line 369
    .line 370
    iget-object v14, v9, Lm1/o;->b:Ll2/g1;

    .line 371
    .line 372
    invoke-virtual {v14}, Ll2/g1;->o()I

    .line 373
    .line 374
    .line 375
    move-result v14

    .line 376
    move-object/from16 v48, v8

    .line 377
    .line 378
    iget-object v8, v9, Lm1/o;->e:Ljava/lang/Object;

    .line 379
    .line 380
    invoke-static {v14, v8, v2}, Lo1/y;->i(ILjava/lang/Object;Lo1/b0;)I

    .line 381
    .line 382
    .line 383
    move-result v8

    .line 384
    if-eq v14, v8, :cond_6

    .line 385
    .line 386
    move/from16 v49, v6

    .line 387
    .line 388
    iget-object v6, v9, Lm1/o;->b:Ll2/g1;

    .line 389
    .line 390
    invoke-virtual {v6, v8}, Ll2/g1;->p(I)V

    .line 391
    .line 392
    .line 393
    iget-object v6, v9, Lm1/o;->f:Lo1/g0;

    .line 394
    .line 395
    invoke-virtual {v6, v14}, Lo1/g0;->a(I)V

    .line 396
    .line 397
    .line 398
    goto :goto_7

    .line 399
    :cond_6
    move/from16 v49, v6

    .line 400
    .line 401
    :goto_7
    if-lt v8, v3, :cond_8

    .line 402
    .line 403
    if-gtz v3, :cond_7

    .line 404
    .line 405
    goto :goto_8

    .line 406
    :cond_7
    add-int/lit8 v6, v3, -0x1

    .line 407
    .line 408
    invoke-virtual {v1, v6}, Lca/m;->i(I)I

    .line 409
    .line 410
    .line 411
    move-result v1

    .line 412
    const/4 v6, 0x0

    .line 413
    goto :goto_9

    .line 414
    :catchall_0
    move-exception v0

    .line 415
    goto/16 :goto_4c

    .line 416
    .line 417
    :cond_8
    :goto_8
    invoke-virtual {v1, v8}, Lca/m;->i(I)I

    .line 418
    .line 419
    .line 420
    move-result v1

    .line 421
    iget-object v6, v9, Lm1/o;->c:Ll2/g1;

    .line 422
    .line 423
    invoke-virtual {v6}, Ll2/g1;->o()I

    .line 424
    .line 425
    .line 426
    move-result v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 427
    :goto_9
    invoke-static {v4, v15, v7}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 428
    .line 429
    .line 430
    iget-object v4, v13, Ln1/v;->q:Lo1/i0;

    .line 431
    .line 432
    iget-object v7, v13, Ln1/v;->n:Lg1/r;

    .line 433
    .line 434
    invoke-static {v2, v4, v7}, Lo1/y;->g(Lo1/b0;Lo1/i0;Lg1/r;)Ljava/util/List;

    .line 435
    .line 436
    .line 437
    move-result-object v2

    .line 438
    invoke-interface {v12}, Lt3/t;->I()Z

    .line 439
    .line 440
    .line 441
    move-result v4

    .line 442
    if-nez v4, :cond_a

    .line 443
    .line 444
    if-nez v26, :cond_9

    .line 445
    .line 446
    goto :goto_a

    .line 447
    :cond_9
    iget-object v4, v13, Ln1/v;->v:Lb81/a;

    .line 448
    .line 449
    iget-object v4, v4, Lb81/a;->f:Ljava/lang/Object;

    .line 450
    .line 451
    check-cast v4, Lc1/k;

    .line 452
    .line 453
    iget-object v4, v4, Lc1/k;->e:Ll2/j1;

    .line 454
    .line 455
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v4

    .line 459
    check-cast v4, Ljava/lang/Number;

    .line 460
    .line 461
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 462
    .line 463
    .line 464
    move-result v4

    .line 465
    goto :goto_b

    .line 466
    :cond_a
    :goto_a
    iget v4, v13, Ln1/v;->g:F

    .line 467
    .line 468
    :goto_b
    iget-object v7, v13, Ln1/v;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 469
    .line 470
    invoke-interface {v12}, Lt3/t;->I()Z

    .line 471
    .line 472
    .line 473
    move-result v24

    .line 474
    iget-object v8, v13, Ln1/v;->c:Ln1/n;

    .line 475
    .line 476
    iget-object v9, v13, Ln1/v;->r:Ll2/b1;

    .line 477
    .line 478
    if-ltz v49, :cond_b

    .line 479
    .line 480
    goto :goto_c

    .line 481
    :cond_b
    const-string v14, "negative beforeContentPadding"

    .line 482
    .line 483
    invoke-static {v14}, Lj1/b;->a(Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    :goto_c
    if-ltz v38, :cond_c

    .line 487
    .line 488
    goto :goto_d

    .line 489
    :cond_c
    const-string v14, "negative afterContentPadding"

    .line 490
    .line 491
    invoke-static {v14}, Lj1/b;->a(Ljava/lang/String;)V

    .line 492
    .line 493
    .line 494
    :goto_d
    sget-object v14, Lmx0/t;->d:Lmx0/t;

    .line 495
    .line 496
    iget-object v15, v5, Ln1/k;->f:Ln1/h;

    .line 497
    .line 498
    const/16 v23, 0x1

    .line 499
    .line 500
    move/from16 v18, v1

    .line 501
    .line 502
    iget-object v1, v0, Ln1/m;->f:Lvy0/b0;

    .line 503
    .line 504
    move-object/from16 v29, v1

    .line 505
    .line 506
    iget-object v1, v0, Ln1/m;->g:Le3/w;

    .line 507
    .line 508
    move/from16 v19, v4

    .line 509
    .line 510
    move-object/from16 v22, v5

    .line 511
    .line 512
    const-wide/16 v4, 0x0

    .line 513
    .line 514
    move-object/from16 v41, v13

    .line 515
    .line 516
    sget-object v13, Lmx0/s;->d:Lmx0/s;

    .line 517
    .line 518
    if-gtz v3, :cond_e

    .line 519
    .line 520
    invoke-static/range {v45 .. v46}, Lt4/a;->j(J)I

    .line 521
    .line 522
    .line 523
    move-result v18

    .line 524
    invoke-static/range {v45 .. v46}, Lt4/a;->i(J)I

    .line 525
    .line 526
    .line 527
    move-result v19

    .line 528
    new-instance v20, Ljava/util/ArrayList;

    .line 529
    .line 530
    invoke-direct/range {v20 .. v20}, Ljava/util/ArrayList;-><init>()V

    .line 531
    .line 532
    .line 533
    iget-object v0, v15, Ln1/h;->c:Lbb/g0;

    .line 534
    .line 535
    const/16 v27, 0x0

    .line 536
    .line 537
    const/16 v28, 0x0

    .line 538
    .line 539
    const/16 v17, 0x0

    .line 540
    .line 541
    move-object/from16 v21, v0

    .line 542
    .line 543
    move-object/from16 v30, v1

    .line 544
    .line 545
    move-object/from16 v16, v7

    .line 546
    .line 547
    invoke-virtual/range {v16 .. v30}, Landroidx/compose/foundation/lazy/layout/b;->d(IIILjava/util/ArrayList;Lbb/g0;Lap0/o;ZZIZIILvy0/b0;Le3/w;)V

    .line 548
    .line 549
    .line 550
    move-object/from16 v1, v16

    .line 551
    .line 552
    if-nez v24, :cond_d

    .line 553
    .line 554
    invoke-virtual {v1}, Landroidx/compose/foundation/lazy/layout/b;->b()J

    .line 555
    .line 556
    .line 557
    move-result-wide v0

    .line 558
    invoke-static {v0, v1, v4, v5}, Lt4/l;->a(JJ)Z

    .line 559
    .line 560
    .line 561
    move-result v2

    .line 562
    if-nez v2, :cond_d

    .line 563
    .line 564
    shr-long v2, v0, v33

    .line 565
    .line 566
    long-to-int v2, v2

    .line 567
    move-wide/from16 v3, v45

    .line 568
    .line 569
    invoke-static {v2, v3, v4}, Lt4/b;->g(IJ)I

    .line 570
    .line 571
    .line 572
    move-result v18

    .line 573
    and-long v0, v0, v34

    .line 574
    .line 575
    long-to-int v0, v0

    .line 576
    invoke-static {v0, v3, v4}, Lt4/b;->f(IJ)I

    .line 577
    .line 578
    .line 579
    move-result v19

    .line 580
    :cond_d
    new-instance v0, Ldj/a;

    .line 581
    .line 582
    const/16 v1, 0xe

    .line 583
    .line 584
    invoke-direct {v0, v1}, Ldj/a;-><init>(I)V

    .line 585
    .line 586
    .line 587
    add-int v1, v18, v44

    .line 588
    .line 589
    invoke-static {v1, v10, v11}, Lt4/b;->g(IJ)I

    .line 590
    .line 591
    .line 592
    move-result v1

    .line 593
    add-int v2, v19, v43

    .line 594
    .line 595
    invoke-static {v2, v10, v11}, Lt4/b;->f(IJ)I

    .line 596
    .line 597
    .line 598
    move-result v2

    .line 599
    invoke-interface {v12, v1, v2, v14, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 600
    .line 601
    .line 602
    move-result-object v5

    .line 603
    move/from16 v7, v49

    .line 604
    .line 605
    neg-int v14, v7

    .line 606
    add-int v15, v47, v38

    .line 607
    .line 608
    new-instance v0, Ln1/n;

    .line 609
    .line 610
    const/4 v7, 0x0

    .line 611
    const/16 v16, 0x0

    .line 612
    .line 613
    const/4 v1, 0x0

    .line 614
    const/4 v2, 0x0

    .line 615
    const/4 v3, 0x0

    .line 616
    const/4 v4, 0x0

    .line 617
    const/4 v6, 0x0

    .line 618
    move-object/from16 v9, p1

    .line 619
    .line 620
    move-object/from16 v57, v12

    .line 621
    .line 622
    move/from16 v10, v25

    .line 623
    .line 624
    move-object/from16 v8, v29

    .line 625
    .line 626
    move-object/from16 v17, v36

    .line 627
    .line 628
    move/from16 v19, v37

    .line 629
    .line 630
    move/from16 v18, v38

    .line 631
    .line 632
    move-object/from16 v11, v39

    .line 633
    .line 634
    move-object/from16 v12, v40

    .line 635
    .line 636
    move-object/from16 v58, v41

    .line 637
    .line 638
    invoke-direct/range {v0 .. v19}, Ln1/n;-><init>(Ln1/p;IZFLt3/r0;FZLvy0/b0;Lt4/c;ILay0/k;Lay0/k;Ljava/util/List;IIILg1/w1;II)V

    .line 639
    .line 640
    .line 641
    goto/16 :goto_4b

    .line 642
    .line 643
    :cond_e
    move-object/from16 v30, v1

    .line 644
    .line 645
    move-object v1, v7

    .line 646
    move-object/from16 v51, v9

    .line 647
    .line 648
    move-object/from16 v57, v12

    .line 649
    .line 650
    move-object/from16 v4, v22

    .line 651
    .line 652
    move/from16 v12, v37

    .line 653
    .line 654
    move/from16 v32, v38

    .line 655
    .line 656
    move-object/from16 v5, v39

    .line 657
    .line 658
    move-object/from16 v59, v40

    .line 659
    .line 660
    move-object/from16 v58, v41

    .line 661
    .line 662
    move/from16 v7, v49

    .line 663
    .line 664
    move-object/from16 v9, p1

    .line 665
    .line 666
    invoke-static/range {v19 .. v19}, Ljava/lang/Math;->round(F)I

    .line 667
    .line 668
    .line 669
    move-result v20

    .line 670
    sub-int v6, v6, v20

    .line 671
    .line 672
    if-nez v18, :cond_f

    .line 673
    .line 674
    if-gez v6, :cond_f

    .line 675
    .line 676
    add-int v20, v20, v6

    .line 677
    .line 678
    const/4 v6, 0x0

    .line 679
    :cond_f
    move-object/from16 v22, v1

    .line 680
    .line 681
    new-instance v1, Lmx0/l;

    .line 682
    .line 683
    invoke-direct {v1}, Lmx0/l;-><init>()V

    .line 684
    .line 685
    .line 686
    move-object/from16 v60, v5

    .line 687
    .line 688
    neg-int v5, v7

    .line 689
    if-gez v12, :cond_10

    .line 690
    .line 691
    move/from16 v27, v12

    .line 692
    .line 693
    :goto_e
    move/from16 v61, v5

    .line 694
    .line 695
    goto :goto_f

    .line 696
    :cond_10
    const/16 v27, 0x0

    .line 697
    .line 698
    goto :goto_e

    .line 699
    :goto_f
    add-int v5, v61, v27

    .line 700
    .line 701
    add-int/2addr v6, v5

    .line 702
    :goto_10
    if-gez v6, :cond_11

    .line 703
    .line 704
    if-lez v18, :cond_11

    .line 705
    .line 706
    move/from16 v62, v12

    .line 707
    .line 708
    add-int/lit8 v12, v18, -0x1

    .line 709
    .line 710
    move-object/from16 v27, v13

    .line 711
    .line 712
    move-object/from16 v13, v48

    .line 713
    .line 714
    move-object/from16 v48, v14

    .line 715
    .line 716
    invoke-virtual {v13, v12}, Ln1/l;->b(I)Ln1/p;

    .line 717
    .line 718
    .line 719
    move-result-object v14

    .line 720
    move/from16 v18, v12

    .line 721
    .line 722
    const/4 v12, 0x0

    .line 723
    invoke-virtual {v1, v12, v14}, Lmx0/l;->add(ILjava/lang/Object;)V

    .line 724
    .line 725
    .line 726
    iget v14, v14, Ln1/p;->g:I

    .line 727
    .line 728
    add-int/2addr v6, v14

    .line 729
    move-object/from16 v14, v48

    .line 730
    .line 731
    move/from16 v12, v62

    .line 732
    .line 733
    move-object/from16 v48, v13

    .line 734
    .line 735
    move-object/from16 v13, v27

    .line 736
    .line 737
    goto :goto_10

    .line 738
    :cond_11
    move/from16 v62, v12

    .line 739
    .line 740
    move-object/from16 v27, v13

    .line 741
    .line 742
    move-object/from16 v13, v48

    .line 743
    .line 744
    const/4 v12, 0x0

    .line 745
    move-object/from16 v48, v14

    .line 746
    .line 747
    if-ge v6, v5, :cond_12

    .line 748
    .line 749
    sub-int v6, v5, v6

    .line 750
    .line 751
    sub-int v20, v20, v6

    .line 752
    .line 753
    move v6, v5

    .line 754
    :cond_12
    move/from16 v14, v20

    .line 755
    .line 756
    sub-int/2addr v6, v5

    .line 757
    add-int v56, v47, v32

    .line 758
    .line 759
    if-gez v56, :cond_13

    .line 760
    .line 761
    goto :goto_11

    .line 762
    :cond_13
    move/from16 v12, v56

    .line 763
    .line 764
    :goto_11
    neg-int v10, v6

    .line 765
    move/from16 v36, v6

    .line 766
    .line 767
    move/from16 v28, v18

    .line 768
    .line 769
    const/4 v11, 0x0

    .line 770
    const/16 v20, 0x0

    .line 771
    .line 772
    :goto_12
    iget v6, v1, Lmx0/l;->f:I

    .line 773
    .line 774
    if-ge v11, v6, :cond_15

    .line 775
    .line 776
    if-lt v10, v12, :cond_14

    .line 777
    .line 778
    invoke-virtual {v1, v11}, Lmx0/l;->e(I)Ljava/lang/Object;

    .line 779
    .line 780
    .line 781
    move/from16 v20, v31

    .line 782
    .line 783
    goto :goto_12

    .line 784
    :cond_14
    add-int/lit8 v28, v28, 0x1

    .line 785
    .line 786
    invoke-virtual {v1, v11}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 787
    .line 788
    .line 789
    move-result-object v6

    .line 790
    check-cast v6, Ln1/p;

    .line 791
    .line 792
    iget v6, v6, Ln1/p;->g:I

    .line 793
    .line 794
    add-int/2addr v10, v6

    .line 795
    add-int/lit8 v11, v11, 0x1

    .line 796
    .line 797
    goto :goto_12

    .line 798
    :cond_15
    move/from16 v6, v20

    .line 799
    .line 800
    move/from16 v11, v28

    .line 801
    .line 802
    :goto_13
    if-ge v11, v3, :cond_17

    .line 803
    .line 804
    if-lt v10, v12, :cond_16

    .line 805
    .line 806
    if-lez v10, :cond_16

    .line 807
    .line 808
    invoke-virtual {v1}, Lmx0/l;->isEmpty()Z

    .line 809
    .line 810
    .line 811
    move-result v20

    .line 812
    if-eqz v20, :cond_17

    .line 813
    .line 814
    :cond_16
    move/from16 v63, v6

    .line 815
    .line 816
    goto :goto_15

    .line 817
    :cond_17
    move/from16 v63, v6

    .line 818
    .line 819
    :goto_14
    move/from16 v5, v47

    .line 820
    .line 821
    goto :goto_17

    .line 822
    :goto_15
    invoke-virtual {v13, v11}, Ln1/l;->b(I)Ln1/p;

    .line 823
    .line 824
    .line 825
    move-result-object v6

    .line 826
    move/from16 v20, v11

    .line 827
    .line 828
    iget v11, v6, Ln1/p;->g:I

    .line 829
    .line 830
    move/from16 v28, v11

    .line 831
    .line 832
    iget-object v11, v6, Ln1/p;->b:[Ln1/o;

    .line 833
    .line 834
    move/from16 v37, v12

    .line 835
    .line 836
    array-length v12, v11

    .line 837
    if-nez v12, :cond_18

    .line 838
    .line 839
    goto :goto_14

    .line 840
    :cond_18
    add-int v10, v10, v28

    .line 841
    .line 842
    if-gt v10, v5, :cond_19

    .line 843
    .line 844
    invoke-static {v11}, Lmx0/n;->I([Ljava/lang/Object;)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v11

    .line 848
    check-cast v11, Ln1/o;

    .line 849
    .line 850
    iget v11, v11, Ln1/o;->a:I

    .line 851
    .line 852
    add-int/lit8 v12, v3, -0x1

    .line 853
    .line 854
    if-eq v11, v12, :cond_19

    .line 855
    .line 856
    add-int/lit8 v11, v20, 0x1

    .line 857
    .line 858
    sub-int v36, v36, v28

    .line 859
    .line 860
    move/from16 v18, v11

    .line 861
    .line 862
    move/from16 v6, v31

    .line 863
    .line 864
    goto :goto_16

    .line 865
    :cond_19
    invoke-virtual {v1, v6}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 866
    .line 867
    .line 868
    move/from16 v6, v63

    .line 869
    .line 870
    :goto_16
    add-int/lit8 v11, v20, 0x1

    .line 871
    .line 872
    move/from16 v12, v37

    .line 873
    .line 874
    goto :goto_13

    .line 875
    :goto_17
    if-ge v10, v5, :cond_1b

    .line 876
    .line 877
    sub-int v6, v5, v10

    .line 878
    .line 879
    sub-int v36, v36, v6

    .line 880
    .line 881
    add-int/2addr v10, v6

    .line 882
    move/from16 v11, v36

    .line 883
    .line 884
    :goto_18
    if-ge v11, v7, :cond_1a

    .line 885
    .line 886
    if-lez v18, :cond_1a

    .line 887
    .line 888
    add-int/lit8 v12, v18, -0x1

    .line 889
    .line 890
    move/from16 v18, v6

    .line 891
    .line 892
    invoke-virtual {v13, v12}, Ln1/l;->b(I)Ln1/p;

    .line 893
    .line 894
    .line 895
    move-result-object v6

    .line 896
    move/from16 v47, v7

    .line 897
    .line 898
    const/4 v7, 0x0

    .line 899
    invoke-virtual {v1, v7, v6}, Lmx0/l;->add(ILjava/lang/Object;)V

    .line 900
    .line 901
    .line 902
    iget v6, v6, Ln1/p;->g:I

    .line 903
    .line 904
    add-int/2addr v11, v6

    .line 905
    move/from16 v6, v18

    .line 906
    .line 907
    move/from16 v7, v47

    .line 908
    .line 909
    move/from16 v18, v12

    .line 910
    .line 911
    goto :goto_18

    .line 912
    :cond_1a
    move/from16 v18, v6

    .line 913
    .line 914
    move/from16 v47, v7

    .line 915
    .line 916
    add-int v6, v14, v18

    .line 917
    .line 918
    if-gez v11, :cond_1c

    .line 919
    .line 920
    add-int/2addr v6, v11

    .line 921
    add-int/2addr v10, v11

    .line 922
    const/4 v11, 0x0

    .line 923
    goto :goto_19

    .line 924
    :cond_1b
    move/from16 v47, v7

    .line 925
    .line 926
    move v6, v14

    .line 927
    move/from16 v11, v36

    .line 928
    .line 929
    :cond_1c
    :goto_19
    invoke-static/range {v19 .. v19}, Ljava/lang/Math;->round(F)I

    .line 930
    .line 931
    .line 932
    move-result v7

    .line 933
    invoke-static {v7}, Ljava/lang/Integer;->signum(I)I

    .line 934
    .line 935
    .line 936
    move-result v7

    .line 937
    invoke-static {v6}, Ljava/lang/Integer;->signum(I)I

    .line 938
    .line 939
    .line 940
    move-result v12

    .line 941
    if-ne v7, v12, :cond_1d

    .line 942
    .line 943
    invoke-static/range {v19 .. v19}, Ljava/lang/Math;->round(F)I

    .line 944
    .line 945
    .line 946
    move-result v7

    .line 947
    invoke-static {v7}, Ljava/lang/Math;->abs(I)I

    .line 948
    .line 949
    .line 950
    move-result v7

    .line 951
    invoke-static {v6}, Ljava/lang/Math;->abs(I)I

    .line 952
    .line 953
    .line 954
    move-result v12

    .line 955
    if-lt v7, v12, :cond_1d

    .line 956
    .line 957
    int-to-float v7, v6

    .line 958
    goto :goto_1a

    .line 959
    :cond_1d
    move/from16 v7, v19

    .line 960
    .line 961
    :goto_1a
    sub-float v12, v19, v7

    .line 962
    .line 963
    const/16 v18, 0x0

    .line 964
    .line 965
    if-eqz v24, :cond_1e

    .line 966
    .line 967
    if-le v6, v14, :cond_1e

    .line 968
    .line 969
    cmpg-float v19, v12, v18

    .line 970
    .line 971
    if-gtz v19, :cond_1e

    .line 972
    .line 973
    sub-int/2addr v6, v14

    .line 974
    int-to-float v6, v6

    .line 975
    add-float v18, v6, v12

    .line 976
    .line 977
    :cond_1e
    move/from16 v6, v18

    .line 978
    .line 979
    if-ltz v11, :cond_1f

    .line 980
    .line 981
    goto :goto_1b

    .line 982
    :cond_1f
    const-string v12, "negative initial offset"

    .line 983
    .line 984
    invoke-static {v12}, Lj1/b;->a(Ljava/lang/String;)V

    .line 985
    .line 986
    .line 987
    :goto_1b
    neg-int v12, v11

    .line 988
    invoke-virtual {v1}, Lmx0/l;->first()Ljava/lang/Object;

    .line 989
    .line 990
    .line 991
    move-result-object v14

    .line 992
    check-cast v14, Ln1/p;

    .line 993
    .line 994
    move/from16 v64, v6

    .line 995
    .line 996
    iget-object v6, v14, Ln1/p;->b:[Ln1/o;

    .line 997
    .line 998
    invoke-static {v6}, Lmx0/n;->w([Ljava/lang/Object;)Ljava/lang/Object;

    .line 999
    .line 1000
    .line 1001
    move-result-object v6

    .line 1002
    check-cast v6, Ln1/o;

    .line 1003
    .line 1004
    if-eqz v6, :cond_20

    .line 1005
    .line 1006
    iget v6, v6, Ln1/o;->a:I

    .line 1007
    .line 1008
    goto :goto_1c

    .line 1009
    :cond_20
    const/4 v6, 0x0

    .line 1010
    :goto_1c
    invoke-virtual {v1}, Lmx0/l;->n()Ljava/lang/Object;

    .line 1011
    .line 1012
    .line 1013
    move-result-object v18

    .line 1014
    move/from16 v19, v11

    .line 1015
    .line 1016
    move-object/from16 v11, v18

    .line 1017
    .line 1018
    check-cast v11, Ln1/p;

    .line 1019
    .line 1020
    if-eqz v11, :cond_22

    .line 1021
    .line 1022
    iget-object v11, v11, Ln1/p;->b:[Ln1/o;

    .line 1023
    .line 1024
    move/from16 v18, v12

    .line 1025
    .line 1026
    array-length v12, v11

    .line 1027
    if-nez v12, :cond_21

    .line 1028
    .line 1029
    move-object/from16 v11, v16

    .line 1030
    .line 1031
    goto :goto_1d

    .line 1032
    :cond_21
    array-length v12, v11

    .line 1033
    add-int/lit8 v12, v12, -0x1

    .line 1034
    .line 1035
    aget-object v11, v11, v12

    .line 1036
    .line 1037
    :goto_1d
    if-eqz v11, :cond_23

    .line 1038
    .line 1039
    iget v11, v11, Ln1/o;->a:I

    .line 1040
    .line 1041
    goto :goto_1e

    .line 1042
    :cond_22
    move/from16 v18, v12

    .line 1043
    .line 1044
    :cond_23
    const/4 v11, 0x0

    .line 1045
    :goto_1e
    move-object v12, v2

    .line 1046
    check-cast v12, Ljava/util/Collection;

    .line 1047
    .line 1048
    move-object/from16 v20, v12

    .line 1049
    .line 1050
    invoke-interface/range {v20 .. v20}, Ljava/util/Collection;->size()I

    .line 1051
    .line 1052
    .line 1053
    move-result v12

    .line 1054
    move-object/from16 v52, v14

    .line 1055
    .line 1056
    move-object/from16 v28, v16

    .line 1057
    .line 1058
    const/4 v14, 0x0

    .line 1059
    :goto_1f
    if-ge v14, v12, :cond_26

    .line 1060
    .line 1061
    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1062
    .line 1063
    .line 1064
    move-result-object v36

    .line 1065
    check-cast v36, Ljava/lang/Number;

    .line 1066
    .line 1067
    move/from16 v53, v12

    .line 1068
    .line 1069
    invoke-virtual/range {v36 .. v36}, Ljava/lang/Number;->intValue()I

    .line 1070
    .line 1071
    .line 1072
    move-result v12

    .line 1073
    if-ltz v12, :cond_25

    .line 1074
    .line 1075
    if-ge v12, v6, :cond_25

    .line 1076
    .line 1077
    move/from16 v54, v6

    .line 1078
    .line 1079
    move-object/from16 v6, v17

    .line 1080
    .line 1081
    move/from16 v17, v14

    .line 1082
    .line 1083
    iget v14, v6, Lca/m;->d:I

    .line 1084
    .line 1085
    invoke-virtual {v6, v12}, Lca/m;->m(I)I

    .line 1086
    .line 1087
    .line 1088
    move-result v14

    .line 1089
    move/from16 v39, v12

    .line 1090
    .line 1091
    const/4 v12, 0x0

    .line 1092
    invoke-virtual {v13, v12, v14}, Ln1/l;->a(II)J

    .line 1093
    .line 1094
    .line 1095
    move-result-wide v37

    .line 1096
    const/16 v40, 0x0

    .line 1097
    .line 1098
    iget v12, v4, Ln1/k;->h:I

    .line 1099
    .line 1100
    move-object/from16 v36, v4

    .line 1101
    .line 1102
    move/from16 v42, v12

    .line 1103
    .line 1104
    move/from16 v41, v14

    .line 1105
    .line 1106
    invoke-virtual/range {v36 .. v42}, Ln1/k;->b0(JIIII)Ln1/o;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v4

    .line 1110
    move-object/from16 v12, v36

    .line 1111
    .line 1112
    if-nez v28, :cond_24

    .line 1113
    .line 1114
    new-instance v28, Ljava/util/ArrayList;

    .line 1115
    .line 1116
    invoke-direct/range {v28 .. v28}, Ljava/util/ArrayList;-><init>()V

    .line 1117
    .line 1118
    .line 1119
    :cond_24
    move-object/from16 v14, v28

    .line 1120
    .line 1121
    invoke-interface {v14, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1122
    .line 1123
    .line 1124
    move-object/from16 v28, v14

    .line 1125
    .line 1126
    goto :goto_20

    .line 1127
    :cond_25
    move-object v12, v4

    .line 1128
    move/from16 v54, v6

    .line 1129
    .line 1130
    move-object/from16 v6, v17

    .line 1131
    .line 1132
    move/from16 v17, v14

    .line 1133
    .line 1134
    :goto_20
    add-int/lit8 v14, v17, 0x1

    .line 1135
    .line 1136
    move-object/from16 v17, v6

    .line 1137
    .line 1138
    move-object v4, v12

    .line 1139
    move/from16 v12, v53

    .line 1140
    .line 1141
    move/from16 v6, v54

    .line 1142
    .line 1143
    goto :goto_1f

    .line 1144
    :cond_26
    move-object v12, v4

    .line 1145
    move/from16 v54, v6

    .line 1146
    .line 1147
    move-object/from16 v6, v17

    .line 1148
    .line 1149
    if-nez v28, :cond_27

    .line 1150
    .line 1151
    move-object/from16 v4, v27

    .line 1152
    .line 1153
    goto :goto_21

    .line 1154
    :cond_27
    move-object/from16 v4, v28

    .line 1155
    .line 1156
    :goto_21
    const/4 v14, -0x1

    .line 1157
    if-eqz v24, :cond_33

    .line 1158
    .line 1159
    if-eqz v8, :cond_33

    .line 1160
    .line 1161
    iget-object v8, v8, Ln1/n;->m:Ljava/lang/Object;

    .line 1162
    .line 1163
    move-object/from16 v17, v8

    .line 1164
    .line 1165
    check-cast v17, Ljava/util/Collection;

    .line 1166
    .line 1167
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->isEmpty()Z

    .line 1168
    .line 1169
    .line 1170
    move-result v17

    .line 1171
    if-nez v17, :cond_33

    .line 1172
    .line 1173
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 1174
    .line 1175
    .line 1176
    move-result v17

    .line 1177
    add-int/lit8 v17, v17, -0x1

    .line 1178
    .line 1179
    move/from16 v0, v17

    .line 1180
    .line 1181
    :goto_22
    if-ge v14, v0, :cond_2a

    .line 1182
    .line 1183
    invoke-interface {v8, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v17

    .line 1187
    move/from16 v28, v14

    .line 1188
    .line 1189
    move-object/from16 v14, v17

    .line 1190
    .line 1191
    check-cast v14, Ln1/o;

    .line 1192
    .line 1193
    iget v14, v14, Ln1/o;->a:I

    .line 1194
    .line 1195
    if-le v14, v11, :cond_29

    .line 1196
    .line 1197
    if-eqz v0, :cond_28

    .line 1198
    .line 1199
    add-int/lit8 v14, v0, -0x1

    .line 1200
    .line 1201
    invoke-interface {v8, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1202
    .line 1203
    .line 1204
    move-result-object v14

    .line 1205
    check-cast v14, Ln1/o;

    .line 1206
    .line 1207
    iget v14, v14, Ln1/o;->a:I

    .line 1208
    .line 1209
    if-gt v14, v11, :cond_29

    .line 1210
    .line 1211
    :cond_28
    invoke-interface {v8, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1212
    .line 1213
    .line 1214
    move-result-object v0

    .line 1215
    check-cast v0, Ln1/o;

    .line 1216
    .line 1217
    goto :goto_23

    .line 1218
    :cond_29
    add-int/lit8 v0, v0, -0x1

    .line 1219
    .line 1220
    move/from16 v14, v28

    .line 1221
    .line 1222
    goto :goto_22

    .line 1223
    :cond_2a
    move/from16 v28, v14

    .line 1224
    .line 1225
    move-object/from16 v0, v16

    .line 1226
    .line 1227
    :goto_23
    invoke-static {v8}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v8

    .line 1231
    check-cast v8, Ln1/o;

    .line 1232
    .line 1233
    invoke-static {v1}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v14

    .line 1237
    check-cast v14, Ln1/p;

    .line 1238
    .line 1239
    if-eqz v14, :cond_2b

    .line 1240
    .line 1241
    iget v14, v14, Ln1/p;->a:I

    .line 1242
    .line 1243
    add-int/lit8 v14, v14, 0x1

    .line 1244
    .line 1245
    goto :goto_24

    .line 1246
    :cond_2b
    const/4 v14, 0x0

    .line 1247
    :goto_24
    if-eqz v0, :cond_32

    .line 1248
    .line 1249
    iget v0, v0, Ln1/o;->a:I

    .line 1250
    .line 1251
    iget v8, v8, Ln1/o;->a:I

    .line 1252
    .line 1253
    move/from16 v53, v11

    .line 1254
    .line 1255
    add-int/lit8 v11, v3, -0x1

    .line 1256
    .line 1257
    invoke-static {v8, v11}, Ljava/lang/Math;->min(II)I

    .line 1258
    .line 1259
    .line 1260
    move-result v8

    .line 1261
    if-gt v0, v8, :cond_31

    .line 1262
    .line 1263
    move-object/from16 v11, v16

    .line 1264
    .line 1265
    :goto_25
    if-eqz v11, :cond_2f

    .line 1266
    .line 1267
    move-object/from16 v55, v15

    .line 1268
    .line 1269
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 1270
    .line 1271
    .line 1272
    move-result v15

    .line 1273
    move/from16 v65, v7

    .line 1274
    .line 1275
    const/4 v7, 0x0

    .line 1276
    :goto_26
    if-ge v7, v15, :cond_2e

    .line 1277
    .line 1278
    invoke-interface {v11, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1279
    .line 1280
    .line 1281
    move-result-object v17

    .line 1282
    move/from16 v36, v7

    .line 1283
    .line 1284
    move-object/from16 v7, v17

    .line 1285
    .line 1286
    check-cast v7, Ln1/p;

    .line 1287
    .line 1288
    iget-object v7, v7, Ln1/p;->b:[Ln1/o;

    .line 1289
    .line 1290
    move-object/from16 v17, v11

    .line 1291
    .line 1292
    array-length v11, v7

    .line 1293
    move-object/from16 v37, v7

    .line 1294
    .line 1295
    const/4 v7, 0x0

    .line 1296
    :goto_27
    if-ge v7, v11, :cond_2d

    .line 1297
    .line 1298
    move/from16 v38, v7

    .line 1299
    .line 1300
    aget-object v7, v37, v38

    .line 1301
    .line 1302
    iget v7, v7, Ln1/o;->a:I

    .line 1303
    .line 1304
    if-ne v7, v0, :cond_2c

    .line 1305
    .line 1306
    move-object/from16 v11, v17

    .line 1307
    .line 1308
    goto :goto_2b

    .line 1309
    :cond_2c
    add-int/lit8 v7, v38, 0x1

    .line 1310
    .line 1311
    goto :goto_27

    .line 1312
    :cond_2d
    add-int/lit8 v7, v36, 0x1

    .line 1313
    .line 1314
    move-object/from16 v11, v17

    .line 1315
    .line 1316
    goto :goto_26

    .line 1317
    :cond_2e
    :goto_28
    move-object/from16 v17, v11

    .line 1318
    .line 1319
    goto :goto_29

    .line 1320
    :cond_2f
    move/from16 v65, v7

    .line 1321
    .line 1322
    move-object/from16 v55, v15

    .line 1323
    .line 1324
    goto :goto_28

    .line 1325
    :goto_29
    if-nez v17, :cond_30

    .line 1326
    .line 1327
    new-instance v11, Ljava/util/ArrayList;

    .line 1328
    .line 1329
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 1330
    .line 1331
    .line 1332
    goto :goto_2a

    .line 1333
    :cond_30
    move-object/from16 v11, v17

    .line 1334
    .line 1335
    :goto_2a
    invoke-virtual {v13, v14}, Ln1/l;->b(I)Ln1/p;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v7

    .line 1339
    add-int/lit8 v14, v14, 0x1

    .line 1340
    .line 1341
    invoke-interface {v11, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1342
    .line 1343
    .line 1344
    :goto_2b
    if-eq v0, v8, :cond_34

    .line 1345
    .line 1346
    add-int/lit8 v0, v0, 0x1

    .line 1347
    .line 1348
    move-object/from16 v15, v55

    .line 1349
    .line 1350
    move/from16 v7, v65

    .line 1351
    .line 1352
    goto :goto_25

    .line 1353
    :cond_31
    move/from16 v65, v7

    .line 1354
    .line 1355
    :goto_2c
    move-object/from16 v55, v15

    .line 1356
    .line 1357
    goto :goto_2d

    .line 1358
    :cond_32
    move/from16 v65, v7

    .line 1359
    .line 1360
    move/from16 v53, v11

    .line 1361
    .line 1362
    goto :goto_2c

    .line 1363
    :cond_33
    move/from16 v65, v7

    .line 1364
    .line 1365
    move/from16 v53, v11

    .line 1366
    .line 1367
    move/from16 v28, v14

    .line 1368
    .line 1369
    goto :goto_2c

    .line 1370
    :goto_2d
    move-object/from16 v11, v16

    .line 1371
    .line 1372
    :cond_34
    if-nez v11, :cond_35

    .line 1373
    .line 1374
    move-object/from16 v11, v27

    .line 1375
    .line 1376
    :cond_35
    invoke-interface/range {v20 .. v20}, Ljava/util/Collection;->size()I

    .line 1377
    .line 1378
    .line 1379
    move-result v0

    .line 1380
    const/4 v15, 0x0

    .line 1381
    :goto_2e
    if-ge v15, v0, :cond_3b

    .line 1382
    .line 1383
    invoke-interface {v2, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1384
    .line 1385
    .line 1386
    move-result-object v7

    .line 1387
    check-cast v7, Ljava/lang/Number;

    .line 1388
    .line 1389
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 1390
    .line 1391
    .line 1392
    move-result v7

    .line 1393
    add-int/lit8 v8, v53, 0x1

    .line 1394
    .line 1395
    if-gt v8, v7, :cond_3a

    .line 1396
    .line 1397
    if-ge v7, v3, :cond_3a

    .line 1398
    .line 1399
    if-eqz v24, :cond_38

    .line 1400
    .line 1401
    move-object v8, v11

    .line 1402
    check-cast v8, Ljava/util/Collection;

    .line 1403
    .line 1404
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 1405
    .line 1406
    .line 1407
    move-result v8

    .line 1408
    const/4 v14, 0x0

    .line 1409
    :goto_2f
    if-ge v14, v8, :cond_38

    .line 1410
    .line 1411
    invoke-interface {v11, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1412
    .line 1413
    .line 1414
    move-result-object v17

    .line 1415
    move/from16 v20, v0

    .line 1416
    .line 1417
    move-object/from16 v0, v17

    .line 1418
    .line 1419
    check-cast v0, Ln1/p;

    .line 1420
    .line 1421
    iget-object v0, v0, Ln1/p;->b:[Ln1/o;

    .line 1422
    .line 1423
    move-object/from16 v17, v2

    .line 1424
    .line 1425
    array-length v2, v0

    .line 1426
    move-object/from16 v36, v0

    .line 1427
    .line 1428
    const/4 v0, 0x0

    .line 1429
    :goto_30
    if-ge v0, v2, :cond_37

    .line 1430
    .line 1431
    move/from16 v37, v0

    .line 1432
    .line 1433
    aget-object v0, v36, v37

    .line 1434
    .line 1435
    iget v0, v0, Ln1/o;->a:I

    .line 1436
    .line 1437
    if-ne v0, v7, :cond_36

    .line 1438
    .line 1439
    goto :goto_31

    .line 1440
    :cond_36
    add-int/lit8 v0, v37, 0x1

    .line 1441
    .line 1442
    goto :goto_30

    .line 1443
    :cond_37
    add-int/lit8 v14, v14, 0x1

    .line 1444
    .line 1445
    move-object/from16 v2, v17

    .line 1446
    .line 1447
    move/from16 v0, v20

    .line 1448
    .line 1449
    goto :goto_2f

    .line 1450
    :cond_38
    move/from16 v20, v0

    .line 1451
    .line 1452
    move-object/from16 v17, v2

    .line 1453
    .line 1454
    iget v0, v6, Lca/m;->d:I

    .line 1455
    .line 1456
    invoke-virtual {v6, v7}, Lca/m;->m(I)I

    .line 1457
    .line 1458
    .line 1459
    move-result v0

    .line 1460
    const/4 v2, 0x0

    .line 1461
    invoke-virtual {v13, v2, v0}, Ln1/l;->a(II)J

    .line 1462
    .line 1463
    .line 1464
    move-result-wide v37

    .line 1465
    const/16 v40, 0x0

    .line 1466
    .line 1467
    iget v2, v12, Ln1/k;->h:I

    .line 1468
    .line 1469
    move/from16 v41, v0

    .line 1470
    .line 1471
    move/from16 v42, v2

    .line 1472
    .line 1473
    move/from16 v39, v7

    .line 1474
    .line 1475
    move-object/from16 v36, v12

    .line 1476
    .line 1477
    invoke-virtual/range {v36 .. v42}, Ln1/k;->b0(JIIII)Ln1/o;

    .line 1478
    .line 1479
    .line 1480
    move-result-object v0

    .line 1481
    if-nez v16, :cond_39

    .line 1482
    .line 1483
    new-instance v16, Ljava/util/ArrayList;

    .line 1484
    .line 1485
    invoke-direct/range {v16 .. v16}, Ljava/util/ArrayList;-><init>()V

    .line 1486
    .line 1487
    .line 1488
    :cond_39
    move-object/from16 v2, v16

    .line 1489
    .line 1490
    invoke-interface {v2, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1491
    .line 1492
    .line 1493
    move-object/from16 v16, v2

    .line 1494
    .line 1495
    goto :goto_32

    .line 1496
    :cond_3a
    move/from16 v20, v0

    .line 1497
    .line 1498
    move-object/from16 v17, v2

    .line 1499
    .line 1500
    :goto_31
    move-object/from16 v36, v12

    .line 1501
    .line 1502
    :goto_32
    add-int/lit8 v15, v15, 0x1

    .line 1503
    .line 1504
    move-object/from16 v2, v17

    .line 1505
    .line 1506
    move/from16 v0, v20

    .line 1507
    .line 1508
    move-object/from16 v12, v36

    .line 1509
    .line 1510
    goto/16 :goto_2e

    .line 1511
    .line 1512
    :cond_3b
    move-object/from16 v36, v12

    .line 1513
    .line 1514
    if-nez v16, :cond_3c

    .line 1515
    .line 1516
    move-object/from16 v0, v27

    .line 1517
    .line 1518
    goto :goto_33

    .line 1519
    :cond_3c
    move-object/from16 v0, v16

    .line 1520
    .line 1521
    :goto_33
    if-gtz v47, :cond_3e

    .line 1522
    .line 1523
    if-gez v62, :cond_3d

    .line 1524
    .line 1525
    goto :goto_34

    .line 1526
    :cond_3d
    move/from16 v2, v19

    .line 1527
    .line 1528
    move-object/from16 v14, v52

    .line 1529
    .line 1530
    goto :goto_36

    .line 1531
    :cond_3e
    :goto_34
    invoke-virtual {v1}, Lmx0/l;->c()I

    .line 1532
    .line 1533
    .line 1534
    move-result v2

    .line 1535
    move/from16 v6, v19

    .line 1536
    .line 1537
    move-object/from16 v14, v52

    .line 1538
    .line 1539
    const/4 v15, 0x0

    .line 1540
    :goto_35
    if-ge v15, v2, :cond_3f

    .line 1541
    .line 1542
    invoke-virtual {v1, v15}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1543
    .line 1544
    .line 1545
    move-result-object v7

    .line 1546
    check-cast v7, Ln1/p;

    .line 1547
    .line 1548
    iget v7, v7, Ln1/p;->g:I

    .line 1549
    .line 1550
    if-eqz v6, :cond_3f

    .line 1551
    .line 1552
    if-gt v7, v6, :cond_3f

    .line 1553
    .line 1554
    invoke-static {v1}, Ljp/k1;->h(Ljava/util/List;)I

    .line 1555
    .line 1556
    .line 1557
    move-result v8

    .line 1558
    if-eq v15, v8, :cond_3f

    .line 1559
    .line 1560
    sub-int/2addr v6, v7

    .line 1561
    add-int/lit8 v15, v15, 0x1

    .line 1562
    .line 1563
    invoke-virtual {v1, v15}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1564
    .line 1565
    .line 1566
    move-result-object v7

    .line 1567
    move-object v14, v7

    .line 1568
    check-cast v14, Ln1/p;

    .line 1569
    .line 1570
    goto :goto_35

    .line 1571
    :cond_3f
    move v2, v6

    .line 1572
    :goto_36
    invoke-static/range {v45 .. v46}, Lt4/a;->h(J)I

    .line 1573
    .line 1574
    .line 1575
    move-result v6

    .line 1576
    move-wide/from16 v7, v45

    .line 1577
    .line 1578
    invoke-static {v10, v7, v8}, Lt4/b;->f(IJ)I

    .line 1579
    .line 1580
    .line 1581
    move-result v12

    .line 1582
    invoke-interface {v11}, Ljava/util/List;->isEmpty()Z

    .line 1583
    .line 1584
    .line 1585
    move-result v15

    .line 1586
    if-eqz v15, :cond_40

    .line 1587
    .line 1588
    goto :goto_37

    .line 1589
    :cond_40
    check-cast v11, Ljava/lang/Iterable;

    .line 1590
    .line 1591
    invoke-static {v11, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 1592
    .line 1593
    .line 1594
    move-result-object v1

    .line 1595
    :goto_37
    invoke-static {v12, v5}, Ljava/lang/Math;->min(II)I

    .line 1596
    .line 1597
    .line 1598
    move-result v11

    .line 1599
    if-ge v10, v11, :cond_41

    .line 1600
    .line 1601
    move/from16 v15, v31

    .line 1602
    .line 1603
    goto :goto_38

    .line 1604
    :cond_41
    const/4 v15, 0x0

    .line 1605
    :goto_38
    if-eqz v15, :cond_43

    .line 1606
    .line 1607
    if-nez v18, :cond_42

    .line 1608
    .line 1609
    goto :goto_39

    .line 1610
    :cond_42
    const-string v11, "non-zero firstLineScrollOffset"

    .line 1611
    .line 1612
    invoke-static {v11}, Lj1/b;->c(Ljava/lang/String;)V

    .line 1613
    .line 1614
    .line 1615
    :cond_43
    :goto_39
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 1616
    .line 1617
    .line 1618
    move-result v11

    .line 1619
    move/from16 v27, v2

    .line 1620
    .line 1621
    move/from16 v37, v3

    .line 1622
    .line 1623
    const/4 v2, 0x0

    .line 1624
    const/4 v3, 0x0

    .line 1625
    :goto_3a
    if-ge v2, v11, :cond_44

    .line 1626
    .line 1627
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1628
    .line 1629
    .line 1630
    move-result-object v16

    .line 1631
    move/from16 v17, v2

    .line 1632
    .line 1633
    move-object/from16 v2, v16

    .line 1634
    .line 1635
    check-cast v2, Ln1/p;

    .line 1636
    .line 1637
    iget-object v2, v2, Ln1/p;->b:[Ln1/o;

    .line 1638
    .line 1639
    array-length v2, v2

    .line 1640
    add-int/2addr v3, v2

    .line 1641
    add-int/lit8 v2, v17, 0x1

    .line 1642
    .line 1643
    goto :goto_3a

    .line 1644
    :cond_44
    new-instance v2, Ljava/util/ArrayList;

    .line 1645
    .line 1646
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 1647
    .line 1648
    .line 1649
    if-eqz v15, :cond_4b

    .line 1650
    .line 1651
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1652
    .line 1653
    .line 1654
    move-result v3

    .line 1655
    if-eqz v3, :cond_45

    .line 1656
    .line 1657
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 1658
    .line 1659
    .line 1660
    move-result v0

    .line 1661
    if-eqz v0, :cond_45

    .line 1662
    .line 1663
    goto :goto_3b

    .line 1664
    :cond_45
    const-string v0, "no items"

    .line 1665
    .line 1666
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 1667
    .line 1668
    .line 1669
    :goto_3b
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 1670
    .line 1671
    .line 1672
    move-result v0

    .line 1673
    new-array v3, v0, [I

    .line 1674
    .line 1675
    const/4 v15, 0x0

    .line 1676
    :goto_3c
    if-ge v15, v0, :cond_46

    .line 1677
    .line 1678
    invoke-interface {v1, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1679
    .line 1680
    .line 1681
    move-result-object v4

    .line 1682
    check-cast v4, Ln1/p;

    .line 1683
    .line 1684
    iget v4, v4, Ln1/p;->f:I

    .line 1685
    .line 1686
    aput v4, v3, v15

    .line 1687
    .line 1688
    add-int/lit8 v15, v15, 0x1

    .line 1689
    .line 1690
    goto :goto_3c

    .line 1691
    :cond_46
    new-array v0, v0, [I

    .line 1692
    .line 1693
    move-object/from16 v15, v21

    .line 1694
    .line 1695
    invoke-interface {v15, v9, v12, v3, v0}, Lk1/i;->b(Lt4/c;I[I[I)V

    .line 1696
    .line 1697
    .line 1698
    invoke-static {v0}, Lmx0/n;->z([I)Lgy0/j;

    .line 1699
    .line 1700
    .line 1701
    move-result-object v3

    .line 1702
    iget v4, v3, Lgy0/h;->d:I

    .line 1703
    .line 1704
    iget v11, v3, Lgy0/h;->e:I

    .line 1705
    .line 1706
    iget v3, v3, Lgy0/h;->f:I

    .line 1707
    .line 1708
    if-lez v3, :cond_47

    .line 1709
    .line 1710
    if-le v4, v11, :cond_48

    .line 1711
    .line 1712
    :cond_47
    if-gez v3, :cond_4a

    .line 1713
    .line 1714
    if-gt v11, v4, :cond_4a

    .line 1715
    .line 1716
    :cond_48
    :goto_3d
    aget v15, v0, v4

    .line 1717
    .line 1718
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1719
    .line 1720
    .line 1721
    move-result-object v16

    .line 1722
    move-object/from16 v17, v0

    .line 1723
    .line 1724
    move-object/from16 v0, v16

    .line 1725
    .line 1726
    check-cast v0, Ln1/p;

    .line 1727
    .line 1728
    invoke-virtual {v0, v15, v6, v12}, Ln1/p;->a(III)[Ln1/o;

    .line 1729
    .line 1730
    .line 1731
    move-result-object v0

    .line 1732
    array-length v15, v0

    .line 1733
    move-object/from16 v16, v0

    .line 1734
    .line 1735
    const/4 v0, 0x0

    .line 1736
    :goto_3e
    if-ge v0, v15, :cond_49

    .line 1737
    .line 1738
    move/from16 v18, v0

    .line 1739
    .line 1740
    aget-object v0, v16, v18

    .line 1741
    .line 1742
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1743
    .line 1744
    .line 1745
    add-int/lit8 v0, v18, 0x1

    .line 1746
    .line 1747
    goto :goto_3e

    .line 1748
    :cond_49
    if-eq v4, v11, :cond_4a

    .line 1749
    .line 1750
    add-int/2addr v4, v3

    .line 1751
    move-object/from16 v0, v17

    .line 1752
    .line 1753
    goto :goto_3d

    .line 1754
    :cond_4a
    move/from16 v4, v65

    .line 1755
    .line 1756
    const/4 v11, 0x0

    .line 1757
    goto/16 :goto_44

    .line 1758
    .line 1759
    :cond_4b
    move-object v3, v4

    .line 1760
    check-cast v3, Ljava/util/Collection;

    .line 1761
    .line 1762
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 1763
    .line 1764
    .line 1765
    move-result v3

    .line 1766
    add-int/lit8 v3, v3, -0x1

    .line 1767
    .line 1768
    if-ltz v3, :cond_4d

    .line 1769
    .line 1770
    move/from16 v11, v18

    .line 1771
    .line 1772
    :goto_3f
    add-int/lit8 v15, v3, -0x1

    .line 1773
    .line 1774
    invoke-interface {v4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1775
    .line 1776
    .line 1777
    move-result-object v3

    .line 1778
    check-cast v3, Ln1/o;

    .line 1779
    .line 1780
    move-object/from16 v16, v4

    .line 1781
    .line 1782
    iget v4, v3, Ln1/o;->o:I

    .line 1783
    .line 1784
    sub-int/2addr v11, v4

    .line 1785
    const/4 v4, 0x0

    .line 1786
    invoke-virtual {v3, v11, v4, v6, v12}, Ln1/o;->a(IIII)V

    .line 1787
    .line 1788
    .line 1789
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1790
    .line 1791
    .line 1792
    if-gez v15, :cond_4c

    .line 1793
    .line 1794
    goto :goto_40

    .line 1795
    :cond_4c
    move v3, v15

    .line 1796
    move-object/from16 v4, v16

    .line 1797
    .line 1798
    goto :goto_3f

    .line 1799
    :cond_4d
    :goto_40
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 1800
    .line 1801
    .line 1802
    move-result v3

    .line 1803
    move/from16 v4, v18

    .line 1804
    .line 1805
    const/4 v15, 0x0

    .line 1806
    :goto_41
    if-ge v15, v3, :cond_4f

    .line 1807
    .line 1808
    invoke-interface {v1, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1809
    .line 1810
    .line 1811
    move-result-object v11

    .line 1812
    check-cast v11, Ln1/p;

    .line 1813
    .line 1814
    move-object/from16 v16, v1

    .line 1815
    .line 1816
    invoke-virtual {v11, v4, v6, v12}, Ln1/p;->a(III)[Ln1/o;

    .line 1817
    .line 1818
    .line 1819
    move-result-object v1

    .line 1820
    move/from16 v17, v3

    .line 1821
    .line 1822
    array-length v3, v1

    .line 1823
    move-object/from16 v18, v1

    .line 1824
    .line 1825
    const/4 v1, 0x0

    .line 1826
    :goto_42
    if-ge v1, v3, :cond_4e

    .line 1827
    .line 1828
    move/from16 v19, v1

    .line 1829
    .line 1830
    aget-object v1, v18, v19

    .line 1831
    .line 1832
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1833
    .line 1834
    .line 1835
    add-int/lit8 v1, v19, 0x1

    .line 1836
    .line 1837
    goto :goto_42

    .line 1838
    :cond_4e
    iget v1, v11, Ln1/p;->g:I

    .line 1839
    .line 1840
    add-int/2addr v4, v1

    .line 1841
    add-int/lit8 v15, v15, 0x1

    .line 1842
    .line 1843
    move-object/from16 v1, v16

    .line 1844
    .line 1845
    move/from16 v3, v17

    .line 1846
    .line 1847
    goto :goto_41

    .line 1848
    :cond_4f
    move-object v1, v0

    .line 1849
    check-cast v1, Ljava/util/Collection;

    .line 1850
    .line 1851
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 1852
    .line 1853
    .line 1854
    move-result v1

    .line 1855
    const/4 v15, 0x0

    .line 1856
    :goto_43
    if-ge v15, v1, :cond_50

    .line 1857
    .line 1858
    invoke-interface {v0, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1859
    .line 1860
    .line 1861
    move-result-object v3

    .line 1862
    check-cast v3, Ln1/o;

    .line 1863
    .line 1864
    const/4 v11, 0x0

    .line 1865
    invoke-virtual {v3, v4, v11, v6, v12}, Ln1/o;->a(IIII)V

    .line 1866
    .line 1867
    .line 1868
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1869
    .line 1870
    .line 1871
    iget v3, v3, Ln1/o;->o:I

    .line 1872
    .line 1873
    add-int/2addr v4, v3

    .line 1874
    add-int/lit8 v15, v15, 0x1

    .line 1875
    .line 1876
    goto :goto_43

    .line 1877
    :cond_50
    const/4 v11, 0x0

    .line 1878
    move/from16 v4, v65

    .line 1879
    .line 1880
    :goto_44
    float-to-int v0, v4

    .line 1881
    move-object/from16 v1, v55

    .line 1882
    .line 1883
    iget-object v3, v1, Ln1/h;->c:Lbb/g0;

    .line 1884
    .line 1885
    move/from16 v17, v0

    .line 1886
    .line 1887
    move-object/from16 v20, v2

    .line 1888
    .line 1889
    move-object/from16 v21, v3

    .line 1890
    .line 1891
    move/from16 v18, v6

    .line 1892
    .line 1893
    move/from16 v28, v10

    .line 1894
    .line 1895
    move/from16 v19, v12

    .line 1896
    .line 1897
    move-object/from16 v16, v22

    .line 1898
    .line 1899
    move-object/from16 v22, v36

    .line 1900
    .line 1901
    invoke-virtual/range {v16 .. v30}, Landroidx/compose/foundation/lazy/layout/b;->d(IIILjava/util/ArrayList;Lbb/g0;Lap0/o;ZZIZIILvy0/b0;Le3/w;)V

    .line 1902
    .line 1903
    .line 1904
    move-object/from16 v0, v22

    .line 1905
    .line 1906
    move/from16 v17, v54

    .line 1907
    .line 1908
    move/from16 v54, v24

    .line 1909
    .line 1910
    if-nez v54, :cond_53

    .line 1911
    .line 1912
    move/from16 v19, v12

    .line 1913
    .line 1914
    invoke-virtual/range {v16 .. v16}, Landroidx/compose/foundation/lazy/layout/b;->b()J

    .line 1915
    .line 1916
    .line 1917
    move-result-wide v11

    .line 1918
    move/from16 v65, v4

    .line 1919
    .line 1920
    const-wide/16 v3, 0x0

    .line 1921
    .line 1922
    invoke-static {v11, v12, v3, v4}, Lt4/l;->a(JJ)Z

    .line 1923
    .line 1924
    .line 1925
    move-result v3

    .line 1926
    if-nez v3, :cond_52

    .line 1927
    .line 1928
    shr-long v3, v11, v33

    .line 1929
    .line 1930
    long-to-int v3, v3

    .line 1931
    invoke-static {v6, v3}, Ljava/lang/Math;->max(II)I

    .line 1932
    .line 1933
    .line 1934
    move-result v3

    .line 1935
    invoke-static {v3, v7, v8}, Lt4/b;->g(IJ)I

    .line 1936
    .line 1937
    .line 1938
    move-result v6

    .line 1939
    and-long v3, v11, v34

    .line 1940
    .line 1941
    long-to-int v3, v3

    .line 1942
    move/from16 v12, v19

    .line 1943
    .line 1944
    invoke-static {v12, v3}, Ljava/lang/Math;->max(II)I

    .line 1945
    .line 1946
    .line 1947
    move-result v3

    .line 1948
    invoke-static {v3, v7, v8}, Lt4/b;->f(IJ)I

    .line 1949
    .line 1950
    .line 1951
    move-result v3

    .line 1952
    if-eq v3, v12, :cond_51

    .line 1953
    .line 1954
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 1955
    .line 1956
    .line 1957
    move-result v4

    .line 1958
    const/4 v7, 0x0

    .line 1959
    :goto_45
    if-ge v7, v4, :cond_51

    .line 1960
    .line 1961
    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1962
    .line 1963
    .line 1964
    move-result-object v8

    .line 1965
    check-cast v8, Ln1/o;

    .line 1966
    .line 1967
    iput v3, v8, Ln1/o;->p:I

    .line 1968
    .line 1969
    iget v11, v8, Ln1/o;->f:I

    .line 1970
    .line 1971
    add-int/2addr v11, v3

    .line 1972
    iput v11, v8, Ln1/o;->r:I

    .line 1973
    .line 1974
    add-int/lit8 v7, v7, 0x1

    .line 1975
    .line 1976
    goto :goto_45

    .line 1977
    :cond_51
    move/from16 v23, v3

    .line 1978
    .line 1979
    :goto_46
    move/from16 v22, v6

    .line 1980
    .line 1981
    goto :goto_48

    .line 1982
    :cond_52
    move/from16 v12, v19

    .line 1983
    .line 1984
    goto :goto_47

    .line 1985
    :cond_53
    move/from16 v65, v4

    .line 1986
    .line 1987
    :goto_47
    move/from16 v23, v12

    .line 1988
    .line 1989
    goto :goto_46

    .line 1990
    :goto_48
    iget-object v1, v1, Ln1/h;->b:Ln1/g;

    .line 1991
    .line 1992
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1993
    .line 1994
    .line 1995
    sget-object v20, Landroidx/collection/o;->a:Landroidx/collection/a0;

    .line 1996
    .line 1997
    new-instance v1, Ll2/v1;

    .line 1998
    .line 1999
    const/16 v3, 0x13

    .line 2000
    .line 2001
    invoke-direct {v1, v3, v13, v0}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 2002
    .line 2003
    .line 2004
    move-object/from16 v0, p0

    .line 2005
    .line 2006
    iget-object v0, v0, Ln1/m;->h:Lo1/f0;

    .line 2007
    .line 2008
    move-object/from16 v16, v0

    .line 2009
    .line 2010
    move-object/from16 v24, v1

    .line 2011
    .line 2012
    move-object/from16 v19, v2

    .line 2013
    .line 2014
    move/from16 v21, v47

    .line 2015
    .line 2016
    move/from16 v18, v53

    .line 2017
    .line 2018
    invoke-static/range {v16 .. v24}, Lo1/y;->f(Lo1/f0;IILjava/util/ArrayList;Landroidx/collection/a0;IIILay0/k;)Ljava/util/List;

    .line 2019
    .line 2020
    .line 2021
    move-result-object v53

    .line 2022
    move/from16 v6, v17

    .line 2023
    .line 2024
    move/from16 v11, v18

    .line 2025
    .line 2026
    add-int/lit8 v0, v37, -0x1

    .line 2027
    .line 2028
    if-ne v11, v0, :cond_55

    .line 2029
    .line 2030
    if-le v10, v5, :cond_54

    .line 2031
    .line 2032
    goto :goto_49

    .line 2033
    :cond_54
    const/4 v3, 0x0

    .line 2034
    goto :goto_4a

    .line 2035
    :cond_55
    :goto_49
    move/from16 v3, v31

    .line 2036
    .line 2037
    :goto_4a
    new-instance v50, Lm1/k;

    .line 2038
    .line 2039
    const/16 v55, 0x1

    .line 2040
    .line 2041
    move-object/from16 v52, v2

    .line 2042
    .line 2043
    invoke-direct/range {v50 .. v55}, Lm1/k;-><init>(Ll2/b1;Ljava/util/ArrayList;Ljava/util/List;ZI)V

    .line 2044
    .line 2045
    .line 2046
    move-object/from16 v1, v50

    .line 2047
    .line 2048
    move-object/from16 v0, v53

    .line 2049
    .line 2050
    add-int v4, v22, v44

    .line 2051
    .line 2052
    move-wide/from16 v7, p2

    .line 2053
    .line 2054
    invoke-static {v4, v7, v8}, Lt4/b;->g(IJ)I

    .line 2055
    .line 2056
    .line 2057
    move-result v4

    .line 2058
    add-int v5, v23, v43

    .line 2059
    .line 2060
    invoke-static {v5, v7, v8}, Lt4/b;->f(IJ)I

    .line 2061
    .line 2062
    .line 2063
    move-result v5

    .line 2064
    move-object/from16 v8, v48

    .line 2065
    .line 2066
    move-object/from16 v7, v57

    .line 2067
    .line 2068
    invoke-interface {v7, v4, v5, v8, v1}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 2069
    .line 2070
    .line 2071
    move-result-object v5

    .line 2072
    invoke-static {v6, v11, v2, v0}, Lo1/y;->m(IILjava/util/ArrayList;Ljava/util/List;)Ljava/util/List;

    .line 2073
    .line 2074
    .line 2075
    move-result-object v13

    .line 2076
    sget-object v17, Lg1/w1;->d:Lg1/w1;

    .line 2077
    .line 2078
    new-instance v0, Ln1/n;

    .line 2079
    .line 2080
    move-object v1, v14

    .line 2081
    move/from16 v10, v25

    .line 2082
    .line 2083
    move/from16 v2, v27

    .line 2084
    .line 2085
    move-object/from16 v8, v29

    .line 2086
    .line 2087
    move/from16 v18, v32

    .line 2088
    .line 2089
    move/from16 v16, v37

    .line 2090
    .line 2091
    move/from16 v15, v56

    .line 2092
    .line 2093
    move-object/from16 v12, v59

    .line 2094
    .line 2095
    move-object/from16 v11, v60

    .line 2096
    .line 2097
    move/from16 v14, v61

    .line 2098
    .line 2099
    move/from16 v19, v62

    .line 2100
    .line 2101
    move/from16 v7, v63

    .line 2102
    .line 2103
    move/from16 v6, v64

    .line 2104
    .line 2105
    move/from16 v4, v65

    .line 2106
    .line 2107
    invoke-direct/range {v0 .. v19}, Ln1/n;-><init>(Ln1/p;IZFLt3/r0;FZLvy0/b0;Lt4/c;ILay0/k;Lay0/k;Ljava/util/List;IIILg1/w1;II)V

    .line 2108
    .line 2109
    .line 2110
    :goto_4b
    invoke-interface/range {v57 .. v57}, Lt3/t;->I()Z

    .line 2111
    .line 2112
    .line 2113
    move-result v1

    .line 2114
    move-object/from16 v2, v58

    .line 2115
    .line 2116
    const/4 v12, 0x0

    .line 2117
    invoke-virtual {v2, v0, v1, v12}, Ln1/v;->f(Ln1/n;ZZ)V

    .line 2118
    .line 2119
    .line 2120
    return-object v0

    .line 2121
    :goto_4c
    invoke-static {v4, v15, v7}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 2122
    .line 2123
    .line 2124
    throw v0
.end method
