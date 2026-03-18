.class public final Lh2/j9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/j9;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/j9;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move-object/from16 v1, p2

    .line 6
    .line 7
    iget v2, v0, Lh2/j9;->a:I

    .line 8
    .line 9
    packed-switch v2, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-static/range {p3 .. p4}, Lt4/a;->g(J)I

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    new-instance v5, Lod0/n;

    .line 21
    .line 22
    const/16 v6, 0x16

    .line 23
    .line 24
    invoke-direct {v5, v6, v1, v0}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 28
    .line 29
    invoke-interface {v3, v2, v4, v0, v5}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    return-object v0

    .line 34
    :pswitch_0
    iget-object v0, v0, Lh2/j9;->b:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lay0/n;

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    const/4 v11, 0x0

    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    move-object v0, v1

    .line 43
    check-cast v0, Ljava/util/Collection;

    .line 44
    .line 45
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    move v4, v11

    .line 50
    :goto_0
    if-ge v4, v0, :cond_1

    .line 51
    .line 52
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    move-object v12, v5

    .line 57
    check-cast v12, Lt3/p0;

    .line 58
    .line 59
    invoke-static {v12}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    const-string v6, "text"

    .line 64
    .line 65
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    if-eqz v5, :cond_0

    .line 70
    .line 71
    const/4 v9, 0x0

    .line 72
    const/16 v10, 0xb

    .line 73
    .line 74
    const/4 v6, 0x0

    .line 75
    const/4 v7, 0x0

    .line 76
    const/4 v8, 0x0

    .line 77
    move-wide/from16 v4, p3

    .line 78
    .line 79
    invoke-static/range {v4 .. v10}, Lt4/a;->a(JIIIII)J

    .line 80
    .line 81
    .line 82
    move-result-wide v0

    .line 83
    invoke-interface {v12, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    move-object v1, v0

    .line 88
    goto :goto_1

    .line 89
    :cond_0
    move-wide/from16 v5, p3

    .line 90
    .line 91
    add-int/lit8 v4, v4, 0x1

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_1
    const-string v0, "Collection contains no element matching the predicate."

    .line 95
    .line 96
    invoke-static {v0}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    throw v0

    .line 101
    :cond_2
    move-object v1, v2

    .line 102
    :goto_1
    if-eqz v1, :cond_3

    .line 103
    .line 104
    iget v0, v1, Lt3/e1;->d:I

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_3
    move v0, v11

    .line 108
    :goto_2
    invoke-static {v0, v11}, Ljava/lang/Math;->max(II)I

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    sget v0, Lh2/wa;->a:F

    .line 113
    .line 114
    invoke-interface {v3, v0}, Lt4/c;->Q(F)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-eqz v1, :cond_4

    .line 119
    .line 120
    iget v5, v1, Lt3/e1;->e:I

    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_4
    move v5, v11

    .line 124
    :goto_3
    add-int/2addr v11, v5

    .line 125
    sget-wide v5, Lh2/wa;->e:J

    .line 126
    .line 127
    invoke-interface {v3, v5, v6}, Lt4/c;->z0(J)I

    .line 128
    .line 129
    .line 130
    move-result v5

    .line 131
    add-int/2addr v5, v11

    .line 132
    invoke-static {v0, v5}, Ljava/lang/Math;->max(II)I

    .line 133
    .line 134
    .line 135
    move-result v5

    .line 136
    if-eqz v1, :cond_5

    .line 137
    .line 138
    sget-object v0, Lt3/d;->a:Lt3/o;

    .line 139
    .line 140
    invoke-virtual {v1, v0}, Lt3/e1;->a0(Lt3/a;)I

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    move-object v6, v0

    .line 149
    goto :goto_4

    .line 150
    :cond_5
    move-object v6, v2

    .line 151
    :goto_4
    if-eqz v1, :cond_6

    .line 152
    .line 153
    sget-object v0, Lt3/d;->b:Lt3/o;

    .line 154
    .line 155
    invoke-virtual {v1, v0}, Lt3/e1;->a0(Lt3/a;)I

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    move-object v7, v0

    .line 164
    goto :goto_5

    .line 165
    :cond_6
    move-object v7, v2

    .line 166
    :goto_5
    new-instance v0, Lh2/j3;

    .line 167
    .line 168
    invoke-direct/range {v0 .. v7}, Lh2/j3;-><init>(Lt3/e1;Lt3/e1;Lt3/s0;IILjava/lang/Integer;Ljava/lang/Integer;)V

    .line 169
    .line 170
    .line 171
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 172
    .line 173
    invoke-interface {v3, v4, v5, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    return-object v0

    .line 178
    :pswitch_1
    move-wide/from16 v5, p3

    .line 179
    .line 180
    iget-object v0, v0, Lh2/j9;->b:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v0, Lh2/s9;

    .line 183
    .line 184
    iget v2, v0, Lh2/s9;->a:I

    .line 185
    .line 186
    iget-object v4, v0, Lh2/s9;->g:[F

    .line 187
    .line 188
    iget-object v7, v0, Lh2/s9;->m:Lg1/w1;

    .line 189
    .line 190
    move-object v8, v1

    .line 191
    check-cast v8, Ljava/util/Collection;

    .line 192
    .line 193
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 194
    .line 195
    .line 196
    move-result v8

    .line 197
    const/4 v9, 0x0

    .line 198
    move v10, v9

    .line 199
    :goto_6
    const-string v11, "Collection contains no element matching the predicate."

    .line 200
    .line 201
    if-ge v10, v8, :cond_11

    .line 202
    .line 203
    invoke-interface {v1, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v12

    .line 207
    check-cast v12, Lt3/p0;

    .line 208
    .line 209
    invoke-static {v12}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v13

    .line 213
    sget-object v14, Lh2/v8;->d:Lh2/v8;

    .line 214
    .line 215
    if-ne v13, v14, :cond_10

    .line 216
    .line 217
    invoke-interface {v12, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 218
    .line 219
    .line 220
    move-result-object v8

    .line 221
    move-object v10, v1

    .line 222
    check-cast v10, Ljava/util/Collection;

    .line 223
    .line 224
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 225
    .line 226
    .line 227
    move-result v10

    .line 228
    move v12, v9

    .line 229
    :goto_7
    if-ge v12, v10, :cond_f

    .line 230
    .line 231
    invoke-interface {v1, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v13

    .line 235
    check-cast v13, Lt3/p0;

    .line 236
    .line 237
    invoke-static {v13}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v14

    .line 241
    sget-object v15, Lh2/v8;->e:Lh2/v8;

    .line 242
    .line 243
    if-ne v14, v15, :cond_e

    .line 244
    .line 245
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 246
    .line 247
    const/4 v10, 0x1

    .line 248
    const/4 v11, 0x2

    .line 249
    if-ne v7, v1, :cond_7

    .line 250
    .line 251
    iget v12, v8, Lt3/e1;->e:I

    .line 252
    .line 253
    neg-int v12, v12

    .line 254
    invoke-static {v5, v6, v9, v12, v10}, Lt4/b;->j(JIII)J

    .line 255
    .line 256
    .line 257
    move-result-wide v14

    .line 258
    const/16 v19, 0x0

    .line 259
    .line 260
    const/16 v20, 0xe

    .line 261
    .line 262
    const/16 v16, 0x0

    .line 263
    .line 264
    const/16 v17, 0x0

    .line 265
    .line 266
    const/16 v18, 0x0

    .line 267
    .line 268
    invoke-static/range {v14 .. v20}, Lt4/a;->a(JIIIII)J

    .line 269
    .line 270
    .line 271
    move-result-wide v5

    .line 272
    invoke-interface {v13, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 273
    .line 274
    .line 275
    move-result-object v5

    .line 276
    goto :goto_8

    .line 277
    :cond_7
    iget v12, v8, Lt3/e1;->d:I

    .line 278
    .line 279
    neg-int v12, v12

    .line 280
    invoke-static {v5, v6, v12, v9, v11}, Lt4/b;->j(JIII)J

    .line 281
    .line 282
    .line 283
    move-result-wide v14

    .line 284
    const/16 v19, 0x0

    .line 285
    .line 286
    const/16 v20, 0xb

    .line 287
    .line 288
    const/16 v16, 0x0

    .line 289
    .line 290
    const/16 v17, 0x0

    .line 291
    .line 292
    const/16 v18, 0x0

    .line 293
    .line 294
    invoke-static/range {v14 .. v20}, Lt4/a;->a(JIIIII)J

    .line 295
    .line 296
    .line 297
    move-result-wide v5

    .line 298
    invoke-interface {v13, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 299
    .line 300
    .line 301
    move-result-object v5

    .line 302
    :goto_8
    new-instance v6, Lkotlin/jvm/internal/d0;

    .line 303
    .line 304
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v0}, Lh2/s9;->c()F

    .line 308
    .line 309
    .line 310
    move-result v12

    .line 311
    invoke-static {v4}, Lmx0/n;->v([F)Ljava/lang/Float;

    .line 312
    .line 313
    .line 314
    move-result-object v13

    .line 315
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    .line 316
    .line 317
    .line 318
    move-result v13

    .line 319
    if-nez v13, :cond_9

    .line 320
    .line 321
    invoke-static {v4}, Lmx0/n;->K([F)Ljava/lang/Float;

    .line 322
    .line 323
    .line 324
    move-result-object v4

    .line 325
    invoke-static {v12, v4}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    .line 326
    .line 327
    .line 328
    move-result v4

    .line 329
    if-eqz v4, :cond_8

    .line 330
    .line 331
    goto :goto_9

    .line 332
    :cond_8
    move v10, v9

    .line 333
    :cond_9
    :goto_9
    sget-object v4, Lh2/q9;->e:Lt3/r1;

    .line 334
    .line 335
    invoke-virtual {v5, v4}, Lt3/e1;->a0(Lt3/a;)I

    .line 336
    .line 337
    .line 338
    move-result v4

    .line 339
    const/high16 v13, -0x80000000

    .line 340
    .line 341
    if-eq v4, v13, :cond_a

    .line 342
    .line 343
    move v9, v4

    .line 344
    :cond_a
    if-ne v7, v1, :cond_c

    .line 345
    .line 346
    iget v1, v5, Lt3/e1;->d:I

    .line 347
    .line 348
    iget v4, v8, Lt3/e1;->d:I

    .line 349
    .line 350
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    .line 351
    .line 352
    .line 353
    move-result v1

    .line 354
    iget v4, v8, Lt3/e1;->e:I

    .line 355
    .line 356
    iget v7, v5, Lt3/e1;->e:I

    .line 357
    .line 358
    add-int v13, v4, v7

    .line 359
    .line 360
    iget v14, v5, Lt3/e1;->d:I

    .line 361
    .line 362
    sub-int v14, v1, v14

    .line 363
    .line 364
    div-int/2addr v14, v11

    .line 365
    div-int/2addr v4, v11

    .line 366
    iget v15, v8, Lt3/e1;->d:I

    .line 367
    .line 368
    sub-int v15, v1, v15

    .line 369
    .line 370
    div-int/2addr v15, v11

    .line 371
    if-lez v2, :cond_b

    .line 372
    .line 373
    if-nez v10, :cond_b

    .line 374
    .line 375
    mul-int/lit8 v2, v9, 0x2

    .line 376
    .line 377
    sub-int/2addr v7, v2

    .line 378
    int-to-float v2, v7

    .line 379
    mul-float/2addr v2, v12

    .line 380
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 381
    .line 382
    .line 383
    move-result v2

    .line 384
    add-int/2addr v2, v9

    .line 385
    goto :goto_a

    .line 386
    :cond_b
    int-to-float v2, v7

    .line 387
    mul-float/2addr v2, v12

    .line 388
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 389
    .line 390
    .line 391
    move-result v2

    .line 392
    :goto_a
    iput v2, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 393
    .line 394
    :goto_b
    move/from16 v18, v4

    .line 395
    .line 396
    move/from16 v17, v14

    .line 397
    .line 398
    move/from16 v20, v15

    .line 399
    .line 400
    goto :goto_e

    .line 401
    :cond_c
    iget v1, v8, Lt3/e1;->d:I

    .line 402
    .line 403
    iget v4, v5, Lt3/e1;->d:I

    .line 404
    .line 405
    add-int/2addr v1, v4

    .line 406
    iget v4, v5, Lt3/e1;->e:I

    .line 407
    .line 408
    iget v7, v8, Lt3/e1;->e:I

    .line 409
    .line 410
    invoke-static {v4, v7}, Ljava/lang/Math;->max(II)I

    .line 411
    .line 412
    .line 413
    move-result v13

    .line 414
    iget v4, v8, Lt3/e1;->d:I

    .line 415
    .line 416
    div-int/lit8 v14, v4, 0x2

    .line 417
    .line 418
    iget v4, v5, Lt3/e1;->e:I

    .line 419
    .line 420
    sub-int v4, v13, v4

    .line 421
    .line 422
    div-int/2addr v4, v11

    .line 423
    if-lez v2, :cond_d

    .line 424
    .line 425
    if-nez v10, :cond_d

    .line 426
    .line 427
    iget v2, v5, Lt3/e1;->d:I

    .line 428
    .line 429
    mul-int/lit8 v7, v9, 0x2

    .line 430
    .line 431
    sub-int/2addr v2, v7

    .line 432
    int-to-float v2, v2

    .line 433
    mul-float/2addr v2, v12

    .line 434
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 435
    .line 436
    .line 437
    move-result v2

    .line 438
    add-int/2addr v2, v9

    .line 439
    :goto_c
    move v15, v2

    .line 440
    goto :goto_d

    .line 441
    :cond_d
    iget v2, v5, Lt3/e1;->d:I

    .line 442
    .line 443
    int-to-float v2, v2

    .line 444
    mul-float/2addr v2, v12

    .line 445
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 446
    .line 447
    .line 448
    move-result v2

    .line 449
    goto :goto_c

    .line 450
    :goto_d
    iget v2, v8, Lt3/e1;->e:I

    .line 451
    .line 452
    sub-int v2, v13, v2

    .line 453
    .line 454
    div-int/2addr v2, v11

    .line 455
    iput v2, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 456
    .line 457
    goto :goto_b

    .line 458
    :goto_e
    iget-object v2, v0, Lh2/s9;->h:Ll2/g1;

    .line 459
    .line 460
    invoke-virtual {v2, v1}, Ll2/g1;->p(I)V

    .line 461
    .line 462
    .line 463
    iget-object v0, v0, Lh2/s9;->i:Ll2/g1;

    .line 464
    .line 465
    invoke-virtual {v0, v13}, Ll2/g1;->p(I)V

    .line 466
    .line 467
    .line 468
    new-instance v15, Lh2/k9;

    .line 469
    .line 470
    move-object/from16 v16, v5

    .line 471
    .line 472
    move-object/from16 v21, v6

    .line 473
    .line 474
    move-object/from16 v19, v8

    .line 475
    .line 476
    invoke-direct/range {v15 .. v21}, Lh2/k9;-><init>(Lt3/e1;IILt3/e1;ILkotlin/jvm/internal/d0;)V

    .line 477
    .line 478
    .line 479
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 480
    .line 481
    invoke-interface {v3, v1, v13, v0, v15}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 482
    .line 483
    .line 484
    move-result-object v0

    .line 485
    return-object v0

    .line 486
    :cond_e
    move-object/from16 v19, v8

    .line 487
    .line 488
    add-int/lit8 v12, v12, 0x1

    .line 489
    .line 490
    goto/16 :goto_7

    .line 491
    .line 492
    :cond_f
    invoke-static {v11}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 493
    .line 494
    .line 495
    move-result-object v0

    .line 496
    throw v0

    .line 497
    :cond_10
    add-int/lit8 v10, v10, 0x1

    .line 498
    .line 499
    goto/16 :goto_6

    .line 500
    .line 501
    :cond_11
    invoke-static {v11}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 502
    .line 503
    .line 504
    move-result-object v0

    .line 505
    throw v0

    .line 506
    :pswitch_2
    move-wide/from16 v5, p3

    .line 507
    .line 508
    iget-object v0, v0, Lh2/j9;->b:Ljava/lang/Object;

    .line 509
    .line 510
    check-cast v0, Lh2/u7;

    .line 511
    .line 512
    iget v2, v0, Lh2/u7;->a:I

    .line 513
    .line 514
    iget-object v4, v0, Lh2/u7;->e:Ll2/f1;

    .line 515
    .line 516
    iget-object v7, v0, Lh2/u7;->d:Ll2/f1;

    .line 517
    .line 518
    iget-object v8, v0, Lh2/u7;->l:Ll2/g1;

    .line 519
    .line 520
    iget-object v9, v0, Lh2/u7;->g:[F

    .line 521
    .line 522
    iget-object v10, v0, Lh2/u7;->r:Ll2/f1;

    .line 523
    .line 524
    iget-object v11, v0, Lh2/u7;->s:Ll2/f1;

    .line 525
    .line 526
    move-object v12, v1

    .line 527
    check-cast v12, Ljava/util/Collection;

    .line 528
    .line 529
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 530
    .line 531
    .line 532
    move-result v12

    .line 533
    const/4 v14, 0x0

    .line 534
    :goto_f
    const-string v15, "Collection contains no element matching the predicate."

    .line 535
    .line 536
    if-ge v14, v12, :cond_20

    .line 537
    .line 538
    invoke-interface {v1, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    move-result-object v16

    .line 542
    move-object/from16 v13, v16

    .line 543
    .line 544
    check-cast v13, Lt3/p0;

    .line 545
    .line 546
    move/from16 v16, v2

    .line 547
    .line 548
    invoke-static {v13}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 549
    .line 550
    .line 551
    move-result-object v2

    .line 552
    move-object/from16 v17, v4

    .line 553
    .line 554
    sget-object v4, Lh2/s7;->e:Lh2/s7;

    .line 555
    .line 556
    if-ne v2, v4, :cond_1f

    .line 557
    .line 558
    invoke-interface {v13, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 559
    .line 560
    .line 561
    move-result-object v2

    .line 562
    move-object v4, v1

    .line 563
    check-cast v4, Ljava/util/Collection;

    .line 564
    .line 565
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 566
    .line 567
    .line 568
    move-result v12

    .line 569
    const/4 v13, 0x0

    .line 570
    :goto_10
    if-ge v13, v12, :cond_1e

    .line 571
    .line 572
    invoke-interface {v1, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v14

    .line 576
    check-cast v14, Lt3/p0;

    .line 577
    .line 578
    move-object/from16 v18, v4

    .line 579
    .line 580
    invoke-static {v14}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    move-result-object v4

    .line 584
    move-object/from16 v19, v7

    .line 585
    .line 586
    sget-object v7, Lh2/s7;->d:Lh2/s7;

    .line 587
    .line 588
    if-ne v4, v7, :cond_1d

    .line 589
    .line 590
    invoke-interface {v14, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 591
    .line 592
    .line 593
    move-result-object v4

    .line 594
    invoke-interface/range {v18 .. v18}, Ljava/util/Collection;->size()I

    .line 595
    .line 596
    .line 597
    move-result v7

    .line 598
    const/4 v12, 0x0

    .line 599
    :goto_11
    if-ge v12, v7, :cond_1c

    .line 600
    .line 601
    invoke-interface {v1, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 602
    .line 603
    .line 604
    move-result-object v13

    .line 605
    check-cast v13, Lt3/p0;

    .line 606
    .line 607
    invoke-static {v13}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 608
    .line 609
    .line 610
    move-result-object v14

    .line 611
    sget-object v1, Lh2/s7;->f:Lh2/s7;

    .line 612
    .line 613
    if-ne v14, v1, :cond_1b

    .line 614
    .line 615
    iget v1, v2, Lt3/e1;->d:I

    .line 616
    .line 617
    iget v7, v4, Lt3/e1;->d:I

    .line 618
    .line 619
    add-int/2addr v1, v7

    .line 620
    neg-int v1, v1

    .line 621
    const/4 v7, 0x2

    .line 622
    div-int/2addr v1, v7

    .line 623
    const/4 v14, 0x0

    .line 624
    invoke-static {v5, v6, v1, v14, v7}, Lt4/b;->j(JIII)J

    .line 625
    .line 626
    .line 627
    move-result-wide v20

    .line 628
    const/16 v25, 0x0

    .line 629
    .line 630
    const/16 v26, 0xb

    .line 631
    .line 632
    const/16 v22, 0x0

    .line 633
    .line 634
    const/16 v23, 0x0

    .line 635
    .line 636
    const/16 v24, 0x0

    .line 637
    .line 638
    invoke-static/range {v20 .. v26}, Lt4/a;->a(JIIIII)J

    .line 639
    .line 640
    .line 641
    move-result-wide v5

    .line 642
    invoke-interface {v13, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 643
    .line 644
    .line 645
    move-result-object v1

    .line 646
    iget v5, v1, Lt3/e1;->d:I

    .line 647
    .line 648
    iget v6, v2, Lt3/e1;->d:I

    .line 649
    .line 650
    iget v12, v4, Lt3/e1;->d:I

    .line 651
    .line 652
    add-int/2addr v6, v12

    .line 653
    div-int/2addr v6, v7

    .line 654
    add-int/2addr v6, v5

    .line 655
    iget v5, v1, Lt3/e1;->e:I

    .line 656
    .line 657
    iget v12, v2, Lt3/e1;->e:I

    .line 658
    .line 659
    iget v13, v4, Lt3/e1;->e:I

    .line 660
    .line 661
    invoke-static {v12, v13}, Ljava/lang/Math;->max(II)I

    .line 662
    .line 663
    .line 664
    move-result v12

    .line 665
    invoke-static {v5, v12}, Ljava/lang/Math;->max(II)I

    .line 666
    .line 667
    .line 668
    move-result v5

    .line 669
    invoke-virtual {v8, v6}, Ll2/g1;->p(I)V

    .line 670
    .line 671
    .line 672
    invoke-virtual {v8}, Ll2/g1;->o()I

    .line 673
    .line 674
    .line 675
    move-result v8

    .line 676
    int-to-float v8, v8

    .line 677
    iget-object v12, v0, Lh2/u7;->j:Ll2/f1;

    .line 678
    .line 679
    invoke-virtual {v12}, Ll2/f1;->o()F

    .line 680
    .line 681
    .line 682
    move-result v12

    .line 683
    int-to-float v13, v7

    .line 684
    div-float/2addr v12, v13

    .line 685
    sub-float/2addr v8, v12

    .line 686
    const/4 v12, 0x0

    .line 687
    invoke-static {v8, v12}, Ljava/lang/Math;->max(FF)F

    .line 688
    .line 689
    .line 690
    move-result v8

    .line 691
    iget-object v12, v0, Lh2/u7;->h:Ll2/f1;

    .line 692
    .line 693
    invoke-virtual {v12}, Ll2/f1;->o()F

    .line 694
    .line 695
    .line 696
    move-result v12

    .line 697
    div-float/2addr v12, v13

    .line 698
    invoke-static {v12, v8}, Ljava/lang/Math;->min(FF)F

    .line 699
    .line 700
    .line 701
    move-result v12

    .line 702
    iget-object v13, v0, Lh2/u7;->o:Ll2/j1;

    .line 703
    .line 704
    invoke-virtual {v13}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 705
    .line 706
    .line 707
    move-result-object v13

    .line 708
    check-cast v13, Ljava/lang/Boolean;

    .line 709
    .line 710
    invoke-virtual {v13}, Ljava/lang/Boolean;->booleanValue()Z

    .line 711
    .line 712
    .line 713
    move-result v13

    .line 714
    if-nez v13, :cond_13

    .line 715
    .line 716
    invoke-virtual {v11}, Ll2/f1;->o()F

    .line 717
    .line 718
    .line 719
    move-result v13

    .line 720
    cmpg-float v13, v13, v12

    .line 721
    .line 722
    if-nez v13, :cond_12

    .line 723
    .line 724
    invoke-virtual {v10}, Ll2/f1;->o()F

    .line 725
    .line 726
    .line 727
    move-result v13

    .line 728
    cmpg-float v13, v13, v8

    .line 729
    .line 730
    if-nez v13, :cond_12

    .line 731
    .line 732
    invoke-virtual/range {v19 .. v19}, Ll2/f1;->o()F

    .line 733
    .line 734
    .line 735
    move-result v13

    .line 736
    invoke-virtual/range {v17 .. v17}, Ll2/f1;->o()F

    .line 737
    .line 738
    .line 739
    move-result v15

    .line 740
    cmpg-float v13, v13, v15

    .line 741
    .line 742
    if-nez v13, :cond_12

    .line 743
    .line 744
    goto :goto_12

    .line 745
    :cond_12
    invoke-virtual {v11, v12}, Ll2/f1;->p(F)V

    .line 746
    .line 747
    .line 748
    invoke-virtual {v10, v8}, Ll2/f1;->p(F)V

    .line 749
    .line 750
    .line 751
    invoke-virtual {v11}, Ll2/f1;->o()F

    .line 752
    .line 753
    .line 754
    move-result v8

    .line 755
    invoke-virtual {v10}, Ll2/f1;->o()F

    .line 756
    .line 757
    .line 758
    move-result v12

    .line 759
    invoke-virtual/range {v19 .. v19}, Ll2/f1;->o()F

    .line 760
    .line 761
    .line 762
    move-result v13

    .line 763
    invoke-virtual {v0, v8, v12, v13}, Lh2/u7;->f(FFF)F

    .line 764
    .line 765
    .line 766
    move-result v8

    .line 767
    iget-object v12, v0, Lh2/u7;->m:Ll2/f1;

    .line 768
    .line 769
    invoke-virtual {v12, v8}, Ll2/f1;->p(F)V

    .line 770
    .line 771
    .line 772
    invoke-virtual {v11}, Ll2/f1;->o()F

    .line 773
    .line 774
    .line 775
    move-result v8

    .line 776
    invoke-virtual {v10}, Ll2/f1;->o()F

    .line 777
    .line 778
    .line 779
    move-result v10

    .line 780
    invoke-virtual/range {v17 .. v17}, Ll2/f1;->o()F

    .line 781
    .line 782
    .line 783
    move-result v11

    .line 784
    invoke-virtual {v0, v8, v10, v11}, Lh2/u7;->f(FFF)F

    .line 785
    .line 786
    .line 787
    move-result v8

    .line 788
    iget-object v10, v0, Lh2/u7;->n:Ll2/f1;

    .line 789
    .line 790
    invoke-virtual {v10, v8}, Ll2/f1;->p(F)V

    .line 791
    .line 792
    .line 793
    :cond_13
    :goto_12
    invoke-virtual {v0}, Lh2/u7;->b()F

    .line 794
    .line 795
    .line 796
    move-result v8

    .line 797
    invoke-static {v9}, Lmx0/n;->v([F)Ljava/lang/Float;

    .line 798
    .line 799
    .line 800
    move-result-object v10

    .line 801
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    .line 802
    .line 803
    .line 804
    move-result v10

    .line 805
    const/4 v11, 0x1

    .line 806
    if-nez v10, :cond_15

    .line 807
    .line 808
    invoke-static {v9}, Lmx0/n;->K([F)Ljava/lang/Float;

    .line 809
    .line 810
    .line 811
    move-result-object v10

    .line 812
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    .line 813
    .line 814
    .line 815
    move-result v10

    .line 816
    if-eqz v10, :cond_14

    .line 817
    .line 818
    goto :goto_13

    .line 819
    :cond_14
    move v10, v14

    .line 820
    goto :goto_14

    .line 821
    :cond_15
    :goto_13
    move v10, v11

    .line 822
    :goto_14
    invoke-virtual {v0}, Lh2/u7;->a()F

    .line 823
    .line 824
    .line 825
    move-result v0

    .line 826
    invoke-static {v9}, Lmx0/n;->v([F)Ljava/lang/Float;

    .line 827
    .line 828
    .line 829
    move-result-object v12

    .line 830
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    .line 831
    .line 832
    .line 833
    move-result v12

    .line 834
    if-nez v12, :cond_17

    .line 835
    .line 836
    invoke-static {v9}, Lmx0/n;->K([F)Ljava/lang/Float;

    .line 837
    .line 838
    .line 839
    move-result-object v9

    .line 840
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->a(FLjava/lang/Float;)Z

    .line 841
    .line 842
    .line 843
    move-result v9

    .line 844
    if-eqz v9, :cond_16

    .line 845
    .line 846
    goto :goto_15

    .line 847
    :cond_16
    move v11, v14

    .line 848
    :cond_17
    :goto_15
    iget v9, v2, Lt3/e1;->d:I

    .line 849
    .line 850
    div-int/lit8 v20, v9, 0x2

    .line 851
    .line 852
    sget-object v9, Lh2/q9;->e:Lt3/r1;

    .line 853
    .line 854
    invoke-virtual {v1, v9}, Lt3/e1;->a0(Lt3/a;)I

    .line 855
    .line 856
    .line 857
    move-result v9

    .line 858
    const/high16 v12, -0x80000000

    .line 859
    .line 860
    if-eq v9, v12, :cond_18

    .line 861
    .line 862
    move v13, v9

    .line 863
    goto :goto_16

    .line 864
    :cond_18
    move v13, v14

    .line 865
    :goto_16
    if-lez v16, :cond_19

    .line 866
    .line 867
    if-nez v10, :cond_19

    .line 868
    .line 869
    iget v9, v1, Lt3/e1;->d:I

    .line 870
    .line 871
    mul-int/lit8 v10, v13, 0x2

    .line 872
    .line 873
    sub-int/2addr v9, v10

    .line 874
    int-to-float v9, v9

    .line 875
    mul-float/2addr v9, v8

    .line 876
    invoke-static {v9}, Lcy0/a;->i(F)I

    .line 877
    .line 878
    .line 879
    move-result v8

    .line 880
    add-int/2addr v8, v13

    .line 881
    :goto_17
    move/from16 v23, v8

    .line 882
    .line 883
    goto :goto_18

    .line 884
    :cond_19
    iget v9, v1, Lt3/e1;->d:I

    .line 885
    .line 886
    int-to-float v9, v9

    .line 887
    mul-float/2addr v9, v8

    .line 888
    invoke-static {v9}, Lcy0/a;->i(F)I

    .line 889
    .line 890
    .line 891
    move-result v8

    .line 892
    goto :goto_17

    .line 893
    :goto_18
    iget v8, v2, Lt3/e1;->d:I

    .line 894
    .line 895
    iget v9, v4, Lt3/e1;->d:I

    .line 896
    .line 897
    sub-int/2addr v8, v9

    .line 898
    div-int/2addr v8, v7

    .line 899
    if-lez v16, :cond_1a

    .line 900
    .line 901
    if-nez v11, :cond_1a

    .line 902
    .line 903
    iget v9, v1, Lt3/e1;->d:I

    .line 904
    .line 905
    mul-int/lit8 v10, v13, 0x2

    .line 906
    .line 907
    sub-int/2addr v9, v10

    .line 908
    int-to-float v9, v9

    .line 909
    mul-float/2addr v9, v0

    .line 910
    int-to-float v0, v8

    .line 911
    add-float/2addr v9, v0

    .line 912
    invoke-static {v9}, Lcy0/a;->i(F)I

    .line 913
    .line 914
    .line 915
    move-result v0

    .line 916
    add-int/2addr v0, v13

    .line 917
    :goto_19
    move/from16 v26, v0

    .line 918
    .line 919
    goto :goto_1a

    .line 920
    :cond_1a
    iget v9, v1, Lt3/e1;->d:I

    .line 921
    .line 922
    int-to-float v9, v9

    .line 923
    mul-float/2addr v9, v0

    .line 924
    int-to-float v0, v8

    .line 925
    add-float/2addr v9, v0

    .line 926
    invoke-static {v9}, Lcy0/a;->i(F)I

    .line 927
    .line 928
    .line 929
    move-result v0

    .line 930
    goto :goto_19

    .line 931
    :goto_1a
    iget v0, v1, Lt3/e1;->e:I

    .line 932
    .line 933
    sub-int v0, v5, v0

    .line 934
    .line 935
    div-int/lit8 v21, v0, 0x2

    .line 936
    .line 937
    iget v0, v2, Lt3/e1;->e:I

    .line 938
    .line 939
    sub-int v0, v5, v0

    .line 940
    .line 941
    div-int/lit8 v24, v0, 0x2

    .line 942
    .line 943
    iget v0, v4, Lt3/e1;->e:I

    .line 944
    .line 945
    sub-int v0, v5, v0

    .line 946
    .line 947
    div-int/lit8 v27, v0, 0x2

    .line 948
    .line 949
    new-instance v18, Lh2/i9;

    .line 950
    .line 951
    move-object/from16 v19, v1

    .line 952
    .line 953
    move-object/from16 v22, v2

    .line 954
    .line 955
    move-object/from16 v25, v4

    .line 956
    .line 957
    invoke-direct/range {v18 .. v27}, Lh2/i9;-><init>(Lt3/e1;IILt3/e1;IILt3/e1;II)V

    .line 958
    .line 959
    .line 960
    move-object/from16 v0, v18

    .line 961
    .line 962
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 963
    .line 964
    invoke-interface {v3, v6, v5, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 965
    .line 966
    .line 967
    move-result-object v0

    .line 968
    return-object v0

    .line 969
    :cond_1b
    move-object/from16 v22, v2

    .line 970
    .line 971
    move-object/from16 v25, v4

    .line 972
    .line 973
    const/4 v14, 0x0

    .line 974
    add-int/lit8 v12, v12, 0x1

    .line 975
    .line 976
    move-object/from16 v1, p2

    .line 977
    .line 978
    goto/16 :goto_11

    .line 979
    .line 980
    :cond_1c
    invoke-static {v15}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 981
    .line 982
    .line 983
    move-result-object v0

    .line 984
    throw v0

    .line 985
    :cond_1d
    move-object/from16 v22, v2

    .line 986
    .line 987
    const/4 v14, 0x0

    .line 988
    add-int/lit8 v13, v13, 0x1

    .line 989
    .line 990
    move-object/from16 v1, p2

    .line 991
    .line 992
    move-object/from16 v4, v18

    .line 993
    .line 994
    move-object/from16 v7, v19

    .line 995
    .line 996
    goto/16 :goto_10

    .line 997
    .line 998
    :cond_1e
    invoke-static {v15}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 999
    .line 1000
    .line 1001
    move-result-object v0

    .line 1002
    throw v0

    .line 1003
    :cond_1f
    move-object/from16 v19, v7

    .line 1004
    .line 1005
    const/4 v1, 0x0

    .line 1006
    add-int/lit8 v14, v14, 0x1

    .line 1007
    .line 1008
    move-object/from16 v1, p2

    .line 1009
    .line 1010
    move/from16 v2, v16

    .line 1011
    .line 1012
    move-object/from16 v4, v17

    .line 1013
    .line 1014
    goto/16 :goto_f

    .line 1015
    .line 1016
    :cond_20
    invoke-static {v15}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v0

    .line 1020
    throw v0

    .line 1021
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
