.class public abstract Lkp/d8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lug/c;ILl2/o;I)V
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "condition"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v3, v0, Lug/c;->f:Z

    .line 13
    .line 14
    move-object/from16 v4, p2

    .line 15
    .line 16
    check-cast v4, Ll2/t;

    .line 17
    .line 18
    const v5, -0x6241f72c

    .line 19
    .line 20
    .line 21
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    if-eqz v5, :cond_0

    .line 29
    .line 30
    const/4 v5, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v5, 0x2

    .line 33
    :goto_0
    or-int/2addr v5, v2

    .line 34
    invoke-virtual {v4, v1}, Ll2/t;->e(I)Z

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    const/16 v8, 0x10

    .line 39
    .line 40
    if-eqz v7, :cond_1

    .line 41
    .line 42
    const/16 v7, 0x20

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    move v7, v8

    .line 46
    :goto_1
    or-int/2addr v5, v7

    .line 47
    and-int/lit8 v7, v5, 0x13

    .line 48
    .line 49
    const/16 v9, 0x12

    .line 50
    .line 51
    const/4 v10, 0x1

    .line 52
    const/4 v11, 0x0

    .line 53
    if-eq v7, v9, :cond_2

    .line 54
    .line 55
    move v7, v10

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    move v7, v11

    .line 58
    :goto_2
    and-int/2addr v5, v10

    .line 59
    invoke-virtual {v4, v5, v7}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    if-eqz v5, :cond_e

    .line 64
    .line 65
    const/16 v5, 0x8

    .line 66
    .line 67
    if-eqz v3, :cond_3

    .line 68
    .line 69
    int-to-float v7, v5

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    const/16 v7, 0xc

    .line 72
    .line 73
    int-to-float v7, v7

    .line 74
    :goto_3
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 75
    .line 76
    const/high16 v12, 0x3f800000    # 1.0f

    .line 77
    .line 78
    invoke-static {v9, v12}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v13

    .line 82
    int-to-float v8, v8

    .line 83
    invoke-static {v13, v8, v7}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v8

    .line 87
    sget-object v13, Lk1/j;->c:Lk1/e;

    .line 88
    .line 89
    sget-object v14, Lx2/c;->p:Lx2/h;

    .line 90
    .line 91
    invoke-static {v13, v14, v4, v11}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 92
    .line 93
    .line 94
    move-result-object v13

    .line 95
    iget-wide v14, v4, Ll2/t;->T:J

    .line 96
    .line 97
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 98
    .line 99
    .line 100
    move-result v14

    .line 101
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 102
    .line 103
    .line 104
    move-result-object v15

    .line 105
    invoke-static {v4, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 110
    .line 111
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 115
    .line 116
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 117
    .line 118
    .line 119
    iget-boolean v6, v4, Ll2/t;->S:Z

    .line 120
    .line 121
    if-eqz v6, :cond_4

    .line 122
    .line 123
    invoke-virtual {v4, v5}, Ll2/t;->l(Lay0/a;)V

    .line 124
    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_4
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 128
    .line 129
    .line 130
    :goto_4
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 131
    .line 132
    invoke-static {v6, v13, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 133
    .line 134
    .line 135
    sget-object v13, Lv3/j;->f:Lv3/h;

    .line 136
    .line 137
    invoke-static {v13, v15, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v15, Lv3/j;->j:Lv3/h;

    .line 141
    .line 142
    iget-boolean v10, v4, Ll2/t;->S:Z

    .line 143
    .line 144
    if-nez v10, :cond_5

    .line 145
    .line 146
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v10

    .line 150
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 151
    .line 152
    .line 153
    move-result-object v11

    .line 154
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v10

    .line 158
    if-nez v10, :cond_6

    .line 159
    .line 160
    :cond_5
    invoke-static {v14, v4, v14, v15}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 161
    .line 162
    .line 163
    :cond_6
    sget-object v10, Lv3/j;->d:Lv3/h;

    .line 164
    .line 165
    invoke-static {v10, v8, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    invoke-static {v9, v12}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    sget-object v11, Lk1/j;->a:Lk1/c;

    .line 173
    .line 174
    sget-object v14, Lx2/c;->m:Lx2/i;

    .line 175
    .line 176
    const/4 v12, 0x0

    .line 177
    invoke-static {v11, v14, v4, v12}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 178
    .line 179
    .line 180
    move-result-object v11

    .line 181
    move-object v14, v13

    .line 182
    iget-wide v12, v4, Ll2/t;->T:J

    .line 183
    .line 184
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 185
    .line 186
    .line 187
    move-result v12

    .line 188
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 189
    .line 190
    .line 191
    move-result-object v13

    .line 192
    invoke-static {v4, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 193
    .line 194
    .line 195
    move-result-object v8

    .line 196
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 197
    .line 198
    .line 199
    move/from16 v26, v3

    .line 200
    .line 201
    iget-boolean v3, v4, Ll2/t;->S:Z

    .line 202
    .line 203
    if-eqz v3, :cond_7

    .line 204
    .line 205
    invoke-virtual {v4, v5}, Ll2/t;->l(Lay0/a;)V

    .line 206
    .line 207
    .line 208
    goto :goto_5

    .line 209
    :cond_7
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 210
    .line 211
    .line 212
    :goto_5
    invoke-static {v6, v11, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 213
    .line 214
    .line 215
    invoke-static {v14, v13, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 216
    .line 217
    .line 218
    iget-boolean v3, v4, Ll2/t;->S:Z

    .line 219
    .line 220
    if-nez v3, :cond_8

    .line 221
    .line 222
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 227
    .line 228
    .line 229
    move-result-object v5

    .line 230
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    move-result v3

    .line 234
    if-nez v3, :cond_9

    .line 235
    .line 236
    :cond_8
    invoke-static {v12, v4, v12, v15}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 237
    .line 238
    .line 239
    :cond_9
    invoke-static {v10, v8, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 240
    .line 241
    .line 242
    move-object/from16 v22, v4

    .line 243
    .line 244
    iget-object v4, v0, Lug/c;->a:Ljava/lang/String;

    .line 245
    .line 246
    sget-object v3, Lt3/d;->a:Lt3/o;

    .line 247
    .line 248
    new-instance v5, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    .line 249
    .line 250
    invoke-direct {v5, v3}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Lt3/a;)V

    .line 251
    .line 252
    .line 253
    new-instance v3, Ljava/lang/StringBuilder;

    .line 254
    .line 255
    const-string v6, "tariff_details_caption_"

    .line 256
    .line 257
    invoke-direct {v3, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 261
    .line 262
    .line 263
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 264
    .line 265
    .line 266
    move-result-object v3

    .line 267
    invoke-static {v5, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 268
    .line 269
    .line 270
    move-result-object v6

    .line 271
    invoke-static/range {v22 .. v22}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 272
    .line 273
    .line 274
    move-result-object v3

    .line 275
    invoke-virtual {v3}, Lj91/f;->b()Lg4/p0;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    invoke-static/range {v22 .. v22}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    invoke-virtual {v3}, Lj91/e;->q()J

    .line 284
    .line 285
    .line 286
    move-result-wide v10

    .line 287
    const/16 v24, 0x0

    .line 288
    .line 289
    const v25, 0xfff0

    .line 290
    .line 291
    .line 292
    move v14, v7

    .line 293
    move-object v12, v9

    .line 294
    move-wide v7, v10

    .line 295
    const-wide/16 v9, 0x0

    .line 296
    .line 297
    const/4 v11, 0x0

    .line 298
    move-object v3, v12

    .line 299
    const-wide/16 v12, 0x0

    .line 300
    .line 301
    move v15, v14

    .line 302
    const/4 v14, 0x0

    .line 303
    move/from16 v20, v15

    .line 304
    .line 305
    const/4 v15, 0x0

    .line 306
    const/16 v21, 0x4

    .line 307
    .line 308
    const/16 v23, 0x1

    .line 309
    .line 310
    const-wide/16 v16, 0x0

    .line 311
    .line 312
    const/16 v27, 0x0

    .line 313
    .line 314
    const/16 v18, 0x0

    .line 315
    .line 316
    const/high16 v28, 0x3f800000    # 1.0f

    .line 317
    .line 318
    const/16 v19, 0x0

    .line 319
    .line 320
    move/from16 v29, v20

    .line 321
    .line 322
    const/16 v20, 0x0

    .line 323
    .line 324
    move/from16 v30, v21

    .line 325
    .line 326
    const/16 v21, 0x0

    .line 327
    .line 328
    move/from16 v31, v23

    .line 329
    .line 330
    const/16 v23, 0x0

    .line 331
    .line 332
    move-object/from16 v27, v3

    .line 333
    .line 334
    move/from16 v3, v30

    .line 335
    .line 336
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 337
    .line 338
    .line 339
    move-object/from16 v4, v22

    .line 340
    .line 341
    iget-boolean v5, v0, Lug/c;->c:Z

    .line 342
    .line 343
    if-eqz v5, :cond_a

    .line 344
    .line 345
    const v5, 0x61fc96bc

    .line 346
    .line 347
    .line 348
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 349
    .line 350
    .line 351
    move-object/from16 v22, v4

    .line 352
    .line 353
    iget-object v4, v0, Lug/c;->b:Ljava/lang/String;

    .line 354
    .line 355
    int-to-float v13, v3

    .line 356
    const/16 v16, 0x0

    .line 357
    .line 358
    const/16 v17, 0xe

    .line 359
    .line 360
    const/4 v14, 0x0

    .line 361
    const/4 v15, 0x0

    .line 362
    move-object/from16 v12, v27

    .line 363
    .line 364
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 365
    .line 366
    .line 367
    move-result-object v3

    .line 368
    sget-object v5, Lt3/d;->a:Lt3/o;

    .line 369
    .line 370
    new-instance v6, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    .line 371
    .line 372
    invoke-direct {v6, v5}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Lt3/a;)V

    .line 373
    .line 374
    .line 375
    invoke-interface {v3, v6}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 376
    .line 377
    .line 378
    move-result-object v3

    .line 379
    new-instance v5, Ljava/lang/StringBuilder;

    .line 380
    .line 381
    const-string v6, "tariff_details_sub_caption_"

    .line 382
    .line 383
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 387
    .line 388
    .line 389
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 390
    .line 391
    .line 392
    move-result-object v5

    .line 393
    invoke-static {v3, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 394
    .line 395
    .line 396
    move-result-object v6

    .line 397
    invoke-static/range {v22 .. v22}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 398
    .line 399
    .line 400
    move-result-object v3

    .line 401
    invoke-virtual {v3}, Lj91/f;->b()Lg4/p0;

    .line 402
    .line 403
    .line 404
    move-result-object v5

    .line 405
    invoke-static/range {v22 .. v22}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 406
    .line 407
    .line 408
    move-result-object v3

    .line 409
    invoke-virtual {v3}, Lj91/e;->q()J

    .line 410
    .line 411
    .line 412
    move-result-wide v7

    .line 413
    const/16 v24, 0x0

    .line 414
    .line 415
    const v25, 0xfff0

    .line 416
    .line 417
    .line 418
    const-wide/16 v9, 0x0

    .line 419
    .line 420
    const/4 v11, 0x0

    .line 421
    const-wide/16 v12, 0x0

    .line 422
    .line 423
    const/4 v14, 0x0

    .line 424
    const/4 v15, 0x0

    .line 425
    const-wide/16 v16, 0x0

    .line 426
    .line 427
    const/16 v18, 0x0

    .line 428
    .line 429
    const/16 v19, 0x0

    .line 430
    .line 431
    const/16 v20, 0x0

    .line 432
    .line 433
    const/16 v21, 0x0

    .line 434
    .line 435
    const/16 v23, 0x0

    .line 436
    .line 437
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 438
    .line 439
    .line 440
    move-object/from16 v4, v22

    .line 441
    .line 442
    const/4 v3, 0x0

    .line 443
    :goto_6
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 444
    .line 445
    .line 446
    const/high16 v5, 0x3f800000    # 1.0f

    .line 447
    .line 448
    goto :goto_7

    .line 449
    :cond_a
    const/4 v3, 0x0

    .line 450
    const v5, 0x61b7a8f4

    .line 451
    .line 452
    .line 453
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 454
    .line 455
    .line 456
    goto :goto_6

    .line 457
    :goto_7
    float-to-double v6, v5

    .line 458
    const-wide/16 v8, 0x0

    .line 459
    .line 460
    cmpl-double v6, v6, v8

    .line 461
    .line 462
    if-lez v6, :cond_b

    .line 463
    .line 464
    goto :goto_8

    .line 465
    :cond_b
    const-string v6, "invalid weight; must be greater than zero"

    .line 466
    .line 467
    invoke-static {v6}, Ll1/a;->a(Ljava/lang/String;)V

    .line 468
    .line 469
    .line 470
    :goto_8
    new-instance v6, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 471
    .line 472
    const v12, 0x7f7fffff    # Float.MAX_VALUE

    .line 473
    .line 474
    .line 475
    cmpl-float v7, v5, v12

    .line 476
    .line 477
    if-lez v7, :cond_c

    .line 478
    .line 479
    :goto_9
    const/4 v5, 0x1

    .line 480
    goto :goto_a

    .line 481
    :cond_c
    move v12, v5

    .line 482
    goto :goto_9

    .line 483
    :goto_a
    invoke-direct {v6, v12, v5}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 484
    .line 485
    .line 486
    invoke-static {v4, v6}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 487
    .line 488
    .line 489
    move-object/from16 v22, v4

    .line 490
    .line 491
    iget-object v4, v0, Lug/c;->d:Ljava/lang/String;

    .line 492
    .line 493
    const/16 v6, 0x8

    .line 494
    .line 495
    int-to-float v13, v6

    .line 496
    const/16 v16, 0x0

    .line 497
    .line 498
    const/16 v17, 0xe

    .line 499
    .line 500
    const/4 v14, 0x0

    .line 501
    const/4 v15, 0x0

    .line 502
    move-object/from16 v12, v27

    .line 503
    .line 504
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 505
    .line 506
    .line 507
    move-result-object v6

    .line 508
    sget-object v7, Lt3/d;->a:Lt3/o;

    .line 509
    .line 510
    new-instance v8, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    .line 511
    .line 512
    invoke-direct {v8, v7}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Lt3/a;)V

    .line 513
    .line 514
    .line 515
    invoke-interface {v6, v8}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 516
    .line 517
    .line 518
    move-result-object v6

    .line 519
    new-instance v7, Ljava/lang/StringBuilder;

    .line 520
    .line 521
    const-string v8, "tariff_details_value_"

    .line 522
    .line 523
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 527
    .line 528
    .line 529
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 530
    .line 531
    .line 532
    move-result-object v7

    .line 533
    invoke-static {v6, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 534
    .line 535
    .line 536
    move-result-object v6

    .line 537
    invoke-static/range {v22 .. v22}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 538
    .line 539
    .line 540
    move-result-object v7

    .line 541
    invoke-virtual {v7}, Lj91/f;->a()Lg4/p0;

    .line 542
    .line 543
    .line 544
    move-result-object v7

    .line 545
    invoke-static/range {v22 .. v22}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 546
    .line 547
    .line 548
    move-result-object v8

    .line 549
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 550
    .line 551
    .line 552
    move-result-wide v8

    .line 553
    const/16 v24, 0x0

    .line 554
    .line 555
    const v25, 0xfff0

    .line 556
    .line 557
    .line 558
    move/from16 v31, v5

    .line 559
    .line 560
    move-object v5, v7

    .line 561
    move-wide v7, v8

    .line 562
    const-wide/16 v9, 0x0

    .line 563
    .line 564
    const/4 v11, 0x0

    .line 565
    const-wide/16 v12, 0x0

    .line 566
    .line 567
    const/4 v14, 0x0

    .line 568
    const/4 v15, 0x0

    .line 569
    const-wide/16 v16, 0x0

    .line 570
    .line 571
    const/16 v18, 0x0

    .line 572
    .line 573
    const/16 v19, 0x0

    .line 574
    .line 575
    const/16 v20, 0x0

    .line 576
    .line 577
    const/16 v21, 0x0

    .line 578
    .line 579
    const/16 v23, 0x0

    .line 580
    .line 581
    move/from16 v3, v31

    .line 582
    .line 583
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 584
    .line 585
    .line 586
    move-object/from16 v4, v22

    .line 587
    .line 588
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 589
    .line 590
    .line 591
    if-eqz v26, :cond_d

    .line 592
    .line 593
    const v5, 0x7ec22765

    .line 594
    .line 595
    .line 596
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 597
    .line 598
    .line 599
    move-object/from16 v22, v4

    .line 600
    .line 601
    iget-object v4, v0, Lug/c;->e:Ljava/lang/String;

    .line 602
    .line 603
    const/16 v16, 0x0

    .line 604
    .line 605
    const/16 v17, 0xd

    .line 606
    .line 607
    const/4 v13, 0x0

    .line 608
    const/4 v15, 0x0

    .line 609
    move-object/from16 v12, v27

    .line 610
    .line 611
    move/from16 v14, v29

    .line 612
    .line 613
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 614
    .line 615
    .line 616
    move-result-object v5

    .line 617
    const-string v6, "tariff_details_description"

    .line 618
    .line 619
    invoke-static {v5, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 620
    .line 621
    .line 622
    move-result-object v6

    .line 623
    invoke-static/range {v22 .. v22}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 624
    .line 625
    .line 626
    move-result-object v5

    .line 627
    invoke-virtual {v5}, Lj91/f;->e()Lg4/p0;

    .line 628
    .line 629
    .line 630
    move-result-object v5

    .line 631
    invoke-static/range {v22 .. v22}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 632
    .line 633
    .line 634
    move-result-object v7

    .line 635
    invoke-virtual {v7}, Lj91/e;->s()J

    .line 636
    .line 637
    .line 638
    move-result-wide v7

    .line 639
    const/16 v24, 0x0

    .line 640
    .line 641
    const v25, 0xfff0

    .line 642
    .line 643
    .line 644
    const-wide/16 v9, 0x0

    .line 645
    .line 646
    const/4 v11, 0x0

    .line 647
    const-wide/16 v12, 0x0

    .line 648
    .line 649
    const/4 v14, 0x0

    .line 650
    const/4 v15, 0x0

    .line 651
    const-wide/16 v16, 0x0

    .line 652
    .line 653
    const/16 v18, 0x0

    .line 654
    .line 655
    const/16 v19, 0x0

    .line 656
    .line 657
    const/16 v20, 0x0

    .line 658
    .line 659
    const/16 v21, 0x0

    .line 660
    .line 661
    const/16 v23, 0x0

    .line 662
    .line 663
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 664
    .line 665
    .line 666
    move-object/from16 v4, v22

    .line 667
    .line 668
    const/4 v12, 0x0

    .line 669
    :goto_b
    invoke-virtual {v4, v12}, Ll2/t;->q(Z)V

    .line 670
    .line 671
    .line 672
    goto :goto_c

    .line 673
    :cond_d
    const/4 v12, 0x0

    .line 674
    const v5, 0x7e6f92f8

    .line 675
    .line 676
    .line 677
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 678
    .line 679
    .line 680
    goto :goto_b

    .line 681
    :goto_c
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 682
    .line 683
    .line 684
    goto :goto_d

    .line 685
    :cond_e
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 686
    .line 687
    .line 688
    :goto_d
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 689
    .line 690
    .line 691
    move-result-object v3

    .line 692
    if-eqz v3, :cond_f

    .line 693
    .line 694
    new-instance v4, Ld90/h;

    .line 695
    .line 696
    const/16 v5, 0xe

    .line 697
    .line 698
    invoke-direct {v4, v0, v1, v2, v5}, Ld90/h;-><init>(Ljava/lang/Object;III)V

    .line 699
    .line 700
    .line 701
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 702
    .line 703
    :cond_f
    return-void
.end method

.method public static final b(Lug/d;ILjava/lang/String;FLl2/o;I)V
    .locals 32

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move/from16 v4, p3

    .line 8
    .line 9
    move/from16 v5, p5

    .line 10
    .line 11
    const-string v0, "conditionGroup"

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, v1, Lug/d;->b:Ljava/util/ArrayList;

    .line 17
    .line 18
    move-object/from16 v6, p4

    .line 19
    .line 20
    check-cast v6, Ll2/t;

    .line 21
    .line 22
    const v7, 0xaa945b

    .line 23
    .line 24
    .line 25
    invoke-virtual {v6, v7}, Ll2/t;->a0(I)Ll2/t;

    .line 26
    .line 27
    .line 28
    and-int/lit8 v7, v5, 0x6

    .line 29
    .line 30
    if-nez v7, :cond_2

    .line 31
    .line 32
    and-int/lit8 v7, v5, 0x8

    .line 33
    .line 34
    if-nez v7, :cond_0

    .line 35
    .line 36
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    :goto_0
    if-eqz v7, :cond_1

    .line 46
    .line 47
    const/4 v7, 0x4

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    const/4 v7, 0x2

    .line 50
    :goto_1
    or-int/2addr v7, v5

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v7, v5

    .line 53
    :goto_2
    and-int/lit8 v8, v5, 0x30

    .line 54
    .line 55
    const/16 v9, 0x10

    .line 56
    .line 57
    if-nez v8, :cond_4

    .line 58
    .line 59
    invoke-virtual {v6, v2}, Ll2/t;->e(I)Z

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    if-eqz v8, :cond_3

    .line 64
    .line 65
    const/16 v8, 0x20

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    move v8, v9

    .line 69
    :goto_3
    or-int/2addr v7, v8

    .line 70
    :cond_4
    and-int/lit16 v8, v5, 0x180

    .line 71
    .line 72
    if-nez v8, :cond_6

    .line 73
    .line 74
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v8

    .line 78
    if-eqz v8, :cond_5

    .line 79
    .line 80
    const/16 v8, 0x100

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    const/16 v8, 0x80

    .line 84
    .line 85
    :goto_4
    or-int/2addr v7, v8

    .line 86
    :cond_6
    and-int/lit16 v8, v5, 0xc00

    .line 87
    .line 88
    if-nez v8, :cond_8

    .line 89
    .line 90
    invoke-virtual {v6, v4}, Ll2/t;->d(F)Z

    .line 91
    .line 92
    .line 93
    move-result v8

    .line 94
    if-eqz v8, :cond_7

    .line 95
    .line 96
    const/16 v8, 0x800

    .line 97
    .line 98
    goto :goto_5

    .line 99
    :cond_7
    const/16 v8, 0x400

    .line 100
    .line 101
    :goto_5
    or-int/2addr v7, v8

    .line 102
    :cond_8
    and-int/lit16 v8, v7, 0x493

    .line 103
    .line 104
    const/16 v10, 0x492

    .line 105
    .line 106
    const/4 v11, 0x1

    .line 107
    const/4 v12, 0x0

    .line 108
    if-eq v8, v10, :cond_9

    .line 109
    .line 110
    move v8, v11

    .line 111
    goto :goto_6

    .line 112
    :cond_9
    move v8, v12

    .line 113
    :goto_6
    and-int/2addr v7, v11

    .line 114
    invoke-virtual {v6, v7, v8}, Ll2/t;->O(IZ)Z

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    if-eqz v7, :cond_11

    .line 119
    .line 120
    const/high16 v7, 0x3f800000    # 1.0f

    .line 121
    .line 122
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 123
    .line 124
    invoke-static {v8, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 125
    .line 126
    .line 127
    move-result-object v7

    .line 128
    new-instance v10, Ljava/lang/StringBuilder;

    .line 129
    .line 130
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string v13, "conditions_group_"

    .line 137
    .line 138
    invoke-virtual {v10, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v10, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v10

    .line 148
    invoke-static {v7, v10}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    sget-object v10, Lk1/j;->c:Lk1/e;

    .line 153
    .line 154
    sget-object v13, Lx2/c;->p:Lx2/h;

    .line 155
    .line 156
    invoke-static {v10, v13, v6, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 157
    .line 158
    .line 159
    move-result-object v10

    .line 160
    iget-wide v13, v6, Ll2/t;->T:J

    .line 161
    .line 162
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 163
    .line 164
    .line 165
    move-result v13

    .line 166
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 167
    .line 168
    .line 169
    move-result-object v14

    .line 170
    invoke-static {v6, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 171
    .line 172
    .line 173
    move-result-object v7

    .line 174
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 175
    .line 176
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 180
    .line 181
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 182
    .line 183
    .line 184
    iget-boolean v11, v6, Ll2/t;->S:Z

    .line 185
    .line 186
    if-eqz v11, :cond_a

    .line 187
    .line 188
    invoke-virtual {v6, v15}, Ll2/t;->l(Lay0/a;)V

    .line 189
    .line 190
    .line 191
    goto :goto_7

    .line 192
    :cond_a
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 193
    .line 194
    .line 195
    :goto_7
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 196
    .line 197
    invoke-static {v11, v10, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 201
    .line 202
    invoke-static {v10, v14, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 203
    .line 204
    .line 205
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 206
    .line 207
    iget-boolean v11, v6, Ll2/t;->S:Z

    .line 208
    .line 209
    if-nez v11, :cond_b

    .line 210
    .line 211
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v11

    .line 215
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 216
    .line 217
    .line 218
    move-result-object v14

    .line 219
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v11

    .line 223
    if-nez v11, :cond_c

    .line 224
    .line 225
    :cond_b
    invoke-static {v13, v6, v13, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 226
    .line 227
    .line 228
    :cond_c
    sget-object v10, Lv3/j;->d:Lv3/h;

    .line 229
    .line 230
    invoke-static {v10, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 231
    .line 232
    .line 233
    iget-boolean v7, v1, Lug/d;->c:Z

    .line 234
    .line 235
    if-eqz v7, :cond_d

    .line 236
    .line 237
    const v7, 0x7a77e741

    .line 238
    .line 239
    .line 240
    invoke-virtual {v6, v7}, Ll2/t;->Y(I)V

    .line 241
    .line 242
    .line 243
    iget-object v7, v1, Lug/d;->a:Ljava/lang/String;

    .line 244
    .line 245
    int-to-float v10, v9

    .line 246
    const/16 v11, 0x14

    .line 247
    .line 248
    int-to-float v11, v11

    .line 249
    invoke-static {v8, v10, v4, v10, v11}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 250
    .line 251
    .line 252
    move-result-object v10

    .line 253
    const-string v11, "tariff_details_title"

    .line 254
    .line 255
    invoke-static {v10, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v10

    .line 259
    sget-object v11, Lj91/j;->a:Ll2/u2;

    .line 260
    .line 261
    invoke-virtual {v6, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v11

    .line 265
    check-cast v11, Lj91/f;

    .line 266
    .line 267
    invoke-virtual {v11}, Lj91/f;->k()Lg4/p0;

    .line 268
    .line 269
    .line 270
    move-result-object v11

    .line 271
    const/16 v26, 0x0

    .line 272
    .line 273
    const v27, 0xfff8

    .line 274
    .line 275
    .line 276
    move-object v13, v8

    .line 277
    move v14, v9

    .line 278
    move-object v8, v10

    .line 279
    const-wide/16 v9, 0x0

    .line 280
    .line 281
    move-object/from16 v24, v6

    .line 282
    .line 283
    move-object v6, v7

    .line 284
    move-object v7, v11

    .line 285
    move v15, v12

    .line 286
    const-wide/16 v11, 0x0

    .line 287
    .line 288
    move-object/from16 v16, v13

    .line 289
    .line 290
    const/4 v13, 0x0

    .line 291
    move/from16 v17, v14

    .line 292
    .line 293
    move/from16 v18, v15

    .line 294
    .line 295
    const-wide/16 v14, 0x0

    .line 296
    .line 297
    move-object/from16 v19, v16

    .line 298
    .line 299
    const/16 v16, 0x0

    .line 300
    .line 301
    move/from16 v20, v17

    .line 302
    .line 303
    const/16 v17, 0x0

    .line 304
    .line 305
    move/from16 v22, v18

    .line 306
    .line 307
    move-object/from16 v21, v19

    .line 308
    .line 309
    const-wide/16 v18, 0x0

    .line 310
    .line 311
    move/from16 v23, v20

    .line 312
    .line 313
    const/16 v20, 0x0

    .line 314
    .line 315
    move-object/from16 v25, v21

    .line 316
    .line 317
    const/16 v21, 0x0

    .line 318
    .line 319
    move/from16 v28, v22

    .line 320
    .line 321
    const/16 v22, 0x0

    .line 322
    .line 323
    move/from16 v29, v23

    .line 324
    .line 325
    const/16 v23, 0x0

    .line 326
    .line 327
    move-object/from16 v30, v25

    .line 328
    .line 329
    const/16 v25, 0x0

    .line 330
    .line 331
    move-object/from16 v31, v0

    .line 332
    .line 333
    move/from16 v0, v28

    .line 334
    .line 335
    move/from16 v2, v29

    .line 336
    .line 337
    move-object/from16 v1, v30

    .line 338
    .line 339
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 340
    .line 341
    .line 342
    move-object/from16 v6, v24

    .line 343
    .line 344
    :goto_8
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 345
    .line 346
    .line 347
    goto :goto_9

    .line 348
    :cond_d
    move-object/from16 v31, v0

    .line 349
    .line 350
    move-object v1, v8

    .line 351
    move v2, v9

    .line 352
    move v0, v12

    .line 353
    const v7, 0x7a4cbc3d

    .line 354
    .line 355
    .line 356
    invoke-virtual {v6, v7}, Ll2/t;->Y(I)V

    .line 357
    .line 358
    .line 359
    goto :goto_8

    .line 360
    :goto_9
    const v7, -0x4ea11de2

    .line 361
    .line 362
    .line 363
    invoke-virtual {v6, v7}, Ll2/t;->Y(I)V

    .line 364
    .line 365
    .line 366
    invoke-interface/range {v31 .. v31}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 367
    .line 368
    .line 369
    move-result-object v7

    .line 370
    move v12, v0

    .line 371
    :goto_a
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 372
    .line 373
    .line 374
    move-result v8

    .line 375
    if-eqz v8, :cond_10

    .line 376
    .line 377
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v8

    .line 381
    add-int/lit8 v9, v12, 0x1

    .line 382
    .line 383
    if-ltz v12, :cond_f

    .line 384
    .line 385
    check-cast v8, Lug/c;

    .line 386
    .line 387
    invoke-static {v8, v12, v6, v0}, Lkp/d8;->a(Lug/c;ILl2/o;I)V

    .line 388
    .line 389
    .line 390
    invoke-static/range {v31 .. v31}, Ljp/k1;->h(Ljava/util/List;)I

    .line 391
    .line 392
    .line 393
    move-result v8

    .line 394
    if-eq v12, v8, :cond_e

    .line 395
    .line 396
    const v8, 0x748096d6

    .line 397
    .line 398
    .line 399
    invoke-virtual {v6, v8}, Ll2/t;->Y(I)V

    .line 400
    .line 401
    .line 402
    const/16 v8, 0x8

    .line 403
    .line 404
    int-to-float v8, v8

    .line 405
    int-to-float v10, v2

    .line 406
    invoke-static {v1, v10, v8}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 407
    .line 408
    .line 409
    move-result-object v8

    .line 410
    invoke-static {v0, v0, v6, v8}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 411
    .line 412
    .line 413
    :goto_b
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 414
    .line 415
    .line 416
    goto :goto_c

    .line 417
    :cond_e
    const v8, 0x744cc7cd

    .line 418
    .line 419
    .line 420
    invoke-virtual {v6, v8}, Ll2/t;->Y(I)V

    .line 421
    .line 422
    .line 423
    goto :goto_b

    .line 424
    :goto_c
    move v12, v9

    .line 425
    goto :goto_a

    .line 426
    :cond_f
    invoke-static {}, Ljp/k1;->r()V

    .line 427
    .line 428
    .line 429
    const/4 v0, 0x0

    .line 430
    throw v0

    .line 431
    :cond_10
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 432
    .line 433
    .line 434
    const/4 v0, 0x1

    .line 435
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 436
    .line 437
    .line 438
    goto :goto_d

    .line 439
    :cond_11
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 440
    .line 441
    .line 442
    :goto_d
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 443
    .line 444
    .line 445
    move-result-object v6

    .line 446
    if-eqz v6, :cond_12

    .line 447
    .line 448
    new-instance v0, Li91/g0;

    .line 449
    .line 450
    move-object/from16 v1, p0

    .line 451
    .line 452
    move/from16 v2, p1

    .line 453
    .line 454
    invoke-direct/range {v0 .. v5}, Li91/g0;-><init>(Lug/d;ILjava/lang/String;FI)V

    .line 455
    .line 456
    .line 457
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 458
    .line 459
    :cond_12
    return-void
.end method

.method public static varargs c(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 7

    .line 1
    array-length v0, p1

    .line 2
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    mul-int/lit8 v0, v0, 0x10

    .line 7
    .line 8
    new-instance v2, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    add-int/2addr v1, v0

    .line 11
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    move v1, v0

    .line 16
    :goto_0
    array-length v3, p1

    .line 17
    if-ge v0, v3, :cond_1

    .line 18
    .line 19
    const-string v4, "%s"

    .line 20
    .line 21
    invoke-virtual {p0, v4, v1}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    const/4 v5, -0x1

    .line 26
    if-ne v4, v5, :cond_0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    invoke-virtual {v2, p0, v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    add-int/lit8 v1, v0, 0x1

    .line 33
    .line 34
    aget-object v0, p1, v0

    .line 35
    .line 36
    invoke-static {v0}, Lkp/d8;->d(Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    add-int/lit8 v0, v4, 0x2

    .line 44
    .line 45
    move v6, v1

    .line 46
    move v1, v0

    .line 47
    move v0, v6

    .line 48
    goto :goto_0

    .line 49
    :cond_1
    :goto_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    invoke-virtual {v2, p0, v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    if-ge v0, v3, :cond_3

    .line 57
    .line 58
    const-string p0, " ["

    .line 59
    .line 60
    :goto_2
    array-length v1, p1

    .line 61
    if-ge v0, v1, :cond_2

    .line 62
    .line 63
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    aget-object p0, p1, v0

    .line 67
    .line 68
    invoke-static {p0}, Lkp/d8;->d(Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    add-int/lit8 v0, v0, 0x1

    .line 76
    .line 77
    const-string p0, ", "

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_2
    const/16 p0, 0x5d

    .line 81
    .line 82
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    :cond_3
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0
.end method

.method public static d(Ljava/lang/Object;)Ljava/lang/String;
    .locals 6

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "null"

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    return-object p0

    .line 11
    :catch_0
    move-exception v0

    .line 12
    move-object v5, v0

    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    add-int/lit8 v1, v1, 0x1

    .line 38
    .line 39
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    new-instance v3, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    add-int/2addr v1, v2

    .line 46
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 47
    .line 48
    .line 49
    const-string v1, "@"

    .line 50
    .line 51
    invoke-static {v3, v0, v1, p0}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    const-string v0, "com.google.common.base.Strings"

    .line 56
    .line 57
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 62
    .line 63
    const-string v3, "lenientToString"

    .line 64
    .line 65
    const-string v2, "Exception during lenientFormat for "

    .line 66
    .line 67
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    const-string v2, "com.google.common.base.Strings"

    .line 72
    .line 73
    invoke-virtual/range {v0 .. v5}, Ljava/util/logging/Logger;->logp(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    add-int/lit8 v1, v1, 0x8

    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    new-instance v3, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    add-int/2addr v1, v2

    .line 97
    add-int/lit8 v1, v1, 0x1

    .line 98
    .line 99
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 100
    .line 101
    .line 102
    const-string v1, "<"

    .line 103
    .line 104
    const-string v2, " threw "

    .line 105
    .line 106
    invoke-static {v3, v1, p0, v2, v0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    const-string p0, ">"

    .line 110
    .line 111
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0
.end method
