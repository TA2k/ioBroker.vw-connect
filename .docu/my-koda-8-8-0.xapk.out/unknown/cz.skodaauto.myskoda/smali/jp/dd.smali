.class public abstract Ljp/dd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ILay0/k;Ll2/o;Lx31/o;Lz70/b;)V
    .locals 39

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move-object/from16 v0, p3

    .line 6
    .line 7
    move-object/from16 v8, p4

    .line 8
    .line 9
    sget-object v9, Lx2/c;->p:Lx2/h;

    .line 10
    .line 11
    const-string v2, "viewState"

    .line 12
    .line 13
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v2, "onEvent"

    .line 17
    .line 18
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    move-object/from16 v13, p2

    .line 22
    .line 23
    check-cast v13, Ll2/t;

    .line 24
    .line 25
    const v2, 0x6469efe5

    .line 26
    .line 27
    .line 28
    invoke-virtual {v13, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 29
    .line 30
    .line 31
    and-int/lit8 v2, v1, 0x6

    .line 32
    .line 33
    if-nez v2, :cond_2

    .line 34
    .line 35
    and-int/lit8 v2, v1, 0x8

    .line 36
    .line 37
    if-nez v2, :cond_0

    .line 38
    .line 39
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    :goto_0
    if-eqz v2, :cond_1

    .line 49
    .line 50
    const/4 v2, 0x4

    .line 51
    goto :goto_1

    .line 52
    :cond_1
    const/4 v2, 0x2

    .line 53
    :goto_1
    or-int/2addr v2, v1

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move v2, v1

    .line 56
    :goto_2
    and-int/lit8 v4, v1, 0x30

    .line 57
    .line 58
    if-nez v4, :cond_4

    .line 59
    .line 60
    invoke-virtual {v13, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_3

    .line 65
    .line 66
    const/16 v4, 0x20

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    const/16 v4, 0x10

    .line 70
    .line 71
    :goto_3
    or-int/2addr v2, v4

    .line 72
    :cond_4
    and-int/lit16 v4, v1, 0x180

    .line 73
    .line 74
    if-nez v4, :cond_6

    .line 75
    .line 76
    invoke-virtual {v13, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eqz v4, :cond_5

    .line 81
    .line 82
    const/16 v4, 0x100

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_5
    const/16 v4, 0x80

    .line 86
    .line 87
    :goto_4
    or-int/2addr v2, v4

    .line 88
    :cond_6
    and-int/lit16 v4, v2, 0x93

    .line 89
    .line 90
    const/16 v6, 0x92

    .line 91
    .line 92
    const/4 v7, 0x1

    .line 93
    const/4 v10, 0x0

    .line 94
    if-eq v4, v6, :cond_7

    .line 95
    .line 96
    move v4, v7

    .line 97
    goto :goto_5

    .line 98
    :cond_7
    move v4, v10

    .line 99
    :goto_5
    and-int/lit8 v6, v2, 0x1

    .line 100
    .line 101
    invoke-virtual {v13, v6, v4}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-eqz v4, :cond_1e

    .line 106
    .line 107
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 108
    .line 109
    invoke-static {v10, v7, v13}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    const/16 v11, 0xe

    .line 114
    .line 115
    invoke-static {v4, v6, v11}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 120
    .line 121
    invoke-static {v6, v9, v13, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 122
    .line 123
    .line 124
    move-result-object v6

    .line 125
    iget-wide v11, v13, Ll2/t;->T:J

    .line 126
    .line 127
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 128
    .line 129
    .line 130
    move-result v11

    .line 131
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 132
    .line 133
    .line 134
    move-result-object v12

    .line 135
    invoke-static {v13, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 140
    .line 141
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 145
    .line 146
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 147
    .line 148
    .line 149
    iget-boolean v15, v13, Ll2/t;->S:Z

    .line 150
    .line 151
    if-eqz v15, :cond_8

    .line 152
    .line 153
    invoke-virtual {v13, v14}, Ll2/t;->l(Lay0/a;)V

    .line 154
    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_8
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 158
    .line 159
    .line 160
    :goto_6
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 161
    .line 162
    invoke-static {v14, v6, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 163
    .line 164
    .line 165
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 166
    .line 167
    invoke-static {v6, v12, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 168
    .line 169
    .line 170
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 171
    .line 172
    iget-boolean v12, v13, Ll2/t;->S:Z

    .line 173
    .line 174
    if-nez v12, :cond_9

    .line 175
    .line 176
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v12

    .line 180
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object v14

    .line 184
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v12

    .line 188
    if-nez v12, :cond_a

    .line 189
    .line 190
    :cond_9
    invoke-static {v11, v13, v11, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 191
    .line 192
    .line 193
    :cond_a
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 194
    .line 195
    invoke-static {v6, v4, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 196
    .line 197
    .line 198
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 199
    .line 200
    invoke-virtual {v13, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    check-cast v4, Lj91/c;

    .line 205
    .line 206
    iget v4, v4, Lj91/c;->d:F

    .line 207
    .line 208
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 209
    .line 210
    invoke-static {v14, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    const/high16 v6, 0x3f800000    # 1.0f

    .line 215
    .line 216
    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 217
    .line 218
    .line 219
    move-result-object v4

    .line 220
    invoke-static {v13, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 221
    .line 222
    .line 223
    const v4, 0x3ad5bcd9

    .line 224
    .line 225
    .line 226
    invoke-virtual {v13, v4}, Ll2/t;->Y(I)V

    .line 227
    .line 228
    .line 229
    iget-object v4, v0, Lx31/o;->e:Ljava/util/List;

    .line 230
    .line 231
    const v11, 0x3ad5c777

    .line 232
    .line 233
    .line 234
    invoke-virtual {v13, v11}, Ll2/t;->Y(I)V

    .line 235
    .line 236
    .line 237
    move-object v11, v4

    .line 238
    check-cast v11, Ljava/lang/Iterable;

    .line 239
    .line 240
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 241
    .line 242
    .line 243
    move-result-object v32

    .line 244
    move v11, v10

    .line 245
    move v12, v11

    .line 246
    :goto_7
    invoke-interface/range {v32 .. v32}, Ljava/util/Iterator;->hasNext()Z

    .line 247
    .line 248
    .line 249
    move-result v15

    .line 250
    if-eqz v15, :cond_1d

    .line 251
    .line 252
    invoke-interface/range {v32 .. v32}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v15

    .line 256
    add-int/lit8 v33, v11, 0x1

    .line 257
    .line 258
    if-ltz v11, :cond_1c

    .line 259
    .line 260
    check-cast v15, Li31/d;

    .line 261
    .line 262
    if-lez v11, :cond_b

    .line 263
    .line 264
    add-int/lit8 v11, v11, -0x1

    .line 265
    .line 266
    invoke-interface {v4, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v11

    .line 270
    check-cast v11, Li31/d;

    .line 271
    .line 272
    iget-object v11, v11, Li31/d;->c:Ljava/util/List;

    .line 273
    .line 274
    invoke-interface {v11}, Ljava/util/List;->size()I

    .line 275
    .line 276
    .line 277
    move-result v11

    .line 278
    add-int/2addr v11, v12

    .line 279
    move/from16 v34, v11

    .line 280
    .line 281
    goto :goto_8

    .line 282
    :cond_b
    move/from16 v34, v10

    .line 283
    .line 284
    :goto_8
    sget-object v11, Lj91/a;->a:Ll2/u2;

    .line 285
    .line 286
    invoke-virtual {v13, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v11

    .line 290
    check-cast v11, Lj91/c;

    .line 291
    .line 292
    iget v11, v11, Lj91/c;->c:F

    .line 293
    .line 294
    const/16 v19, 0x7

    .line 295
    .line 296
    move-object v12, v15

    .line 297
    const/4 v15, 0x0

    .line 298
    const/16 v16, 0x0

    .line 299
    .line 300
    const/16 v17, 0x0

    .line 301
    .line 302
    move/from16 v18, v11

    .line 303
    .line 304
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 305
    .line 306
    .line 307
    move-result-object v11

    .line 308
    move v15, v10

    .line 309
    iget-object v10, v12, Li31/d;->b:Ljava/lang/String;

    .line 310
    .line 311
    iget-object v12, v12, Li31/d;->c:Ljava/util/List;

    .line 312
    .line 313
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 314
    .line 315
    invoke-virtual {v13, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v7

    .line 319
    check-cast v7, Lj91/f;

    .line 320
    .line 321
    invoke-virtual {v7}, Lj91/f;->k()Lg4/p0;

    .line 322
    .line 323
    .line 324
    move-result-object v7

    .line 325
    new-instance v15, Lr4/k;

    .line 326
    .line 327
    const/4 v5, 0x5

    .line 328
    invoke-direct {v15, v5}, Lr4/k;-><init>(I)V

    .line 329
    .line 330
    .line 331
    const/16 v30, 0x0

    .line 332
    .line 333
    const v31, 0xfbf8

    .line 334
    .line 335
    .line 336
    move-object/from16 v28, v13

    .line 337
    .line 338
    move-object v5, v14

    .line 339
    const-wide/16 v13, 0x0

    .line 340
    .line 341
    move-object/from16 v21, v15

    .line 342
    .line 343
    const/16 v17, 0x0

    .line 344
    .line 345
    const-wide/16 v15, 0x0

    .line 346
    .line 347
    move/from16 v18, v17

    .line 348
    .line 349
    const/16 v17, 0x0

    .line 350
    .line 351
    move/from16 v20, v18

    .line 352
    .line 353
    const-wide/16 v18, 0x0

    .line 354
    .line 355
    move/from16 v22, v20

    .line 356
    .line 357
    const/16 v20, 0x0

    .line 358
    .line 359
    move/from16 v24, v22

    .line 360
    .line 361
    const-wide/16 v22, 0x0

    .line 362
    .line 363
    move/from16 v25, v24

    .line 364
    .line 365
    const/16 v24, 0x0

    .line 366
    .line 367
    move/from16 v26, v25

    .line 368
    .line 369
    const/16 v25, 0x0

    .line 370
    .line 371
    move/from16 v27, v26

    .line 372
    .line 373
    const/16 v26, 0x0

    .line 374
    .line 375
    move/from16 v29, v27

    .line 376
    .line 377
    const/16 v27, 0x0

    .line 378
    .line 379
    move/from16 v36, v29

    .line 380
    .line 381
    const/16 v29, 0x0

    .line 382
    .line 383
    move-object/from16 v38, v7

    .line 384
    .line 385
    move-object v7, v5

    .line 386
    move/from16 v5, v36

    .line 387
    .line 388
    move-object/from16 v36, v12

    .line 389
    .line 390
    move-object v12, v11

    .line 391
    move-object/from16 v11, v38

    .line 392
    .line 393
    invoke-static/range {v10 .. v31}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 394
    .line 395
    .line 396
    move-object/from16 v13, v28

    .line 397
    .line 398
    invoke-static {v7, v6}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 399
    .line 400
    .line 401
    move-result-object v10

    .line 402
    sget-object v11, Lk1/j;->c:Lk1/e;

    .line 403
    .line 404
    invoke-static {v11, v9, v13, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 405
    .line 406
    .line 407
    move-result-object v11

    .line 408
    iget-wide v14, v13, Ll2/t;->T:J

    .line 409
    .line 410
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 411
    .line 412
    .line 413
    move-result v12

    .line 414
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 415
    .line 416
    .line 417
    move-result-object v14

    .line 418
    invoke-static {v13, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 419
    .line 420
    .line 421
    move-result-object v10

    .line 422
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 423
    .line 424
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 425
    .line 426
    .line 427
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 428
    .line 429
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 430
    .line 431
    .line 432
    iget-boolean v6, v13, Ll2/t;->S:Z

    .line 433
    .line 434
    if-eqz v6, :cond_c

    .line 435
    .line 436
    invoke-virtual {v13, v15}, Ll2/t;->l(Lay0/a;)V

    .line 437
    .line 438
    .line 439
    goto :goto_9

    .line 440
    :cond_c
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 441
    .line 442
    .line 443
    :goto_9
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 444
    .line 445
    invoke-static {v6, v11, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 446
    .line 447
    .line 448
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 449
    .line 450
    invoke-static {v6, v14, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 451
    .line 452
    .line 453
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 454
    .line 455
    iget-boolean v11, v13, Ll2/t;->S:Z

    .line 456
    .line 457
    if-nez v11, :cond_d

    .line 458
    .line 459
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v11

    .line 463
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 464
    .line 465
    .line 466
    move-result-object v14

    .line 467
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result v11

    .line 471
    if-nez v11, :cond_e

    .line 472
    .line 473
    :cond_d
    invoke-static {v12, v13, v12, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 474
    .line 475
    .line 476
    :cond_e
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 477
    .line 478
    invoke-static {v6, v10, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 479
    .line 480
    .line 481
    const v6, 0x71e287c2

    .line 482
    .line 483
    .line 484
    invoke-virtual {v13, v6}, Ll2/t;->Y(I)V

    .line 485
    .line 486
    .line 487
    move-object/from16 v12, v36

    .line 488
    .line 489
    check-cast v12, Ljava/lang/Iterable;

    .line 490
    .line 491
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 492
    .line 493
    .line 494
    move-result-object v17

    .line 495
    move v10, v5

    .line 496
    :goto_a
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->hasNext()Z

    .line 497
    .line 498
    .line 499
    move-result v6

    .line 500
    if-eqz v6, :cond_1b

    .line 501
    .line 502
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v6

    .line 506
    add-int/lit8 v18, v10, 0x1

    .line 507
    .line 508
    if-ltz v10, :cond_1a

    .line 509
    .line 510
    check-cast v6, Li31/e;

    .line 511
    .line 512
    add-int v11, v34, v10

    .line 513
    .line 514
    iget-object v12, v0, Lx31/o;->i:Ljava/util/List;

    .line 515
    .line 516
    invoke-static {v11, v12}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v12

    .line 520
    check-cast v12, Lp31/f;

    .line 521
    .line 522
    if-eqz v12, :cond_19

    .line 523
    .line 524
    const v15, 0x11f8121c

    .line 525
    .line 526
    .line 527
    invoke-virtual {v13, v15}, Ll2/t;->Y(I)V

    .line 528
    .line 529
    .line 530
    iget-object v15, v6, Li31/e;->h:Ljava/lang/String;

    .line 531
    .line 532
    iget-object v14, v6, Li31/e;->e:Li31/f;

    .line 533
    .line 534
    move-object/from16 v19, v6

    .line 535
    .line 536
    if-eqz v14, :cond_10

    .line 537
    .line 538
    iget-wide v5, v14, Li31/f;->b:D

    .line 539
    .line 540
    iget-object v14, v14, Li31/f;->a:Ljava/lang/String;

    .line 541
    .line 542
    new-instance v0, Ljava/lang/StringBuilder;

    .line 543
    .line 544
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 545
    .line 546
    .line 547
    invoke-virtual {v0, v5, v6}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 548
    .line 549
    .line 550
    const-string v5, " "

    .line 551
    .line 552
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 553
    .line 554
    .line 555
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 556
    .line 557
    .line 558
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 559
    .line 560
    .line 561
    move-result-object v0

    .line 562
    if-nez v0, :cond_f

    .line 563
    .line 564
    goto :goto_c

    .line 565
    :cond_f
    const/4 v5, 0x0

    .line 566
    :goto_b
    move-object/from16 v21, v0

    .line 567
    .line 568
    goto :goto_d

    .line 569
    :cond_10
    :goto_c
    iget-object v0, v8, Lz70/b;->a:Lij0/a;

    .line 570
    .line 571
    const/4 v5, 0x0

    .line 572
    new-array v6, v5, [Ljava/lang/Object;

    .line 573
    .line 574
    check-cast v0, Ljj0/f;

    .line 575
    .line 576
    const v14, 0x7f121139

    .line 577
    .line 578
    .line 579
    invoke-virtual {v0, v14, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 580
    .line 581
    .line 582
    move-result-object v0

    .line 583
    goto :goto_b

    .line 584
    :goto_d
    iget-boolean v0, v12, Lp31/f;->b:Z

    .line 585
    .line 586
    if-eqz v0, :cond_11

    .line 587
    .line 588
    sget-object v0, Li91/i1;->e:Li91/i1;

    .line 589
    .line 590
    goto :goto_e

    .line 591
    :cond_11
    sget-object v0, Li91/i1;->f:Li91/i1;

    .line 592
    .line 593
    :goto_e
    and-int/lit8 v14, v2, 0x70

    .line 594
    .line 595
    const/16 v6, 0x20

    .line 596
    .line 597
    move-object/from16 v20, v4

    .line 598
    .line 599
    move-object/from16 v4, v19

    .line 600
    .line 601
    if-ne v14, v6, :cond_12

    .line 602
    .line 603
    const/16 v19, 0x1

    .line 604
    .line 605
    goto :goto_f

    .line 606
    :cond_12
    move/from16 v19, v5

    .line 607
    .line 608
    :goto_f
    invoke-virtual {v13, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 609
    .line 610
    .line 611
    move-result v22

    .line 612
    or-int v19, v19, v22

    .line 613
    .line 614
    invoke-virtual {v13, v11}, Ll2/t;->e(I)Z

    .line 615
    .line 616
    .line 617
    move-result v22

    .line 618
    or-int v19, v19, v22

    .line 619
    .line 620
    invoke-virtual {v13, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 621
    .line 622
    .line 623
    move-result v22

    .line 624
    or-int v19, v19, v22

    .line 625
    .line 626
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object v5

    .line 630
    move-object/from16 v23, v7

    .line 631
    .line 632
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 633
    .line 634
    if-nez v19, :cond_13

    .line 635
    .line 636
    if-ne v5, v7, :cond_14

    .line 637
    .line 638
    :cond_13
    move v5, v2

    .line 639
    goto :goto_10

    .line 640
    :cond_14
    move-object/from16 v16, v12

    .line 641
    .line 642
    move v12, v6

    .line 643
    move-object/from16 v6, v16

    .line 644
    .line 645
    move/from16 v16, v2

    .line 646
    .line 647
    move-object v2, v5

    .line 648
    move v5, v11

    .line 649
    move-object/from16 v31, v20

    .line 650
    .line 651
    move-object/from16 v37, v23

    .line 652
    .line 653
    move-object v11, v7

    .line 654
    goto :goto_11

    .line 655
    :goto_10
    new-instance v2, Lc41/m;

    .line 656
    .line 657
    move-object/from16 v19, v7

    .line 658
    .line 659
    const/4 v7, 0x0

    .line 660
    move-object/from16 v16, v12

    .line 661
    .line 662
    move v12, v6

    .line 663
    move-object/from16 v6, v16

    .line 664
    .line 665
    move/from16 v16, v5

    .line 666
    .line 667
    move v5, v11

    .line 668
    move-object/from16 v11, v19

    .line 669
    .line 670
    move-object/from16 v31, v20

    .line 671
    .line 672
    move-object/from16 v37, v23

    .line 673
    .line 674
    invoke-direct/range {v2 .. v7}, Lc41/m;-><init>(Lay0/k;Li31/e;ILp31/f;I)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 678
    .line 679
    .line 680
    :goto_11
    check-cast v2, Lay0/a;

    .line 681
    .line 682
    new-instance v3, Li91/o1;

    .line 683
    .line 684
    invoke-direct {v3, v0, v2}, Li91/o1;-><init>(Li91/i1;Lay0/a;)V

    .line 685
    .line 686
    .line 687
    if-ne v14, v12, :cond_15

    .line 688
    .line 689
    const/4 v7, 0x1

    .line 690
    goto :goto_12

    .line 691
    :cond_15
    const/4 v7, 0x0

    .line 692
    :goto_12
    invoke-virtual {v13, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 693
    .line 694
    .line 695
    move-result v0

    .line 696
    or-int/2addr v0, v7

    .line 697
    invoke-virtual {v13, v5}, Ll2/t;->e(I)Z

    .line 698
    .line 699
    .line 700
    move-result v2

    .line 701
    or-int/2addr v0, v2

    .line 702
    invoke-virtual {v13, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 703
    .line 704
    .line 705
    move-result v2

    .line 706
    or-int/2addr v0, v2

    .line 707
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v2

    .line 711
    if-nez v0, :cond_17

    .line 712
    .line 713
    if-ne v2, v11, :cond_16

    .line 714
    .line 715
    goto :goto_13

    .line 716
    :cond_16
    move-object/from16 v23, v3

    .line 717
    .line 718
    goto :goto_14

    .line 719
    :cond_17
    :goto_13
    new-instance v2, Lc41/m;

    .line 720
    .line 721
    const/4 v7, 0x1

    .line 722
    move-object/from16 v23, v3

    .line 723
    .line 724
    move-object/from16 v3, p1

    .line 725
    .line 726
    invoke-direct/range {v2 .. v7}, Lc41/m;-><init>(Lay0/k;Li31/e;ILp31/f;I)V

    .line 727
    .line 728
    .line 729
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 730
    .line 731
    .line 732
    :goto_14
    move-object/from16 v28, v2

    .line 733
    .line 734
    check-cast v28, Lay0/a;

    .line 735
    .line 736
    new-instance v19, Li91/c2;

    .line 737
    .line 738
    const/16 v22, 0x0

    .line 739
    .line 740
    const/16 v24, 0x1

    .line 741
    .line 742
    const/16 v25, 0x0

    .line 743
    .line 744
    const/16 v26, 0x0

    .line 745
    .line 746
    const-string v27, "service_item"

    .line 747
    .line 748
    const/16 v29, 0x6e0

    .line 749
    .line 750
    move-object/from16 v20, v15

    .line 751
    .line 752
    invoke-direct/range {v19 .. v29}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 753
    .line 754
    .line 755
    const/4 v14, 0x0

    .line 756
    const/4 v15, 0x6

    .line 757
    const/4 v11, 0x0

    .line 758
    move/from16 v35, v12

    .line 759
    .line 760
    const/4 v12, 0x0

    .line 761
    move v5, v10

    .line 762
    move-object/from16 v10, v19

    .line 763
    .line 764
    const/high16 v0, 0x3f800000    # 1.0f

    .line 765
    .line 766
    const v2, 0x11b0a342

    .line 767
    .line 768
    .line 769
    const/4 v3, 0x1

    .line 770
    invoke-static/range {v10 .. v15}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 771
    .line 772
    .line 773
    invoke-interface/range {v36 .. v36}, Ljava/util/List;->size()I

    .line 774
    .line 775
    .line 776
    move-result v4

    .line 777
    sub-int/2addr v4, v3

    .line 778
    if-ge v5, v4, :cond_18

    .line 779
    .line 780
    const v2, 0x1217560b

    .line 781
    .line 782
    .line 783
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 784
    .line 785
    .line 786
    const/4 v4, 0x0

    .line 787
    const/4 v5, 0x0

    .line 788
    invoke-static {v5, v3, v13, v4}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 789
    .line 790
    .line 791
    :goto_15
    invoke-virtual {v13, v5}, Ll2/t;->q(Z)V

    .line 792
    .line 793
    .line 794
    goto :goto_16

    .line 795
    :cond_18
    const/4 v4, 0x0

    .line 796
    const/4 v5, 0x0

    .line 797
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 798
    .line 799
    .line 800
    goto :goto_15

    .line 801
    :goto_16
    invoke-virtual {v13, v5}, Ll2/t;->q(Z)V

    .line 802
    .line 803
    .line 804
    goto :goto_17

    .line 805
    :cond_19
    move/from16 v16, v2

    .line 806
    .line 807
    move-object/from16 v31, v4

    .line 808
    .line 809
    move-object/from16 v37, v7

    .line 810
    .line 811
    const/high16 v0, 0x3f800000    # 1.0f

    .line 812
    .line 813
    const v2, 0x11b0a342

    .line 814
    .line 815
    .line 816
    const/4 v3, 0x1

    .line 817
    const/4 v4, 0x0

    .line 818
    const/16 v35, 0x20

    .line 819
    .line 820
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 821
    .line 822
    .line 823
    goto :goto_16

    .line 824
    :goto_17
    move-object/from16 v3, p1

    .line 825
    .line 826
    move-object/from16 v0, p3

    .line 827
    .line 828
    move/from16 v2, v16

    .line 829
    .line 830
    move/from16 v10, v18

    .line 831
    .line 832
    move-object/from16 v4, v31

    .line 833
    .line 834
    move-object/from16 v7, v37

    .line 835
    .line 836
    goto/16 :goto_a

    .line 837
    .line 838
    :cond_1a
    const/4 v4, 0x0

    .line 839
    invoke-static {}, Ljp/k1;->r()V

    .line 840
    .line 841
    .line 842
    throw v4

    .line 843
    :cond_1b
    move/from16 v16, v2

    .line 844
    .line 845
    move-object/from16 v31, v4

    .line 846
    .line 847
    move-object/from16 v37, v7

    .line 848
    .line 849
    const/high16 v0, 0x3f800000    # 1.0f

    .line 850
    .line 851
    const/4 v3, 0x1

    .line 852
    const/16 v35, 0x20

    .line 853
    .line 854
    invoke-virtual {v13, v5}, Ll2/t;->q(Z)V

    .line 855
    .line 856
    .line 857
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 858
    .line 859
    .line 860
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 861
    .line 862
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 863
    .line 864
    .line 865
    move-result-object v2

    .line 866
    check-cast v2, Lj91/c;

    .line 867
    .line 868
    iget v2, v2, Lj91/c;->e:F

    .line 869
    .line 870
    move-object/from16 v14, v37

    .line 871
    .line 872
    invoke-static {v14, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 873
    .line 874
    .line 875
    move-result-object v2

    .line 876
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 877
    .line 878
    .line 879
    move-result-object v2

    .line 880
    invoke-static {v13, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 881
    .line 882
    .line 883
    move v6, v0

    .line 884
    move v7, v3

    .line 885
    move v10, v5

    .line 886
    move/from16 v2, v16

    .line 887
    .line 888
    move/from16 v11, v33

    .line 889
    .line 890
    move/from16 v12, v34

    .line 891
    .line 892
    move-object/from16 v3, p1

    .line 893
    .line 894
    move-object/from16 v0, p3

    .line 895
    .line 896
    goto/16 :goto_7

    .line 897
    .line 898
    :cond_1c
    const/4 v4, 0x0

    .line 899
    invoke-static {}, Ljp/k1;->r()V

    .line 900
    .line 901
    .line 902
    throw v4

    .line 903
    :cond_1d
    move v3, v7

    .line 904
    move v5, v10

    .line 905
    invoke-static {v13, v5, v5, v3}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 906
    .line 907
    .line 908
    goto :goto_18

    .line 909
    :cond_1e
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 910
    .line 911
    .line 912
    :goto_18
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 913
    .line 914
    .line 915
    move-result-object v6

    .line 916
    if-eqz v6, :cond_1f

    .line 917
    .line 918
    new-instance v0, La2/f;

    .line 919
    .line 920
    const/4 v2, 0x4

    .line 921
    move-object/from16 v4, p1

    .line 922
    .line 923
    move-object/from16 v3, p3

    .line 924
    .line 925
    move-object v5, v8

    .line 926
    invoke-direct/range {v0 .. v5}, La2/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 927
    .line 928
    .line 929
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 930
    .line 931
    :cond_1f
    return-void
.end method

.method public static final b(Lp1/v;)J
    .locals 4

    .line 1
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-long v0, v0

    .line 6
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    int-to-long v2, v2

    .line 11
    mul-long/2addr v0, v2

    .line 12
    iget-object v2, p0, Lp1/v;->d:Lh8/o;

    .line 13
    .line 14
    iget-object v2, v2, Lh8/o;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ll2/f1;

    .line 17
    .line 18
    invoke-virtual {v2}, Ll2/f1;->o()F

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    int-to-float p0, p0

    .line 27
    mul-float/2addr v2, p0

    .line 28
    float-to-double v2, v2

    .line 29
    invoke-static {v2, v3}, Lcy0/a;->j(D)J

    .line 30
    .line 31
    .line 32
    move-result-wide v2

    .line 33
    add-long/2addr v2, v0

    .line 34
    return-wide v2
.end method
