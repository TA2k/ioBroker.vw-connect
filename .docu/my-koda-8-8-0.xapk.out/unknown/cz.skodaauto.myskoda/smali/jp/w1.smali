.class public abstract Ljp/w1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lc1/w1;Lx2/s;Lc1/a0;Lay0/k;Lt2/b;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    move/from16 v7, p6

    .line 6
    .line 7
    iget-object v0, v1, Lc1/w1;->a:Lap0/o;

    .line 8
    .line 9
    move-object/from16 v8, p5

    .line 10
    .line 11
    check-cast v8, Ll2/t;

    .line 12
    .line 13
    const v2, -0x6fe6665e

    .line 14
    .line 15
    .line 16
    invoke-virtual {v8, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v2, v7, 0x6

    .line 20
    .line 21
    if-nez v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v2, v7

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v2, v7

    .line 35
    :goto_1
    and-int/lit8 v4, v7, 0x30

    .line 36
    .line 37
    if-nez v4, :cond_3

    .line 38
    .line 39
    invoke-virtual {v8, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    :cond_3
    and-int/lit16 v4, v7, 0x180

    .line 52
    .line 53
    if-nez v4, :cond_5

    .line 54
    .line 55
    move-object/from16 v4, p2

    .line 56
    .line 57
    invoke-virtual {v8, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    if-eqz v5, :cond_4

    .line 62
    .line 63
    const/16 v5, 0x100

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    const/16 v5, 0x80

    .line 67
    .line 68
    :goto_3
    or-int/2addr v2, v5

    .line 69
    goto :goto_4

    .line 70
    :cond_5
    move-object/from16 v4, p2

    .line 71
    .line 72
    :goto_4
    or-int/lit16 v2, v2, 0xc00

    .line 73
    .line 74
    and-int/lit16 v5, v7, 0x6000

    .line 75
    .line 76
    if-nez v5, :cond_7

    .line 77
    .line 78
    move-object/from16 v5, p4

    .line 79
    .line 80
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v9

    .line 84
    if-eqz v9, :cond_6

    .line 85
    .line 86
    const/16 v9, 0x4000

    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_6
    const/16 v9, 0x2000

    .line 90
    .line 91
    :goto_5
    or-int/2addr v2, v9

    .line 92
    goto :goto_6

    .line 93
    :cond_7
    move-object/from16 v5, p4

    .line 94
    .line 95
    :goto_6
    and-int/lit16 v9, v2, 0x2493

    .line 96
    .line 97
    const/16 v10, 0x2492

    .line 98
    .line 99
    const/4 v11, 0x1

    .line 100
    const/4 v12, 0x0

    .line 101
    if-eq v9, v10, :cond_8

    .line 102
    .line 103
    move v9, v11

    .line 104
    goto :goto_7

    .line 105
    :cond_8
    move v9, v12

    .line 106
    :goto_7
    and-int/lit8 v10, v2, 0x1

    .line 107
    .line 108
    invoke-virtual {v8, v10, v9}, Ll2/t;->O(IZ)Z

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    if-eqz v9, :cond_1c

    .line 113
    .line 114
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v9

    .line 118
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 119
    .line 120
    if-ne v9, v10, :cond_9

    .line 121
    .line 122
    sget-object v9, Lb1/c;->m:Lb1/c;

    .line 123
    .line 124
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    :cond_9
    check-cast v9, Lay0/k;

    .line 128
    .line 129
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v13

    .line 133
    if-ne v13, v10, :cond_a

    .line 134
    .line 135
    new-instance v13, Lv2/o;

    .line 136
    .line 137
    invoke-direct {v13}, Lv2/o;-><init>()V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v0}, Lap0/o;->D()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v14

    .line 144
    invoke-virtual {v13, v14}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    invoke-virtual {v8, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    :cond_a
    check-cast v13, Lv2/o;

    .line 151
    .line 152
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v14

    .line 156
    if-ne v14, v10, :cond_b

    .line 157
    .line 158
    sget-object v14, Landroidx/collection/y0;->a:[J

    .line 159
    .line 160
    new-instance v14, Landroidx/collection/q0;

    .line 161
    .line 162
    invoke-direct {v14}, Landroidx/collection/q0;-><init>()V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v8, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    :cond_b
    check-cast v14, Landroidx/collection/q0;

    .line 169
    .line 170
    iget-object v15, v1, Lc1/w1;->d:Ll2/j1;

    .line 171
    .line 172
    invoke-virtual {v0}, Lap0/o;->D()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v3

    .line 180
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-eqz v0, :cond_11

    .line 185
    .line 186
    const v0, 0x1324f7c8

    .line 187
    .line 188
    .line 189
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v13}, Lv2/o;->size()I

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-ne v0, v11, :cond_d

    .line 197
    .line 198
    invoke-virtual {v13, v12}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v0

    .line 210
    if-nez v0, :cond_c

    .line 211
    .line 212
    goto :goto_8

    .line 213
    :cond_c
    const v0, 0x1329ebe0

    .line 214
    .line 215
    .line 216
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 220
    .line 221
    .line 222
    goto :goto_a

    .line 223
    :cond_d
    :goto_8
    const v0, 0x1327049a

    .line 224
    .line 225
    .line 226
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 227
    .line 228
    .line 229
    and-int/lit8 v0, v2, 0xe

    .line 230
    .line 231
    const/4 v2, 0x4

    .line 232
    if-ne v0, v2, :cond_e

    .line 233
    .line 234
    move v0, v11

    .line 235
    goto :goto_9

    .line 236
    :cond_e
    move v0, v12

    .line 237
    :goto_9
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    if-nez v0, :cond_f

    .line 242
    .line 243
    if-ne v2, v10, :cond_10

    .line 244
    .line 245
    :cond_f
    new-instance v2, La3/f;

    .line 246
    .line 247
    const/16 v0, 0x8

    .line 248
    .line 249
    invoke-direct {v2, v1, v0}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v8, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    :cond_10
    check-cast v2, Lay0/k;

    .line 256
    .line 257
    invoke-static {v13, v2}, Lmx0/q;->c0(Ljava/util/List;Lay0/k;)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v14}, Landroidx/collection/q0;->a()V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 264
    .line 265
    .line 266
    :goto_a
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 267
    .line 268
    .line 269
    goto :goto_b

    .line 270
    :cond_11
    const v0, 0x132a0320

    .line 271
    .line 272
    .line 273
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 277
    .line 278
    .line 279
    :goto_b
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    invoke-virtual {v14, v0}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result v0

    .line 287
    if-nez v0, :cond_16

    .line 288
    .line 289
    const v0, 0x132af01b

    .line 290
    .line 291
    .line 292
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v13}, Lv2/o;->listIterator()Ljava/util/ListIterator;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    move v2, v12

    .line 300
    :goto_c
    move-object v3, v0

    .line 301
    check-cast v3, Lnx0/a;

    .line 302
    .line 303
    invoke-virtual {v3}, Lnx0/a;->hasNext()Z

    .line 304
    .line 305
    .line 306
    move-result v10

    .line 307
    const/4 v11, -0x1

    .line 308
    if-eqz v10, :cond_13

    .line 309
    .line 310
    invoke-virtual {v3}, Lnx0/a;->next()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v3

    .line 314
    invoke-interface {v9, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v3

    .line 318
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v10

    .line 322
    invoke-interface {v9, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v10

    .line 326
    invoke-static {v3, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v3

    .line 330
    if-eqz v3, :cond_12

    .line 331
    .line 332
    goto :goto_d

    .line 333
    :cond_12
    add-int/lit8 v2, v2, 0x1

    .line 334
    .line 335
    const/4 v11, 0x1

    .line 336
    goto :goto_c

    .line 337
    :cond_13
    move v2, v11

    .line 338
    :goto_d
    if-ne v2, v11, :cond_14

    .line 339
    .line 340
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v0

    .line 344
    invoke-virtual {v13, v0}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    goto :goto_e

    .line 348
    :cond_14
    invoke-virtual {v15}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v0

    .line 352
    invoke-virtual {v13, v2, v0}, Lv2/o;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    :goto_e
    invoke-virtual {v14}, Landroidx/collection/q0;->a()V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v13}, Lv2/o;->size()I

    .line 359
    .line 360
    .line 361
    move-result v10

    .line 362
    move v11, v12

    .line 363
    :goto_f
    if-ge v11, v10, :cond_15

    .line 364
    .line 365
    invoke-virtual {v13, v11}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v3

    .line 369
    new-instance v0, Lb1/g0;

    .line 370
    .line 371
    const/4 v5, 0x0

    .line 372
    move-object v2, v4

    .line 373
    move-object/from16 v4, p4

    .line 374
    .line 375
    invoke-direct/range {v0 .. v5}, Lb1/g0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 376
    .line 377
    .line 378
    const v1, -0x37b2e7f5

    .line 379
    .line 380
    .line 381
    invoke-static {v1, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 382
    .line 383
    .line 384
    move-result-object v0

    .line 385
    invoke-virtual {v14, v3, v0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    add-int/lit8 v11, v11, 0x1

    .line 389
    .line 390
    move-object/from16 v1, p0

    .line 391
    .line 392
    move-object/from16 v4, p2

    .line 393
    .line 394
    move-object/from16 v5, p4

    .line 395
    .line 396
    goto :goto_f

    .line 397
    :cond_15
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 398
    .line 399
    .line 400
    goto :goto_10

    .line 401
    :cond_16
    const v0, 0x133645e0

    .line 402
    .line 403
    .line 404
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 405
    .line 406
    .line 407
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 408
    .line 409
    .line 410
    :goto_10
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 411
    .line 412
    invoke-static {v0, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    iget-wide v1, v8, Ll2/t;->T:J

    .line 417
    .line 418
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 419
    .line 420
    .line 421
    move-result v1

    .line 422
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 423
    .line 424
    .line 425
    move-result-object v2

    .line 426
    invoke-static {v8, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 431
    .line 432
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 433
    .line 434
    .line 435
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 436
    .line 437
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 438
    .line 439
    .line 440
    iget-boolean v5, v8, Ll2/t;->S:Z

    .line 441
    .line 442
    if-eqz v5, :cond_17

    .line 443
    .line 444
    invoke-virtual {v8, v4}, Ll2/t;->l(Lay0/a;)V

    .line 445
    .line 446
    .line 447
    goto :goto_11

    .line 448
    :cond_17
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 449
    .line 450
    .line 451
    :goto_11
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 452
    .line 453
    invoke-static {v4, v0, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 454
    .line 455
    .line 456
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 457
    .line 458
    invoke-static {v0, v2, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 459
    .line 460
    .line 461
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 462
    .line 463
    iget-boolean v2, v8, Ll2/t;->S:Z

    .line 464
    .line 465
    if-nez v2, :cond_18

    .line 466
    .line 467
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    move-result-object v2

    .line 471
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 472
    .line 473
    .line 474
    move-result-object v4

    .line 475
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    move-result v2

    .line 479
    if-nez v2, :cond_19

    .line 480
    .line 481
    :cond_18
    invoke-static {v1, v8, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 482
    .line 483
    .line 484
    :cond_19
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 485
    .line 486
    invoke-static {v0, v3, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 487
    .line 488
    .line 489
    const v0, -0x4e3e53b8

    .line 490
    .line 491
    .line 492
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 493
    .line 494
    .line 495
    invoke-virtual {v13}, Lv2/o;->size()I

    .line 496
    .line 497
    .line 498
    move-result v0

    .line 499
    move v1, v12

    .line 500
    :goto_12
    if-ge v1, v0, :cond_1b

    .line 501
    .line 502
    invoke-virtual {v13, v1}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v2

    .line 506
    const v3, 0x45d4d0b9

    .line 507
    .line 508
    .line 509
    invoke-interface {v9, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    move-result-object v4

    .line 513
    invoke-virtual {v8, v3, v4}, Ll2/t;->V(ILjava/lang/Object;)V

    .line 514
    .line 515
    .line 516
    invoke-virtual {v14, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v2

    .line 520
    check-cast v2, Lay0/n;

    .line 521
    .line 522
    if-nez v2, :cond_1a

    .line 523
    .line 524
    const v2, 0x74c5d4d0

    .line 525
    .line 526
    .line 527
    invoke-virtual {v8, v2}, Ll2/t;->Y(I)V

    .line 528
    .line 529
    .line 530
    :goto_13
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 531
    .line 532
    .line 533
    goto :goto_14

    .line 534
    :cond_1a
    const v3, 0x45d4d551

    .line 535
    .line 536
    .line 537
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 538
    .line 539
    .line 540
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 541
    .line 542
    .line 543
    move-result-object v3

    .line 544
    invoke-interface {v2, v8, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 545
    .line 546
    .line 547
    goto :goto_13

    .line 548
    :goto_14
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 549
    .line 550
    .line 551
    add-int/lit8 v1, v1, 0x1

    .line 552
    .line 553
    goto :goto_12

    .line 554
    :cond_1b
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 555
    .line 556
    .line 557
    const/4 v0, 0x1

    .line 558
    invoke-virtual {v8, v0}, Ll2/t;->q(Z)V

    .line 559
    .line 560
    .line 561
    move-object v4, v9

    .line 562
    goto :goto_15

    .line 563
    :cond_1c
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 564
    .line 565
    .line 566
    move-object/from16 v4, p3

    .line 567
    .line 568
    :goto_15
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 569
    .line 570
    .line 571
    move-result-object v8

    .line 572
    if-eqz v8, :cond_1d

    .line 573
    .line 574
    new-instance v0, Lb1/h0;

    .line 575
    .line 576
    move-object/from16 v1, p0

    .line 577
    .line 578
    move-object/from16 v3, p2

    .line 579
    .line 580
    move-object/from16 v5, p4

    .line 581
    .line 582
    move-object v2, v6

    .line 583
    move v6, v7

    .line 584
    invoke-direct/range {v0 .. v6}, Lb1/h0;-><init>(Lc1/w1;Lx2/s;Lc1/a0;Lay0/k;Lt2/b;I)V

    .line 585
    .line 586
    .line 587
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 588
    .line 589
    :cond_1d
    return-void
.end method

.method public static final b(Ljava/lang/Object;Lx2/s;Lc1/a0;Ljava/lang/String;Lt2/b;Ll2/o;II)V
    .locals 14

    .line 1
    move/from16 v6, p6

    .line 2
    .line 3
    move-object/from16 v12, p5

    .line 4
    .line 5
    check-cast v12, Ll2/t;

    .line 6
    .line 7
    const v0, -0x1e970fed

    .line 8
    .line 9
    .line 10
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v0, v6, 0x6

    .line 14
    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    and-int/lit8 v0, v6, 0x8

    .line 18
    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {v12, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {v12, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    :goto_0
    if-eqz v0, :cond_1

    .line 31
    .line 32
    const/4 v0, 0x4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const/4 v0, 0x2

    .line 35
    :goto_1
    or-int/2addr v0, v6

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    move v0, v6

    .line 38
    :goto_2
    and-int/lit8 v1, p7, 0x2

    .line 39
    .line 40
    if-eqz v1, :cond_3

    .line 41
    .line 42
    or-int/lit8 v0, v0, 0x30

    .line 43
    .line 44
    goto :goto_4

    .line 45
    :cond_3
    and-int/lit8 v2, v6, 0x30

    .line 46
    .line 47
    if-nez v2, :cond_5

    .line 48
    .line 49
    invoke-virtual {v12, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_4

    .line 54
    .line 55
    const/16 v2, 0x20

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_4
    const/16 v2, 0x10

    .line 59
    .line 60
    :goto_3
    or-int/2addr v0, v2

    .line 61
    :cond_5
    :goto_4
    and-int/lit8 v2, p7, 0x4

    .line 62
    .line 63
    if-eqz v2, :cond_7

    .line 64
    .line 65
    or-int/lit16 v0, v0, 0x180

    .line 66
    .line 67
    :cond_6
    move-object/from16 v3, p2

    .line 68
    .line 69
    goto :goto_6

    .line 70
    :cond_7
    and-int/lit16 v3, v6, 0x180

    .line 71
    .line 72
    if-nez v3, :cond_6

    .line 73
    .line 74
    move-object/from16 v3, p2

    .line 75
    .line 76
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eqz v4, :cond_8

    .line 81
    .line 82
    const/16 v4, 0x100

    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_8
    const/16 v4, 0x80

    .line 86
    .line 87
    :goto_5
    or-int/2addr v0, v4

    .line 88
    :goto_6
    and-int/lit8 v4, p7, 0x8

    .line 89
    .line 90
    if-eqz v4, :cond_a

    .line 91
    .line 92
    or-int/lit16 v0, v0, 0xc00

    .line 93
    .line 94
    :cond_9
    move-object/from16 v5, p3

    .line 95
    .line 96
    goto :goto_8

    .line 97
    :cond_a
    and-int/lit16 v5, v6, 0xc00

    .line 98
    .line 99
    if-nez v5, :cond_9

    .line 100
    .line 101
    move-object/from16 v5, p3

    .line 102
    .line 103
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v7

    .line 107
    if-eqz v7, :cond_b

    .line 108
    .line 109
    const/16 v7, 0x800

    .line 110
    .line 111
    goto :goto_7

    .line 112
    :cond_b
    const/16 v7, 0x400

    .line 113
    .line 114
    :goto_7
    or-int/2addr v0, v7

    .line 115
    :goto_8
    and-int/lit16 v7, v6, 0x6000

    .line 116
    .line 117
    move-object/from16 v11, p4

    .line 118
    .line 119
    if-nez v7, :cond_d

    .line 120
    .line 121
    invoke-virtual {v12, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v7

    .line 125
    if-eqz v7, :cond_c

    .line 126
    .line 127
    const/16 v7, 0x4000

    .line 128
    .line 129
    goto :goto_9

    .line 130
    :cond_c
    const/16 v7, 0x2000

    .line 131
    .line 132
    :goto_9
    or-int/2addr v0, v7

    .line 133
    :cond_d
    and-int/lit16 v7, v0, 0x2493

    .line 134
    .line 135
    const/16 v8, 0x2492

    .line 136
    .line 137
    const/4 v9, 0x0

    .line 138
    if-eq v7, v8, :cond_e

    .line 139
    .line 140
    const/4 v7, 0x1

    .line 141
    goto :goto_a

    .line 142
    :cond_e
    move v7, v9

    .line 143
    :goto_a
    and-int/lit8 v8, v0, 0x1

    .line 144
    .line 145
    invoke-virtual {v12, v8, v7}, Ll2/t;->O(IZ)Z

    .line 146
    .line 147
    .line 148
    move-result v7

    .line 149
    if-eqz v7, :cond_12

    .line 150
    .line 151
    if-eqz v1, :cond_f

    .line 152
    .line 153
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 154
    .line 155
    :cond_f
    move-object v8, p1

    .line 156
    if-eqz v2, :cond_10

    .line 157
    .line 158
    const/4 p1, 0x7

    .line 159
    const/4 v1, 0x0

    .line 160
    invoke-static {v9, v9, v1, p1}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    goto :goto_b

    .line 165
    :cond_10
    move-object p1, v3

    .line 166
    :goto_b
    if-eqz v4, :cond_11

    .line 167
    .line 168
    const-string v1, "Crossfade"

    .line 169
    .line 170
    goto :goto_c

    .line 171
    :cond_11
    move-object v1, v5

    .line 172
    :goto_c
    and-int/lit8 v2, v0, 0xe

    .line 173
    .line 174
    shr-int/lit8 v3, v0, 0x6

    .line 175
    .line 176
    and-int/lit8 v3, v3, 0x70

    .line 177
    .line 178
    or-int/2addr v2, v3

    .line 179
    invoke-static {p0, v1, v12, v2, v9}, Lc1/z1;->f(Ljava/lang/Object;Ljava/lang/String;Ll2/o;II)Lc1/w1;

    .line 180
    .line 181
    .line 182
    move-result-object v7

    .line 183
    const v2, 0xe3f0

    .line 184
    .line 185
    .line 186
    and-int v13, v0, v2

    .line 187
    .line 188
    const/4 v10, 0x0

    .line 189
    move-object v9, p1

    .line 190
    invoke-static/range {v7 .. v13}, Ljp/w1;->a(Lc1/w1;Lx2/s;Lc1/a0;Lay0/k;Lt2/b;Ll2/o;I)V

    .line 191
    .line 192
    .line 193
    move-object v4, v1

    .line 194
    move-object v2, v8

    .line 195
    move-object v3, v9

    .line 196
    goto :goto_d

    .line 197
    :cond_12
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 198
    .line 199
    .line 200
    move-object v2, p1

    .line 201
    move-object v4, v5

    .line 202
    :goto_d
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    if-eqz p1, :cond_13

    .line 207
    .line 208
    new-instance v0, Lb1/e0;

    .line 209
    .line 210
    const/4 v8, 0x0

    .line 211
    move-object v1, p0

    .line 212
    move-object/from16 v5, p4

    .line 213
    .line 214
    move/from16 v7, p7

    .line 215
    .line 216
    invoke-direct/range {v0 .. v8}, Lb1/e0;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;III)V

    .line 217
    .line 218
    .line 219
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 220
    .line 221
    :cond_13
    return-void
.end method

.method public static c(Ljava/lang/Class;)Llx0/i;
    .locals 3

    .line 1
    sget-object v0, Llx0/j;->d:Llx0/j;

    .line 2
    .line 3
    new-instance v1, Lmc/e;

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    invoke-direct {v1, p0, v2}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
