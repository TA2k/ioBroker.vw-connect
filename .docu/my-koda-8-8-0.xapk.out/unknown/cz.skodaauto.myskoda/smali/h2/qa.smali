.class public abstract Lh2/qa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:I


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public static final a(Lh2/ra;Lt2/b;Lx2/s;ZZZLay0/k;Lt2/b;Ll2/o;II)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v9, p9

    .line 4
    .line 5
    const/16 v0, 0x36

    .line 6
    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    move-object/from16 v2, p8

    .line 12
    .line 13
    check-cast v2, Ll2/t;

    .line 14
    .line 15
    const v3, -0x2c325226

    .line 16
    .line 17
    .line 18
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_0

    .line 26
    .line 27
    const/4 v3, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v3, 0x2

    .line 30
    :goto_0
    or-int/2addr v3, v9

    .line 31
    and-int/lit8 v4, p10, 0x4

    .line 32
    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    or-int/lit16 v3, v3, 0x180

    .line 36
    .line 37
    move-object/from16 v5, p2

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_1
    move-object/from16 v5, p2

    .line 41
    .line 42
    invoke-virtual {v2, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    const/16 v6, 0x100

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_2
    const/16 v6, 0x80

    .line 52
    .line 53
    :goto_1
    or-int/2addr v3, v6

    .line 54
    :goto_2
    and-int/lit8 v6, p10, 0x8

    .line 55
    .line 56
    if-eqz v6, :cond_4

    .line 57
    .line 58
    or-int/lit16 v3, v3, 0xc00

    .line 59
    .line 60
    :cond_3
    move/from16 v8, p3

    .line 61
    .line 62
    goto :goto_4

    .line 63
    :cond_4
    and-int/lit16 v8, v9, 0xc00

    .line 64
    .line 65
    if-nez v8, :cond_3

    .line 66
    .line 67
    move/from16 v8, p3

    .line 68
    .line 69
    invoke-virtual {v2, v8}, Ll2/t;->h(Z)Z

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    if-eqz v10, :cond_5

    .line 74
    .line 75
    const/16 v10, 0x800

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_5
    const/16 v10, 0x400

    .line 79
    .line 80
    :goto_3
    or-int/2addr v3, v10

    .line 81
    :goto_4
    const v10, 0x36000

    .line 82
    .line 83
    .line 84
    or-int/2addr v10, v3

    .line 85
    and-int/lit8 v11, p10, 0x40

    .line 86
    .line 87
    if-eqz v11, :cond_6

    .line 88
    .line 89
    const v10, 0x1b6000

    .line 90
    .line 91
    .line 92
    or-int/2addr v3, v10

    .line 93
    move v10, v3

    .line 94
    move-object/from16 v3, p6

    .line 95
    .line 96
    goto :goto_6

    .line 97
    :cond_6
    move-object/from16 v3, p6

    .line 98
    .line 99
    invoke-virtual {v2, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v13

    .line 103
    if-eqz v13, :cond_7

    .line 104
    .line 105
    const/high16 v13, 0x100000

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_7
    const/high16 v13, 0x80000

    .line 109
    .line 110
    :goto_5
    or-int/2addr v10, v13

    .line 111
    :goto_6
    const v13, 0x492493

    .line 112
    .line 113
    .line 114
    and-int/2addr v13, v10

    .line 115
    const v14, 0x492492

    .line 116
    .line 117
    .line 118
    if-eq v13, v14, :cond_8

    .line 119
    .line 120
    const/4 v13, 0x1

    .line 121
    goto :goto_7

    .line 122
    :cond_8
    const/4 v13, 0x0

    .line 123
    :goto_7
    and-int/lit8 v14, v10, 0x1

    .line 124
    .line 125
    invoke-virtual {v2, v14, v13}, Ll2/t;->O(IZ)Z

    .line 126
    .line 127
    .line 128
    move-result v13

    .line 129
    if-eqz v13, :cond_21

    .line 130
    .line 131
    if-eqz v4, :cond_9

    .line 132
    .line 133
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 134
    .line 135
    move-object v5, v4

    .line 136
    :cond_9
    if-eqz v6, :cond_a

    .line 137
    .line 138
    const/4 v8, 0x1

    .line 139
    :cond_a
    const/16 v4, 0x12

    .line 140
    .line 141
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 142
    .line 143
    if-eqz v11, :cond_c

    .line 144
    .line 145
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    if-ne v3, v6, :cond_b

    .line 150
    .line 151
    new-instance v3, Lh10/d;

    .line 152
    .line 153
    invoke-direct {v3, v4}, Lh10/d;-><init>(I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    :cond_b
    check-cast v3, Lay0/k;

    .line 160
    .line 161
    :cond_c
    iget-object v11, v1, Lh2/ra;->a:Lg1/q;

    .line 162
    .line 163
    iget-object v13, v1, Lh2/ra;->a:Lg1/q;

    .line 164
    .line 165
    sget-object v14, Lg1/w1;->d:Lg1/w1;

    .line 166
    .line 167
    iget-object v14, v11, Lg1/q;->e:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v14, Ll2/j1;

    .line 170
    .line 171
    invoke-virtual {v14}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v14

    .line 175
    check-cast v14, Lh2/sa;

    .line 176
    .line 177
    sget-object v4, Lh2/sa;->f:Lh2/sa;

    .line 178
    .line 179
    if-ne v14, v4, :cond_d

    .line 180
    .line 181
    const/4 v4, 0x1

    .line 182
    goto :goto_8

    .line 183
    :cond_d
    const/4 v4, 0x0

    .line 184
    :goto_8
    iget-object v14, v1, Lh2/ra;->b:Lay0/k;

    .line 185
    .line 186
    if-eqz v14, :cond_11

    .line 187
    .line 188
    const v14, 0x171a04b1

    .line 189
    .line 190
    .line 191
    invoke-virtual {v2, v14}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    sget-object v14, Lg1/b;->a:Lc1/a2;

    .line 195
    .line 196
    iget-object v14, v1, Lh2/ra;->b:Lay0/k;

    .line 197
    .line 198
    if-eqz v14, :cond_10

    .line 199
    .line 200
    sget-object v17, Lg1/b;->a:Lc1/a2;

    .line 201
    .line 202
    const/16 p3, 0x0

    .line 203
    .line 204
    sget-object v7, Lg1/b;->a:Lc1/a2;

    .line 205
    .line 206
    sget-object v12, Lw3/h1;->h:Ll2/u2;

    .line 207
    .line 208
    invoke-virtual {v2, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v12

    .line 212
    check-cast v12, Lt4/c;

    .line 213
    .line 214
    invoke-virtual {v2, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v18

    .line 218
    invoke-virtual {v2, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v19

    .line 222
    or-int v18, v18, v19

    .line 223
    .line 224
    invoke-virtual {v2, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move-result v19

    .line 228
    or-int v18, v18, v19

    .line 229
    .line 230
    invoke-virtual {v2, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    move-result v19

    .line 234
    or-int v18, v18, v19

    .line 235
    .line 236
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v15

    .line 240
    if-nez v18, :cond_e

    .line 241
    .line 242
    if-ne v15, v6, :cond_f

    .line 243
    .line 244
    :cond_e
    new-instance v15, Ld2/g;

    .line 245
    .line 246
    const/16 v9, 0xf

    .line 247
    .line 248
    invoke-direct {v15, v12, v9}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 249
    .line 250
    .line 251
    new-instance v9, Lgw0/c;

    .line 252
    .line 253
    const/16 v12, 0x10

    .line 254
    .line 255
    invoke-direct {v9, v13, v14, v15, v12}, Lgw0/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 256
    .line 257
    .line 258
    sget v12, Lh1/k;->a:F

    .line 259
    .line 260
    new-instance v15, Lh1/g;

    .line 261
    .line 262
    sget-object v12, Landroidx/compose/foundation/gestures/a;->b:Lc1/u;

    .line 263
    .line 264
    invoke-direct {v15, v9, v12, v7}, Lh1/g;-><init>(Lh1/l;Lc1/u;Lc1/j;)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v2, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    :cond_f
    check-cast v15, Lh1/g;

    .line 271
    .line 272
    const/4 v7, 0x0

    .line 273
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 274
    .line 275
    .line 276
    goto :goto_9

    .line 277
    :cond_10
    const/16 p3, 0x0

    .line 278
    .line 279
    const-string v0, "positionalThreshold"

    .line 280
    .line 281
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    throw p3

    .line 285
    :cond_11
    const/16 p3, 0x0

    .line 286
    .line 287
    const/4 v7, 0x0

    .line 288
    const v9, -0x33d65a5d    # -4.4471948E7f

    .line 289
    .line 290
    .line 291
    invoke-virtual {v2, v9}, Ll2/t;->Y(I)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 295
    .line 296
    .line 297
    move-object/from16 v15, p3

    .line 298
    .line 299
    :goto_9
    invoke-static {v5, v11, v4, v15}, Landroidx/compose/foundation/gestures/a;->c(Lx2/s;Lg1/q;ZLh1/g;)Lx2/s;

    .line 300
    .line 301
    .line 302
    move-result-object v4

    .line 303
    sget-object v7, Lx2/c;->d:Lx2/j;

    .line 304
    .line 305
    const/4 v9, 0x1

    .line 306
    invoke-static {v7, v9}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 307
    .line 308
    .line 309
    move-result-object v7

    .line 310
    iget-wide v11, v2, Ll2/t;->T:J

    .line 311
    .line 312
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 313
    .line 314
    .line 315
    move-result v9

    .line 316
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 317
    .line 318
    .line 319
    move-result-object v11

    .line 320
    invoke-static {v2, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 321
    .line 322
    .line 323
    move-result-object v4

    .line 324
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 325
    .line 326
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 327
    .line 328
    .line 329
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 330
    .line 331
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 332
    .line 333
    .line 334
    iget-boolean v14, v2, Ll2/t;->S:Z

    .line 335
    .line 336
    if-eqz v14, :cond_12

    .line 337
    .line 338
    invoke-virtual {v2, v12}, Ll2/t;->l(Lay0/a;)V

    .line 339
    .line 340
    .line 341
    goto :goto_a

    .line 342
    :cond_12
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 343
    .line 344
    .line 345
    :goto_a
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 346
    .line 347
    invoke-static {v14, v7, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 348
    .line 349
    .line 350
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 351
    .line 352
    invoke-static {v7, v11, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 353
    .line 354
    .line 355
    sget-object v11, Lv3/j;->j:Lv3/h;

    .line 356
    .line 357
    iget-boolean v15, v2, Ll2/t;->S:Z

    .line 358
    .line 359
    if-nez v15, :cond_13

    .line 360
    .line 361
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v15

    .line 365
    move-object/from16 v18, v5

    .line 366
    .line 367
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 368
    .line 369
    .line 370
    move-result-object v5

    .line 371
    invoke-static {v15, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 372
    .line 373
    .line 374
    move-result v5

    .line 375
    if-nez v5, :cond_14

    .line 376
    .line 377
    goto :goto_b

    .line 378
    :cond_13
    move-object/from16 v18, v5

    .line 379
    .line 380
    :goto_b
    invoke-static {v9, v2, v9, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 381
    .line 382
    .line 383
    :cond_14
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 384
    .line 385
    invoke-static {v5, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 386
    .line 387
    .line 388
    sget-object v4, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 389
    .line 390
    invoke-virtual {v4}, Landroidx/compose/foundation/layout/b;->b()Lx2/s;

    .line 391
    .line 392
    .line 393
    move-result-object v4

    .line 394
    sget-object v9, Lk1/j;->a:Lk1/c;

    .line 395
    .line 396
    sget-object v15, Lx2/c;->m:Lx2/i;

    .line 397
    .line 398
    move-object/from16 p4, v3

    .line 399
    .line 400
    move-object/from16 p5, v13

    .line 401
    .line 402
    const/4 v3, 0x0

    .line 403
    invoke-static {v9, v15, v2, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 404
    .line 405
    .line 406
    move-result-object v13

    .line 407
    move/from16 v20, v8

    .line 408
    .line 409
    move-object/from16 p6, v9

    .line 410
    .line 411
    iget-wide v8, v2, Ll2/t;->T:J

    .line 412
    .line 413
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 414
    .line 415
    .line 416
    move-result v3

    .line 417
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 418
    .line 419
    .line 420
    move-result-object v8

    .line 421
    invoke-static {v2, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 422
    .line 423
    .line 424
    move-result-object v4

    .line 425
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 426
    .line 427
    .line 428
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 429
    .line 430
    if-eqz v9, :cond_15

    .line 431
    .line 432
    invoke-virtual {v2, v12}, Ll2/t;->l(Lay0/a;)V

    .line 433
    .line 434
    .line 435
    goto :goto_c

    .line 436
    :cond_15
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 437
    .line 438
    .line 439
    :goto_c
    invoke-static {v14, v13, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 440
    .line 441
    .line 442
    invoke-static {v7, v8, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 443
    .line 444
    .line 445
    iget-boolean v8, v2, Ll2/t;->S:Z

    .line 446
    .line 447
    if-nez v8, :cond_16

    .line 448
    .line 449
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v8

    .line 453
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 454
    .line 455
    .line 456
    move-result-object v9

    .line 457
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 458
    .line 459
    .line 460
    move-result v8

    .line 461
    if-nez v8, :cond_17

    .line 462
    .line 463
    :cond_16
    invoke-static {v3, v2, v3, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 464
    .line 465
    .line 466
    :cond_17
    invoke-static {v5, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 467
    .line 468
    .line 469
    sget-object v3, Lk1/i1;->a:Lk1/i1;

    .line 470
    .line 471
    move-object/from16 v4, p1

    .line 472
    .line 473
    invoke-virtual {v4, v3, v2, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    const/4 v9, 0x1

    .line 477
    invoke-virtual {v2, v9}, Ll2/t;->q(Z)V

    .line 478
    .line 479
    .line 480
    and-int/lit16 v8, v10, 0x1c00

    .line 481
    .line 482
    const/16 v9, 0x800

    .line 483
    .line 484
    if-ne v8, v9, :cond_18

    .line 485
    .line 486
    const/4 v8, 0x1

    .line 487
    goto :goto_d

    .line 488
    :cond_18
    const/4 v8, 0x0

    .line 489
    :goto_d
    invoke-virtual {v2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 490
    .line 491
    .line 492
    move-result v9

    .line 493
    or-int/2addr v8, v9

    .line 494
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v9

    .line 498
    if-nez v8, :cond_1a

    .line 499
    .line 500
    if-ne v9, v6, :cond_19

    .line 501
    .line 502
    goto :goto_e

    .line 503
    :cond_19
    move/from16 v8, v20

    .line 504
    .line 505
    goto :goto_f

    .line 506
    :cond_1a
    :goto_e
    new-instance v9, Lbl/f;

    .line 507
    .line 508
    move/from16 v8, v20

    .line 509
    .line 510
    invoke-direct {v9, v1, v8}, Lbl/f;-><init>(Lh2/ra;Z)V

    .line 511
    .line 512
    .line 513
    invoke-virtual {v2, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 514
    .line 515
    .line 516
    :goto_f
    check-cast v9, Lay0/n;

    .line 517
    .line 518
    move-object/from16 v13, p5

    .line 519
    .line 520
    invoke-static {v13, v9}, Landroidx/compose/material3/internal/a;->c(Lg1/q;Lay0/n;)Lx2/s;

    .line 521
    .line 522
    .line 523
    move-result-object v9

    .line 524
    move-object/from16 v4, p6

    .line 525
    .line 526
    move/from16 v20, v8

    .line 527
    .line 528
    const/4 v8, 0x0

    .line 529
    invoke-static {v4, v15, v2, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 530
    .line 531
    .line 532
    move-result-object v4

    .line 533
    move-object/from16 p5, v9

    .line 534
    .line 535
    iget-wide v8, v2, Ll2/t;->T:J

    .line 536
    .line 537
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 538
    .line 539
    .line 540
    move-result v8

    .line 541
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 542
    .line 543
    .line 544
    move-result-object v9

    .line 545
    move-object/from16 v15, p5

    .line 546
    .line 547
    invoke-static {v2, v15}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 548
    .line 549
    .line 550
    move-result-object v15

    .line 551
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 552
    .line 553
    .line 554
    move/from16 v16, v10

    .line 555
    .line 556
    iget-boolean v10, v2, Ll2/t;->S:Z

    .line 557
    .line 558
    if-eqz v10, :cond_1b

    .line 559
    .line 560
    invoke-virtual {v2, v12}, Ll2/t;->l(Lay0/a;)V

    .line 561
    .line 562
    .line 563
    goto :goto_10

    .line 564
    :cond_1b
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 565
    .line 566
    .line 567
    :goto_10
    invoke-static {v14, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 568
    .line 569
    .line 570
    invoke-static {v7, v9, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 571
    .line 572
    .line 573
    iget-boolean v4, v2, Ll2/t;->S:Z

    .line 574
    .line 575
    if-nez v4, :cond_1c

    .line 576
    .line 577
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v4

    .line 581
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 582
    .line 583
    .line 584
    move-result-object v7

    .line 585
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 586
    .line 587
    .line 588
    move-result v4

    .line 589
    if-nez v4, :cond_1d

    .line 590
    .line 591
    :cond_1c
    invoke-static {v8, v2, v8, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 592
    .line 593
    .line 594
    :cond_1d
    invoke-static {v5, v15, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 595
    .line 596
    .line 597
    move-object/from16 v4, p7

    .line 598
    .line 599
    invoke-virtual {v4, v3, v2, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    const/4 v9, 0x1

    .line 603
    invoke-virtual {v2, v9}, Ll2/t;->q(Z)V

    .line 604
    .line 605
    .line 606
    invoke-virtual {v2, v9}, Ll2/t;->q(Z)V

    .line 607
    .line 608
    .line 609
    iget-object v0, v13, Lg1/q;->e:Ljava/lang/Object;

    .line 610
    .line 611
    check-cast v0, Ll2/j1;

    .line 612
    .line 613
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 614
    .line 615
    .line 616
    move-result-object v0

    .line 617
    check-cast v0, Lh2/sa;

    .line 618
    .line 619
    invoke-virtual {v2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 620
    .line 621
    .line 622
    move-result v3

    .line 623
    const/high16 v5, 0x380000

    .line 624
    .line 625
    and-int v5, v16, v5

    .line 626
    .line 627
    const/high16 v7, 0x100000

    .line 628
    .line 629
    if-ne v5, v7, :cond_1e

    .line 630
    .line 631
    move v15, v9

    .line 632
    goto :goto_11

    .line 633
    :cond_1e
    const/4 v15, 0x0

    .line 634
    :goto_11
    or-int/2addr v3, v15

    .line 635
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 636
    .line 637
    .line 638
    move-result-object v5

    .line 639
    if-nez v3, :cond_20

    .line 640
    .line 641
    if-ne v5, v6, :cond_1f

    .line 642
    .line 643
    goto :goto_12

    .line 644
    :cond_1f
    move-object/from16 v3, p4

    .line 645
    .line 646
    goto :goto_13

    .line 647
    :cond_20
    :goto_12
    new-instance v5, Le30/p;

    .line 648
    .line 649
    move-object/from16 v7, p3

    .line 650
    .line 651
    move-object/from16 v3, p4

    .line 652
    .line 653
    const/16 v6, 0x12

    .line 654
    .line 655
    invoke-direct {v5, v6, v1, v3, v7}, Le30/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 656
    .line 657
    .line 658
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 659
    .line 660
    .line 661
    :goto_13
    check-cast v5, Lay0/n;

    .line 662
    .line 663
    invoke-static {v0, v3, v5, v2}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 664
    .line 665
    .line 666
    move-object v7, v3

    .line 667
    move v5, v9

    .line 668
    move v6, v5

    .line 669
    move-object/from16 v3, v18

    .line 670
    .line 671
    move/from16 v4, v20

    .line 672
    .line 673
    goto :goto_14

    .line 674
    :cond_21
    move-object/from16 v4, p7

    .line 675
    .line 676
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 677
    .line 678
    .line 679
    move/from16 v6, p5

    .line 680
    .line 681
    move-object v7, v3

    .line 682
    move-object v3, v5

    .line 683
    move v4, v8

    .line 684
    move/from16 v5, p4

    .line 685
    .line 686
    :goto_14
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 687
    .line 688
    .line 689
    move-result-object v11

    .line 690
    if-eqz v11, :cond_22

    .line 691
    .line 692
    new-instance v0, Lh2/pa;

    .line 693
    .line 694
    move-object/from16 v2, p1

    .line 695
    .line 696
    move-object/from16 v8, p7

    .line 697
    .line 698
    move/from16 v9, p9

    .line 699
    .line 700
    move/from16 v10, p10

    .line 701
    .line 702
    invoke-direct/range {v0 .. v10}, Lh2/pa;-><init>(Lh2/ra;Lt2/b;Lx2/s;ZZZLay0/k;Lt2/b;II)V

    .line 703
    .line 704
    .line 705
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 706
    .line 707
    :cond_22
    return-void
.end method
