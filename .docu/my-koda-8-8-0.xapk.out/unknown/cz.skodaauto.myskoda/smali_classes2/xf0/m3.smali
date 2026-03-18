.class public abstract Lxf0/m3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lxf0/m3;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lxf0/j3;Ll2/o;I)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    check-cast v2, Ll2/t;

    .line 6
    .line 7
    const v3, -0x6382068b

    .line 8
    .line 9
    .line 10
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    const/4 v4, 0x2

    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    const/4 v3, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v3, v4

    .line 23
    :goto_0
    or-int v3, p2, v3

    .line 24
    .line 25
    and-int/lit8 v5, v3, 0x3

    .line 26
    .line 27
    const/4 v6, 0x1

    .line 28
    const/4 v7, 0x0

    .line 29
    if-eq v5, v4, :cond_1

    .line 30
    .line 31
    move v4, v6

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v4, v7

    .line 34
    :goto_1
    and-int/2addr v3, v6

    .line 35
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_a

    .line 40
    .line 41
    sget-object v3, Lx2/c;->q:Lx2/h;

    .line 42
    .line 43
    const/high16 v4, 0x3f800000    # 1.0f

    .line 44
    .line 45
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 46
    .line 47
    invoke-static {v5, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    sget-object v8, Lk1/j;->c:Lk1/e;

    .line 52
    .line 53
    const/16 v9, 0x30

    .line 54
    .line 55
    invoke-static {v8, v3, v2, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    iget-wide v8, v2, Ll2/t;->T:J

    .line 60
    .line 61
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    invoke-static {v2, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 74
    .line 75
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 79
    .line 80
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 81
    .line 82
    .line 83
    iget-boolean v11, v2, Ll2/t;->S:Z

    .line 84
    .line 85
    if-eqz v11, :cond_2

    .line 86
    .line 87
    invoke-virtual {v2, v10}, Ll2/t;->l(Lay0/a;)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_2
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 92
    .line 93
    .line 94
    :goto_2
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 95
    .line 96
    invoke-static {v10, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 100
    .line 101
    invoke-static {v3, v9, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 102
    .line 103
    .line 104
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 105
    .line 106
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 107
    .line 108
    if-nez v9, :cond_3

    .line 109
    .line 110
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v9

    .line 114
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v9

    .line 122
    if-nez v9, :cond_4

    .line 123
    .line 124
    :cond_3
    invoke-static {v8, v2, v8, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 125
    .line 126
    .line 127
    :cond_4
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 128
    .line 129
    invoke-static {v3, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    iget-boolean v3, v0, Lxf0/j3;->d:Z

    .line 133
    .line 134
    iget-object v4, v0, Lxf0/j3;->f:Ljava/lang/String;

    .line 135
    .line 136
    iget-object v8, v0, Lxf0/j3;->e:Ljava/lang/String;

    .line 137
    .line 138
    if-eqz v3, :cond_5

    .line 139
    .line 140
    const v3, -0x2df84ad3

    .line 141
    .line 142
    .line 143
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 147
    .line 148
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    check-cast v4, Lj91/c;

    .line 153
    .line 154
    iget v4, v4, Lj91/c;->d:F

    .line 155
    .line 156
    invoke-static {v5, v4, v2, v3}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    check-cast v4, Lj91/c;

    .line 161
    .line 162
    iget v4, v4, Lj91/c;->c:F

    .line 163
    .line 164
    invoke-static {v4}, Ls1/f;->b(F)Ls1/e;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    invoke-static {v5, v6, v4}, Lxf0/y1;->G(Lx2/s;ZLe3/n0;)Lx2/s;

    .line 169
    .line 170
    .line 171
    move-result-object v4

    .line 172
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v8

    .line 176
    check-cast v8, Lj91/c;

    .line 177
    .line 178
    iget v8, v8, Lj91/c;->c:F

    .line 179
    .line 180
    const/16 v9, 0x60

    .line 181
    .line 182
    int-to-float v9, v9

    .line 183
    invoke-static {v4, v9, v8}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    invoke-static {v4, v2, v7}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    check-cast v4, Lj91/c;

    .line 195
    .line 196
    iget v4, v4, Lj91/c;->b:F

    .line 197
    .line 198
    invoke-static {v5, v4, v2, v3}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    check-cast v4, Lj91/c;

    .line 203
    .line 204
    iget v4, v4, Lj91/c;->c:F

    .line 205
    .line 206
    invoke-static {v4}, Ls1/f;->b(F)Ls1/e;

    .line 207
    .line 208
    .line 209
    move-result-object v4

    .line 210
    invoke-static {v5, v6, v4}, Lxf0/y1;->G(Lx2/s;ZLe3/n0;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v3

    .line 218
    check-cast v3, Lj91/c;

    .line 219
    .line 220
    iget v3, v3, Lj91/c;->c:F

    .line 221
    .line 222
    const/16 v5, 0x98

    .line 223
    .line 224
    int-to-float v5, v5

    .line 225
    invoke-static {v4, v5, v3}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 226
    .line 227
    .line 228
    move-result-object v3

    .line 229
    invoke-static {v3, v2, v7}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 233
    .line 234
    .line 235
    move v15, v6

    .line 236
    goto/16 :goto_8

    .line 237
    .line 238
    :cond_5
    const v3, -0x2dee5152

    .line 239
    .line 240
    .line 241
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 242
    .line 243
    .line 244
    if-nez v8, :cond_7

    .line 245
    .line 246
    if-eqz v4, :cond_6

    .line 247
    .line 248
    goto :goto_3

    .line 249
    :cond_6
    const v3, -0x2e2fd949

    .line 250
    .line 251
    .line 252
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 256
    .line 257
    .line 258
    goto :goto_4

    .line 259
    :cond_7
    :goto_3
    const v3, -0x2ded639d

    .line 260
    .line 261
    .line 262
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 263
    .line 264
    .line 265
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 266
    .line 267
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v3

    .line 271
    check-cast v3, Lj91/c;

    .line 272
    .line 273
    iget v3, v3, Lj91/c;->d:F

    .line 274
    .line 275
    invoke-static {v5, v3, v2, v7}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 276
    .line 277
    .line 278
    :goto_4
    if-nez v8, :cond_8

    .line 279
    .line 280
    const v3, -0x2deb86df

    .line 281
    .line 282
    .line 283
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 284
    .line 285
    .line 286
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 287
    .line 288
    .line 289
    move-object/from16 v25, v4

    .line 290
    .line 291
    move-object v1, v5

    .line 292
    move v0, v7

    .line 293
    goto/16 :goto_5

    .line 294
    .line 295
    :cond_8
    const v3, -0x2deb86de

    .line 296
    .line 297
    .line 298
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 299
    .line 300
    .line 301
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 302
    .line 303
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    check-cast v3, Lj91/f;

    .line 308
    .line 309
    invoke-virtual {v3}, Lj91/f;->e()Lg4/p0;

    .line 310
    .line 311
    .line 312
    move-result-object v3

    .line 313
    sget-object v9, Lj91/h;->a:Ll2/u2;

    .line 314
    .line 315
    invoke-virtual {v2, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v9

    .line 319
    check-cast v9, Lj91/e;

    .line 320
    .line 321
    invoke-virtual {v9}, Lj91/e;->t()J

    .line 322
    .line 323
    .line 324
    move-result-wide v9

    .line 325
    const/16 v22, 0x0

    .line 326
    .line 327
    const v23, 0xfff4

    .line 328
    .line 329
    .line 330
    move-object v11, v4

    .line 331
    const/4 v4, 0x0

    .line 332
    move-object/from16 v20, v2

    .line 333
    .line 334
    move v12, v7

    .line 335
    move-object v2, v8

    .line 336
    const-wide/16 v7, 0x0

    .line 337
    .line 338
    move-object v13, v5

    .line 339
    move-wide/from16 v28, v9

    .line 340
    .line 341
    move v10, v6

    .line 342
    move-wide/from16 v5, v28

    .line 343
    .line 344
    const/4 v9, 0x0

    .line 345
    move v15, v10

    .line 346
    move-object v14, v11

    .line 347
    const-wide/16 v10, 0x0

    .line 348
    .line 349
    move/from16 v16, v12

    .line 350
    .line 351
    const/4 v12, 0x0

    .line 352
    move-object/from16 v17, v13

    .line 353
    .line 354
    const/4 v13, 0x0

    .line 355
    move-object/from16 v18, v14

    .line 356
    .line 357
    move/from16 v19, v15

    .line 358
    .line 359
    const-wide/16 v14, 0x0

    .line 360
    .line 361
    move/from16 v21, v16

    .line 362
    .line 363
    const/16 v16, 0x0

    .line 364
    .line 365
    move-object/from16 v24, v17

    .line 366
    .line 367
    const/16 v17, 0x0

    .line 368
    .line 369
    move-object/from16 v25, v18

    .line 370
    .line 371
    const/16 v18, 0x0

    .line 372
    .line 373
    move/from16 v26, v19

    .line 374
    .line 375
    const/16 v19, 0x0

    .line 376
    .line 377
    move/from16 v27, v21

    .line 378
    .line 379
    const/16 v21, 0x0

    .line 380
    .line 381
    move-object/from16 v1, v24

    .line 382
    .line 383
    move/from16 v0, v27

    .line 384
    .line 385
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 386
    .line 387
    .line 388
    move-object/from16 v2, v20

    .line 389
    .line 390
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 391
    .line 392
    .line 393
    :goto_5
    if-nez v25, :cond_9

    .line 394
    .line 395
    const v1, -0x2de7b586

    .line 396
    .line 397
    .line 398
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 399
    .line 400
    .line 401
    :goto_6
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 402
    .line 403
    .line 404
    goto :goto_7

    .line 405
    :cond_9
    const v3, -0x2de7b585

    .line 406
    .line 407
    .line 408
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 409
    .line 410
    .line 411
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 412
    .line 413
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v3

    .line 417
    check-cast v3, Lj91/c;

    .line 418
    .line 419
    iget v3, v3, Lj91/c;->b:F

    .line 420
    .line 421
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    invoke-static {v2, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 426
    .line 427
    .line 428
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 429
    .line 430
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v1

    .line 434
    check-cast v1, Lj91/f;

    .line 435
    .line 436
    invoke-virtual {v1}, Lj91/f;->e()Lg4/p0;

    .line 437
    .line 438
    .line 439
    move-result-object v3

    .line 440
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 441
    .line 442
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 443
    .line 444
    .line 445
    move-result-object v1

    .line 446
    check-cast v1, Lj91/e;

    .line 447
    .line 448
    invoke-virtual {v1}, Lj91/e;->t()J

    .line 449
    .line 450
    .line 451
    move-result-wide v5

    .line 452
    const/16 v22, 0x0

    .line 453
    .line 454
    const v23, 0xfff4

    .line 455
    .line 456
    .line 457
    const/4 v4, 0x0

    .line 458
    const-wide/16 v7, 0x0

    .line 459
    .line 460
    const/4 v9, 0x0

    .line 461
    const-wide/16 v10, 0x0

    .line 462
    .line 463
    const/4 v12, 0x0

    .line 464
    const/4 v13, 0x0

    .line 465
    const-wide/16 v14, 0x0

    .line 466
    .line 467
    const/16 v16, 0x0

    .line 468
    .line 469
    const/16 v17, 0x0

    .line 470
    .line 471
    const/16 v18, 0x0

    .line 472
    .line 473
    const/16 v19, 0x0

    .line 474
    .line 475
    const/16 v21, 0x0

    .line 476
    .line 477
    move-object/from16 v20, v2

    .line 478
    .line 479
    move-object/from16 v2, v25

    .line 480
    .line 481
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 482
    .line 483
    .line 484
    move-object/from16 v2, v20

    .line 485
    .line 486
    goto :goto_6

    .line 487
    :goto_7
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 488
    .line 489
    .line 490
    const/4 v15, 0x1

    .line 491
    :goto_8
    invoke-virtual {v2, v15}, Ll2/t;->q(Z)V

    .line 492
    .line 493
    .line 494
    goto :goto_9

    .line 495
    :cond_a
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 496
    .line 497
    .line 498
    :goto_9
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    if-eqz v0, :cond_b

    .line 503
    .line 504
    new-instance v1, Ltj/g;

    .line 505
    .line 506
    const/16 v2, 0x16

    .line 507
    .line 508
    move-object/from16 v3, p0

    .line 509
    .line 510
    move/from16 v4, p2

    .line 511
    .line 512
    invoke-direct {v1, v3, v4, v2}, Ltj/g;-><init>(Ljava/lang/Object;II)V

    .line 513
    .line 514
    .line 515
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 516
    .line 517
    :cond_b
    return-void
.end method

.method public static final b(Lxf0/j3;Lt2/b;Ll2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v6, p2

    .line 4
    .line 5
    check-cast v6, Ll2/t;

    .line 6
    .line 7
    const v3, -0x34af778b    # -1.3666421E7f

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    const/4 v4, 0x2

    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    const/4 v3, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v3, v4

    .line 23
    :goto_0
    or-int v10, p3, v3

    .line 24
    .line 25
    and-int/lit8 v3, v10, 0x13

    .line 26
    .line 27
    const/16 v5, 0x12

    .line 28
    .line 29
    const/4 v11, 0x0

    .line 30
    if-eq v3, v5, :cond_1

    .line 31
    .line 32
    const/4 v3, 0x1

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v3, v11

    .line 35
    :goto_1
    and-int/lit8 v5, v10, 0x1

    .line 36
    .line 37
    invoke-virtual {v6, v5, v3}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_f

    .line 42
    .line 43
    iget-wide v7, v0, Lxf0/j3;->a:D

    .line 44
    .line 45
    sget-object v13, Lj91/h;->a:Ll2/u2;

    .line 46
    .line 47
    invoke-virtual {v6, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Lj91/e;

    .line 52
    .line 53
    invoke-virtual {v3}, Lj91/e;->d()J

    .line 54
    .line 55
    .line 56
    move-result-wide v14

    .line 57
    move-object/from16 v16, v13

    .line 58
    .line 59
    iget-wide v12, v0, Lxf0/j3;->b:D

    .line 60
    .line 61
    div-double/2addr v7, v12

    .line 62
    const/16 v3, 0x168

    .line 63
    .line 64
    int-to-double v12, v3

    .line 65
    mul-double/2addr v7, v12

    .line 66
    double-to-float v3, v7

    .line 67
    const/16 v5, 0xc8

    .line 68
    .line 69
    sget-object v7, Lc1/z;->c:Lc1/s;

    .line 70
    .line 71
    invoke-static {v5, v11, v7, v4}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    const/4 v7, 0x0

    .line 76
    const/16 v8, 0x1c

    .line 77
    .line 78
    const/4 v5, 0x0

    .line 79
    invoke-static/range {v3 .. v8}, Lc1/e;->b(FLc1/a0;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    sget-object v4, Lk1/j;->e:Lk1/f;

    .line 84
    .line 85
    sget-object v5, Lx2/c;->q:Lx2/h;

    .line 86
    .line 87
    const/high16 v7, 0x3f800000    # 1.0f

    .line 88
    .line 89
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 90
    .line 91
    invoke-static {v8, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    const/16 v12, 0x36

    .line 96
    .line 97
    invoke-static {v4, v5, v6, v12}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 98
    .line 99
    .line 100
    move-result-object v13

    .line 101
    iget-wide v11, v6, Ll2/t;->T:J

    .line 102
    .line 103
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 104
    .line 105
    .line 106
    move-result v11

    .line 107
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 108
    .line 109
    .line 110
    move-result-object v12

    .line 111
    invoke-static {v6, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    sget-object v19, Lv3/k;->m1:Lv3/j;

    .line 116
    .line 117
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 121
    .line 122
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 123
    .line 124
    .line 125
    move/from16 v20, v10

    .line 126
    .line 127
    iget-boolean v10, v6, Ll2/t;->S:Z

    .line 128
    .line 129
    if-eqz v10, :cond_2

    .line 130
    .line 131
    invoke-virtual {v6, v9}, Ll2/t;->l(Lay0/a;)V

    .line 132
    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_2
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 136
    .line 137
    .line 138
    :goto_2
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 139
    .line 140
    invoke-static {v10, v13, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 141
    .line 142
    .line 143
    sget-object v13, Lv3/j;->f:Lv3/h;

    .line 144
    .line 145
    invoke-static {v13, v12, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 146
    .line 147
    .line 148
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 149
    .line 150
    iget-boolean v2, v6, Ll2/t;->S:Z

    .line 151
    .line 152
    if-nez v2, :cond_3

    .line 153
    .line 154
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    if-nez v1, :cond_4

    .line 167
    .line 168
    :cond_3
    invoke-static {v11, v6, v11, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 169
    .line 170
    .line 171
    :cond_4
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 172
    .line 173
    invoke-static {v1, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 174
    .line 175
    .line 176
    const/16 v2, 0xb4

    .line 177
    .line 178
    int-to-float v2, v2

    .line 179
    invoke-static {v8, v2}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    and-int/lit8 v7, v20, 0xe

    .line 184
    .line 185
    const/4 v11, 0x4

    .line 186
    if-ne v7, v11, :cond_5

    .line 187
    .line 188
    const/4 v11, 0x1

    .line 189
    goto :goto_3

    .line 190
    :cond_5
    const/4 v11, 0x0

    .line 191
    :goto_3
    invoke-virtual {v6, v14, v15}, Ll2/t;->f(J)Z

    .line 192
    .line 193
    .line 194
    move-result v19

    .line 195
    or-int v11, v11, v19

    .line 196
    .line 197
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v19

    .line 201
    or-int v11, v11, v19

    .line 202
    .line 203
    move/from16 v19, v7

    .line 204
    .line 205
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v7

    .line 209
    if-nez v11, :cond_6

    .line 210
    .line 211
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 212
    .line 213
    if-ne v7, v11, :cond_7

    .line 214
    .line 215
    :cond_6
    new-instance v7, Lxf0/k3;

    .line 216
    .line 217
    invoke-direct {v7, v0, v14, v15, v3}, Lxf0/k3;-><init>(Lxf0/j3;JLl2/t2;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v6, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    :cond_7
    check-cast v7, Lay0/k;

    .line 224
    .line 225
    invoke-static {v2, v7}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    const/16 v3, 0x36

    .line 230
    .line 231
    invoke-static {v4, v5, v6, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 232
    .line 233
    .line 234
    move-result-object v3

    .line 235
    iget-wide v4, v6, Ll2/t;->T:J

    .line 236
    .line 237
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 238
    .line 239
    .line 240
    move-result v4

    .line 241
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 242
    .line 243
    .line 244
    move-result-object v5

    .line 245
    invoke-static {v6, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 250
    .line 251
    .line 252
    iget-boolean v7, v6, Ll2/t;->S:Z

    .line 253
    .line 254
    if-eqz v7, :cond_8

    .line 255
    .line 256
    invoke-virtual {v6, v9}, Ll2/t;->l(Lay0/a;)V

    .line 257
    .line 258
    .line 259
    goto :goto_4

    .line 260
    :cond_8
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 261
    .line 262
    .line 263
    :goto_4
    invoke-static {v10, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 264
    .line 265
    .line 266
    invoke-static {v13, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 267
    .line 268
    .line 269
    iget-boolean v3, v6, Ll2/t;->S:Z

    .line 270
    .line 271
    if-nez v3, :cond_9

    .line 272
    .line 273
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v3

    .line 277
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 278
    .line 279
    .line 280
    move-result-object v5

    .line 281
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v3

    .line 285
    if-nez v3, :cond_a

    .line 286
    .line 287
    :cond_9
    invoke-static {v4, v6, v4, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 288
    .line 289
    .line 290
    :cond_a
    invoke-static {v1, v2, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 291
    .line 292
    .line 293
    iget-boolean v2, v0, Lxf0/j3;->d:Z

    .line 294
    .line 295
    if-eqz v2, :cond_e

    .line 296
    .line 297
    const v2, 0xcea802d

    .line 298
    .line 299
    .line 300
    invoke-virtual {v6, v2}, Ll2/t;->Y(I)V

    .line 301
    .line 302
    .line 303
    sget-object v2, Lk1/j;->a:Lk1/c;

    .line 304
    .line 305
    sget-object v3, Lx2/c;->m:Lx2/i;

    .line 306
    .line 307
    const/4 v4, 0x0

    .line 308
    invoke-static {v2, v3, v6, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 309
    .line 310
    .line 311
    move-result-object v2

    .line 312
    iget-wide v14, v6, Ll2/t;->T:J

    .line 313
    .line 314
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 315
    .line 316
    .line 317
    move-result v3

    .line 318
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 319
    .line 320
    .line 321
    move-result-object v5

    .line 322
    invoke-static {v6, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 323
    .line 324
    .line 325
    move-result-object v7

    .line 326
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 327
    .line 328
    .line 329
    iget-boolean v11, v6, Ll2/t;->S:Z

    .line 330
    .line 331
    if-eqz v11, :cond_b

    .line 332
    .line 333
    invoke-virtual {v6, v9}, Ll2/t;->l(Lay0/a;)V

    .line 334
    .line 335
    .line 336
    goto :goto_5

    .line 337
    :cond_b
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 338
    .line 339
    .line 340
    :goto_5
    invoke-static {v10, v2, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 341
    .line 342
    .line 343
    invoke-static {v13, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 344
    .line 345
    .line 346
    iget-boolean v2, v6, Ll2/t;->S:Z

    .line 347
    .line 348
    if-nez v2, :cond_c

    .line 349
    .line 350
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v2

    .line 354
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 355
    .line 356
    .line 357
    move-result-object v5

    .line 358
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    move-result v2

    .line 362
    if-nez v2, :cond_d

    .line 363
    .line 364
    :cond_c
    invoke-static {v3, v6, v3, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 365
    .line 366
    .line 367
    :cond_d
    invoke-static {v1, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 368
    .line 369
    .line 370
    const v1, 0x7f1201aa

    .line 371
    .line 372
    .line 373
    invoke-static {v6, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v3

    .line 377
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 378
    .line 379
    invoke-virtual {v6, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    check-cast v1, Lj91/f;

    .line 384
    .line 385
    invoke-virtual {v1}, Lj91/f;->h()Lg4/p0;

    .line 386
    .line 387
    .line 388
    move-result-object v1

    .line 389
    move-object/from16 v2, v16

    .line 390
    .line 391
    invoke-virtual {v6, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v2

    .line 395
    check-cast v2, Lj91/e;

    .line 396
    .line 397
    invoke-virtual {v2}, Lj91/e;->d()J

    .line 398
    .line 399
    .line 400
    move-result-wide v9

    .line 401
    const/16 v23, 0x0

    .line 402
    .line 403
    const v24, 0xfff4

    .line 404
    .line 405
    .line 406
    const/4 v5, 0x0

    .line 407
    move-object/from16 v21, v6

    .line 408
    .line 409
    move-object v2, v8

    .line 410
    move-wide v6, v9

    .line 411
    const-wide/16 v8, 0x0

    .line 412
    .line 413
    const/4 v10, 0x0

    .line 414
    const-wide/16 v11, 0x0

    .line 415
    .line 416
    const/4 v13, 0x0

    .line 417
    const/4 v14, 0x0

    .line 418
    const-wide/16 v15, 0x0

    .line 419
    .line 420
    const/16 v17, 0x0

    .line 421
    .line 422
    const/16 v18, 0x0

    .line 423
    .line 424
    move/from16 v20, v19

    .line 425
    .line 426
    const/16 v19, 0x0

    .line 427
    .line 428
    move/from16 v22, v20

    .line 429
    .line 430
    const/16 v20, 0x0

    .line 431
    .line 432
    move/from16 v25, v22

    .line 433
    .line 434
    const/16 v22, 0x0

    .line 435
    .line 436
    move-object v4, v1

    .line 437
    move-object v0, v2

    .line 438
    move/from16 v1, v25

    .line 439
    .line 440
    const/4 v2, 0x1

    .line 441
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 442
    .line 443
    .line 444
    move-object/from16 v6, v21

    .line 445
    .line 446
    invoke-virtual {v6, v2}, Ll2/t;->q(Z)V

    .line 447
    .line 448
    .line 449
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 450
    .line 451
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v4

    .line 455
    check-cast v4, Lj91/c;

    .line 456
    .line 457
    iget v4, v4, Lj91/c;->c:F

    .line 458
    .line 459
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v3

    .line 463
    check-cast v3, Lj91/c;

    .line 464
    .line 465
    iget v3, v3, Lj91/c;->i:F

    .line 466
    .line 467
    invoke-static {v0, v3, v4}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    invoke-static {v0, v2}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 472
    .line 473
    .line 474
    move-result-object v0

    .line 475
    const/4 v4, 0x0

    .line 476
    invoke-static {v0, v6, v4}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 477
    .line 478
    .line 479
    invoke-virtual {v6, v4}, Ll2/t;->q(Z)V

    .line 480
    .line 481
    .line 482
    move-object/from16 v3, p1

    .line 483
    .line 484
    goto :goto_6

    .line 485
    :cond_e
    move/from16 v1, v19

    .line 486
    .line 487
    const/4 v2, 0x1

    .line 488
    const/4 v4, 0x0

    .line 489
    const v0, 0xcf26a32

    .line 490
    .line 491
    .line 492
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 493
    .line 494
    .line 495
    const/4 v0, 0x6

    .line 496
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 497
    .line 498
    .line 499
    move-result-object v0

    .line 500
    move-object/from16 v3, p1

    .line 501
    .line 502
    invoke-virtual {v3, v6, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    invoke-virtual {v6, v4}, Ll2/t;->q(Z)V

    .line 506
    .line 507
    .line 508
    :goto_6
    invoke-virtual {v6, v2}, Ll2/t;->q(Z)V

    .line 509
    .line 510
    .line 511
    move-object/from16 v0, p0

    .line 512
    .line 513
    invoke-static {v0, v6, v1}, Lxf0/m3;->a(Lxf0/j3;Ll2/o;I)V

    .line 514
    .line 515
    .line 516
    invoke-virtual {v6, v2}, Ll2/t;->q(Z)V

    .line 517
    .line 518
    .line 519
    goto :goto_7

    .line 520
    :cond_f
    move-object/from16 v3, p1

    .line 521
    .line 522
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 523
    .line 524
    .line 525
    :goto_7
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 526
    .line 527
    .line 528
    move-result-object v1

    .line 529
    if-eqz v1, :cond_10

    .line 530
    .line 531
    new-instance v2, Lx40/n;

    .line 532
    .line 533
    const/4 v4, 0x6

    .line 534
    move/from16 v5, p3

    .line 535
    .line 536
    invoke-direct {v2, v5, v4, v0, v3}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 537
    .line 538
    .line 539
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 540
    .line 541
    :cond_10
    return-void
.end method
