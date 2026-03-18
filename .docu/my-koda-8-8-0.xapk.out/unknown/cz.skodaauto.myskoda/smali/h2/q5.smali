.class public abstract Lh2/q5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F

.field public static final f:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x30

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lh2/q5;->a:F

    .line 5
    .line 6
    sput v0, Lh2/q5;->b:F

    .line 7
    .line 8
    const/16 v0, 0xc

    .line 9
    .line 10
    int-to-float v0, v0

    .line 11
    sput v0, Lh2/q5;->c:F

    .line 12
    .line 13
    const/16 v0, 0x8

    .line 14
    .line 15
    int-to-float v0, v0

    .line 16
    sput v0, Lh2/q5;->d:F

    .line 17
    .line 18
    const/16 v0, 0x70

    .line 19
    .line 20
    int-to-float v0, v0

    .line 21
    sput v0, Lh2/q5;->e:F

    .line 22
    .line 23
    const/16 v0, 0x118

    .line 24
    .line 25
    int-to-float v0, v0

    .line 26
    sput v0, Lh2/q5;->f:F

    .line 27
    .line 28
    return-void
.end method

.method public static final a(Lx2/s;Lc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v0, p3

    .line 6
    .line 7
    move-object/from16 v10, p9

    .line 8
    .line 9
    move-object/from16 v2, p10

    .line 10
    .line 11
    check-cast v2, Ll2/t;

    .line 12
    .line 13
    const v3, 0x329a8275

    .line 14
    .line 15
    .line 16
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    const/4 v3, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v3, 0x2

    .line 28
    :goto_0
    or-int v3, p11, v3

    .line 29
    .line 30
    invoke-virtual {v2, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v5, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v3, v5

    .line 42
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-eqz v5, :cond_2

    .line 47
    .line 48
    const/16 v5, 0x800

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v5, 0x400

    .line 52
    .line 53
    :goto_2
    or-int/2addr v3, v5

    .line 54
    move-object/from16 v9, p4

    .line 55
    .line 56
    invoke-virtual {v2, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_3

    .line 61
    .line 62
    const/16 v5, 0x4000

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v5, 0x2000

    .line 66
    .line 67
    :goto_3
    or-int/2addr v3, v5

    .line 68
    move-wide/from16 v7, p5

    .line 69
    .line 70
    invoke-virtual {v2, v7, v8}, Ll2/t;->f(J)Z

    .line 71
    .line 72
    .line 73
    move-result v5

    .line 74
    if-eqz v5, :cond_4

    .line 75
    .line 76
    const/high16 v5, 0x20000

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/high16 v5, 0x10000

    .line 80
    .line 81
    :goto_4
    or-int/2addr v3, v5

    .line 82
    move/from16 v5, p7

    .line 83
    .line 84
    invoke-virtual {v2, v5}, Ll2/t;->d(F)Z

    .line 85
    .line 86
    .line 87
    move-result v11

    .line 88
    if-eqz v11, :cond_5

    .line 89
    .line 90
    const/high16 v11, 0x100000

    .line 91
    .line 92
    goto :goto_5

    .line 93
    :cond_5
    const/high16 v11, 0x80000

    .line 94
    .line 95
    :goto_5
    or-int/2addr v3, v11

    .line 96
    move/from16 v11, p8

    .line 97
    .line 98
    invoke-virtual {v2, v11}, Ll2/t;->d(F)Z

    .line 99
    .line 100
    .line 101
    move-result v12

    .line 102
    if-eqz v12, :cond_6

    .line 103
    .line 104
    const/high16 v12, 0x800000

    .line 105
    .line 106
    goto :goto_6

    .line 107
    :cond_6
    const/high16 v12, 0x400000

    .line 108
    .line 109
    :goto_6
    or-int/2addr v3, v12

    .line 110
    const/4 v12, 0x0

    .line 111
    invoke-virtual {v2, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v13

    .line 115
    if-eqz v13, :cond_7

    .line 116
    .line 117
    const/high16 v13, 0x4000000

    .line 118
    .line 119
    goto :goto_7

    .line 120
    :cond_7
    const/high16 v13, 0x2000000

    .line 121
    .line 122
    :goto_7
    or-int/2addr v3, v13

    .line 123
    invoke-virtual {v2, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v13

    .line 127
    if-eqz v13, :cond_8

    .line 128
    .line 129
    const/high16 v13, 0x20000000

    .line 130
    .line 131
    goto :goto_8

    .line 132
    :cond_8
    const/high16 v13, 0x10000000

    .line 133
    .line 134
    :goto_8
    or-int v18, v3, v13

    .line 135
    .line 136
    const v3, 0x12492493

    .line 137
    .line 138
    .line 139
    and-int v3, v18, v3

    .line 140
    .line 141
    const v13, 0x12492492

    .line 142
    .line 143
    .line 144
    const/16 v19, 0x1

    .line 145
    .line 146
    if-eq v3, v13, :cond_9

    .line 147
    .line 148
    move/from16 v3, v19

    .line 149
    .line 150
    goto :goto_9

    .line 151
    :cond_9
    const/4 v3, 0x0

    .line 152
    :goto_9
    and-int/lit8 v13, v18, 0x1

    .line 153
    .line 154
    invoke-virtual {v2, v13, v3}, Ll2/t;->O(IZ)Z

    .line 155
    .line 156
    .line 157
    move-result v3

    .line 158
    if-eqz v3, :cond_11

    .line 159
    .line 160
    shr-int/lit8 v3, v18, 0x3

    .line 161
    .line 162
    and-int/lit8 v3, v3, 0xe

    .line 163
    .line 164
    const/16 v13, 0x30

    .line 165
    .line 166
    or-int/2addr v3, v13

    .line 167
    const-string v13, "DropDownMenu"

    .line 168
    .line 169
    invoke-static {v4, v13, v2, v3}, Lc1/z1;->e(Lc1/n0;Ljava/lang/String;Ll2/o;I)Lc1/w1;

    .line 170
    .line 171
    .line 172
    move-result-object v3

    .line 173
    sget-object v13, Lk2/w;->e:Lk2/w;

    .line 174
    .line 175
    invoke-static {v13, v2}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 176
    .line 177
    .line 178
    move-result-object v13

    .line 179
    sget-object v15, Lk2/w;->g:Lk2/w;

    .line 180
    .line 181
    invoke-static {v15, v2}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 182
    .line 183
    .line 184
    move-result-object v20

    .line 185
    sget-object v15, Lc1/d;->j:Lc1/b2;

    .line 186
    .line 187
    iget-object v12, v3, Lc1/w1;->a:Lap0/o;

    .line 188
    .line 189
    iget-object v6, v3, Lc1/w1;->d:Ll2/j1;

    .line 190
    .line 191
    invoke-virtual {v12}, Lap0/o;->D()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v12

    .line 195
    check-cast v12, Ljava/lang/Boolean;

    .line 196
    .line 197
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 198
    .line 199
    .line 200
    move-result v12

    .line 201
    const v14, 0x894b891

    .line 202
    .line 203
    .line 204
    invoke-virtual {v2, v14}, Ll2/t;->Y(I)V

    .line 205
    .line 206
    .line 207
    const v17, 0x3f4ccccd    # 0.8f

    .line 208
    .line 209
    .line 210
    const/high16 v22, 0x3f800000    # 1.0f

    .line 211
    .line 212
    if-eqz v12, :cond_a

    .line 213
    .line 214
    move/from16 v12, v22

    .line 215
    .line 216
    :goto_a
    const/4 v14, 0x0

    .line 217
    goto :goto_b

    .line 218
    :cond_a
    move/from16 v12, v17

    .line 219
    .line 220
    goto :goto_a

    .line 221
    :goto_b
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 222
    .line 223
    .line 224
    invoke-static {v12}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 225
    .line 226
    .line 227
    move-result-object v12

    .line 228
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v23

    .line 232
    check-cast v23, Ljava/lang/Boolean;

    .line 233
    .line 234
    invoke-virtual/range {v23 .. v23}, Ljava/lang/Boolean;->booleanValue()Z

    .line 235
    .line 236
    .line 237
    move-result v23

    .line 238
    const v14, 0x894b891

    .line 239
    .line 240
    .line 241
    invoke-virtual {v2, v14}, Ll2/t;->Y(I)V

    .line 242
    .line 243
    .line 244
    if-eqz v23, :cond_b

    .line 245
    .line 246
    move/from16 v17, v22

    .line 247
    .line 248
    :cond_b
    const/4 v14, 0x0

    .line 249
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 250
    .line 251
    .line 252
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 253
    .line 254
    .line 255
    move-result-object v16

    .line 256
    invoke-virtual {v3}, Lc1/w1;->f()Lc1/r1;

    .line 257
    .line 258
    .line 259
    move-object/from16 v17, v3

    .line 260
    .line 261
    const v3, -0x2c766954

    .line 262
    .line 263
    .line 264
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 268
    .line 269
    .line 270
    move-object/from16 v11, v17

    .line 271
    .line 272
    const/16 v17, 0x0

    .line 273
    .line 274
    move v3, v14

    .line 275
    move-object v14, v13

    .line 276
    move-object/from16 v13, v16

    .line 277
    .line 278
    move-object/from16 v16, v2

    .line 279
    .line 280
    move/from16 v2, v19

    .line 281
    .line 282
    const/16 v19, 0x0

    .line 283
    .line 284
    invoke-static/range {v11 .. v17}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 285
    .line 286
    .line 287
    move-result-object v12

    .line 288
    move-object v13, v11

    .line 289
    move-object/from16 v11, v16

    .line 290
    .line 291
    iget-object v14, v13, Lc1/w1;->a:Lap0/o;

    .line 292
    .line 293
    invoke-virtual {v14}, Lap0/o;->D()Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v14

    .line 297
    check-cast v14, Ljava/lang/Boolean;

    .line 298
    .line 299
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 300
    .line 301
    .line 302
    move-result v14

    .line 303
    const v2, 0x353675a5

    .line 304
    .line 305
    .line 306
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 307
    .line 308
    .line 309
    const/16 v16, 0x0

    .line 310
    .line 311
    if-eqz v14, :cond_c

    .line 312
    .line 313
    move/from16 v14, v22

    .line 314
    .line 315
    goto :goto_c

    .line 316
    :cond_c
    move/from16 v14, v16

    .line 317
    .line 318
    :goto_c
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 319
    .line 320
    .line 321
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 322
    .line 323
    .line 324
    move-result-object v14

    .line 325
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v6

    .line 329
    check-cast v6, Ljava/lang/Boolean;

    .line 330
    .line 331
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 332
    .line 333
    .line 334
    move-result v6

    .line 335
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 336
    .line 337
    .line 338
    if-eqz v6, :cond_d

    .line 339
    .line 340
    goto :goto_d

    .line 341
    :cond_d
    move/from16 v22, v16

    .line 342
    .line 343
    :goto_d
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 344
    .line 345
    .line 346
    invoke-static/range {v22 .. v22}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 347
    .line 348
    .line 349
    move-result-object v2

    .line 350
    invoke-virtual {v13}, Lc1/w1;->f()Lc1/r1;

    .line 351
    .line 352
    .line 353
    const v6, 0x2b53c0

    .line 354
    .line 355
    .line 356
    invoke-virtual {v11, v6}, Ll2/t;->Y(I)V

    .line 357
    .line 358
    .line 359
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 360
    .line 361
    .line 362
    move-object/from16 v16, v11

    .line 363
    .line 364
    move-object v6, v12

    .line 365
    move-object v11, v13

    .line 366
    move-object v12, v14

    .line 367
    move-object/from16 v14, v20

    .line 368
    .line 369
    move-object v13, v2

    .line 370
    invoke-static/range {v11 .. v17}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 371
    .line 372
    .line 373
    move-result-object v2

    .line 374
    move-object/from16 v11, v16

    .line 375
    .line 376
    sget-object v12, Lw3/q1;->a:Ll2/u2;

    .line 377
    .line 378
    invoke-virtual {v11, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v12

    .line 382
    check-cast v12, Ljava/lang/Boolean;

    .line 383
    .line 384
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 385
    .line 386
    .line 387
    move-result v12

    .line 388
    invoke-virtual {v11, v12}, Ll2/t;->h(Z)Z

    .line 389
    .line 390
    .line 391
    move-result v13

    .line 392
    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    move-result v14

    .line 396
    or-int/2addr v13, v14

    .line 397
    and-int/lit8 v14, v18, 0x70

    .line 398
    .line 399
    const/16 v15, 0x20

    .line 400
    .line 401
    if-eq v14, v15, :cond_e

    .line 402
    .line 403
    goto :goto_e

    .line 404
    :cond_e
    const/4 v3, 0x1

    .line 405
    :goto_e
    or-int/2addr v3, v13

    .line 406
    invoke-virtual {v11, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 407
    .line 408
    .line 409
    move-result v13

    .line 410
    or-int/2addr v3, v13

    .line 411
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v13

    .line 415
    if-nez v3, :cond_f

    .line 416
    .line 417
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 418
    .line 419
    if-ne v13, v3, :cond_10

    .line 420
    .line 421
    :cond_f
    move-object v7, v2

    .line 422
    new-instance v2, Lca/e;

    .line 423
    .line 424
    const/4 v3, 0x2

    .line 425
    move-object/from16 v5, p2

    .line 426
    .line 427
    move v8, v12

    .line 428
    invoke-direct/range {v2 .. v8}, Lca/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    move-object v13, v2

    .line 435
    :cond_10
    check-cast v13, Lay0/k;

    .line 436
    .line 437
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 438
    .line 439
    invoke-static {v2, v13}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    new-instance v3, Lf2/b0;

    .line 444
    .line 445
    const/4 v4, 0x1

    .line 446
    invoke-direct {v3, v1, v0, v10, v4}, Lf2/b0;-><init>(Lx2/s;Le1/n1;Lt2/b;I)V

    .line 447
    .line 448
    .line 449
    const v4, -0x5739c786

    .line 450
    .line 451
    .line 452
    invoke-static {v4, v11, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 453
    .line 454
    .line 455
    move-result-object v20

    .line 456
    shr-int/lit8 v3, v18, 0x9

    .line 457
    .line 458
    and-int/lit8 v4, v3, 0x70

    .line 459
    .line 460
    const/high16 v5, 0xc00000

    .line 461
    .line 462
    or-int/2addr v4, v5

    .line 463
    and-int/lit16 v3, v3, 0x380

    .line 464
    .line 465
    or-int/2addr v3, v4

    .line 466
    shr-int/lit8 v4, v18, 0x6

    .line 467
    .line 468
    const v5, 0xe000

    .line 469
    .line 470
    .line 471
    and-int/2addr v5, v4

    .line 472
    or-int/2addr v3, v5

    .line 473
    const/high16 v5, 0x70000

    .line 474
    .line 475
    and-int/2addr v5, v4

    .line 476
    or-int/2addr v3, v5

    .line 477
    const/high16 v5, 0x380000

    .line 478
    .line 479
    and-int/2addr v4, v5

    .line 480
    or-int v22, v3, v4

    .line 481
    .line 482
    const/16 v23, 0x8

    .line 483
    .line 484
    const-wide/16 v15, 0x0

    .line 485
    .line 486
    move-wide/from16 v13, p5

    .line 487
    .line 488
    move/from16 v17, p7

    .line 489
    .line 490
    move/from16 v18, p8

    .line 491
    .line 492
    move-object v12, v9

    .line 493
    move-object/from16 v21, v11

    .line 494
    .line 495
    move-object v11, v2

    .line 496
    invoke-static/range {v11 .. v23}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 497
    .line 498
    .line 499
    move-object/from16 v11, v21

    .line 500
    .line 501
    goto :goto_f

    .line 502
    :cond_11
    move-object v11, v2

    .line 503
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 504
    .line 505
    .line 506
    :goto_f
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 507
    .line 508
    .line 509
    move-result-object v12

    .line 510
    if-eqz v12, :cond_12

    .line 511
    .line 512
    new-instance v0, Lh2/o5;

    .line 513
    .line 514
    move-object/from16 v2, p1

    .line 515
    .line 516
    move-object/from16 v3, p2

    .line 517
    .line 518
    move-object/from16 v4, p3

    .line 519
    .line 520
    move-object/from16 v5, p4

    .line 521
    .line 522
    move-wide/from16 v6, p5

    .line 523
    .line 524
    move/from16 v8, p7

    .line 525
    .line 526
    move/from16 v9, p8

    .line 527
    .line 528
    move/from16 v11, p11

    .line 529
    .line 530
    invoke-direct/range {v0 .. v11}, Lh2/o5;-><init>(Lx2/s;Lc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;I)V

    .line 531
    .line 532
    .line 533
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 534
    .line 535
    :cond_12
    return-void
.end method

.method public static final b(Lt2/b;Lay0/a;Lx2/s;ZLh2/n5;Lk1/z0;Ll2/o;I)V
    .locals 13

    .line 1
    move/from16 v3, p3

    .line 2
    .line 3
    move-object/from16 v7, p4

    .line 4
    .line 5
    move-object/from16 v8, p5

    .line 6
    .line 7
    move/from16 v9, p7

    .line 8
    .line 9
    move-object/from16 v10, p6

    .line 10
    .line 11
    check-cast v10, Ll2/t;

    .line 12
    .line 13
    const v0, -0x4efcd6dc

    .line 14
    .line 15
    .line 16
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, v9, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v10, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int/2addr v0, v9

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, v9

    .line 35
    :goto_1
    and-int/lit8 v1, v9, 0x30

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {v10, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit16 v1, v9, 0x180

    .line 52
    .line 53
    if-nez v1, :cond_5

    .line 54
    .line 55
    invoke-virtual {v10, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_4

    .line 60
    .line 61
    const/16 v2, 0x100

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_4
    const/16 v2, 0x80

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v2

    .line 67
    :cond_5
    and-int/lit16 v2, v9, 0xc00

    .line 68
    .line 69
    const/4 v4, 0x0

    .line 70
    if-nez v2, :cond_7

    .line 71
    .line 72
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_6

    .line 77
    .line 78
    const/16 v2, 0x800

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_6
    const/16 v2, 0x400

    .line 82
    .line 83
    :goto_4
    or-int/2addr v0, v2

    .line 84
    :cond_7
    and-int/lit16 v2, v9, 0x6000

    .line 85
    .line 86
    if-nez v2, :cond_9

    .line 87
    .line 88
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    if-eqz v2, :cond_8

    .line 93
    .line 94
    const/16 v2, 0x4000

    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_8
    const/16 v2, 0x2000

    .line 98
    .line 99
    :goto_5
    or-int/2addr v0, v2

    .line 100
    :cond_9
    const/high16 v2, 0x30000

    .line 101
    .line 102
    and-int/2addr v2, v9

    .line 103
    if-nez v2, :cond_b

    .line 104
    .line 105
    invoke-virtual {v10, v3}, Ll2/t;->h(Z)Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_a

    .line 110
    .line 111
    const/high16 v2, 0x20000

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_a
    const/high16 v2, 0x10000

    .line 115
    .line 116
    :goto_6
    or-int/2addr v0, v2

    .line 117
    :cond_b
    const/high16 v2, 0x180000

    .line 118
    .line 119
    and-int/2addr v2, v9

    .line 120
    if-nez v2, :cond_d

    .line 121
    .line 122
    invoke-virtual {v10, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    if-eqz v2, :cond_c

    .line 127
    .line 128
    const/high16 v2, 0x100000

    .line 129
    .line 130
    goto :goto_7

    .line 131
    :cond_c
    const/high16 v2, 0x80000

    .line 132
    .line 133
    :goto_7
    or-int/2addr v0, v2

    .line 134
    :cond_d
    const/high16 v2, 0xc00000

    .line 135
    .line 136
    and-int/2addr v2, v9

    .line 137
    if-nez v2, :cond_f

    .line 138
    .line 139
    invoke-virtual {v10, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-eqz v2, :cond_e

    .line 144
    .line 145
    const/high16 v2, 0x800000

    .line 146
    .line 147
    goto :goto_8

    .line 148
    :cond_e
    const/high16 v2, 0x400000

    .line 149
    .line 150
    :goto_8
    or-int/2addr v0, v2

    .line 151
    :cond_f
    const/high16 v2, 0x6000000

    .line 152
    .line 153
    and-int/2addr v2, v9

    .line 154
    const/4 v1, 0x0

    .line 155
    if-nez v2, :cond_11

    .line 156
    .line 157
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v2

    .line 161
    if-eqz v2, :cond_10

    .line 162
    .line 163
    const/high16 v2, 0x4000000

    .line 164
    .line 165
    goto :goto_9

    .line 166
    :cond_10
    const/high16 v2, 0x2000000

    .line 167
    .line 168
    :goto_9
    or-int/2addr v0, v2

    .line 169
    :cond_11
    const v2, 0x2492493

    .line 170
    .line 171
    .line 172
    and-int/2addr v2, v0

    .line 173
    const v4, 0x2492492

    .line 174
    .line 175
    .line 176
    const/4 v11, 0x1

    .line 177
    if-eq v2, v4, :cond_12

    .line 178
    .line 179
    move v2, v11

    .line 180
    goto :goto_a

    .line 181
    :cond_12
    const/4 v2, 0x0

    .line 182
    :goto_a
    and-int/2addr v0, v11

    .line 183
    invoke-virtual {v10, v0, v2}, Ll2/t;->O(IZ)Z

    .line 184
    .line 185
    .line 186
    move-result v0

    .line 187
    if-eqz v0, :cond_16

    .line 188
    .line 189
    const/4 v0, 0x0

    .line 190
    const-wide/16 v4, 0x0

    .line 191
    .line 192
    const/4 v2, 0x6

    .line 193
    invoke-static {v4, v5, v0, v2, v11}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    const/4 v4, 0x0

    .line 198
    const/16 v6, 0x18

    .line 199
    .line 200
    move-object v5, p1

    .line 201
    move-object v0, p2

    .line 202
    invoke-static/range {v0 .. v6}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    const/high16 v0, 0x3f800000    # 1.0f

    .line 207
    .line 208
    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    sget v1, Lh2/q5;->b:F

    .line 213
    .line 214
    const/16 v2, 0x8

    .line 215
    .line 216
    sget v4, Lh2/q5;->e:F

    .line 217
    .line 218
    sget v5, Lh2/q5;->f:F

    .line 219
    .line 220
    invoke-static {v0, v4, v1, v5, v2}, Landroidx/compose/foundation/layout/d;->q(Lx2/s;FFFI)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-static {v0, v8}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 229
    .line 230
    sget-object v2, Lk1/j;->a:Lk1/c;

    .line 231
    .line 232
    const/16 v4, 0x30

    .line 233
    .line 234
    invoke-static {v2, v1, v10, v4}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    iget-wide v5, v10, Ll2/t;->T:J

    .line 239
    .line 240
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 241
    .line 242
    .line 243
    move-result v2

    .line 244
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 245
    .line 246
    .line 247
    move-result-object v5

    .line 248
    invoke-static {v10, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 253
    .line 254
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 255
    .line 256
    .line 257
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 258
    .line 259
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 260
    .line 261
    .line 262
    iget-boolean v12, v10, Ll2/t;->S:Z

    .line 263
    .line 264
    if-eqz v12, :cond_13

    .line 265
    .line 266
    invoke-virtual {v10, v6}, Ll2/t;->l(Lay0/a;)V

    .line 267
    .line 268
    .line 269
    goto :goto_b

    .line 270
    :cond_13
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 271
    .line 272
    .line 273
    :goto_b
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 274
    .line 275
    invoke-static {v6, v1, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 276
    .line 277
    .line 278
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 279
    .line 280
    invoke-static {v1, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 281
    .line 282
    .line 283
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 284
    .line 285
    iget-boolean v5, v10, Ll2/t;->S:Z

    .line 286
    .line 287
    if-nez v5, :cond_14

    .line 288
    .line 289
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v5

    .line 293
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 294
    .line 295
    .line 296
    move-result-object v6

    .line 297
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 298
    .line 299
    .line 300
    move-result v5

    .line 301
    if-nez v5, :cond_15

    .line 302
    .line 303
    :cond_14
    invoke-static {v2, v10, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 304
    .line 305
    .line 306
    :cond_15
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 307
    .line 308
    invoke-static {v1, v0, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 309
    .line 310
    .line 311
    sget-object v0, Lh2/ec;->a:Ll2/u2;

    .line 312
    .line 313
    invoke-virtual {v10, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    check-cast v0, Lh2/dc;

    .line 318
    .line 319
    iget-object v0, v0, Lh2/dc;->m:Lg4/p0;

    .line 320
    .line 321
    new-instance v1, Lh2/p5;

    .line 322
    .line 323
    invoke-direct {v1, v7, v3, p0}, Lh2/p5;-><init>(Lh2/n5;ZLt2/b;)V

    .line 324
    .line 325
    .line 326
    const v2, 0x339e1c39

    .line 327
    .line 328
    .line 329
    invoke-static {v2, v10, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    invoke-static {v0, v1, v10, v4}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v10, v11}, Ll2/t;->q(Z)V

    .line 337
    .line 338
    .line 339
    goto :goto_c

    .line 340
    :cond_16
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 341
    .line 342
    .line 343
    :goto_c
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 344
    .line 345
    .line 346
    move-result-object v10

    .line 347
    if-eqz v10, :cond_17

    .line 348
    .line 349
    new-instance v0, Le71/c;

    .line 350
    .line 351
    move-object v1, p0

    .line 352
    move-object v2, p1

    .line 353
    move v4, v3

    .line 354
    move-object v5, v7

    .line 355
    move-object v6, v8

    .line 356
    move v7, v9

    .line 357
    move-object v3, p2

    .line 358
    invoke-direct/range {v0 .. v7}, Le71/c;-><init>(Lt2/b;Lay0/a;Lx2/s;ZLh2/n5;Lk1/z0;I)V

    .line 359
    .line 360
    .line 361
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 362
    .line 363
    :cond_17
    return-void
.end method
